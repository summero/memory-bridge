"""Descriptor-based, read-only enumeration of Markdown files under a root.

Every path step is opened relative to an already-open parent directory with
``O_NOFOLLOW``, and every check that matters (file type, link count, size) is
made with ``fstat`` on the open descriptor. That closes the gap between checking
a path and opening it: a symlink or special file swapped in after listing is
refused at open time rather than followed.

Nothing in this module writes, creates, renames, or deletes.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from typing import Callable, Iterator, Sequence

from . import acl
from .errors import MemoryBridgeError, unavailable

# Conservative ASCII names: no leading dot (hidden files), no separators, no spaces.
NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}")
MARKDOWN_SUFFIX = ".md"
# Longest document id and deepest id the read tool accepts. Search must never return an id that
# read would reject, so the walk skips anything past these bounds (decided by names alone).
MAX_ID_CHARS = 512
MAX_ID_SEGMENTS = 16
# Smallest possible file name ("a.md"), used to prune directories that cannot hold a readable id.
_MIN_FILE_ID_CHARS = 1 + len(MARKDOWN_SUFFIX)
# Root-owned sticky directories that are accepted as transit points on a trusted path. Sticky
# semantics stop other users from replacing the *next* entry, and every entry is owner-checked in
# turn. Any other sticky or writable directory is refused, whoever owns it.
SYSTEM_TEMP_DIRS = frozenset({"/private/tmp", "/private/var/tmp", "/tmp", "/var/tmp"})
# Total bytes read in one search, independent of per-file and entry limits.
MAX_SCAN_BYTES = 16 * 1024 * 1024
# Hard ceiling on raw directory entries listed in one call, denied and skipped names included.
MAX_SCAN_ENTRIES = 50_000

_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | _CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_NOCTTY", 0) | _CLOEXEC


@dataclass(frozen=True)
class Document:
    id: str  # root-relative POSIX path using on-disk names
    text: str


@dataclass
class ScanStats:
    scanned: int = 0  # raw directory entries listed, including denied and skipped names
    entries: int = 0  # allowed Markdown candidates considered
    bytes_read: int = 0
    truncated: bool = False
    stopped: bool = False
    files_opened: list = field(default_factory=list)


def is_valid_name(name: str) -> bool:
    return bool(NAME_RE.fullmatch(name)) and name not in (".", "..")


def is_markdown_name(name: str) -> bool:
    return name.casefold().endswith(MARKDOWN_SUFFIX) and len(name) > len(MARKDOWN_SUFFIX)


def read_bounded(fd: int, max_bytes: int, stats=None) -> bytes:
    """Read at most ``max_bytes + 1`` bytes so callers can detect oversize content.

    With ``stats``, each chunk is charged to ``stats.bytes_read`` as soon as it is read, so bytes
    already consumed stay counted even if a later read raises."""
    chunks = []
    remaining = max_bytes + 1
    while remaining > 0:
        chunk = os.read(fd, min(remaining, 65536))
        if not chunk:
            break
        if stats is not None:
            stats.bytes_read += len(chunk)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def check_trusted_directory(fd: int, info, path: str, final: bool) -> None:
    """Refuse a directory that someone other than the operator or root could alter.

    Applied to every component of the policy path and of the memory-root path, to the final
    directory of each, and to every directory traversed below the root. A directory passes only if:

    * it is a directory owned by root or the running user;
    * it is not group- or world-writable. The single exception is a root-owned sticky directory
      that is exactly one of ``SYSTEM_TEMP_DIRS`` *and only as an intermediate transit ancestor*
      (``final`` false): sticky stops other users replacing the next entry, which is owner-checked
      in turn. The final directory, whose entries Memory Bridge actually uses, never gets it;
    * its ACL, read from the open descriptor, grants write-class access to no one but the
      running user or root. If the ACL cannot be inspected, the directory is refused.
    """
    if not stat.S_ISDIR(info.st_mode):
        raise unavailable("directory_not_directory")
    if info.st_uid not in (0, os.getuid()):
        raise unavailable("directory_wrong_owner")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        sticky_transit = (not final and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
                          and path in SYSTEM_TEMP_DIRS)
        if not sticky_transit:
            raise unavailable("directory_writable_by_others")
    acl.require_no_foreign_write_acl(fd)


def check_trusted_file(fd: int, info) -> None:
    """Refuse a file that someone other than the operator or root could alter."""
    if info.st_uid not in (0, os.getuid()):
        raise unavailable("file_wrong_owner")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise unavailable("file_writable_by_others")
    acl.require_no_foreign_write_acl(fd)


def open_directory_path(path: str, check=None) -> int:
    """Walk from the filesystem root using pinned, no-follow descriptors.

    No absolute open after validation: each component is resolved only against
    its open parent. The optional checker, ``check(fd, info, path_so_far, is_final)``, runs on
    every component before that directory is used; ``is_final`` marks the last one. This uses portable openat semantics on both
    macOS and Linux.
    """
    if (not isinstance(path, str) or not path.startswith("/") or
            path.startswith("//") or "\x00" in path or os.path.normpath(path) != path):
        raise OSError("noncanonical directory path")
    fd = os.open("/", _DIR_FLAGS)
    try:
        components = [c for c in path.split("/")[1:] if c]
        if check is not None:
            check(fd, os.fstat(fd), "/", not components)
        walked = ""
        for index, component in enumerate(components):
            child = os.open(component, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
            walked += "/" + component
            if check is not None:
                check(fd, os.fstat(fd), walked, index == len(components) - 1)
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_root(root: str) -> int:
    """Open the memory root, requiring every ancestor and the root itself to be trusted."""
    try:
        return open_directory_path(root, check_trusted_directory)
    except OSError as exc:
        raise unavailable("root_unopenable") from exc


def open_subdir(parent_fd: int, name: str, root_dev: int):
    """Open a child directory without following symlinks; None if refused."""
    if not is_valid_name(name):
        return None
    try:
        fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if stat.S_ISDIR(info.st_mode) and info.st_dev == root_dev:
            # Descendants get the root's trust rule with no sticky exception; an untrusted
            # directory is skipped, like a symlink or a directory on another device.
            check_trusted_directory(fd, info, "", True)
            return fd
    except (OSError, MemoryBridgeError):
        pass
    os.close(fd)
    return None


def read_markdown_file(parent_fd: int, name: str, max_bytes: int, root_dev=None, stats=None):
    """Return decoded text of a single-link regular file within limits, else None.

    Every byte actually read is charged to ``stats.bytes_read`` before the content is judged,
    so oversized, binary, and invalid-UTF-8 files use up the scan budget like any other."""
    if not is_valid_name(name):
        return None
    try:
        if root_dev is None:
            root_dev = os.fstat(parent_fd).st_dev
        fd = os.open(name, _FILE_FLAGS, dir_fd=parent_fd)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_size > max_bytes or info.st_dev != root_dev):
            return None
        check_trusted_file(fd, info)  # before any content is read
        data = read_bounded(fd, max_bytes, stats)
    except (OSError, MemoryBridgeError):
        return None
    finally:
        os.close(fd)
    if len(data) > max_bytes or b"\x00" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def iter_documents(
    root: str,
    is_allowed: Callable[[Sequence[str]], bool],
    may_descend: Callable[[Sequence[str]], bool],
    *,
    max_file_bytes: int,
    max_entries: int,
    max_depth: int,
    stats: ScanStats,
) -> Iterator[Document]:
    """Yield allowed Markdown documents. Denied files and fully denied directories are
    filtered by name before they are opened."""
    root_fd = open_root(root)
    try:
        root_dev = os.fstat(root_fd).st_dev
        yield from _walk(root_fd, (), 1, root_dev, is_allowed, may_descend,
                         max_file_bytes, max_entries, max_depth, stats)
    finally:
        os.close(root_fd)


def _list_names(dir_fd: int, stats: ScanStats):
    """All (name, is_dir) pairs in a directory, sorted. Symlinks and invalid names are skipped.

    Every raw entry counts toward the hard ``MAX_SCAN_ENTRIES`` ceiling. Crossing it refuses the
    whole call: a partial result would have a cut-off that depends on names the caller may not see.
    """
    found = []
    try:
        with os.scandir(dir_fd) as entries:
            for entry in entries:
                stats.scanned += 1
                if stats.scanned > MAX_SCAN_ENTRIES:
                    raise unavailable("scan_limit_exceeded")
                name = entry.name
                if not is_valid_name(name) or entry.is_symlink():
                    continue
                found.append((name, entry.is_dir(follow_symlinks=False)))
    except OSError:
        return []
    found.sort()
    return found


def _cannot_hold_readable_id(parts, is_dir: bool) -> bool:
    """True if no document at or below ``parts`` can have an id the read tool accepts.

    Uses the read tool's own bounds (``MAX_ID_SEGMENTS`` segments, ``MAX_ID_CHARS`` characters),
    decided by names alone. A directory still needs room for one more segment and "/a.md"."""
    if is_dir:
        return (len(parts) >= MAX_ID_SEGMENTS or
                len("/".join(parts)) + 1 + _MIN_FILE_ID_CHARS > MAX_ID_CHARS)
    return len(parts) > MAX_ID_SEGMENTS or len("/".join(parts)) > MAX_ID_CHARS


def _allowed_below(dir_fd, parts, root_dev, is_allowed, may_descend, stats) -> bool:
    """True if an allowed Markdown name with a readable id exists in this directory or below it.

    Lists names only (no file is opened or read) and charges every listed entry to the hard
    entry ceiling. Recursion is bounded by the id limits, never by an arbitrary depth, so a tree
    of only denied, empty, or unreadable-id names answers False. Directories go through the same
    trust check as the walk."""
    for name, is_dir in _list_names(dir_fd, stats):
        child_parts = parts + (name,)
        if _cannot_hold_readable_id(child_parts, is_dir):
            continue
        if is_dir:
            if not may_descend(child_parts):
                continue
            sub_fd = open_subdir(dir_fd, name, root_dev)
            if sub_fd is None:
                continue
            try:
                if _allowed_below(sub_fd, child_parts, root_dev, is_allowed, may_descend, stats):
                    return True
            finally:
                os.close(sub_fd)
        elif is_markdown_name(name) and is_allowed(child_parts):
            return True
    return False


def _walk(dir_fd, parts, depth, root_dev, is_allowed, may_descend,
          max_file_bytes, max_entries, max_depth, stats):
    for name, is_dir in _list_names(dir_fd, stats):
        if stats.stopped:
            return
        child_parts = parts + (name,)
        if is_dir:
            # Decided by names alone: nothing below can have an id that the read tool accepts.
            if _cannot_hold_readable_id(child_parts, True):
                continue
            if not may_descend(child_parts):
                continue
            sub_fd = open_subdir(dir_fd, name, root_dev)
            if sub_fd is None:
                continue
            if depth >= max_depth:
                # Truncated only if an allowed document exists past the boundary; names that
                # are denied or filtered must not change the flag.
                try:
                    if _allowed_below(sub_fd, child_parts, root_dev, is_allowed, may_descend, stats):
                        stats.truncated = True
                finally:
                    os.close(sub_fd)
                continue
            try:
                yield from _walk(sub_fd, child_parts, depth + 1, root_dev, is_allowed, may_descend,
                                 max_file_bytes, max_entries, max_depth, stats)
            finally:
                os.close(sub_fd)
            continue
        if not is_markdown_name(name) or _cannot_hold_readable_id(child_parts, False):
            continue
        if not is_allowed(child_parts):
            continue
        # Only allowed candidates, visited in sorted order, count toward the soft limits, so
        # denied names can never move the cut-off or the ``truncated`` flag.
        if stats.entries >= max_entries or stats.bytes_read >= MAX_SCAN_BYTES:
            stats.truncated = True
            stats.stopped = True
            return
        stats.entries += 1
        doc_id = "/".join(child_parts)
        stats.files_opened.append(doc_id)
        text = read_markdown_file(dir_fd, name, max_file_bytes, root_dev, stats)
        if text is None:
            continue
        yield Document(id=doc_id, text=text)


def read_document(root: str, parts: Sequence[str], max_file_bytes: int):
    """Open one document by path segments under the same rules as the walk; None if refused.

    Each directory is opened relative to its already-open parent without following symlinks,
    so the check and the read happen on the same objects.
    """
    root_fd = open_root(root)
    fds = [root_fd]
    try:
        root_dev = os.fstat(root_fd).st_dev
        for name in parts[:-1]:
            sub_fd = open_subdir(fds[-1], name, root_dev)
            if sub_fd is None:
                return None
            fds.append(sub_fd)
        return read_markdown_file(fds[-1], parts[-1], max_file_bytes, root_dev)
    finally:
        for fd in reversed(fds):
            os.close(fd)
