"""Operator policy: loading, strict validation, and deny-wins path matching.

The policy lives in the calling profile's plugin data directory and is read on
every call. Anything missing, unreadable, malformed, or unexpected fails closed.

Example::

    {
      "version": 1,
      "root": "/absolute/canonical/path/to/memory",
      "allow": ["projects/**", "decisions/*.md"],
      "deny": ["**/private/**"],
      "allow_cron": false,
      "allow_subagents": false,
      "limits": {"max_results": 10, "snippet_chars": 300}
    }
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from . import acl
from .errors import unavailable
from .safe_fs import check_trusted_directory, open_directory_path, read_bounded

POLICY_VERSION = 1
MAX_POLICY_BYTES = 64 * 1024
MAX_PATTERNS = 64
MAX_PATTERN_CHARS = 200

_TOP_LEVEL_KEYS = {"version", "root", "allow", "deny", "allow_cron", "allow_subagents", "limits"}
_PATTERN_SEGMENT = re.compile(r"[a-z0-9_.*-]+")

# name: (default, minimum, hard maximum). Operators may lower limits, never raise them past the cap.
LIMIT_BOUNDS = {
    "max_results": (10, 1, 10),
    "default_results": (5, 1, 10),
    "snippet_chars": (300, 40, 300),
    "total_chars": (4000, 200, 4000),
    "max_file_bytes": (256 * 1024, 1, 1024 * 1024),
    "max_entries": (2000, 1, 10000),
    "max_depth": (8, 1, 16),
    "read_chars": (8000, 200, 8000),
}


@dataclass(frozen=True)
class Limits:
    max_results: int
    default_results: int
    snippet_chars: int
    total_chars: int
    max_file_bytes: int
    max_entries: int
    max_depth: int
    read_chars: int


@dataclass(frozen=True)
class Policy:
    root: str
    allow: tuple
    deny: tuple
    allow_cron: bool
    allow_subagents: bool
    limits: Limits

    def is_allowed(self, parts: Sequence[str]) -> bool:
        """True only if some allow pattern matches and no deny pattern does."""
        folded = [normalize_segment(p) for p in parts]
        if any(_match(pattern, folded) for pattern in self.deny):
            return False
        return any(_match(pattern, folded) for pattern in self.allow)

    def may_descend(self, dir_parts: Sequence[str]) -> bool:
        """False when no allowed file can exist below this directory, so it is never opened."""
        folded = [normalize_segment(p) for p in dir_parts]
        for pattern in self.deny:
            if pattern[-1] == "**" and _match(pattern[:-1], folded):
                return False
        return any(_could_extend(pattern, folded) for pattern in self.allow)


def _could_extend(pattern: tuple, parts: list) -> bool:
    """True if some path that starts with ``parts`` and goes deeper could match ``pattern``."""
    if not parts:
        return bool(pattern)
    if not pattern:
        return False
    head, rest = pattern[0], pattern[1:]
    if head == "**":
        return True
    return fnmatch.fnmatchcase(parts[0], head) and _could_extend(rest, parts[1:])


def normalize_segment(segment: str) -> str:
    # casefold so that matching agrees with case-insensitive filesystems (APFS, NTFS defaults).
    return segment.casefold()


def _match(pattern: tuple, parts: list) -> bool:
    """Segment-wise glob: ``**`` spans zero or more segments, ``*`` stays inside one."""
    if not pattern:
        return not parts
    head, rest = pattern[0], pattern[1:]
    if head == "**":
        return any(_match(rest, parts[i:]) for i in range(len(parts) + 1))
    return bool(parts) and fnmatch.fnmatchcase(parts[0], head) and _match(rest, parts[1:])


def _compile_patterns(value, field: str) -> tuple:
    if not isinstance(value, list) or len(value) > MAX_PATTERNS:
        raise unavailable(f"policy_{field}_invalid")
    compiled = []
    for raw in value:
        if not isinstance(raw, str) or not raw or len(raw) > MAX_PATTERN_CHARS:
            raise unavailable(f"policy_{field}_invalid")
        if raw.startswith("/") or "\\" in raw or "\x00" in raw:
            raise unavailable(f"policy_{field}_invalid")
        segments = raw.casefold().split("/")
        for seg in segments:
            if seg in ("", ".", "..") or not _PATTERN_SEGMENT.fullmatch(seg):
                raise unavailable(f"policy_{field}_invalid")
            if "**" in seg and seg != "**":
                raise unavailable(f"policy_{field}_invalid")
        compiled.append(tuple(segments))
    return tuple(compiled)


def _parse_limits(value) -> Limits:
    if value is None:
        value = {}
    if not isinstance(value, dict) or set(value) - set(LIMIT_BOUNDS):
        raise unavailable("policy_limits_invalid")
    resolved = {}
    for name, (default, low, high) in LIMIT_BOUNDS.items():
        item = value.get(name, default)
        if isinstance(item, bool) or not isinstance(item, int) or not low <= item <= high:
            raise unavailable("policy_limits_invalid")
        resolved[name] = item
    limits = Limits(**resolved)
    if limits.default_results > limits.max_results or limits.total_chars < limits.snippet_chars:
        raise unavailable("policy_limits_invalid")
    return limits


def _validate_root(value) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise unavailable("policy_root_invalid")
    if not os.path.isabs(value):
        raise unavailable("policy_root_invalid")
    # Canonical means no "..", no redundant separators, and no symlinked ancestors.
    if os.path.normpath(value) != value or os.path.realpath(value) != value:
        raise unavailable("policy_root_invalid")
    return value


def parse_policy(data) -> Policy:
    if not isinstance(data, dict) or set(data) - _TOP_LEVEL_KEYS:
        raise unavailable("policy_schema_invalid")
    if data.get("version") != POLICY_VERSION or isinstance(data.get("version"), bool):
        raise unavailable("policy_version_unsupported")
    allow = _compile_patterns(data.get("allow"), "allow")
    if not allow:
        raise unavailable("policy_allow_empty")
    deny = _compile_patterns(data.get("deny", []), "deny")
    flags = {}
    for name in ("allow_cron", "allow_subagents"):
        flag = data.get(name, False)
        if not isinstance(flag, bool):
            raise unavailable("policy_schema_invalid")
        flags[name] = flag
    return Policy(
        root=_validate_root(data.get("root")),
        allow=allow,
        deny=deny,
        limits=_parse_limits(data.get("limits")),
        **flags,
    )


def _reject_duplicate_keys(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError("duplicate key")
        seen[key] = value
    return seen


def load_policy(path: Path) -> Policy:
    """Read and validate the policy file. Never cached: operators can revoke access at any time."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        parent_fd = open_directory_path(str(path.parent), check_trusted_directory)
        try:
            fd = os.open(path.name, flags, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
    except OSError as exc:
        raise unavailable("policy_unreadable") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_POLICY_BYTES:
            raise unavailable("policy_not_regular_or_too_large")
        # Only the operator may control the policy.
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise unavailable("policy_writable_by_others")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise unavailable("policy_wrong_owner")
        # Mode bits do not show ACL grants; refuse (or fail closed) on the open descriptor.
        acl.require_no_foreign_write_acl(fd)
        raw = read_bounded(fd, MAX_POLICY_BYTES)
    except OSError as exc:
        raise unavailable("policy_unreadable") from exc
    finally:
        os.close(fd)
    if len(raw) > MAX_POLICY_BYTES:
        raise unavailable("policy_not_regular_or_too_large")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, ValueError) as exc:
        raise unavailable("policy_json_invalid") from exc
    return parse_policy(data)
