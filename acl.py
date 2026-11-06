"""Reject directories and files whose ACL grants write access to anyone but the operator.

POSIX mode bits do not show ACL grants, so a path can look private (``0700``) or merely
unwritable by others while an ACL lets ``everyone`` or a group write to it. This module reads
the ACL from the *open descriptor* (no path race) and refuses any ``allow`` entry that carries a
write-class permission for a principal other than the running user or root.

The check is deliberately conservative:

* ``deny`` entries are ignored, so an allow entry is never excused by a deny elsewhere.
* An entry that cannot be parsed, a platform without an inspector, or a failing system call all
  raise ``unavailable``. Nothing here falls back to trusting mode bits.

macOS reads the extended ACL through ``acl_get_fd_np``. Linux reads the POSIX access ACL from the
``system.posix_acl_access`` extended attribute. Other platforms are refused.
"""

from __future__ import annotations

import errno
import functools
import os
import struct
import sys

from .errors import unavailable

# macOS permission names that let a principal change the object or the directory's entries.
_DARWIN_WRITE_PERMS = frozenset({
    "write", "append", "add_file", "add_subdirectory", "delete", "delete_child",
    "writeattr", "writeextattr", "writesecurity", "chown",
})
_DARWIN_KNOWN_PERMS = _DARWIN_WRITE_PERMS | frozenset({
    "read", "list", "search", "execute", "readattr", "readextattr", "readsecurity",
    "limited_inherit", "only_inherit", "file_inherit", "directory_inherit",
})
_ACL_TYPE_EXTENDED = 0x00000100

_LINUX_XATTR = "system.posix_acl_access"
_LINUX_ACL_VERSION = 2
_LINUX_UNDEFINED_ID = 0xFFFFFFFF
_LINUX_USER_OBJ, _LINUX_USER, _LINUX_GROUP_OBJ, _LINUX_GROUP, _LINUX_MASK, _LINUX_OTHER = (
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20)
_LINUX_PERM_WRITE = 0x02
_LINUX_PERM_ALL = 0x07
_LINUX_MAX_ENTRIES = 1024
# Only "this attribute does not exist" proves there is no extended ACL. ENOTSUP/EOPNOTSUPP mean
# the filesystem cannot answer, which is not the same thing, so they fail closed.
_NO_ACL_ERRNOS = frozenset(
    code for code in (getattr(errno, "ENODATA", None), getattr(errno, "ENOATTR", None))
    if code is not None)


def darwin_acl_text_is_unsafe(text: str, uid: int) -> bool:
    """True if an ``acl_to_text`` dump allows a write-class permission to anyone but ``uid``/root.

    Raises ``unavailable`` for a dump that does not look like the documented format.
    """
    lines = text.splitlines()
    if not lines or not lines[0].startswith("!#acl"):
        raise unavailable("acl_unparseable")
    unsafe = False
    for line in lines[1:]:
        if not line.strip():
            continue
        fields = line.split(":")
        # tag:guid:name:id:allow|deny:perm[,perm...]
        if len(fields) != 6 or fields[0] not in ("user", "group") or fields[4] not in ("allow", "deny"):
            raise unavailable("acl_unparseable")
        perms = set(fields[5].split(",")) if fields[5] else set()
        if not perms <= _DARWIN_KNOWN_PERMS:
            raise unavailable("acl_unparseable")
        if fields[4] != "allow" or not perms & _DARWIN_WRITE_PERMS:
            continue
        if fields[0] == "user" and fields[3] in (str(uid), "0"):
            continue
        unsafe = True
    return unsafe


def linux_acl_blob_is_unsafe(blob: bytes, uid: int) -> bool:
    """Validate a ``system.posix_acl_access`` value and report whether it gives write access to
    a named user other than ``uid``/root, or to any named group.

    The structure is validated the way the kernel does: version 2; known tags only; permission
    bits within rwx; exactly one each of USER_OBJ, GROUP_OBJ and OTHER; a single MASK that is
    present exactly when named entries are; undefined ids on unnamed tags and real ids on named
    ones; entries in tag order with strictly increasing ids inside USER and GROUP. Anything else
    raises ``unavailable`` instead of being guessed at.
    """
    if (len(blob) < 4 or (len(blob) - 4) % 8 or
            (len(blob) - 4) // 8 > _LINUX_MAX_ENTRIES):
        raise unavailable("acl_unparseable")
    (version,) = struct.unpack_from("<I", blob, 0)
    if version != _LINUX_ACL_VERSION:
        raise unavailable("acl_unparseable")
    entries = [struct.unpack_from("<HHI", blob, offset) for offset in range(4, len(blob), 8)]
    counts = {}
    previous_tag, previous_id = 0, -1
    for tag, perm, ident in entries:
        if tag not in (_LINUX_USER_OBJ, _LINUX_USER, _LINUX_GROUP_OBJ, _LINUX_GROUP,
                       _LINUX_MASK, _LINUX_OTHER) or perm & ~_LINUX_PERM_ALL:
            raise unavailable("acl_unparseable")
        named = tag in (_LINUX_USER, _LINUX_GROUP)
        if (ident == _LINUX_UNDEFINED_ID) == named:
            raise unavailable("acl_unparseable")
        if tag < previous_tag or (tag == previous_tag and named and ident <= previous_id):
            raise unavailable("acl_unparseable")
        previous_tag, previous_id = tag, ident
        counts[tag] = counts.get(tag, 0) + 1
    for tag in (_LINUX_USER_OBJ, _LINUX_GROUP_OBJ, _LINUX_OTHER):
        if counts.get(tag) != 1:
            raise unavailable("acl_unparseable")
    has_named = bool(counts.get(_LINUX_USER) or counts.get(_LINUX_GROUP))
    if counts.get(_LINUX_MASK, 0) != (1 if has_named else 0):
        raise unavailable("acl_unparseable")
    for tag, perm, ident in entries:
        if not perm & _LINUX_PERM_WRITE:
            continue
        if tag == _LINUX_USER and ident in (uid, 0):
            continue
        if tag in (_LINUX_USER, _LINUX_GROUP):
            return True
    return False


@functools.lru_cache(maxsize=1)
def _darwin_libc():
    import ctypes
    import ctypes.util

    name = ctypes.util.find_library("c")
    if not name:
        raise unavailable("acl_unverifiable")
    libc = ctypes.CDLL(name, use_errno=True)
    try:
        libc.acl_get_fd_np, libc.acl_to_text, libc.acl_free
    except AttributeError as exc:
        raise unavailable("acl_unverifiable") from exc
    return libc


def _darwin_acl_text(fd: int):
    import ctypes

    libc = _darwin_libc()
    get_acl, to_text, free = libc.acl_get_fd_np, libc.acl_to_text, libc.acl_free
    get_acl.restype = ctypes.c_void_p
    get_acl.argtypes = [ctypes.c_int, ctypes.c_int]
    to_text.restype = ctypes.c_void_p
    to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t)]
    free.restype = ctypes.c_int
    free.argtypes = [ctypes.c_void_p]

    ctypes.set_errno(0)
    acl = get_acl(fd, _ACL_TYPE_EXTENDED)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:  # documented answer for "no ACL on this object"
            return None
        raise unavailable("acl_unverifiable")
    try:
        raw = to_text(acl, None)
        if not raw:
            raise unavailable("acl_unverifiable")
        try:
            return ctypes.string_at(raw).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise unavailable("acl_unparseable") from exc
        finally:
            free(raw)
    finally:
        free(acl)


def _linux_acl_blob(fd: int):
    try:
        return os.getxattr(fd, _LINUX_XATTR)
    except OSError as exc:
        if exc.errno in _NO_ACL_ERRNOS:
            return None
        raise unavailable("acl_unverifiable") from exc
    except AttributeError as exc:
        raise unavailable("acl_unverifiable") from exc


def require_no_foreign_write_acl(fd: int) -> None:
    """Raise ``unavailable`` if the object behind ``fd`` has an unsafe or unreadable ACL."""
    uid = os.getuid()
    if sys.platform == "darwin":
        text = _darwin_acl_text(fd)
        if text is not None and darwin_acl_text_is_unsafe(text, uid):
            raise unavailable("acl_grants_write")
    elif sys.platform.startswith("linux"):
        blob = _linux_acl_blob(fd)
        if blob is not None and linux_acl_blob_is_unsafe(blob, uid):
            raise unavailable("acl_grants_write")
    else:
        raise unavailable("acl_unsupported_platform")
