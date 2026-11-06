"""Regression fixtures for Security Pass C (C1-C6). Synthetic temporary directories only."""
from pathlib import Path
import dataclasses
import errno
import json
import os
import shutil
import stat
import subprocess
import sys
import unittest
from unittest import mock

from _support import FakeCtx, Sandbox, acl, errors, runtime, safe_fs
from test_security_pass_b import AclParserTests, add_acl

DARWIN = sys.platform == "darwin"
UNSAFE_DIR_MODES = (0o777, 0o770, 0o707, 0o722, 0o1777)
UNSAFE_FILE_MODES = (0o666, 0o664, 0o606, 0o620, 0o602)


def foreign_owner(path, target_module):
    """Patch fstat so the object at ``path`` appears owned by another user."""
    original = os.fstat
    inode = os.stat(path).st_ino

    def fake(fd):
        result = original(fd)
        if result.st_ino == inode:
            values = list(result)
            values[4] = os.getuid() + 4242
            return os.stat_result(values)
        return result
    return mock.patch.object(target_module.os, "fstat", side_effect=fake)


class UntrustedDescendantTests(unittest.TestCase):
    """C1: directories and files below the root get the same trust rule as the root."""

    def setUp(self):
        self.box = Sandbox()
        self.addCleanup(self.box.cleanup)
        self.box.write("top.md", "findable top")
        self.box.write("shared/inner.md", "findable inner")
        self.box.write("shared/deeper/leaf.md", "findable leaf")
        self.box.write_policy()
        self.addCleanup(self.restore)

    def restore(self):
        for path in (self.box.root / "shared", self.box.root / "shared" / "inner.md",
                     self.box.root / "top.md"):
            if path.exists():
                os.chmod(path, 0o700 if path.is_dir() else 0o600)

    def ids(self):
        return sorted(r["id"] for r in self.box.search({"query": "findable"})["results"])

    def test_baseline(self):
        self.assertEqual(self.ids(), ["shared/deeper/leaf.md", "shared/inner.md", "top.md"])

    def test_writable_directory_is_skipped_by_search_and_read(self):
        for mode in UNSAFE_DIR_MODES:
            with self.subTest(mode=oct(mode)):
                os.chmod(self.box.root / "shared", mode)
                self.assertEqual(self.ids(), ["top.md"])
                for doc in ("shared/inner.md", "shared/deeper/leaf.md"):
                    self.assertEqual(self.box.read({"id": doc})["error"], errors.NOT_FOUND_OR_DENIED)
                os.chmod(self.box.root / "shared", 0o700)
        self.assertEqual(len(self.ids()), 3)

    def test_writable_nested_directory_skips_only_its_subtree(self):
        os.chmod(self.box.root / "shared" / "deeper", 0o777)
        self.addCleanup(os.chmod, self.box.root / "shared" / "deeper", 0o700)
        self.assertEqual(self.ids(), ["shared/inner.md", "top.md"])

    def test_foreign_owned_directory_is_skipped(self):
        with foreign_owner(self.box.root / "shared", safe_fs):
            self.assertEqual(self.ids(), ["top.md"])
            self.assertEqual(self.box.read({"id": "shared/inner.md"})["error"], errors.NOT_FOUND_OR_DENIED)

    @unittest.skipUnless(DARWIN, "macOS ACLs")
    def test_acl_writable_directory_is_skipped(self):
        add_acl(self.box.root / "shared", "everyone allow write,add_file,delete_child")
        self.addCleanup(subprocess.run, ["/bin/chmod", "-N", str(self.box.root / "shared")], check=True)
        self.assertEqual(self.ids(), ["top.md"])
        self.assertEqual(self.box.read({"id": "shared/inner.md"})["error"], errors.NOT_FOUND_OR_DENIED)

    def test_writable_markdown_file_is_never_returned(self):
        for mode in UNSAFE_FILE_MODES:
            with self.subTest(mode=oct(mode)):
                os.chmod(self.box.root / "shared" / "inner.md", mode)
                os.chmod(self.box.root / "top.md", mode)
                self.assertEqual(self.ids(), ["shared/deeper/leaf.md"])
                for doc in ("top.md", "shared/inner.md"):
                    self.assertEqual(self.box.read({"id": doc})["error"], errors.NOT_FOUND_OR_DENIED)
                os.chmod(self.box.root / "shared" / "inner.md", 0o600)
                os.chmod(self.box.root / "top.md", 0o600)
        self.assertEqual(len(self.ids()), 3)

    def test_foreign_owned_markdown_file_is_never_returned(self):
        with foreign_owner(self.box.root / "top.md", safe_fs):
            self.assertNotIn("top.md", self.ids())
            self.assertEqual(self.box.read({"id": "top.md"})["error"], errors.NOT_FOUND_OR_DENIED)

    @unittest.skipUnless(DARWIN, "macOS ACLs")
    def test_acl_writable_markdown_file_is_never_returned(self):
        add_acl(self.box.root / "top.md", "everyone allow write,append")
        self.assertNotIn("top.md", self.ids())
        self.assertEqual(self.box.read({"id": "top.md"})["error"], errors.NOT_FOUND_OR_DENIED)

    def test_unsafe_file_is_refused_before_any_read(self):
        os.chmod(self.box.root / "top.md", 0o666)
        fd = safe_fs.open_root(str(self.box.root))
        self.addCleanup(os.close, fd)
        with mock.patch.object(safe_fs.os, "read", side_effect=AssertionError("must not read")):
            self.assertIsNone(safe_fs.read_markdown_file(fd, "top.md", 4096))

    def test_trust_is_checked_on_the_opened_descriptor(self):
        """Mode changed after listing: the check on the open descriptor still refuses."""
        fd = safe_fs.open_root(str(self.box.root))
        self.addCleanup(os.close, fd)
        dev = os.fstat(fd).st_dev
        sub = safe_fs.open_subdir(fd, "shared", dev)
        self.assertIsNotNone(sub)
        os.close(sub)
        os.chmod(self.box.root / "shared", 0o777)
        self.assertIsNone(safe_fs.open_subdir(fd, "shared", dev))

    def test_lookahead_does_not_enter_untrusted_directories(self):
        """An untrusted directory past the depth limit cannot raise ``truncated``."""
        shutil.rmtree(self.box.root / "shared" / "deeper")  # keep other depth-3 content out of it
        self.box.write("a/b/c/deep.md", "findable far")
        self.box.write_policy(limits={"max_depth": 2})
        self.assertTrue(self.box.search({"query": "findable far"})["truncated"])
        os.chmod(self.box.root / "a" / "b", 0o777)
        self.addCleanup(os.chmod, self.box.root / "a" / "b", 0o700)
        self.assertFalse(self.box.search({"query": "findable far"})["truncated"])


class FinalDirectoryStickyTests(unittest.TestCase):
    """C2: the sticky system-temp exception is for transit ancestors only."""

    def setUp(self):
        self.temp = next((p for p in ("/private/tmp", "/tmp")
                          if os.path.isdir(p) and not os.path.islink(p)), None)
        if self.temp is None:
            self.skipTest("no system temp directory")
        info = os.stat(self.temp)
        if not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
            self.skipTest("system temp is not root-owned sticky here")

    def test_system_temp_is_refused_as_memory_root(self):
        with self.assertRaises(errors.MemoryBridgeError) as caught:
            safe_fs.open_root(self.temp)
        self.assertEqual(caught.exception.reason, "directory_writable_by_others")

    def test_system_temp_is_refused_as_policy_directory(self):
        from _support import policy
        with self.assertRaises(errors.MemoryBridgeError) as caught:
            policy.load_policy(Path(self.temp) / "policy.json")
        self.assertEqual(caught.exception.reason, "directory_writable_by_others")

    def test_end_to_end_root_at_system_temp_is_unavailable(self):
        box = Sandbox()
        self.addCleanup(box.cleanup)
        box.write_policy(root=os.path.realpath(self.temp))
        self.assertEqual(box.search({"query": "anything"})["error"], errors.UNAVAILABLE)

    def test_secure_directory_below_system_temp_still_works(self):
        box = Sandbox(parent=self.temp)
        self.addCleanup(box.cleanup)
        box.write("note.md", "synthetic note")
        box.write_policy()
        self.assertEqual([r["id"] for r in box.search({"query": "synthetic"})["results"]], ["note.md"])
        os.close(safe_fs.open_root(str(box.root)))

    def test_checker_flags(self):
        fd = os.open(self.temp, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        info = os.fstat(fd)
        safe_fs.check_trusted_directory(fd, info, os.path.realpath(self.temp), False)
        with self.assertRaises(errors.MemoryBridgeError):
            safe_fs.check_trusted_directory(fd, info, os.path.realpath(self.temp), True)


class DeepTreeTruncationTests(unittest.TestCase):
    """C3: the look-ahead follows the read tool's id limits, not an arbitrary depth."""

    def setUp(self):
        self.box = Sandbox()
        self.addCleanup(self.box.cleanup)

    def scan(self, allow=lambda p: True, max_depth=2):
        stats = safe_fs.ScanStats()
        docs = list(safe_fs.iter_documents(str(self.box.root), allow, lambda p: True,
                                           max_file_bytes=4096, max_entries=100,
                                           max_depth=max_depth, stats=stats))
        return docs, stats

    def chain(self, segments):
        return "/".join(["n"] * (segments - 1))

    def test_very_deep_denied_only_tree_is_not_truncated(self):
        deep = self.chain(60)
        self.box.write(deep + "/hidden.md", "denied")
        self.assertFalse(self.scan(lambda p: p[-1] != "hidden.md")[1].truncated)

    def test_very_deep_empty_tree_is_not_truncated(self):
        (self.box.root / self.chain(60)).mkdir(parents=True)
        self.assertFalse(self.scan()[1].truncated)

    def test_allowed_document_with_unreadable_id_is_not_truncated(self):
        self.box.write(self.chain(18) + "/leaf.md", "allowed but 18 segments")
        self.box.write(self.chain(17) + "/leaf.md", "allowed but 17 segments")
        self.assertFalse(self.scan()[1].truncated)

    def test_allowed_document_at_exactly_the_limit_is_truncated(self):
        self.box.write(self.chain(16) + "/leaf.md", "allowed, 16 segments")
        self.assertTrue(self.scan()[1].truncated)

    def test_overlong_id_is_not_truncated(self):
        long_dirs = "/".join(["d" * 127] * 4)  # 4 * 128 characters before the file name
        self.box.write(long_dirs + "/leaf.md", "id would exceed 512 characters")
        self.assertFalse(self.scan()[1].truncated)

    def test_end_to_end_response_ignores_deep_denied_trees(self):
        self.box.write("projects/ok.md", "garden plan")
        self.box.write_policy(allow=["projects/**"], deny=["**/secret*.md"], limits={"max_depth": 2})
        before = self.box.search_raw({"query": "garden"})
        self.box.write("projects/" + self.chain(40) + "/secret.md", "garden secret")
        (self.box.root / "projects" / "empty" / self.chain(40)).mkdir(parents=True)
        self.assertEqual(self.box.search_raw({"query": "garden"}), before)
        self.assertFalse(json.loads(before)["truncated"])


class LinuxAclStructureTests(unittest.TestCase):
    """C4: malformed or unsupported Linux ACL data fails closed."""

    U = 0xFFFFFFFF

    def blob(self, entries, version=2):
        import struct
        return struct.pack("<I", version) + b"".join(struct.pack("<HHI", *e) for e in entries)

    def valid(self):
        return [(1, 6, self.U), (4, 4, self.U), (0x20, 0, self.U)]

    def test_minimal_acl_is_safe(self):
        self.assertFalse(acl.linux_acl_blob_is_unsafe(self.blob(self.valid()), 1000))

    def test_structural_defects_fail_closed(self):
        U = self.U
        good = self.valid()
        cases = {
            "missing owner": good[1:],
            "missing group": [good[0], good[2]],
            "missing other": good[:2],
            "duplicate owner": [good[0], good[0], good[1], good[2]],
            "named entry without mask": [good[0], (2, 4, 1234), good[1], good[2]],
            "mask without named entries": [good[0], good[1], (0x10, 6, U), good[2]],
            "two masks": [good[0], (2, 4, 1234), good[1], (0x10, 6, U), (0x10, 6, U), good[2]],
            "unknown tag": good + [(0x40, 0, U)],
            "zero tag": [(0, 0, U)] + good,
            "permission bits": [(1, 8, U), good[1], good[2]],
            "unnamed with id": [(1, 6, 5), good[1], good[2]],
            "named without id": [good[0], (2, 4, U), good[1], (0x10, 6, U), good[2]],
            "out of order": [good[1], good[0], good[2]],
            "unsorted named ids": [good[0], (2, 4, 9), (2, 4, 3), good[1], (0x10, 6, U), good[2]],
            "duplicate named id": [good[0], (2, 4, 9), (2, 4, 9), good[1], (0x10, 6, U), good[2]],
            "too many entries": good[:1] + [(2, 4, i) for i in range(1, 1100)]
                                + [good[1], (0x10, 6, U), good[2]],
        }
        for label, entries in cases.items():
            with self.subTest(label), self.assertRaises(errors.MemoryBridgeError):
                acl.linux_acl_blob_is_unsafe(self.blob(entries), 1000)
        for label, raw in (("bad version", self.blob(good, version=1)), ("empty", b""),
                           ("ragged", self.blob(good)[:-3])):
            with self.subTest(label), self.assertRaises(errors.MemoryBridgeError):
                acl.linux_acl_blob_is_unsafe(raw, 1000)

    def test_valid_named_entries_are_judged_on_write_access(self):
        U = self.U
        for named, unsafe in (((2, 6, 1234), True), ((2, 4, 1234), False), ((2, 6, 1000), False),
                              ((2, 6, 0), False), ((8, 2, 77), True), ((8, 4, 77), False)):
            with self.subTest(named=named):
                entries = [(1, 6, U), named, (4, 4, U), (0x10, 6, U), (0x20, 0, U)]
                entries.sort(key=lambda e: (e[0], e[2] if e[0] in (2, 8) else 0))
                self.assertEqual(acl.linux_acl_blob_is_unsafe(self.blob(entries), 1000), unsafe)

    def test_unsupported_and_missing_attribute_are_different(self):
        with mock.patch.object(acl.os, "getxattr", create=True,
                               side_effect=OSError(errno.ENODATA, "no acl")):
            self.assertIsNone(acl._linux_acl_blob(0))
        for code in (errno.ENOTSUP, errno.EOPNOTSUPP):
            with mock.patch.object(acl.os, "getxattr", create=True, side_effect=OSError(code, "no")):
                with self.assertRaises(errors.MemoryBridgeError):
                    acl._linux_acl_blob(0)

    def test_unsupported_filesystem_refuses_the_directory(self):
        box = Sandbox()
        self.addCleanup(box.cleanup)
        with mock.patch.object(acl.sys, "platform", "linux"), \
                mock.patch.object(acl.os, "getxattr", create=True,
                                  side_effect=OSError(errno.EOPNOTSUPP, "no")):
            with self.assertRaises(errors.MemoryBridgeError) as caught:
                safe_fs.open_root(str(box.root))
        self.assertEqual(caught.exception.reason, "acl_unverifiable")


class PartialReadAccountingTests(unittest.TestCase):
    """C5: bytes are charged chunk by chunk, so a failing read cannot hide consumed bytes."""

    def setUp(self):
        self.box = Sandbox()
        self.addCleanup(self.box.cleanup)
        (self.box.root / "big.md").write_bytes(b"x" * 200_000)
        os.chmod(self.box.root / "big.md", 0o600)

    def failing_read(self, good_chunks):
        real = os.read
        state = {"calls": 0}

        def read(fd, size):
            state["calls"] += 1
            if state["calls"] > good_chunks:
                raise OSError(errno.EIO, "disk error")
            return real(fd, size)
        return mock.patch.object(safe_fs.os, "read", side_effect=read)

    def test_chunks_read_before_an_error_are_charged(self):
        fd = safe_fs.open_root(str(self.box.root))
        self.addCleanup(os.close, fd)
        for good in (1, 2, 3):
            with self.subTest(good_chunks=good):
                stats = safe_fs.ScanStats()
                with self.failing_read(good):
                    self.assertIsNone(safe_fs.read_markdown_file(fd, "big.md", 1_000_000, stats=stats))
                self.assertEqual(stats.bytes_read, 65536 * good)

    def test_read_bounded_charges_each_chunk(self):
        stats = safe_fs.ScanStats()
        fd = os.open(self.box.root / "big.md", os.O_RDONLY)
        self.addCleanup(os.close, fd)
        with self.failing_read(2), self.assertRaises(OSError):
            safe_fs.read_bounded(fd, 1_000_000, stats)
        self.assertEqual(stats.bytes_read, 65536 * 2)

    def test_failed_reads_count_against_the_scan_budget(self):
        stats = safe_fs.ScanStats()
        with mock.patch.object(safe_fs, "MAX_SCAN_BYTES", 100_000), self.failing_read(2):
            docs = list(safe_fs.iter_documents(str(self.box.root), lambda p: True, lambda p: True,
                                               max_file_bytes=1_000_000, max_entries=10, max_depth=8,
                                               stats=stats))
        self.assertEqual(docs, [])
        self.assertGreaterEqual(stats.bytes_read, 100_000)

    def test_complete_read_is_charged_once(self):
        stats = safe_fs.ScanStats()
        fd = safe_fs.open_root(str(self.box.root))
        self.addCleanup(os.close, fd)
        text = safe_fs.read_markdown_file(fd, "big.md", 1_000_000, stats=stats)
        self.assertEqual((len(text), stats.bytes_read), (200_000, 200_000))


class LoneScopeHomeTests(unittest.TestCase):
    """C6: a scope home with no override must agree with the home Hermes resolves."""

    def setUp(self):
        self.box = Sandbox()
        self.addCleanup(self.box.cleanup)

    def resolve(self, **kwargs):
        return runtime.resolve_caller(FakeCtx(), self.box.probes(override=False, **kwargs))

    def test_agreeing_scope_home_is_accepted(self):
        for multiplexed in (False, True):
            self.assertEqual(self.resolve(scope_home=str(self.box.home), multiplexed=multiplexed).home,
                             self.box.home)

    def test_scope_home_naming_another_profile_is_refused(self):
        for multiplexed in (False, True):
            with self.subTest(multiplexed=multiplexed), self.assertRaises(errors.MemoryBridgeError) as c:
                self.resolve(scope_home=str(self.box.outside), multiplexed=multiplexed)
            self.assertEqual(c.exception.reason, "profile_context_conflict")

    def test_override_with_agreeing_scope_still_works(self):
        probes = self.box.probes(scope_home=str(self.box.home))
        self.assertEqual(runtime.resolve_caller(FakeCtx(), probes).home, self.box.home)

    def test_no_signals_still_uses_the_hermes_home(self):
        self.assertEqual(self.resolve().home, self.box.home)

    def test_two_routed_profiles_resolve_independently(self):
        other = Sandbox()
        self.addCleanup(other.cleanup)
        for box in (self.box, other):
            probes = box.probes(scope_home=str(box.home), multiplexed=True)
            self.assertEqual(runtime.resolve_caller(FakeCtx(), probes).home, box.home)


if __name__ == "__main__":
    unittest.main()
