"""Regression fixtures for Security Pass B (B1, B2, M3, M4, L7, L8).

Everything lives in disposable temporary directories. ACL tests apply and remove ACLs only on
those synthetic paths and are skipped when the platform cannot set them.
"""
import getpass
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from _support import FakeCtx, Sandbox, acl, errors, policy, reader, safe_fs

DARWIN = sys.platform == "darwin"


def add_acl(path, rule):
    """Attach a synthetic macOS ACL entry; skip the test if the platform refuses."""
    done = subprocess.run(["/bin/chmod", "+a", rule, str(path)], capture_output=True)
    if done.returncode != 0:
        raise unittest.SkipTest("cannot set ACLs here")


def info(mode, uid=None, kind=stat.S_IFDIR):
    uid = os.getuid() if uid is None else uid
    return os.stat_result((kind | mode, 1, 1, 1, uid, 20, 0, 0, 0, 0))


class AclParserTests(unittest.TestCase):
    def test_darwin_unsafe_grants(self):
        text = "!#acl 1\ngroup:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:allow:%s\n"
        for perms in ("write", "add_file", "delete_child", "append,read", "writesecurity", "chown"):
            with self.subTest(perms=perms):
                self.assertTrue(acl.darwin_acl_text_is_unsafe(text % perms, 501))

    def test_darwin_safe_entries(self):
        group = "group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:%s:%s\n"
        user = "user:AAAAAAAA-0000-0000-0000-000000000000:me:501:allow:write\n"
        root = "user:FFFFEEEE-DDDD-CCCC-BBBB-AAAAAAAA0000:root:0:allow:write\n"
        for body in (group % ("deny", "delete"), group % ("allow", "read,list,search"),
                     group % ("deny", "write"), user, root, ""):
            with self.subTest(body=body):
                self.assertFalse(acl.darwin_acl_text_is_unsafe("!#acl 1\n" + body, 501))

    def test_darwin_other_user_write_is_unsafe(self):
        other = "user:AAAAAAAA-0000-0000-0000-000000000000:eve:502:allow:write\n"
        self.assertTrue(acl.darwin_acl_text_is_unsafe("!#acl 1\n" + other, 501))

    def test_darwin_unrecognised_text_fails_closed(self):
        for text in ("", "garbage", "!#acl 1\nnot an entry\n",
                     "!#acl 1\nuser:G:me:501:allow:teleport\n", "!#acl 1\nuser:G:me:501:maybe:write\n"):
            with self.subTest(text=text), self.assertRaises(errors.MemoryBridgeError):
                acl.darwin_acl_text_is_unsafe(text, 501)

    def linux_blob(self, *named, mask=0x6, version=2):
        """A valid ACL (owner rw, group r, other none) plus ``named`` (tag, perm, id) entries."""
        U = 0xFFFFFFFF
        entries = [(1, 6, U)]
        entries += sorted(e for e in named if e[0] == 2)
        entries += [(4, 4, U)]
        entries += sorted(e for e in named if e[0] == 8)
        if named:
            entries += [(0x10, mask, U)]
        entries += [(0x20, 0, U)]
        return struct.pack("<I", version) + b"".join(struct.pack("<HHI", *e) for e in entries)

    def test_linux_blob(self):
        self.assertFalse(acl.linux_acl_blob_is_unsafe(self.linux_blob(), 1000))
        self.assertTrue(acl.linux_acl_blob_is_unsafe(self.linux_blob((2, 2, 1234)), 1000))
        self.assertTrue(acl.linux_acl_blob_is_unsafe(self.linux_blob((8, 2, 50)), 1000))
        self.assertFalse(acl.linux_acl_blob_is_unsafe(self.linux_blob((2, 2, 1000)), 1000))
        self.assertFalse(acl.linux_acl_blob_is_unsafe(self.linux_blob((2, 4, 1234)), 1000))

class AclFailClosedTests(unittest.TestCase):
    """Inspection that cannot be trusted refuses the path instead of trusting mode bits."""

    def setUp(self):
        self.box = Sandbox()
        self.addCleanup(self.box.cleanup)
        self.box.write("a.md", "inside")
        self.box.write_policy()

    def assertPolicyRefused(self, reason):
        with self.assertRaises(errors.MemoryBridgeError) as caught:
            policy.load_policy(self.box.policy_file)
        self.assertEqual(caught.exception.reason, reason)

    def test_unsupported_platform_is_refused(self):
        with mock.patch.object(acl.sys, "platform", "plan9"):
            self.assertPolicyRefused("acl_unsupported_platform")

    def test_uninspectable_acl_is_refused_on_policy_and_root(self):
        boom = errors.unavailable("acl_unverifiable")
        for platform, target in (("darwin", "_darwin_acl_text"), ("linux", "_linux_acl_blob")):
            with self.subTest(target=target), mock.patch.object(acl.sys, "platform", platform), \
                    mock.patch.object(acl, target, side_effect=boom):
                self.assertPolicyRefused("acl_unverifiable")
                with self.assertRaises(errors.MemoryBridgeError):
                    safe_fs.open_root(str(self.box.root))

    def test_linux_unsafe_blob_is_refused(self):
        blob = AclParserTests.linux_blob(None, (8, 2, 50))
        with mock.patch.object(acl.sys, "platform", "linux"), \
                mock.patch.object(acl, "_linux_acl_blob", return_value=blob):
            self.assertPolicyRefused("acl_grants_write")

    def test_linux_missing_attribute_means_no_acl(self):
        import errno
        err = OSError(errno.ENODATA, "no data")
        with mock.patch.object(acl.sys, "platform", "linux"), \
                mock.patch.object(acl.os, "getxattr", side_effect=err, create=True):
            self.assertIsNone(acl._linux_acl_blob(0))
        for code in (errno.EACCES, errno.ENOTSUP, errno.EOPNOTSUPP):
            err = OSError(code, "cannot tell")
            with mock.patch.object(acl.os, "getxattr", side_effect=err, create=True):
                with self.assertRaises(errors.MemoryBridgeError, msg=code):
                    acl._linux_acl_blob(0)
        err = OSError(errno.EACCES, "denied")
        with mock.patch.object(acl.os, "getxattr", side_effect=err, create=True):
            with self.assertRaises(errors.MemoryBridgeError):
                acl._linux_acl_blob(0)


@unittest.skipUnless(DARWIN, "macOS ACLs")
class MacAclTests(unittest.TestCase):
    EVERYONE_DIR = "everyone allow write,add_file,add_subdirectory,delete_child"

    def setUp(self):
        self.box = Sandbox()
        self.addCleanup(self.box.cleanup)
        self.box.write("a.md", "inside")
        self.box.write_policy()

    def assertPolicyRefused(self):
        with self.assertRaises(errors.MemoryBridgeError) as caught:
            policy.load_policy(self.box.policy_file)
        self.assertEqual(caught.exception.reason, "acl_grants_write")

    def test_clean_policy_loads(self):
        self.assertEqual(policy.load_policy(self.box.policy_file).root, str(self.box.root))

    def test_everyone_write_on_policy_file(self):
        add_acl(self.box.policy_file, "everyone allow write,append")
        self.assertPolicyRefused()

    def test_everyone_write_on_each_policy_directory(self):
        for directory in (self.box.policy_file.parent, self.box.policy_file.parent.parent, self.box.home):
            with self.subTest(directory=directory.name):
                add_acl(directory, self.EVERYONE_DIR)
                try:
                    self.assertPolicyRefused()
                finally:
                    subprocess.run(["/bin/chmod", "-N", str(directory)], check=True)
                policy.load_policy(self.box.policy_file)

    def test_group_write_acl_is_refused(self):
        add_acl(self.box.policy_file.parent, "group:staff allow write,add_file,delete_child")
        self.assertPolicyRefused()

    def test_deny_only_and_own_user_acls_are_accepted(self):
        add_acl(self.box.policy_file, "everyone deny delete")
        # Runs before Sandbox.cleanup (LIFO), including when the assertion fails.
        self.addCleanup(subprocess.run,
                        ["/bin/chmod", "-N", str(self.box.policy_file)], check=True)
        add_acl(self.box.policy_file.parent, "%s allow write,add_file" % getpass.getuser())
        policy.load_policy(self.box.policy_file)

    def test_everyone_write_on_memory_root_and_ancestor(self):
        for directory in (self.box.root, self.box.base):
            with self.subTest(directory=directory.name):
                add_acl(directory, self.EVERYONE_DIR)
                try:
                    with self.assertRaises(errors.MemoryBridgeError) as caught:
                        safe_fs.open_root(str(self.box.root))
                    self.assertEqual(caught.exception.reason, "acl_grants_write")
                    self.assertEqual(self.box.search({"query": "inside"})["error"], errors.UNAVAILABLE)
                finally:
                    subprocess.run(["/bin/chmod", "-N", str(directory)], check=True)
                os.close(safe_fs.open_root(str(self.box.root)))


class RootAncestorTrustTests(unittest.TestCase):
    """B2: a memory root is only used if its whole path is operator-controlled."""

    def setUp(self):
        self.box = Sandbox()
        self.addCleanup(self.box.cleanup)
        self.parent = self.box.base / "shared"
        self.parent.mkdir(mode=0o700)
        self.inner = self.parent / "inner"
        self.inner.mkdir(mode=0o700)
        self.root = self.inner / "memory"
        self.root.mkdir(mode=0o700)
        (self.root / "note.md").write_text("trusted note")
        self.box.write_policy(root=str(self.root))

    def search(self):
        return self.box.search({"query": "note"})

    def test_trusted_path_works(self):
        self.assertEqual([r["id"] for r in self.search()["results"]], ["note.md"])

    def test_replaced_writable_ancestor_is_refused(self):
        """Reviewer's repro: an entry in a writable ancestor is swapped for a real directory
        holding other content. Covers the root's parent and a higher ancestor."""
        for writable, replaced in ((self.inner, "memory"), (self.parent, "inner")):
            for mode in (0o777, 0o770, 0o1777, 0o702):
                with self.subTest(writable=writable.name, mode=oct(mode)):
                    os.chmod(writable, mode)
                    saved = self.box.base / "saved"
                    os.rename(writable / replaced, saved)
                    forged = writable / replaced
                    (forged / "memory" if replaced == "inner" else forged).mkdir(parents=True, mode=0o700)
                    (forged / "memory" / "note.md" if replaced == "inner" else forged / "note.md"
                     ).write_text("attacker note")
                    try:
                        response = self.search()
                        self.assertEqual(response.get("error"), errors.UNAVAILABLE)
                        self.assertNotIn("attacker", json.dumps(response))
                    finally:
                        shutil.rmtree(forged)
                        os.rename(saved, writable / replaced)
                        os.chmod(writable, 0o700)
        self.assertEqual([r["id"] for r in self.search()["results"]], ["note.md"])

    def test_group_or_world_writable_root_itself_is_refused(self):
        for mode in (0o770, 0o707, 0o777, 0o1777):
            with self.subTest(mode=oct(mode)):
                os.chmod(self.root, mode)
                try:
                    self.assertEqual(self.search()["error"], errors.UNAVAILABLE)
                    self.assertEqual(self.box.read({"id": "note.md"})["error"], errors.UNAVAILABLE)
                finally:
                    os.chmod(self.root, 0o700)

    def test_wrong_owner_ancestor_is_refused(self):
        original = os.fstat
        target = os.stat(self.parent).st_ino
        def foreign(fd):
            result = original(fd)
            if result.st_ino == target:
                values = list(result)
                values[4] = os.getuid() + 4242
                return os.stat_result(values)
            return result
        with mock.patch.object(safe_fs.os, "fstat", side_effect=foreign):
            self.assertEqual(self.search()["error"], errors.UNAVAILABLE)

    def test_non_directory_component_is_refused(self):
        with self.assertRaises(errors.MemoryBridgeError):
            safe_fs.check_trusted_directory(0, info(0o700, kind=stat.S_IFREG), "/x", False)

    def test_sticky_rules(self):
        """Sticky is never enough on its own: only root-owned system temp directories pass."""
        fd = os.open(self.box.base, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        sticky = 0o1777
        cases = [
            ("root sticky system temp", info(sticky, uid=0), "/private/tmp", True),
            ("root sticky /tmp", info(sticky, uid=0), "/tmp", True),
            ("root sticky elsewhere", info(sticky, uid=0), "/srv/shared", False),
            ("root sticky lookalike", info(sticky, uid=0), "/private/tmp/other", False),
            ("root world-writable no sticky", info(0o777, uid=0), "/private/tmp", False),
            ("root group-writable no sticky", info(0o775, uid=0), "/usr/local", False),
            ("operator sticky world-writable", info(sticky), "/private/tmp", False),
            ("operator private", info(0o700), "/anything", True),
            ("other user", info(0o755, uid=os.getuid() + 1), "/anything", False),
        ]
        for label, stat_info, path, accepted in cases:
            with self.subTest(label):
                if accepted:
                    safe_fs.check_trusted_directory(fd, stat_info, path, False)
                else:
                    with self.assertRaises(errors.MemoryBridgeError):
                        safe_fs.check_trusted_directory(fd, stat_info, path, False)
            if stat_info.st_mode & stat.S_ISVTX and path in safe_fs.SYSTEM_TEMP_DIRS:
                with self.subTest(label + " as final directory"), self.assertRaises(errors.MemoryBridgeError):
                    safe_fs.check_trusted_directory(fd, stat_info, path, True)


class SystemTempWorkflowTests(unittest.TestCase):
    """Synthetic runs under the system temp directory keep working without weakening the rules."""

    def setUp(self):
        temp = next((p for p in ("/private/tmp", "/tmp") if os.path.isdir(p) and not os.path.islink(p)), None)
        if temp is None:
            self.skipTest("no system temp directory")
        info_ = os.stat(temp)
        if not (info_.st_uid == 0 and info_.st_mode & stat.S_ISVTX):
            self.skipTest("system temp is not root-owned sticky here")
        self.box = Sandbox(parent=temp)
        self.addCleanup(self.box.cleanup)
        self.box.write("note.md", "temp note")
        self.box.write_policy()

    def test_search_and_read_under_system_temp(self):
        self.assertEqual([r["id"] for r in self.box.search({"query": "note"})["results"]], ["note.md"])
        self.assertEqual(self.box.read({"id": "note.md"})["content"], "temp note")

    def test_world_writable_directory_below_system_temp_is_still_refused(self):
        os.chmod(self.box.base, 0o777)
        self.assertEqual(self.box.search({"query": "note"})["error"], errors.UNAVAILABLE)


class ScanByteBudgetTests(unittest.TestCase):
    """M3: every byte read is charged, including content that is then rejected."""

    def setUp(self):
        self.box = Sandbox()
        self.addCleanup(self.box.cleanup)

    def scan(self, **kwargs):
        stats = safe_fs.ScanStats()
        params = dict(max_file_bytes=4096, max_entries=100, max_depth=8)
        params.update(kwargs)
        docs = list(safe_fs.iter_documents(str(self.box.root), lambda p: True, lambda p: True,
                                           stats=stats, **params))
        return docs, stats

    def test_binary_and_invalid_utf8_are_charged(self):
        (self.box.root / "a.md").write_bytes(b"\x00" * 300)
        (self.box.root / "b.md").write_bytes(b"\xff\xfe" * 200)
        (self.box.root / "c.md").write_text("x" * 100)
        docs, stats = self.scan()
        self.assertEqual([d.id for d in docs], ["c.md"])
        self.assertEqual(stats.bytes_read, 300 + 400 + 100)

    def test_rejected_files_exhaust_the_budget(self):
        for name in "abcde":
            (self.box.root / f"{name}.md").write_bytes(b"\x00" * 600)
        self.box.write("z.md", "reachable only with budget left")
        with mock.patch.object(safe_fs, "MAX_SCAN_BYTES", 1000):
            docs, stats = self.scan()
        self.assertEqual(docs, [])
        self.assertTrue(stats.truncated)
        self.assertEqual(stats.bytes_read, 1200)  # two 600-byte files, then the budget stopped the scan
        self.assertEqual(stats.files_opened, ["a.md", "b.md"])

    def test_files_refused_before_reading_cost_nothing(self):
        (self.box.root / "big.md").write_bytes(b"x" * 5000)  # over max_file_bytes: refused by size
        os.symlink(self.box.outside, self.box.root / "link.md")
        docs, stats = self.scan()
        self.assertEqual((docs, stats.bytes_read), ([], 0))


class DepthBoundaryTests(unittest.TestCase):
    """M4: names that are denied cannot flip ``truncated`` at the depth limit."""

    def setUp(self):
        self.box = Sandbox()
        self.addCleanup(self.box.cleanup)

    def scan(self, allow, max_depth=2):
        stats = safe_fs.ScanStats()
        docs = list(safe_fs.iter_documents(str(self.box.root), allow, lambda p: True,
                                           max_file_bytes=4096, max_entries=100,
                                           max_depth=max_depth, stats=stats))
        return docs, stats

    def test_denied_only_directory_at_boundary_is_not_truncated(self):
        self.box.write("a/b/hidden.md", "denied")
        self.box.write("a/b/c/also-hidden.md", "denied")
        self.box.write("a/ok.md", "allowed")
        docs, stats = self.scan(lambda p: p[-1] not in ("hidden.md", "also-hidden.md"))
        self.assertEqual([d.id for d in docs], ["a/ok.md"])
        self.assertFalse(stats.truncated)

    def test_allowed_document_past_boundary_is_truncated(self):
        self.box.write("a/b/c/deep.md", "allowed")
        self.assertTrue(self.scan(lambda p: True)[1].truncated)
        self.box.write("a/b/direct.md", "allowed")
        self.assertTrue(self.scan(lambda p: p[-1] == "direct.md")[1].truncated)

    def test_non_markdown_and_invalid_names_do_not_truncate(self):
        self.box.write("a/b/notes.txt", "text")
        self.box.write("a/b/.hidden.md", "hidden")
        self.box.write("a/b/has space.md", "space")
        self.assertFalse(self.scan(lambda p: True)[1].truncated)

    def test_end_to_end_denied_content_cannot_change_response(self):
        self.box.write("projects/a/b/ok.md", "garden plan")
        self.box.write_policy(allow=["projects/**"], deny=["**/secret*.md"], limits={"max_depth": 2})
        before = self.box.search_raw({"query": "garden"})
        self.box.write("projects/a/b/secret-1.md", "garden secret")
        self.box.write("projects/a/b/c/secret-2.md", "garden secret")
        self.assertEqual(self.box.search_raw({"query": "garden"}), before)


class SearchIdsReadableTests(unittest.TestCase):
    """L7: every id search returns is accepted by read; others are never listed."""

    def setUp(self):
        self.box = Sandbox()
        self.addCleanup(self.box.cleanup)

    def path_of_length(self, total):
        """A nested path whose id is exactly ``total`` characters (names stay within 128)."""
        name = "f" * 97 + ".md"  # 100 characters
        dirs = ["d%d" % i + "x" * 125 for i in range(3)]  # 127 characters each
        dirs.append("t" * (total - len(name) - 3 * 128 - 1))
        return "/".join(dirs + [name])

    def test_id_at_the_limit_round_trips_and_one_over_is_not_listed(self):
        exact = self.path_of_length(reader.MAX_ID_CHARS)
        over = self.path_of_length(reader.MAX_ID_CHARS + 1)
        self.assertEqual((len(exact), len(over)), (512, 513))
        self.box.write(exact, "findable marker")
        self.box.write(over.replace("d0", "e0", 1), "findable marker")
        self.box.write_policy(limits={"max_depth": 8})
        response = self.box.search({"query": "findable"})
        self.assertEqual([r["id"] for r in response["results"]], [exact])
        self.assertFalse(response["truncated"])
        self.assertEqual(self.box.read({"id": exact})["content"], "findable marker")

    def test_every_search_id_is_readable_at_maximum_depth(self):
        deep = "/".join(["n"] * 15 + ["leaf.md"])
        self.box.write(deep, "findable deep")
        self.box.write("top.md", "findable top")
        self.box.write_policy(limits={"max_depth": 16})
        ids = [r["id"] for r in self.box.search({"query": "findable", "limit": 10})["results"]]
        self.assertEqual(sorted(ids), sorted([deep, "top.md"]))
        for doc_id in ids:
            self.assertTrue(self.box.read({"id": doc_id})["ok"], doc_id)

    def test_oversized_and_overdeep_directories_are_pruned_without_error(self):
        self.box.write("/".join(["n"] * 16 + ["leaf.md"]), "findable too deep")
        self.box.write_policy(limits={"max_depth": 16})
        self.assertEqual(self.box.search({"query": "findable"})["results"], [])


class DenialLoggingTests(unittest.TestCase):
    """L8: operator logs cannot tell a missing document from a denied one."""

    def setUp(self):
        self.box = Sandbox()
        self.addCleanup(self.box.cleanup)
        self.box.write("open/ok.md", "fine")
        self.box.write("open/private/secret.md", "secret")
        self.box.write("closed/other.md", "outside allow list")
        os.symlink(self.box.outside, self.box.root / "open" / "link")
        self.box.write_policy(allow=["open/**"], deny=["**/private/**"])

    def logged(self, doc_id):
        with self.assertLogs("memory_bridge", level="WARNING") as captured:
            response = self.box.read({"id": doc_id})
        self.assertEqual(response["error"], errors.NOT_FOUND_OR_DENIED)
        return [record.getMessage() for record in captured.records]

    def test_refusal_logs_are_identical(self):
        ids = ["open/private/secret.md",   # denied by pattern
               "closed/other.md",          # outside the allow list
               "open/missing.md",          # allowed but absent
               "open/link/secret.md",      # symlink
               "nope/none.md"]             # outside allow list and absent
        messages = {doc_id: self.logged(doc_id) for doc_id in ids}
        self.assertEqual(len({tuple(m) for m in messages.values()}), 1, messages)
        for text in messages.values():
            self.assertNotIn("secret", " ".join(text))


if __name__ == "__main__":
    unittest.main()
