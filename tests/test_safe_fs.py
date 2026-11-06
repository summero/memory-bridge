import os
import unittest

from _support import Sandbox, errors, safe_fs


def scan(box, *, allow=lambda parts: True, descend=lambda parts: True,
         max_file_bytes=4096, max_entries=1000, max_depth=8):
    stats = safe_fs.ScanStats()
    docs = list(safe_fs.iter_documents(
        str(box.root), allow, descend, max_file_bytes=max_file_bytes,
        max_entries=max_entries, max_depth=max_depth, stats=stats))
    return {d.id: d.text for d in docs}, stats


class NameTests(unittest.TestCase):
    def test_names(self):
        for good in ("notes.md", "2026-11-05_plan.md", "_index.md", "A.MD"):
            self.assertTrue(safe_fs.is_valid_name(good), good)
        for bad in (".hidden.md", ".", "..", "has space.md", "café.md", "a/b.md", "a\\b.md", "", "x" * 200):
            self.assertFalse(safe_fs.is_valid_name(bad), bad)
        self.assertFalse(safe_fs.is_markdown_name(".md"))
        self.assertFalse(safe_fs.is_markdown_name("notes.txt"))


class WalkTests(unittest.TestCase):
    def setUp(self):
        self.box = Sandbox()
        self.addCleanup(self.box.cleanup)
        self.secret = self.box.write("secret.md", "# Outside\nsynthetic outside text", where=self.box.outside)

    def test_returns_regular_markdown_only(self):
        self.box.write("a.md", "alpha")
        self.box.write("sub/b.md", "beta")
        self.box.write("notes.txt", "not markdown")
        self.box.write(".hidden.md", "hidden")
        self.box.write(".git/c.md", "hidden dir")
        self.box.write("bad name.md", "space")
        docs, _ = scan(self.box)
        self.assertEqual(sorted(docs), ["a.md", "sub/b.md"])

    def test_symlinked_file_is_not_followed(self):
        os.symlink(self.secret, self.box.root / "link.md")
        docs, _ = scan(self.box)
        self.assertEqual(docs, {})

    def test_symlinked_directory_is_not_followed(self):
        os.symlink(self.box.outside, self.box.root / "linked")
        docs, _ = scan(self.box)
        self.assertEqual(docs, {})

    def test_hard_links_are_rejected(self):
        os.link(self.secret, self.box.root / "hard.md")
        docs, stats = scan(self.box)
        self.assertEqual(docs, {})
        self.assertIn("hard.md", stats.files_opened)  # opened, then refused on link count

    def test_fifo_with_markdown_name_is_skipped_without_blocking(self):
        os.mkfifo(self.box.root / "pipe.md")
        self.box.write("ok.md", "fine")
        docs, _ = scan(self.box)
        self.assertEqual(list(docs), ["ok.md"])

    def test_oversized_binary_and_invalid_utf8_files_are_skipped(self):
        self.box.write("big.md", "x" * 5000)
        (self.box.root / "nul.md").write_bytes(b"text\x00more")
        (self.box.root / "latin.md").write_bytes(b"caf\xe9")
        self.box.write("ok.md", "fine")
        docs, _ = scan(self.box, max_file_bytes=4096)
        self.assertEqual(list(docs), ["ok.md"])

    def test_denied_files_and_directories_are_never_opened(self):
        self.box.write("open/a.md", "allowed")
        self.box.write("open/denied.md", "denied")
        self.box.write("closed/b.md", "denied dir")
        os.chmod(self.box.root / "closed", 0o000)  # opening it would fail loudly if attempted
        self.addCleanup(os.chmod, self.box.root / "closed", 0o700)
        docs, stats = scan(self.box,
                           allow=lambda parts: parts[-1] != "denied.md",
                           descend=lambda parts: parts[0] != "closed")
        self.assertEqual(list(docs), ["open/a.md"])
        self.assertEqual(stats.files_opened, ["open/a.md"])

    def test_depth_and_entry_limits_truncate(self):
        self.box.write("one/two/three/deep.md", "deep")
        docs, stats = scan(self.box, max_depth=2)
        self.assertEqual(docs, {})
        self.assertTrue(stats.truncated)
        for i in range(5):
            self.box.write(f"n{i}.md", "x")
        docs, stats = scan(self.box, max_entries=3)
        self.assertTrue(stats.truncated)
        self.assertLessEqual(len(docs), 3)

    def test_denied_names_do_not_consume_the_entry_budget(self):
        for i in range(10):
            self.box.write(f"aaa-denied-{i}.md", "denied")
        self.box.write("b.md", "allowed")
        self.box.write("c.md", "allowed")
        docs, stats = scan(self.box, allow=lambda parts: not parts[-1].startswith("aaa-"), max_entries=2)
        self.assertEqual(sorted(docs), ["b.md", "c.md"])
        self.assertFalse(stats.truncated)
        self.assertEqual(stats.scanned, 12)

    def test_read_document_uses_the_same_rules(self):
        self.box.write("sub/ok.md", "fine")
        os.symlink(self.box.outside, self.box.root / "linked")
        os.link(self.secret, self.box.root / "hard.md")
        self.assertEqual(safe_fs.read_document(str(self.box.root), ("sub", "ok.md"), 4096), "fine")
        for parts in (("linked", "secret.md"), ("hard.md",), ("sub", "missing.md"), ("..", "outside", "secret.md")):
            self.assertIsNone(safe_fs.read_document(str(self.box.root), parts, 4096), parts)

    def test_root_that_is_a_symlink_is_refused(self):
        link = self.box.base / "root-link"
        os.symlink(self.box.root, link)
        with self.assertRaises(errors.MemoryBridgeError):
            safe_fs.open_root(str(link))

    def test_missing_root_is_unavailable(self):
        with self.assertRaises(errors.MemoryBridgeError) as caught:
            safe_fs.open_root(str(self.box.base / "missing"))
        self.assertEqual(caught.exception.code, errors.UNAVAILABLE)


class SwapRaceTests(unittest.TestCase):
    """A path that changes between listing and opening is refused at open time."""

    def setUp(self):
        self.box = Sandbox()
        self.addCleanup(self.box.cleanup)
        self.box.write("inside.md", "inside")
        self.box.write("dir/x.md", "x")
        self.outside_file = self.box.write("secret.md", "secret", where=self.box.outside)
        self.root_fd = safe_fs.open_root(str(self.box.root))
        self.root_dev = os.fstat(self.root_fd).st_dev

    def tearDown(self):
        os.close(self.root_fd)

    def test_directory_swapped_for_symlink_is_refused(self):
        os.rename(self.box.root / "dir", self.box.base / "moved")
        os.symlink(self.box.outside, self.box.root / "dir")
        self.assertIsNone(safe_fs.open_subdir(self.root_fd, "dir", self.root_dev))

    def test_file_swapped_for_symlink_is_refused(self):
        os.unlink(self.box.root / "inside.md")
        os.symlink(self.outside_file, self.box.root / "inside.md")
        self.assertIsNone(safe_fs.read_markdown_file(self.root_fd, "inside.md", 4096))

    def test_file_swapped_for_fifo_is_refused(self):
        os.unlink(self.box.root / "inside.md")
        os.mkfifo(self.box.root / "inside.md")
        self.assertIsNone(safe_fs.read_markdown_file(self.root_fd, "inside.md", 4096))

    def test_traversal_names_are_refused_by_the_opener(self):
        self.assertIsNone(safe_fs.open_subdir(self.root_fd, "..", self.root_dev))
        self.assertIsNone(safe_fs.read_markdown_file(self.root_fd, "../outside/secret.md", 4096))


if __name__ == "__main__":
    unittest.main()
