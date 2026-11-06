import json
import os
import unittest

from _support import Sandbox, errors, reader


class ReadTests(unittest.TestCase):
    def setUp(self):
        self.box = Sandbox()
        self.addCleanup(self.box.cleanup)
        self.garden = "# Garden Plan\n\nPlant tulips in October.\n  Keep   spacing exact.\n"
        self.box.write("projects/garden.md", self.garden)
        self.box.write("decisions/use-tulips.md", "# Decision\nWe chose tulips.")
        self.box.write("projects/private/budget.md", "# Secret\nsynthetic private budget")
        self.box.write("projects/denied-note.md", "# Denied\nsynthetic denied note")
        self.box.write("inbox/raw.md", "# Inbox\nsynthetic inbox idea")
        self.outside = self.box.write("secret.md", "synthetic outside secret", where=self.box.outside)
        self.box.write_policy(allow=["projects/**", "decisions/**"],
                              deny=["**/private/**", "**/denied-note.md"])

    def missing_response(self):
        return self.box.read_raw({"id": "projects/does-not-exist.md"})

    def test_returns_full_allowed_document_verbatim(self):
        response = self.box.read({"id": "projects/garden.md"})
        self.assertEqual(response, {"ok": True, "id": "projects/garden.md",
                                    "content": self.garden, "truncated": False})

    def test_reads_ids_returned_by_search(self):
        found = self.box.search({"query": "tulips"})
        ids = [item["id"] for item in found["results"]]
        self.assertEqual(sorted(ids), ["decisions/use-tulips.md", "projects/garden.md"])
        for doc_id in ids:
            self.assertTrue(self.box.read({"id": doc_id})["ok"])

    def test_missing_and_forbidden_documents_get_identical_responses(self):
        os.symlink(self.outside, self.box.root / "projects/link.md")
        os.symlink(self.box.outside, self.box.root / "projects/linked-dir")
        os.link(self.outside, self.box.root / "projects/hard.md")
        os.mkfifo(self.box.root / "projects/pipe.md")
        self.box.write("projects/big.md", "x" * (300 * 1024))
        (self.box.root / "projects/binary.md").write_bytes(b"a\x00b")
        (self.box.root / "projects/latin.md").write_bytes(b"caf\xe9")
        self.box.write("projects/a/b/c/d/e/f/g/h/deep.md", "too deep")
        expected = self.missing_response()
        self.assertEqual(json.loads(expected)["error"], errors.NOT_FOUND_OR_DENIED)
        for doc_id in ("projects/private/budget.md", "projects/PRIVATE/budget.md",
                       "projects/denied-note.md", "projects/DENIED-NOTE.md", "inbox/raw.md",
                       "secret.md", "projects/link.md", "projects/linked-dir/secret.md",
                       "projects/hard.md", "projects/pipe.md", "projects/big.md",
                       "projects/binary.md", "projects/latin.md", "projects/a/b/c/d/e/f/g/h/deep.md",
                       "projects/missing-dir/x.md"):
            self.assertEqual(self.box.read_raw({"id": doc_id}), expected, doc_id)

    def test_malformed_ids_are_invalid_requests_without_touching_disk(self):
        os.chmod(self.box.root, 0o000)  # any filesystem access would fail differently
        self.addCleanup(os.chmod, self.box.root, 0o700)
        for doc_id in ("../outside/secret.md", "/etc/hosts.md", "projects/../inbox/raw.md",
                       "projects\\garden.md", "projects//garden.md", "./projects/garden.md",
                       "projects/.hidden.md", ".git/config.md", "projects/garden.txt",
                       "projects/garden", "projects/garden.md/", "has space.md", "café.md",
                       "a\x00.md", "", "x" * 600, "/".join(["d"] * 16) + "/x.md", 7, None, ["a.md"]):
            response = self.box.read({"id": doc_id})
            self.assertEqual(response["error"], errors.INVALID_REQUEST, repr(doc_id))
        for args in ({}, {"id": "projects/garden.md", "agent": "admin"},
                     {"id": "projects/garden.md", "root": "/"}, {"path": "projects/garden.md"}, "id"):
            self.assertEqual(self.box.read(args)["error"], errors.INVALID_REQUEST, repr(args))

    def test_long_documents_are_truncated_and_marked(self):
        body = "# Long\n" + "".join(f"line {i:05d} synthetic text\n" for i in range(2000))
        self.box.write("projects/long.md", body)
        response = self.box.read({"id": "projects/long.md"})
        self.assertTrue(response["truncated"])
        self.assertLessEqual(len(response["content"]), 8000)
        self.assertTrue(response["content"].endswith(reader.TRUNCATION_MARKER.format(cap=8000)))
        self.assertTrue(body.startswith(response["content"].split("\n\n[Memory Bridge")[0]))

    def test_exactly_at_cap_is_not_truncated(self):
        self.box.write("projects/exact.md", "y" * 8000)
        response = self.box.read({"id": "projects/exact.md"})
        self.assertFalse(response["truncated"])
        self.assertEqual(len(response["content"]), 8000)

    def test_operator_can_lower_the_read_cap(self):
        self.box.write("projects/long.md", "z" * 3000)
        self.box.write_policy(allow=["projects/**"], limits={"read_chars": 500})
        response = self.box.read({"id": "projects/long.md"})
        self.assertTrue(response["truncated"])
        self.assertLessEqual(len(response["content"]), 500)
        self.assertIn("at most 500 characters", response["content"])

    def test_read_cap_cannot_exceed_hard_limit(self):
        self.box.write_policy(allow=["projects/**"], limits={"read_chars": 8001})
        self.assertEqual(self.box.read({"id": "projects/garden.md"})["error"], errors.UNAVAILABLE)

    def test_runtime_gates_apply_to_read(self):
        from _support import FakeCtx
        args = {"id": "projects/garden.md"}
        self.assertEqual(self.box.read(args, ctx=FakeCtx(cron=object()))["error"], errors.UNAVAILABLE)
        self.assertEqual(self.box.read(args, cron_flag="1")["error"], errors.UNAVAILABLE)
        self.assertEqual(self.box.read(args, subagent=True)["error"], errors.UNAVAILABLE)
        self.assertEqual(self.box.read(args, override=False, multiplexed=True)["error"], errors.UNAVAILABLE)
        self.assertTrue(self.box.read(args, multiplexed=True)["ok"])

    def test_policy_changes_apply_immediately(self):
        args = {"id": "decisions/use-tulips.md"}
        self.assertTrue(self.box.read(args)["ok"])
        self.box.write_policy(allow=["projects/**"])
        self.assertEqual(self.box.read_raw(args), self.missing_response())
        os.unlink(self.box.policy_file)
        self.assertEqual(self.box.read(args)["error"], errors.UNAVAILABLE)

    def test_responses_never_contain_paths(self):
        for doc_id in ("projects/garden.md", "projects/private/budget.md", "projects/nope.md", "../x.md"):
            self.assertNotIn(str(self.box.base), self.box.read_raw({"id": doc_id}))
        os.rename(self.box.root, self.box.base / "moved")
        raw = self.box.read_raw({"id": "projects/garden.md"})
        self.assertEqual(json.loads(raw)["error"], errors.UNAVAILABLE)
        self.assertNotIn(str(self.box.base), raw)


if __name__ == "__main__":
    unittest.main()
