import json
import os
import unittest
from unittest import mock

from _support import FakeCtx, Sandbox, errors, plugin, safe_fs


class SearchTests(unittest.TestCase):
    def setUp(self):
        self.box = Sandbox()
        self.box.write("projects/garden.md", "# Garden Plan\nPlant tulips in October. Water the tulips weekly.")
        self.box.write("projects/kitchen.md", "# Kitchen\nPaint the kitchen. Tulips on the table.")
        self.box.write("decisions/use-tulips.md", "# Decision\nWe chose tulips over roses.")
        self.box.write("inbox/raw-tulips.md", "# Inbox\nUnreviewed tulips idea.")
        self.box.write("projects/private/tulips-secret.md", "# Secret\nprivate tulips budget zebra")
        self.box.write_policy(allow=["projects/**", "decisions/**"], deny=["**/private/**"])

    def tearDown(self):
        self.box.cleanup()

    def ids(self, response):
        self.assertTrue(response["ok"], response)
        return [r["id"] for r in response["results"]]

    def test_returns_allowed_documents_ranked(self):
        response = self.box.search({"query": "tulips garden"})
        ids = self.ids(response)
        self.assertEqual(ids[0], "projects/garden.md")
        self.assertEqual(set(ids), {"projects/garden.md", "projects/kitchen.md", "decisions/use-tulips.md"})
        self.assertEqual(response["results"][0]["title"], "Garden Plan")
        self.assertIn("tulips", response["results"][0]["snippet"].lower())
        self.assertNotIn(str(self.box.base), json.dumps(response))

    def test_denied_and_unlisted_documents_never_appear(self):
        ids = self.ids(self.box.search({"query": "tulips", "limit": 10}))
        self.assertNotIn("inbox/raw-tulips.md", ids)
        self.assertNotIn("projects/private/tulips-secret.md", ids)

    def test_denied_content_does_not_change_the_response(self):
        with_secret = self.box.search({"query": "zebra budget"})
        os.unlink(self.box.root / "projects/private/tulips-secret.md")
        without_secret = self.box.search({"query": "zebra budget"})
        self.assertEqual(with_secret, without_secret)
        self.assertEqual(with_secret["results"], [])
        self.assertNotIn("private", json.dumps(with_secret))

    def test_deny_is_case_insensitive(self):
        # A fresh directory, so the on-disk name keeps its capitals even on case-insensitive disks.
        self.box.write("decisions/Private/upper.md", "zebra")
        self.assertEqual(self.ids(self.box.search({"query": "zebra"})), [])
        self.assertEqual(sorted(os.listdir(self.box.root / "decisions")), ["Private", "use-tulips.md"])

    def test_limit_default_and_truncation_flag(self):
        for i in range(8):
            self.box.write(f"projects/n{i}.md", f"# Note {i}\nshared keyword")
        response = self.box.search({"query": "keyword"})
        self.assertEqual(len(response["results"]), 5)
        self.assertTrue(response["truncated"])
        response = self.box.search({"query": "keyword", "limit": 2})
        self.assertEqual(len(response["results"]), 2)

    def test_output_is_bounded(self):
        long_text = "# Long\n" + ("filler " * 200 + "needle ") * 40
        for i in range(10):
            self.box.write(f"projects/long{i}.md", long_text)
        self.box.write_policy(allow=["projects/**"], limits={"snippet_chars": 120, "total_chars": 600})
        response = self.box.search({"query": "needle", "limit": 10})
        total = 0
        for item in response["results"]:
            self.assertLessEqual(len(item["snippet"]), 120)
            total += sum(len(v) for v in item.values())
        self.assertLessEqual(total, 600)
        self.assertTrue(response["truncated"])

    def test_policy_is_reloaded_on_every_call(self):
        self.assertIn("decisions/use-tulips.md", self.ids(self.box.search({"query": "roses"})))
        self.box.write_policy(allow=["projects/**"])
        self.assertEqual(self.ids(self.box.search({"query": "roses"})), [])
        os.unlink(self.box.policy_file)
        self.assertEqual(self.box.search({"query": "roses"})["error"], errors.UNAVAILABLE)


class DeniedContentIsInvisibleTests(unittest.TestCase):
    """Regression: denied names and content must not change any part of a successful response.

    Earlier versions counted every directory entry, denied ones included, toward ``max_entries``
    and stopped in unsorted listing order, so denied files could flip ``truncated`` and change
    which allowed documents were searched.
    """

    QUERY = {"query": "tulips budget", "limit": 10}

    def setUp(self):
        self.box = Sandbox()
        self.secret = self.box.write("secret.md", "tulips budget " * 50, where=self.box.outside)

    def tearDown(self):
        self.box.cleanup()

    def allowed(self, count):
        for i in range(count):
            self.box.write(f"projects/note-{i}.md", f"# Note {i}\n" + "tulips " * (i + 1))

    def add_denied(self, count=25):
        projects = self.box.root / "projects"
        strong = "# Denied\n" + "tulips budget " * 200
        for i in range(count):
            self.box.write(f"projects/aaa-denied-{i:02d}.md", strong)     # denied by pattern, sorts first
            self.box.write(f"projects/private/p-{i:02d}.md", strong)      # inside a pruned folder
            self.box.write(f"projects/sub-{i:02d}/aaa-denied.md", strong)  # denied file in allowed folder
            self.box.write(f"inbox/i-{i:02d}.md", strong)                 # outside the allow list
            self.box.write(f"projects/.hidden-{i:02d}.md", strong)        # hidden name
            self.box.write(f"projects/n-{i:02d}.txt", strong)             # not Markdown
            os.symlink(self.secret, projects / f"aab-link-{i:02d}.md")    # symlink

    def check(self, allowed_count, query=None, **limits):
        query = query or self.QUERY
        self.allowed(allowed_count)
        self.box.write_policy(allow=["projects/**"], deny=["**/private/**", "**/aaa-denied*.md"],
                              limits=limits)
        before = self.box.search_raw(query)
        self.add_denied()
        after = self.box.search_raw(query)
        self.assertEqual(after, before)
        return json.loads(before)

    def test_untruncated_result_stays_untruncated(self):
        response = self.check(3, max_entries=4)
        self.assertFalse(response["truncated"])
        self.assertEqual(len(response["results"]), 3)

    def test_entry_cut_off_ignores_denied_names(self):
        response = self.check(6, max_entries=4)
        self.assertTrue(response["truncated"])
        self.assertEqual(sorted(r["id"] for r in response["results"]),
                         [f"projects/note-{i}.md" for i in range(4)])

    def test_ranking_snippets_and_limit_ignore_denied_content(self):
        response = self.check(8, query={"query": "tulips budget"}, max_results=3, default_results=3)
        self.assertEqual(len(response["results"]), 3)
        self.assertEqual(response["results"][0]["id"], "projects/note-7.md")
        self.assertTrue(response["truncated"])

    def test_output_budget_ignores_denied_content(self):
        response = self.check(10, snippet_chars=100, total_chars=400)
        self.assertTrue(response["truncated"])

    def test_hard_scan_ceiling_refuses_instead_of_returning_partial_results(self):
        self.allowed(2)
        self.box.write_policy(allow=["projects/**"], deny=["**/aaa-denied*.md"])
        with mock.patch.object(safe_fs, "MAX_SCAN_ENTRIES", 20):
            self.assertTrue(self.box.search(self.QUERY)["ok"])
            self.add_denied(10)
            response = self.box.search(self.QUERY)
        self.assertEqual(response, {"ok": False, "error": errors.UNAVAILABLE,
                                    "message": response["message"]})


class RequestValidationTests(unittest.TestCase):
    def setUp(self):
        self.box = Sandbox()
        self.box.write("projects/a.md", "alpha")
        self.box.write_policy(allow=["projects/**"])

    def tearDown(self):
        self.box.cleanup()

    def assertInvalid(self, args):
        response = self.box.search(args)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"], errors.INVALID_REQUEST, args)

    def test_caller_supplied_identity_or_scope_is_rejected(self):
        for extra in ({"agent": "admin"}, {"profile": "other"}, {"root": "/"}, {"path": "../x"},
                      {"allow": ["**"]}):
            self.assertInvalid({"query": "alpha", **extra})

    def test_bad_query_and_limit(self):
        for args in ({}, {"query": ""}, {"query": "   "}, {"query": 7}, {"query": "a"},
                     {"query": "x" * 201}, {"query": "alpha", "limit": 0},
                     {"query": "alpha", "limit": 11}, {"query": "alpha", "limit": True},
                     {"query": "alpha", "limit": "3"}, {"query": "alpha", "limit": 2.0}):
            self.assertInvalid(args)
        response = json.loads(plugin.handle_search(["not", "a", "dict"], FakeCtx(), self.box.probes()))
        self.assertEqual(response["error"], errors.INVALID_REQUEST)


if __name__ == "__main__":
    unittest.main()
