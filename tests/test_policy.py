import json
import os
import unittest

from _support import Sandbox, errors, policy


class PolicyLoadingTests(unittest.TestCase):
    def setUp(self):
        self.box = Sandbox()

    def tearDown(self):
        self.box.cleanup()

    def assertRefused(self, reason=None):
        with self.assertRaises(errors.MemoryBridgeError) as caught:
            policy.load_policy(self.box.policy_file)
        self.assertEqual(caught.exception.code, errors.UNAVAILABLE)
        if reason:
            self.assertEqual(caught.exception.reason, reason)

    def write_raw(self, text, mode=0o600):
        path = self.box.policy_file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        os.chmod(path, mode)

    def test_valid_policy_uses_default_limits(self):
        self.box.write_policy()
        loaded = policy.load_policy(self.box.policy_file)
        self.assertEqual(loaded.root, str(self.box.root))
        self.assertEqual(loaded.limits.max_results, 10)
        self.assertEqual(loaded.limits.default_results, 5)
        self.assertFalse(loaded.allow_cron)
        self.assertFalse(loaded.allow_subagents)

    def test_missing_policy_fails_closed(self):
        self.assertRefused("policy_unreadable")

    def test_malformed_json_fails_closed(self):
        self.write_raw("{not json")
        self.assertRefused("policy_json_invalid")

    def test_duplicate_keys_fail_closed(self):
        self.write_raw('{"version": 1, "root": "%s", "allow": ["**"], "allow": ["x"]}' % self.box.root)
        self.assertRefused("policy_json_invalid")

    def test_symlinked_policy_is_refused(self):
        real = self.box.write("real-policy.json", json.dumps(self.box.policy_data()), where=self.box.outside)
        os.chmod(real, 0o600)
        self.box.policy_file.parent.mkdir(parents=True)
        os.symlink(real, self.box.policy_file)
        self.assertRefused("policy_unreadable")

    def test_policy_writable_by_others_is_refused(self):
        self.write_raw(json.dumps(self.box.policy_data()), mode=0o620)
        self.assertRefused("policy_writable_by_others")

    def test_oversized_policy_is_refused(self):
        self.write_raw(" " * (policy.MAX_POLICY_BYTES + 1))
        self.assertRefused("policy_not_regular_or_too_large")

    def test_fifo_policy_is_refused_without_blocking(self):
        self.box.policy_file.parent.mkdir(parents=True)
        os.mkfifo(self.box.policy_file, 0o600)
        self.assertRefused("policy_not_regular_or_too_large")


class PolicySchemaTests(unittest.TestCase):
    def setUp(self):
        self.box = Sandbox()

    def tearDown(self):
        self.box.cleanup()

    def assertInvalid(self, **overrides):
        with self.assertRaises(errors.MemoryBridgeError) as caught:
            policy.parse_policy(self.box.policy_data(**overrides))
        self.assertEqual(caught.exception.code, errors.UNAVAILABLE)

    def test_rejects_unknown_keys_and_versions(self):
        self.assertInvalid(agent="trusted-agent")
        self.assertInvalid(version=2)
        self.assertInvalid(version=True)
        with self.assertRaises(errors.MemoryBridgeError):
            policy.parse_policy(["not", "an", "object"])

    def test_rejects_bad_allow_and_deny(self):
        self.assertInvalid(allow=[])
        self.assertInvalid(allow="**")
        self.assertInvalid(allow=["/etc/**"])
        self.assertInvalid(allow=["../outside/**"])
        self.assertInvalid(allow=["projects/../../x.md"])
        self.assertInvalid(allow=["projects\\x.md"])
        self.assertInvalid(allow=["projects//x.md"])
        self.assertInvalid(allow=["a**b"])
        self.assertInvalid(allow=["[abc].md"])
        self.assertInvalid(deny=[1])
        self.assertInvalid(deny=["**"] * (policy.MAX_PATTERNS + 1))

    def test_rejects_bad_roots(self):
        self.assertInvalid(root="relative/memory")
        self.assertInvalid(root=str(self.box.root) + "/../memory")
        self.assertInvalid(root=str(self.box.root) + "/")
        link = self.box.base / "memory-link"
        os.symlink(self.box.root, link)
        self.assertInvalid(root=str(link))
        self.assertInvalid(root=None)

    def test_rejects_bad_flags_and_limits(self):
        self.assertInvalid(allow_cron="yes")
        self.assertInvalid(allow_subagents=1)
        self.assertInvalid(limits={"max_results": 11})
        self.assertInvalid(limits={"snippet_chars": 5000})
        self.assertInvalid(limits={"total_chars": 100000})
        self.assertInvalid(limits={"max_results": True})
        self.assertInvalid(limits={"unknown": 1})
        self.assertInvalid(limits={"max_results": 3, "default_results": 5})

    def test_operators_may_lower_limits(self):
        loaded = policy.parse_policy(self.box.policy_data(limits={"max_results": 3, "default_results": 2}))
        self.assertEqual((loaded.limits.max_results, loaded.limits.default_results), (3, 2))


class MatchingTests(unittest.TestCase):
    def make(self, allow, deny=()):
        box = Sandbox()
        self.addCleanup(box.cleanup)
        return policy.parse_policy(box.policy_data(allow=list(allow), deny=list(deny)))

    def test_deny_wins_over_allow(self):
        rules = self.make(["projects/**"], ["projects/secret/**"])
        self.assertTrue(rules.is_allowed(["projects", "a.md"]))
        self.assertFalse(rules.is_allowed(["projects", "secret", "a.md"]))

    def test_nothing_is_allowed_by_default(self):
        rules = self.make(["projects/**"])
        self.assertFalse(rules.is_allowed(["inbox", "a.md"]))
        self.assertFalse(rules.is_allowed(["a.md"]))

    def test_globstar_spans_zero_or_more_segments(self):
        rules = self.make(["**/notes.md"])
        self.assertTrue(rules.is_allowed(["notes.md"]))
        self.assertTrue(rules.is_allowed(["a", "b", "notes.md"]))

    def test_single_star_stays_inside_one_segment(self):
        rules = self.make(["projects/*.md"])
        self.assertTrue(rules.is_allowed(["projects", "a.md"]))
        self.assertFalse(rules.is_allowed(["projects", "sub", "a.md"]))

    def test_matching_ignores_case_in_both_directions(self):
        rules = self.make(["Projects/**"], ["**/private/**"])
        self.assertTrue(rules.is_allowed(["PROJECTS", "a.md"]))
        self.assertFalse(rules.is_allowed(["projects", "Private", "a.md"]))
        self.assertFalse(rules.is_allowed(["projects", "PRIVATE", "x", "a.md"]))

    def test_may_descend_prunes_denied_and_unreachable_directories(self):
        rules = self.make(["projects/**", "decisions/*.md"], ["**/private/**"])
        self.assertTrue(rules.may_descend(["projects"]))
        self.assertTrue(rules.may_descend(["projects", "deep", "deeper"]))
        self.assertTrue(rules.may_descend(["decisions"]))
        self.assertFalse(rules.may_descend(["decisions", "sub"]))
        self.assertFalse(rules.may_descend(["inbox"]))
        self.assertFalse(rules.may_descend(["projects", "Private"]))


if __name__ == "__main__":
    unittest.main()
