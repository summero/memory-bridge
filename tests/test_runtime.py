import dataclasses
import json
import os
import unittest
from unittest import mock

from _support import FakeCtx, Sandbox, errors, plugin, runtime


class RuntimeContextTests(unittest.TestCase):
    def setUp(self):
        self.box = Sandbox()
        self.box.write("projects/a.md", "alpha")
        self.box.write_policy(allow=["projects/**"])

    def tearDown(self):
        self.box.cleanup()

    def assertUnavailable(self, response):
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"], errors.UNAVAILABLE)
        text = json.dumps(response)
        for leak in (str(self.box.base), str(self.box.home), "policy", "plugin-data"):
            self.assertNotIn(leak, text)

    def test_single_profile_uses_hermes_home(self):
        caller = runtime.resolve_caller(FakeCtx(), self.box.probes(override=False))
        self.assertEqual(caller.home, self.box.home)

    def test_secret_scope_home_names_the_profile_when_no_override(self):
        caller = runtime.resolve_caller(
            FakeCtx(), self.box.probes(override=False, scope_home=str(self.box.home), multiplexed=True))
        self.assertEqual(caller.home, self.box.home)

    def test_multiplex_without_profile_context_fails_closed(self):
        self.assertUnavailable(self.box.search({"query": "alpha"}, override=False, multiplexed=True))

    def test_multiplex_with_profile_context_works(self):
        self.assertTrue(self.box.search({"query": "alpha"}, multiplexed=True)["ok"])

    def test_profile_from_another_home_sees_only_its_own_policy(self):
        other = Sandbox()
        self.addCleanup(other.cleanup)
        # The other profile has no policy, so a call routed to it is refused.
        self.assertUnavailable(other.search({"query": "alpha"}))

    def test_cron_is_denied_by_default(self):
        self.assertUnavailable(self.box.search({"query": "alpha"}, ctx=FakeCtx(cron=object())))
        self.assertUnavailable(self.box.search({"query": "alpha"}, cron_flag="1"))

    def test_cron_can_be_allowed_by_operator(self):
        self.box.write_policy(allow=["projects/**"], allow_cron=True)
        self.assertTrue(self.box.search({"query": "alpha"}, ctx=FakeCtx(cron=object()))["ok"])

    def test_subagents_are_denied_by_default(self):
        self.assertUnavailable(self.box.search({"query": "alpha"}, subagent=True))
        self.box.write_policy(allow=["projects/**"], allow_subagents=True)
        self.assertTrue(self.box.search({"query": "alpha"}, subagent=True)["ok"])

    def test_missing_cron_api_fails_closed(self):
        class OldCtx:
            pass
        self.assertUnavailable(json.loads(plugin.handle_search({"query": "alpha"}, OldCtx(), self.box.probes())))

    def test_probe_failure_fails_closed(self):
        def broken():
            raise RuntimeError("internal API changed: /secret/path")
        probes = dataclasses.replace(self.box.probes(), is_delegated_child=broken)
        self.assertUnavailable(json.loads(plugin.handle_search({"query": "alpha"}, FakeCtx(), probes)))

    def test_missing_hermes_internals_fail_closed(self):
        # _support blocks the Hermes modules, as a Hermes release that moved them would.
        with self.assertRaises(errors.MemoryBridgeError) as caught:
            runtime.load_hermes_probes()
        self.assertEqual(caught.exception.reason, "hermes_api_missing")
        self.assertUnavailable(json.loads(plugin.handle_search({"query": "alpha"}, FakeCtx())))

    def test_operator_logs_hold_reason_labels_without_paths(self):
        def broken():
            raise RuntimeError("internal API changed: " + str(self.box.home))
        probes = dataclasses.replace(self.box.probes(), is_delegated_child=broken)
        with self.assertLogs("memory_bridge", "WARNING") as logs:
            plugin.handle_search({"query": "alpha"}, FakeCtx(), probes)
            with mock.patch.object(plugin.search, "run_search", side_effect=OSError(2, "x", str(self.box.root))):
                self.box.search({"query": "alpha"})
            os.unlink(self.box.policy_file)
            self.box.search({"query": "alpha"})
        joined = "\n".join(logs.output)
        self.assertIn("context_probe_failed", joined)
        self.assertIn("policy_unreadable", joined)
        self.assertNotIn(str(self.box.base), joined)

    def test_unexpected_exception_is_generic(self):
        with mock.patch.object(plugin.search, "run_search", side_effect=OSError(2, "No such file", "/x/y")):
            self.assertUnavailable(self.box.search({"query": "alpha"}))


class RegistrationTests(unittest.TestCase):
    NAMES = ["memory_bridge_search", "memory_bridge_read"]

    def test_registers_both_tools_without_override(self):
        ctx = FakeCtx()
        plugin.register(ctx)
        self.assertEqual([call["name"] for call in ctx.registered], self.NAMES)
        for call in ctx.registered:
            self.assertEqual(call["schema"]["name"], call["name"])
            self.assertEqual(call["toolset"], "memory_bridge")
            self.assertNotIn("override", call)
            self.assertFalse(call["schema"]["parameters"]["additionalProperties"])

    def test_manifest_declares_the_registered_tools(self):
        from _support import REPO
        manifest = (REPO / "plugin.yaml").read_text()
        self.assertIn("kind: standalone", manifest)
        for name in self.NAMES:
            self.assertIn(f"- {name}", manifest)

    def test_handlers_accept_hermes_context_keywords(self):
        ctx = FakeCtx()
        plugin.register(ctx)
        for call, args in zip(ctx.registered, ({"query": "alpha"}, {"id": "projects/a.md"})):
            # Outside Hermes the runtime probes are unavailable, so the call fails closed.
            raw = call["handler"](args, task_id="t", session_id="s", user_task="u")
            self.assertEqual(json.loads(raw)["error"], errors.UNAVAILABLE)


if __name__ == "__main__":
    unittest.main()
