"""Shared test helpers: load the plugin package and build synthetic fixtures.

Every fixture lives in a fresh temporary directory. Tests never read real memory
and never bind to a live Hermes install: the Hermes modules the plugin probes are
blocked below, so any code path that tried to reach them fails closed instead.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

if sys.version_info < (3, 11):  # Hermes requires 3.11+; fail loudly instead of testing on an old default
    raise RuntimeError("Memory Bridge tests need Python 3.11 or newer, found %d.%d" % sys.version_info[:2])

for _blocked in ("hermes_constants", "agent.secret_scope", "agent.delegation_context",
                 "gateway.session_context"):
    sys.modules[_blocked] = None  # makes "import <name>" raise ImportError

# Keep refusal logs out of test output; assertLogs still captures them where a test checks them.
logging.getLogger("memory_bridge").addHandler(logging.NullHandler())
logging.getLogger("memory_bridge").propagate = False

REPO = Path(__file__).resolve().parent.parent
PKG = "memory_bridge_under_test"


def load_plugin():
    if PKG in sys.modules:
        return sys.modules[PKG]
    spec = importlib.util.spec_from_file_location(
        PKG, REPO / "__init__.py", submodule_search_locations=[str(REPO)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[PKG] = module
    spec.loader.exec_module(module)
    return module


plugin = load_plugin()
acl = sys.modules[f"{PKG}.acl"]
errors = sys.modules[f"{PKG}.errors"]
policy = sys.modules[f"{PKG}.policy"]
runtime = sys.modules[f"{PKG}.runtime"]
safe_fs = sys.modules[f"{PKG}.safe_fs"]
search = sys.modules[f"{PKG}.search"]
reader = sys.modules[f"{PKG}.reader"]


class FakeCtx:
    """Stands in for Hermes's PluginContext."""

    def __init__(self, cron=None):
        self.cron = cron
        self.registered = []

    def current_cron_execution(self):
        return self.cron

    def register_tool(self, **kwargs):
        self.registered.append(kwargs)


class Sandbox:
    """A temporary profile home plus a synthetic memory root."""

    def __init__(self, parent=None):
        self.base = Path(os.path.realpath(tempfile.mkdtemp(prefix="mb-test-", dir=parent)))
        self.home = self.base / "profile-home"
        self.root = self.base / "memory"
        self.outside = self.base / "outside"
        for path in (self.home, self.root, self.outside):
            path.mkdir()
            os.chmod(path, 0o700)  # independent of the caller's umask

    def cleanup(self):
        shutil.rmtree(self.base)  # cleanup failures must fail the test, not leak fixtures

    def write(self, rel: str, text: str, where=None) -> Path:
        path = (where or self.root) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    @property
    def policy_file(self) -> Path:
        return runtime.policy_path(self.home)

    def policy_data(self, **overrides) -> dict:
        data = {"version": 1, "root": str(self.root), "allow": ["**"], "deny": []}
        data.update(overrides)
        return data

    def write_policy(self, **overrides) -> Path:
        path = self.policy_file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.policy_data(**overrides)), encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def probes(self, *, override=True, scope_home=None, multiplexed=False,
               subagent=False, cron_flag=""):
        home = self.home
        return runtime.Probes(
            home_override=(lambda: str(home)) if override else (lambda: None),
            secret_scope_home=lambda: scope_home,
            is_multiplexed=lambda: multiplexed,
            hermes_home=lambda: home,
            is_delegated_child=lambda: subagent,
            cron_session_flag=lambda: cron_flag,
        )

    def search(self, args, ctx=None, **probe_kwargs) -> dict:
        return json.loads(self.search_raw(args, ctx, **probe_kwargs))

    def search_raw(self, args, ctx=None, **probe_kwargs) -> str:
        return plugin.handle_search(args, ctx or FakeCtx(), self.probes(**probe_kwargs))

    def read(self, args, ctx=None, **probe_kwargs) -> dict:
        return json.loads(self.read_raw(args, ctx, **probe_kwargs))

    def read_raw(self, args, ctx=None, **probe_kwargs) -> str:
        return plugin.handle_read(args, ctx or FakeCtx(), self.probes(**probe_kwargs))
