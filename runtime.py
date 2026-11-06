"""Trusted runtime context for a tool call.

Identity is the Hermes *profile* the call runs in. It comes from context
variables that Hermes binds for each turn, never from tool arguments, which the
model controls. Every Hermes helper used here is an internal API, so any import
or attribute failure is treated as "context unavailable" and the call is denied.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from .errors import MemoryBridgeError, unavailable

PLUGIN_DATA_NAME = "memory-bridge"
POLICY_FILENAME = "policy.json"


@dataclass(frozen=True)
class Probes:
    """Readers for the Hermes runtime state this plugin depends on."""

    home_override: Callable[[], Optional[str]]
    secret_scope_home: Callable[[], Optional[str]]
    is_multiplexed: Callable[[], bool]
    hermes_home: Callable[[], Any]
    is_delegated_child: Callable[[], bool]
    cron_session_flag: Callable[[], str]


@dataclass(frozen=True)
class CallerContext:
    home: Path
    is_cron: bool
    is_subagent: bool


def load_hermes_probes() -> Probes:
    """Bind to the Hermes internals verified for this release; fail closed if any moved."""
    try:
        from hermes_constants import get_hermes_home, get_hermes_home_override
        from agent.secret_scope import current_secret_scope_home, is_multiplex_active
        from agent.delegation_context import is_delegated_child_process_context
        from gateway.session_context import get_session_env
    except Exception as exc:  # ImportError, AttributeError, or anything raised at import time
        raise unavailable("hermes_api_missing") from exc
    return Probes(
        home_override=get_hermes_home_override,
        secret_scope_home=current_secret_scope_home,
        is_multiplexed=is_multiplex_active,
        hermes_home=get_hermes_home,
        is_delegated_child=is_delegated_child_process_context,
        cron_session_flag=lambda: get_session_env("HERMES_CRON_SESSION", ""),
    )


def _profile_home(value) -> Path:
    if not isinstance(value, (str, os.PathLike)) or not str(value):
        raise unavailable("profile_home_invalid")
    home = Path(os.path.expanduser(os.fspath(value)))
    if not home.is_absolute() or ".." in home.parts:
        raise unavailable("profile_home_not_absolute")
    # Lexical comparison deliberately does not follow symlinks to equate profiles.
    return home


def resolve_caller(ctx: Any, probes: Optional[Probes] = None) -> CallerContext:
    """Return the calling profile and run kind, or raise ``unavailable``."""
    if probes is None:
        probes = load_hermes_probes()
    try:
        override = probes.home_override()
        scope_home = probes.secret_scope_home()
        multiplexed = bool(probes.is_multiplexed())
        if override is not None:
            # Let Hermes expand the override exactly as it does for its own paths.
            home = _profile_home(probes.hermes_home())
            if _profile_home(os.path.expandvars(override)) != home:
                raise unavailable("profile_context_conflict")
            if scope_home is not None and _profile_home(scope_home) != home:
                raise unavailable("profile_context_conflict")
        elif scope_home is not None:
            # A scope home with no override is not proof of who is calling: Hermes also stamps
            # owner scopes (MCP, browser lifecycle, kanban) without redirecting its own home.
            # Accept it only when it names the very home Hermes resolves for this call.
            home = _profile_home(scope_home)
            if _profile_home(probes.hermes_home()) != home:
                raise unavailable("profile_context_conflict")
        elif multiplexed:
            # A process serving several profiles must name the caller's profile explicitly.
            raise unavailable("no_profile_context")
        else:
            home = _profile_home(probes.hermes_home())

        current_cron = getattr(ctx, "current_cron_execution", None)
        if not callable(current_cron):
            raise unavailable("hermes_api_missing")
        is_cron = current_cron() is not None or probes.cron_session_flag() == "1"
        is_subagent = bool(probes.is_delegated_child())
    except MemoryBridgeError:
        raise
    except Exception as exc:
        raise unavailable("context_probe_failed") from exc

    if not home.is_absolute():
        raise unavailable("profile_home_not_absolute")
    return CallerContext(home=home, is_cron=is_cron, is_subagent=is_subagent)


def policy_path(home: Path) -> Path:
    """``<profile home>/plugin-data/memory-bridge/policy.json``.

    Same location as Hermes's ``plugin_data_dir()``, computed from the verified
    caller home without creating directories.
    """
    return home / "plugin-data" / PLUGIN_DATA_NAME / POLICY_FILENAME
