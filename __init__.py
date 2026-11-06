"""Memory Bridge: read-only, permission-aware memory access for Hermes Agent.

Registers two tools, ``memory_bridge_search`` and ``memory_bridge_read``. Each call:

1. resolves the calling profile from Hermes runtime context (never from arguments),
2. loads that profile's operator policy from its plugin data directory,
3. refuses cron and delegated-subagent runs unless the policy opts in,
4. touches only allowed Markdown files under the policy root, within fixed limits.

Any failure returns a generic error code. Details go to the operator log as
short reason labels, without paths.
"""

from __future__ import annotations

import json
import logging

from . import errors, policy, reader, runtime, search

logger = logging.getLogger("memory_bridge")

SEARCH_TOOL = "memory_bridge_search"
READ_TOOL = "memory_bridge_read"
TOOLSET = "memory_bridge"

SEARCH_SCHEMA = {
    "name": SEARCH_TOOL,
    "description": (
        "Search the operator-approved shared memory (read-only Markdown notes) for context "
        "relevant to the current task. Returns up to 10 short snippets with document ids; "
        "pass an id to memory_bridge_read for the full text. Access is decided by the "
        "operator's policy for this profile; arguments cannot change it."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Keywords to look for, for example 'release checklist'.",
                "minLength": 1,
                "maxLength": search.MAX_QUERY_CHARS,
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of results (default 5, at most 10).",
                "minimum": 1,
                "maximum": 10,
            },
        },
        "required": ["query"],
        "additionalProperties": False,
    },
}

READ_SCHEMA = {
    "name": READ_TOOL,
    "description": (
        "Read one document from the operator-approved shared memory by the id that "
        "memory_bridge_search returned. Read-only; returns at most 8000 characters and marks "
        "longer documents as truncated. Missing and forbidden documents get the same answer."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "id": {
                "type": "string",
                "description": "Root-relative document id, for example 'projects/garden.md'.",
                "minLength": 1,
                "maxLength": reader.MAX_ID_CHARS,
            },
        },
        "required": ["id"],
        "additionalProperties": False,
    },
}


def _search(args, active):
    terms, limit = search.parse_request(args, active)
    return search.run_search(active, terms, limit)


def _read(args, active):
    doc_id, parts = reader.parse_request(args)
    return reader.run_read(active, doc_id, parts)


def _run_tool(tool: str, operation, args, ctx, probes) -> str:
    """Shared gates for every tool, then ``operation``. Returns JSON; never raises."""
    try:
        caller = runtime.resolve_caller(ctx, probes)
        active = policy.load_policy(runtime.policy_path(caller.home))
        if caller.is_cron and not active.allow_cron:
            raise errors.unavailable("cron_denied")
        if caller.is_subagent and not active.allow_subagents:
            raise errors.unavailable("subagent_denied")
        return json.dumps(operation(args, active), ensure_ascii=False)
    except errors.MemoryBridgeError as exc:
        logger.warning("%s refused: %s (%s)", tool, exc.code, exc.reason)
        return json.dumps(exc.public())
    except Exception as exc:  # defensive: never surface exception text, which may contain paths
        logger.warning("%s failed: unexpected %s", tool, type(exc).__name__)
        return json.dumps(errors.public_unavailable())


def handle_search(args, ctx, probes=None) -> str:
    return _run_tool(SEARCH_TOOL, _search, args, ctx, probes)


def handle_read(args, ctx, probes=None) -> str:
    return _run_tool(READ_TOOL, _read, args, ctx, probes)


def register(ctx) -> None:
    # Hermes passes task/session ids as keywords. They are correlation ids, not identity,
    # so the handlers deliberately ignore them.
    def _search_handler(args, **_kwargs):
        return handle_search(args, ctx)

    def _read_handler(args, **_kwargs):
        return handle_read(args, ctx)

    for name, schema, handler, description in (
        (SEARCH_TOOL, SEARCH_SCHEMA, _search_handler, "Read-only, permission-aware memory search"),
        (READ_TOOL, READ_SCHEMA, _read_handler, "Read one permitted memory document"),
    ):
        ctx.register_tool(name=name, toolset=TOOLSET, schema=schema, handler=handler,
                          description=description, emoji="🧠")
