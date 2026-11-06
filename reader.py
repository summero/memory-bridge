"""Read one allowed document by its root-relative id."""

from __future__ import annotations

from .errors import invalid_request, not_found_or_denied
from .policy import Policy
from .safe_fs import MAX_ID_CHARS, MAX_ID_SEGMENTS, is_markdown_name, is_valid_name, read_document

TRUNCATION_MARKER = "\n\n[Memory Bridge: truncated, showing at most {cap} characters of this document]"
_ALLOWED_ARGS = {"id"}
# One reason for every refusal, so operator logs cannot tell a missing document from a denied one.
_REFUSED = "not_found_or_denied"


def parse_request(args):
    """Validate the id's shape only. Nothing here depends on the filesystem or the policy, so an
    ``invalid_request`` reveals nothing about which documents exist."""
    if not isinstance(args, dict):
        raise invalid_request("args_not_object", "arguments must be an object")
    if set(args) - _ALLOWED_ARGS:
        raise invalid_request("unknown_args", "only 'id' is accepted")
    doc_id = args.get("id")
    if not isinstance(doc_id, str) or not doc_id or len(doc_id) > MAX_ID_CHARS:
        raise invalid_request("bad_id", f"id must be 1-{MAX_ID_CHARS} characters")
    parts = tuple(doc_id.split("/"))
    if (len(parts) > MAX_ID_SEGMENTS or not all(is_valid_name(p) for p in parts)
            or not is_markdown_name(parts[-1])):
        raise invalid_request("bad_id", "id must be a relative .md path as returned by memory_bridge_search")
    return doc_id, parts


def _visible_to_search(policy: Policy, parts) -> bool:
    """Exactly the documents search could reach: within depth, every folder descendable, file allowed."""
    if len(parts) > policy.limits.max_depth or not policy.is_allowed(parts):
        return False
    return all(policy.may_descend(parts[:i]) for i in range(1, len(parts)))


def run_read(policy: Policy, doc_id: str, parts) -> dict:
    # Missing, denied, and unreadable documents all produce the same public response.
    if not _visible_to_search(policy, parts):
        raise not_found_or_denied(_REFUSED)
    text = read_document(policy.root, parts, policy.limits.max_file_bytes)
    if text is None:
        raise not_found_or_denied(_REFUSED)
    cap = policy.limits.read_chars
    truncated = len(text) > cap
    if truncated:
        marker = TRUNCATION_MARKER.format(cap=cap)
        text = text[: cap - len(marker)].rstrip() + marker
    return {"ok": True, "id": doc_id, "content": text, "truncated": truncated}
