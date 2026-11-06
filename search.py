"""Bounded keyword search over the documents a policy allows."""

from __future__ import annotations

import re
from typing import Optional

from .errors import invalid_request
from .policy import Policy
from .safe_fs import ScanStats, iter_documents

MAX_QUERY_CHARS = 200
MAX_TERMS = 16
MIN_TERM_CHARS = 2
MAX_TITLE_CHARS = 120
_ALLOWED_ARGS = {"query", "limit"}
_TERM_RE = re.compile(r"\w+")
_HEADING_RE = re.compile(r"^#\s+(.+?)\s*#*\s*$", re.MULTILINE)
_ELLIPSIS = "…"


def parse_request(args, policy: Policy):
    """Validate model-supplied arguments. Unknown keys are rejected, so no argument
    (an agent name, a profile, a path) can widen access."""
    if not isinstance(args, dict):
        raise invalid_request("args_not_object", "arguments must be an object")
    extra = set(args) - _ALLOWED_ARGS
    if extra:
        raise invalid_request("unknown_args", "only 'query' and 'limit' are accepted")
    query = args.get("query")
    if not isinstance(query, str) or not query.strip() or len(query) > MAX_QUERY_CHARS:
        raise invalid_request("bad_query", f"query must be 1-{MAX_QUERY_CHARS} characters")
    terms = []
    for term in _TERM_RE.findall(query.casefold()):
        if len(term) >= MIN_TERM_CHARS and term not in terms:
            terms.append(term)
    if not terms:
        raise invalid_request("no_terms", f"query needs a word of at least {MIN_TERM_CHARS} characters")
    limits = policy.limits
    limit = args.get("limit", limits.default_results)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= limits.max_results:
        raise invalid_request("bad_limit", f"limit must be an integer from 1 to {limits.max_results}")
    return terms[:MAX_TERMS], limit


def _title(text: str) -> Optional[str]:
    match = _HEADING_RE.search(text[:4096])
    if not match:
        return None
    return _clip(" ".join(match.group(1).split()), MAX_TITLE_CHARS)


def _clip(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 1].rstrip() + _ELLIPSIS


def _snippet(text: str, folded: str, terms, max_chars: int) -> str:
    # Positions found in the casefolded text only map back when casefolding kept the length.
    source = text if len(folded) == len(text) else folded
    positions = [folded.find(t) for t in terms if t in folded]
    center = min(positions) if positions else 0
    start = max(0, center - max_chars // 3)
    window = source[start: start + max_chars * 2]
    body = " ".join(window.split())
    prefix = _ELLIPSIS if start > 0 else ""
    budget = max_chars - len(prefix)
    has_more = start + len(window) < len(source) or len(body) > budget
    if has_more:
        body = body[: budget - 1].rstrip() + _ELLIPSIS
    return prefix + body


def run_search(policy: Policy, terms, limit: int) -> dict:
    limits = policy.limits
    stats = ScanStats()
    scored = []
    for doc in iter_documents(
        policy.root,
        policy.is_allowed,
        policy.may_descend,
        max_file_bytes=limits.max_file_bytes,
        max_entries=limits.max_entries,
        max_depth=limits.max_depth,
        stats=stats,
    ):
        folded = doc.text.casefold()
        id_folded = doc.id.casefold()
        counts = [folded.count(t) for t in terms]
        matched = sum(1 for t, c in zip(terms, counts) if c or t in id_folded)
        if matched:
            scored.append((-matched, -sum(counts), doc.id, doc.text, folded))
    scored.sort(key=lambda item: (item[0], item[1], item[2]))

    results = []
    used = 0
    truncated = stats.truncated or len(scored) > limit
    for _, _, doc_id, text, folded in scored[:limit]:
        item = {"id": doc_id}
        title = _title(text)
        if title:
            item["title"] = title
        item["snippet"] = _snippet(text, folded, terms, limits.snippet_chars)
        size = sum(len(v) for v in item.values())
        if used + size > limits.total_chars:
            truncated = True
            break
        used += size
        results.append(item)
    return {"ok": True, "results": results, "truncated": truncated}
