"""Error types with fixed, generic messages for the model.

Only the public ``code`` and ``message`` reach the model. The ``reason`` is a
short internal label for operator logs; it never contains paths or OS error text.
"""

from __future__ import annotations

INVALID_REQUEST = "invalid_request"
UNAVAILABLE = "unavailable"
NOT_FOUND_OR_DENIED = "not_found_or_denied"

_PUBLIC_MESSAGES = {
    INVALID_REQUEST: "The request is invalid.",
    UNAVAILABLE: "Memory Bridge is not available in this context.",
    NOT_FOUND_OR_DENIED: "The requested memory was not found or access is denied.",
}


class MemoryBridgeError(Exception):
    """A failure that maps to one public error code."""

    def __init__(self, code: str, reason: str, hint: str = "") -> None:
        if code not in _PUBLIC_MESSAGES:
            raise ValueError("unknown error code")
        super().__init__(reason)
        self.code = code
        self.reason = reason
        # A hint describes the caller's own input (for example "limit must be 1-10").
        # It must never describe the filesystem, the policy, or the runtime.
        self.hint = hint

    def public(self) -> dict:
        body = {"ok": False, "error": self.code, "message": _PUBLIC_MESSAGES[self.code]}
        if self.hint:
            body["hint"] = self.hint
        return body


def invalid_request(reason: str, hint: str) -> MemoryBridgeError:
    return MemoryBridgeError(INVALID_REQUEST, reason, hint)


def unavailable(reason: str) -> MemoryBridgeError:
    return MemoryBridgeError(UNAVAILABLE, reason)


def not_found_or_denied(reason: str) -> MemoryBridgeError:
    return MemoryBridgeError(NOT_FOUND_OR_DENIED, reason)


def public_unavailable() -> dict:
    return MemoryBridgeError(UNAVAILABLE, "unexpected").public()
