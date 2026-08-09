"""Per-session call-budget ASGI middleware for the unified server.

Interim guard against a runaway session hammering FortiManager: caps HTTP
requests per MCP session within a sliding time window. Sessions are tracked
in-memory, which is fine for the single-process deployment this server
currently runs as; a multi-process/load-balanced deployment would need a
shared store instead.
"""

from __future__ import annotations

import json
import time
from collections import deque

_NO_SESSION = b"__no_session__"


class RateLimitConfigError(ValueError):
    """Raised when rate limiting is configured with invalid parameters."""


def rate_limit(app, max_requests: int, window_seconds: float):
    """Wrap an ASGI app: cap requests per session to max_requests per window_seconds.

    Sessions are identified by the `Mcp-Session-Id` header that MCP
    streamable-HTTP clients send after `initialize`; requests without one
    (e.g. the `initialize` call itself) share a single bucket.
    """
    if max_requests <= 0 or window_seconds <= 0:
        raise RateLimitConfigError("max_requests and window_seconds must be positive")

    windows: dict[bytes, deque[float]] = {}

    async def wrapped(scope, receive, send):
        if scope["type"] != "http":
            await app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        session_id = headers.get(b"mcp-session-id", _NO_SESSION)

        now = time.monotonic()
        window = windows.setdefault(session_id, deque())
        while window and now - window[0] > window_seconds:
            window.popleft()

        if len(window) >= max_requests:
            body = json.dumps({
                "error": "rate_limited",
                "detail": f"Session exceeded {max_requests} requests per "
                          f"{window_seconds:.0f}s",
            }).encode()
            await send({
                "type": "http.response.start",
                "status": 429,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"retry-after", str(int(window_seconds)).encode()),
                ],
            })
            await send({"type": "http.response.body", "body": body})
            return

        window.append(now)
        await app(scope, receive, send)

    return wrapped
