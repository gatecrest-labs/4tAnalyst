"""ASGI middleware: intercept MCP tools/call requests and log them to analytics.

Must be placed INSIDE the bearer-auth layer so token_label_var is already
populated when __call__ runs.
"""

from __future__ import annotations

import json
from typing import Any

from fwanalyst_server import analytics
from fwanalyst_server.context import token_label_var


class UsageMiddleware:
    """ASGI middleware: log MCP tools/call invocations to analytics.db.

    Eagerly consumes the request body (accumulates all chunks until
    ``more_body`` is False), attempts to log the tool call, then replays
    the body to the downstream application via a synthetic ``receive``
    callable so the downstream sees an unmodified request stream.

    Parameters
    ----------
    app:
        The downstream ASGI application.
    db:
        An explicit ``AnalyticsDB`` instance (useful in tests). When *None*,
        falls back to the module-level singleton initialised by
        ``analytics.init()``.
    """

    def __init__(self, app: Any, db: "analytics.AnalyticsDB | None" = None) -> None:
        self._app = app
        self._db = db  # explicit db for tests; None = use module singleton

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        # Eagerly read the full request body before passing to downstream app.
        chunks: list[bytes] = []
        more = True
        last_msg: dict = {}
        while more:
            msg = await receive()
            if msg["type"] == "http.request":
                chunks.append(msg.get("body", b""))
                more = bool(msg.get("more_body", False))
                last_msg = msg
            else:
                # Non-request message (e.g. http.disconnect): forward and stop.
                last_msg = msg
                more = False

        body = b"".join(chunks)
        self._try_log(body)

        # Replay the consumed body to the downstream app.
        replayed = False

        async def replay_receive() -> dict:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            # If the body-reading loop was interrupted by a non-request event
            # (e.g. http.disconnect arrived mid-body), return that stored event.
            if last_msg.get("type") != "http.request":
                return last_msg
            # Body was fully received normally; proxy subsequent calls to the
            # real receive() so the MCP transport gets the actual http.disconnect
            # signal instead of looping on the replayed request forever.
            return await receive()

        await self._app(scope, replay_receive, send)

    def _try_log(self, body: bytes) -> None:
        try:
            data = json.loads(body)
            if data.get("method") != "tools/call":
                return
            tool_name: str = data.get("params", {}).get("name", "unknown")
            adom: str | None = data.get("params", {}).get("arguments", {}).get("adom")
            token_label = token_label_var.get("-")
            db = self._db or analytics._db
            if db:
                db.log_tool_call(token_label, tool_name, adom)
        except Exception:
            pass
