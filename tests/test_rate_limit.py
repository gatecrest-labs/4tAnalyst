"""
Tests for fwanalyst_server: per-session rate-limiting middleware.
Middleware is driven directly as an ASGI callable — no server needed.
"""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from fwanalyst_server.rate_limit import RateLimitConfigError, rate_limit


async def _echo_app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def _call(app, headers=()):
    sent = []

    async def send(msg):
        sent.append(msg)

    async def receive():
        return {"type": "http.request", "body": b""}

    scope = {"type": "http", "method": "POST", "path": "/mcp",
             "headers": list(headers)}
    asyncio.run(app(scope, receive, send))
    return sent


def test_requests_under_budget_pass_through():
    app = rate_limit(_echo_app, max_requests=2, window_seconds=60)
    for _ in range(2):
        sent = _call(app)
        assert sent[0]["status"] == 200


def test_requests_over_budget_get_429():
    app = rate_limit(_echo_app, max_requests=1, window_seconds=60)
    _call(app)
    sent = _call(app)
    assert sent[0]["status"] == 429
    retry_after = dict(sent[0]["headers"])[b"retry-after"]
    assert retry_after == b"60"


def test_separate_sessions_have_separate_budgets():
    app = rate_limit(_echo_app, max_requests=1, window_seconds=60)
    sent_a = _call(app, [(b"mcp-session-id", b"session-a")])
    sent_b = _call(app, [(b"mcp-session-id", b"session-b")])
    assert sent_a[0]["status"] == 200
    assert sent_b[0]["status"] == 200
    # session-a is now over budget, session-b still has room used up too
    sent_a_again = _call(app, [(b"mcp-session-id", b"session-a")])
    assert sent_a_again[0]["status"] == 429


def test_window_expiry_resets_budget():
    app = rate_limit(_echo_app, max_requests=1, window_seconds=0.05)
    _call(app)
    blocked = _call(app)
    assert blocked[0]["status"] == 429
    import time
    time.sleep(0.06)
    sent = _call(app)
    assert sent[0]["status"] == 200


def test_non_http_scope_passes_through_unmetered():
    app = rate_limit(_echo_app, max_requests=1, window_seconds=60)

    async def _run():
        sent = []

        async def send(msg):
            sent.append(msg)

        async def receive():
            return {"type": "lifespan.startup"}

        await app({"type": "lifespan"}, receive, send)
        return sent

    # lifespan scope has no http status to assert on; just confirm no crash
    # and that it doesn't consume the http rate-limit budget
    asyncio.run(_run())
    sent = _call(app)
    assert sent[0]["status"] == 200


def test_invalid_config_raises():
    with pytest.raises(RateLimitConfigError):
        rate_limit(_echo_app, max_requests=0, window_seconds=60)
    with pytest.raises(RateLimitConfigError):
        rate_limit(_echo_app, max_requests=10, window_seconds=0)
