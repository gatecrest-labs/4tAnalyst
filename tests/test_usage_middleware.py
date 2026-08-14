import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from fwanalyst_server import context as ctx
from fwanalyst_server.analytics import AnalyticsDB
from fwanalyst_server.usage_middleware import UsageMiddleware


async def mcp_app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


async def call(app, path: str, body: bytes = b"") -> None:
    scope = {"type": "http", "path": path, "headers": []}
    body_sent = False

    async def receive():
        nonlocal body_sent
        if not body_sent:
            body_sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(msg):
        pass

    await app(scope, receive, send)


@pytest.mark.anyio
async def test_tool_call_logged(tmp_path):
    db = AnalyticsDB(str(tmp_path / "test.db"))
    body = json.dumps({"jsonrpc": "2.0", "method": "tools/call",
                       "params": {"name": "search_policies"}, "id": 1}).encode()
    token = ctx.token_label_var.set("alice")
    try:
        app = UsageMiddleware(mcp_app, db)
        await call(app, "/mcp/", body)
    finally:
        ctx.token_label_var.reset(token)
    db._queue.join()
    rows = db.query_tool_calls(range_seconds=3600)
    assert len(rows) == 1
    assert rows[0]["tool_name"] == "search_policies"
    assert rows[0]["token_label"] == "alice"


@pytest.mark.anyio
async def test_non_tool_call_not_logged(tmp_path):
    db = AnalyticsDB(str(tmp_path / "test.db"))
    body = json.dumps({"jsonrpc": "2.0", "method": "tools/list", "id": 2}).encode()
    app = UsageMiddleware(mcp_app, db)
    await call(app, "/mcp/", body)
    db._queue.join()
    assert db.query_tool_calls(range_seconds=3600) == []


@pytest.mark.anyio
async def test_non_http_scope_passthrough(tmp_path):
    db = AnalyticsDB(str(tmp_path / "test.db"))
    seen = []

    async def tracker(scope, receive, send):
        seen.append(scope["type"])

    app = UsageMiddleware(tracker, db)
    await app({"type": "lifespan"}, None, None)
    assert seen == ["lifespan"]
