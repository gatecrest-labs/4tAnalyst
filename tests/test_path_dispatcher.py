import pytest
from fwanalyst_server.path_dispatcher import PathDispatcher


def make_app(tag: bytes):
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": tag})
    return app


async def call(app, path: str) -> bytes:
    scope = {"type": "http", "path": path, "query_string": b"", "headers": []}
    chunks = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        if msg["type"] == "http.response.body":
            chunks.append(msg.get("body", b""))

    await app(scope, receive, send)
    return b"".join(chunks)


@pytest.mark.anyio
async def test_admin_prefix_routed():
    d = PathDispatcher(routes={"/admin": make_app(b"admin"), "/api": make_app(b"api")},
                       default=make_app(b"mcp"))
    assert await call(d, "/admin/dashboard") == b"admin"
    assert await call(d, "/api/usage") == b"api"


@pytest.mark.anyio
async def test_default_for_other_paths():
    d = PathDispatcher(routes={"/admin": make_app(b"admin")}, default=make_app(b"mcp"))
    assert await call(d, "/mcp") == b"mcp"
    assert await call(d, "/") == b"mcp"


@pytest.mark.anyio
async def test_non_http_scope_goes_to_default():
    seen = []

    async def tracker(scope, receive, send):
        seen.append(scope["type"])

    d = PathDispatcher(routes={"/admin": make_app(b"admin")}, default=tracker)
    await d({"type": "lifespan"}, None, None)
    assert seen == ["lifespan"]
