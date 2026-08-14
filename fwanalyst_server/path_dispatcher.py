from typing import Any


class PathDispatcher:
    """ASGI middleware: route by URL path prefix."""

    def __init__(self, routes: dict[str, Any], default: Any) -> None:
        self._routes = routes
        self._default = default

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] in ("http", "websocket"):
            path: str = scope.get("path", "/")
            for prefix, app in self._routes.items():
                if path == prefix or path.startswith(prefix + "/"):
                    await app(scope, receive, send)
                    return
        await self._default(scope, receive, send)
