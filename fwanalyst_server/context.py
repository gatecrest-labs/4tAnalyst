"""Shared request-scoped context for the unified server.

Lives here (not in auth.py) so fortimanager_mcp can import allowed_adoms_var
without creating a circular dependency through fwanalyst_server.
"""

import threading
from contextvars import ContextVar

allowed_adoms_var: ContextVar[set[str]] = ContextVar("allowed_adoms")

# Human-readable label for the caller's token ("admin" for the primary token,
# the server.tokens `label` field for named ones). Access logging only — never
# a privilege source. Defaults to "-" so stdio mode, where no HTTP middleware
# ever sets it, logs cleanly instead of raising LookupError.
token_label_var: ContextVar[str] = ContextVar("token_label", default="-")


class TokenRegistry:
    """Thread-safe, hot-reloadable store for server.tokens entries.

    get_tokens() returns None when load() has never been called, signalling
    auth.py to fall back to the static creds dict. After load() it returns a
    list (possibly empty), enabling hot-reload without a server restart.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._tokens: list[dict] | None = None

    def load(self, creds: dict) -> None:
        with self._lock:
            self._tokens = list(creds.get("server", {}).get("tokens", []))

    def get_tokens(self) -> list[dict] | None:
        with self._lock:
            return list(self._tokens) if self._tokens is not None else None

    def update_tokens(self, tokens: list[dict]) -> None:
        with self._lock:
            self._tokens = list(tokens)


token_registry: TokenRegistry = TokenRegistry()
