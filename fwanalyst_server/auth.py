"""Static-bearer ASGI authentication for the unified server.

Interim control until Phase 4 engineer identity (AD/Entra): a single shared
token, checked on every HTTP request. Fail closed — an empty configured
token refuses to start rather than serving unauthenticated.
"""

from __future__ import annotations

import hmac
import json

from fwanalyst_server.context import allowed_adoms_var, token_label_var, token_registry


class AuthConfigError(ValueError):
    """Raised when HTTP mode is requested without a usable token."""


def _resolve_allowed_adoms(token: str, creds: dict) -> set[str] | None:
    """Return the allowed ADOM set for a named token, or None if not in server.tokens.

    Only named tokens from server.tokens are resolved here. The legacy auth_token
    is handled by require_bearer's primary hmac.compare_digest check — it is NOT
    a second lookup target here. This prevents the yaml auth_token from acting as
    a permanent backdoor when FW_ANALYST_TOKEN env var overrides it.

    When adom_restriction: false, recognized named tokens still get {"*"} (ADOM
    filter lifted), but unrecognized tokens return None — auth always enforced.

    Additive: checks token_registry first (if loaded), falls back to static creds
    lookup only when the registry has not yet been initialised (returns None).
    """
    server_cfg = creds.get("server", {})
    restriction_enabled = server_cfg.get("adom_restriction", True)

    # Hot-reloadable registry takes precedence when it has been loaded.
    live_tokens = token_registry.get_tokens()
    token_source = live_tokens if live_tokens is not None else server_cfg.get("tokens", [])

    for entry in token_source:
        if hmac.compare_digest(
            token.encode(), entry.get("token", "").encode()
        ):
            if not restriction_enabled:
                return {"*"}
            adoms = entry.get("adoms", [])
            return {"*"} if "*" in adoms else set(adoms)

    return None


def _resolve_token_label(token: str, creds: dict) -> str:
    """Return the server.tokens `label` for a named token, or "-" if absent.

    Access-logging only — this grants nothing, so unlike _resolve_allowed_adoms
    its return value must never be used to make an authorization decision. Only
    called for tokens already resolved as named ones; the legacy auth_token is
    still never a lookup target here.
    """
    for entry in creds.get("server", {}).get("tokens", []):
        if hmac.compare_digest(token.encode(), entry.get("token", "").encode()):
            return str(entry.get("label", "")).strip() or "-"
    return "-"


def require_bearer(app, token: str, creds: dict | None = None):
    """Wrap an ASGI app: reject requests lacking `Authorization: Bearer <token>`.

    When creds is provided, also resolves the token's allowed ADOM set and
    injects it into allowed_adoms_var for the duration of each request.
    When creds is omitted (or empty), falls back to full access for the
    token — preserving backward-compatibility with existing call sites and tests.
    """
    if not token or not token.strip():
        raise AuthConfigError(
            "Refusing to serve HTTP without an auth token. Set FW_ANALYST_TOKEN "
            "or server.auth_token in credentials.yaml."
        )
    _creds = creds or {}

    async def wrapped(scope, receive, send):
        if scope["type"] != "http":
            await app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        supplied_bytes = headers.get(b"authorization", b"")
        supplied_str = supplied_bytes.decode("latin-1")

        # Strip "Bearer " prefix for resolution
        supplied_token = supplied_str.removeprefix("Bearer ").strip()

        adom_set = _resolve_allowed_adoms(supplied_token, _creds) if supplied_token else None

        # Constant-time check against the primary token
        expected = f"Bearer {token.strip()}".encode()
        if not hmac.compare_digest(supplied_bytes, expected):
            # Also accept any token in the named tokens list (already resolved above)
            if adom_set is None:
                body = json.dumps({"error": "unauthorized"}).encode()
                await send({
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"www-authenticate", b"Bearer"),
                    ],
                })
                await send({"type": "http.response.body", "body": body})
                return

        # Inject ADOM set (full access if no creds provided or legacy token)
        resolved = adom_set if adom_set is not None else {"*"}
        # adom_set is not None only for named tokens; the sole remaining way to
        # reach here is the primary hmac.compare_digest match above.
        label = _resolve_token_label(supplied_token, _creds) if adom_set is not None else "admin"
        token_ctx = allowed_adoms_var.set(resolved)
        label_ctx = token_label_var.set(label)
        try:
            await app(scope, receive, send)
        finally:
            allowed_adoms_var.reset(token_ctx)
            token_label_var.reset(label_ctx)

    return wrapped
