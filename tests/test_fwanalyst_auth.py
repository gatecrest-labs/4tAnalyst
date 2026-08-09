"""
Tests for fwanalyst_server: bearer-auth middleware and tool aggregation.
Middleware is driven directly as an ASGI callable — no server needed.
"""

import asyncio
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from fwanalyst_server.auth import AuthConfigError, require_bearer


async def _echo_app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def _call(app, headers):
    sent = []

    async def send(msg):
        sent.append(msg)

    async def receive():
        return {"type": "http.request", "body": b""}

    scope = {"type": "http", "method": "POST", "path": "/mcp",
             "headers": headers}
    asyncio.run(app(scope, receive, send))
    return sent


def test_missing_token_401():
    app = require_bearer(_echo_app, "secret")
    sent = _call(app, [])
    assert sent[0]["status"] == 401


def test_wrong_token_401():
    app = require_bearer(_echo_app, "secret")
    sent = _call(app, [(b"authorization", b"Bearer wrong")])
    assert sent[0]["status"] == 401


def test_good_token_passes_through():
    app = require_bearer(_echo_app, "secret")
    sent = _call(app, [(b"authorization", b"Bearer secret")])
    assert sent[0]["status"] == 200
    assert sent[1]["body"] == b"ok"


def test_empty_configured_token_raises():
    with pytest.raises(AuthConfigError):
        require_bearer(_echo_app, "")
    with pytest.raises(AuthConfigError):
        require_bearer(_echo_app, "   ")


def test_allowed_hosts_env_var_parses_comma_separated(monkeypatch):
    from fwanalyst_server.__main__ import _allowed_hosts

    monkeypatch.setenv("FW_ANALYST_ALLOWED_HOSTS", "central-server:8000, 10.1.5.62:*")
    assert _allowed_hosts() == ["central-server:8000", "10.1.5.62:*"]


def test_allowed_hosts_defaults_empty_without_env_or_file(monkeypatch, tmp_path):
    from fwanalyst_server.__main__ import _allowed_hosts

    monkeypatch.delenv("FW_ANALYST_ALLOWED_HOSTS", raising=False)
    monkeypatch.setenv("CREDENTIALS_FILE", str(tmp_path / "missing.yaml"))
    assert _allowed_hosts() == []


def test_unified_server_aggregates_all_tools():
    from fwanalyst_server.server import mcp
    tools = asyncio.run(mcp.list_tools())
    names = {t.name for t in tools}
    assert "plan_change" in names
    # one representative per package
    for expected in ("check_ip_traffic", "search_policies", "record_feedback",
                     "parse_spreadsheet_file", "get_naming_convention"):
        assert expected in names, f"missing {expected}"
    assert len(names) == 36  # 35 aggregated + plan_change


def test_context_module_exports_allowed_adoms_var():
    from contextvars import ContextVar

    from fwanalyst_server.context import allowed_adoms_var
    assert isinstance(allowed_adoms_var, ContextVar)


def test_resolve_adoms_restriction_disabled():
    from fwanalyst_server.auth import _resolve_allowed_adoms
    creds = {
        "server": {
            "adom_restriction": False,
            "auth_token": "admin-tok",
            "tokens": [
                {"token": "eng-tok", "label": "alice", "adoms": ["OT-ADOM"]},
            ],
        }
    }
    # Recognized named tokens get {"*"} when restriction is off
    assert _resolve_allowed_adoms("eng-tok", creds) == {"*"}
    # admin-tok is NOT a named token — not resolved here; handled by require_bearer primary check
    assert _resolve_allowed_adoms("admin-tok", creds) is None
    # Unrecognized tokens still return None
    assert _resolve_allowed_adoms("garbage", creds) is None


def test_resolve_adoms_named_token_restricted():
    from fwanalyst_server.auth import _resolve_allowed_adoms
    creds = {
        "server": {
            "adom_restriction": True,
            "auth_token": "admin-tok",
            "tokens": [
                {"token": "eng-tok", "label": "alice", "adoms": ["OT-ADOM", "GAS-ADOM"]},
            ],
        }
    }
    result = _resolve_allowed_adoms("eng-tok", creds)
    assert result == {"OT-ADOM", "GAS-ADOM"}


def test_resolve_adoms_named_token_wildcard():
    from fwanalyst_server.auth import _resolve_allowed_adoms
    creds = {
        "server": {
            "adom_restriction": True,
            "auth_token": "admin-tok",
            "tokens": [
                {"token": "power-tok", "label": "bob", "adoms": ["*"]},
            ],
        }
    }
    assert _resolve_allowed_adoms("power-tok", creds) == {"*"}


def test_resolve_adoms_legacy_auth_token():
    """Legacy auth_token is NOT resolved by _resolve_allowed_adoms; handled by require_bearer's primary check."""
    from fwanalyst_server.auth import _resolve_allowed_adoms
    creds = {"server": {"adom_restriction": True, "auth_token": "legacy", "tokens": []}}
    # auth_token is no longer a lookup target — returns None (not a named token)
    assert _resolve_allowed_adoms("legacy", creds) is None


def test_resolve_adoms_unknown_token_returns_none():
    from fwanalyst_server.auth import _resolve_allowed_adoms
    creds = {"server": {"adom_restriction": True, "auth_token": "real", "tokens": []}}
    assert _resolve_allowed_adoms("garbage", creds) is None


def test_require_bearer_injects_allowed_adoms_into_contextvar():
    from fwanalyst_server.auth import require_bearer
    from fwanalyst_server.context import allowed_adoms_var

    captured = {}

    async def capturing_app(scope, receive, send):
        captured["adoms"] = allowed_adoms_var.get(None)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    creds = {
        "server": {
            "adom_restriction": True,
            "auth_token": "admin",
            "tokens": [
                {"token": "eng-tok", "label": "alice", "adoms": ["OT-ADOM"]},
            ],
        }
    }
    app = require_bearer(capturing_app, "eng-tok", creds)
    _call(app, [(b"authorization", b"Bearer eng-tok")])
    assert captured["adoms"] == {"OT-ADOM"}


def test_require_bearer_unknown_token_still_401():
    from fwanalyst_server.auth import require_bearer

    creds = {
        "server": {
            "adom_restriction": True,
            "auth_token": "admin",
            "tokens": [],
        }
    }
    app = require_bearer(_echo_app, "admin", creds)
    sent = _call(app, [(b"authorization", b"Bearer garbage")])
    assert sent[0]["status"] == 401


def test_require_bearer_named_token_differs_from_primary():
    """A named token from server.tokens is accepted even when it differs from the primary admin token."""
    from fwanalyst_server.auth import require_bearer
    from fwanalyst_server.context import allowed_adoms_var

    captured = {}

    async def capturing_app(scope, receive, send):
        captured["adoms"] = allowed_adoms_var.get(None)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    creds = {
        "server": {
            "adom_restriction": True,
            "auth_token": "admin-token",          # primary token
            "tokens": [
                {"token": "eng-tok", "label": "alice", "adoms": ["OT-ADOM"]},
            ],
        }
    }
    # require_bearer is initialized with the admin token, but eng-tok is submitted
    app = require_bearer(capturing_app, "admin-token", creds)
    sent = _call(app, [(b"authorization", b"Bearer eng-tok")])
    assert sent[0]["status"] == 200
    assert captured["adoms"] == {"OT-ADOM"}


# ---------------------------------------------------------------------------
# Access logging — token label ContextVar + tool wrapper
# ---------------------------------------------------------------------------

_LOGGING_CREDS = {
    "server": {
        "adom_restriction": True,
        "auth_token": "admin-token",
        "tokens": [
            {"token": "eng-tok", "label": "alice", "adoms": ["OT-ADOM"]},
            {"token": "unlabelled-tok", "adoms": ["OT-ADOM"]},
        ],
    }
}


def _capture_label(token: str, creds=None, primary="admin-token"):
    from fwanalyst_server.auth import require_bearer
    from fwanalyst_server.context import token_label_var

    captured = {}

    async def capturing_app(scope, receive, send):
        captured["label"] = token_label_var.get()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    app = require_bearer(capturing_app, primary, creds)
    _call(app, [(b"authorization", f"Bearer {token}".encode())])
    return captured.get("label")


def test_token_label_var_defaults_outside_http():
    """stdio mode never runs the middleware — the ContextVar must still read."""
    from fwanalyst_server.context import token_label_var
    assert token_label_var.get() == "-"


def test_named_token_label_is_resolved():
    assert _capture_label("eng-tok", _LOGGING_CREDS) == "alice"


def test_primary_token_labelled_admin():
    assert _capture_label("admin-token", _LOGGING_CREDS) == "admin"


def test_named_token_without_label_falls_back():
    assert _capture_label("unlabelled-tok", _LOGGING_CREDS) == "-"


def test_primary_token_label_does_not_resolve_via_tokens_list():
    """The primary token must never be looked up in server.tokens."""
    from fwanalyst_server.auth import _resolve_token_label
    assert _resolve_token_label("admin-token", _LOGGING_CREDS) == "-"


def test_token_label_var_is_reset_after_request():
    from fwanalyst_server.context import token_label_var
    _capture_label("eng-tok", _LOGGING_CREDS)
    assert token_label_var.get() == "-"


def test_tool_invocation_logs_name_and_token_label(caplog):
    import logging as _logging

    from fwanalyst_server.context import token_label_var
    from fwanalyst_server.server import _logged

    def get_zones() -> dict:
        """Docstring preserved."""
        return {"zones": []}

    wrapped = _logged(get_zones)
    ctx = token_label_var.set("alice")
    try:
        with caplog.at_level(_logging.INFO, logger="fwanalyst_server.server"):
            wrapped()
    finally:
        token_label_var.reset(ctx)

    assert "tool_call tool=get_zones token=alice" in caplog.text


def test_tool_wrapper_preserves_identity_and_signature():
    import inspect

    from fwanalyst_server.server import _logged

    def sample(src: str, count: int = 1) -> dict:
        """Sample doc."""
        return {"src": src, "count": count}

    wrapped = _logged(sample)
    assert wrapped.__name__ == "sample"
    assert wrapped.__doc__ == "Sample doc."
    assert inspect.signature(wrapped) == inspect.signature(sample)
    assert wrapped("a", 2) == {"src": "a", "count": 2}


def test_tool_schemas_unchanged_by_logging_wrapper():
    """FastMCP must derive identical input schemas from wrapped and raw fns."""
    from mcp.server.fastmcp import FastMCP

    from fortimanager_mcp import server as fmg
    from fwanalyst_server.server import _logged
    from fwanalyst_server.server import mcp as unified
    from zone_mcp import server as zone

    raw = FastMCP(name="schema-baseline")
    for fn in (fmg.search_policies, zone.check_ip_traffic, fmg.get_policy):
        raw.add_tool(fn)

    baseline = {t.name: t.inputSchema for t in asyncio.run(raw.list_tools())}
    live = {t.name: t.inputSchema for t in asyncio.run(unified.list_tools())}
    for name, schema in baseline.items():
        assert live[name] == schema, f"{name} schema drifted"

    # plan_change too — it lives in a `from __future__ import annotations`
    # module, so its annotations are strings and must still resolve.
    plan_raw = FastMCP(name="schema-baseline-plan")
    from fwanalyst_server.server import plan_change
    plan_raw.add_tool(plan_change)
    plan_baseline = {t.name: t.inputSchema for t in asyncio.run(plan_raw.list_tools())}
    assert live["plan_change"] == plan_baseline["plan_change"]

    # sanity: the wrapper is actually in play
    assert _logged(plan_change).__wrapped__ is plan_change


# ---------------------------------------------------------------------------
# credentials.yaml file permissions
# ---------------------------------------------------------------------------

def _write_creds(tmp_path, mode):
    path = tmp_path / "credentials.yaml"
    path.write_text("server:\n  auth_token: tok\n", encoding="utf-8")
    path.chmod(mode)
    return path


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes only")
def test_creds_perms_0600_accepted(tmp_path, monkeypatch):
    from fwanalyst_server.__main__ import _load_creds

    monkeypatch.setenv("CREDENTIALS_FILE", str(_write_creds(tmp_path, 0o600)))
    assert _load_creds(http_mode=True) == {"server": {"auth_token": "tok"}}


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes only")
def test_creds_perms_0644_refused_in_http_mode(tmp_path, monkeypatch):
    from fwanalyst_server.__main__ import _load_creds

    monkeypatch.setenv("CREDENTIALS_FILE", str(_write_creds(tmp_path, 0o644)))
    with pytest.raises(SystemExit) as exc:
        _load_creds(http_mode=True)
    assert "chmod 600" in str(exc.value)


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes only")
def test_creds_perms_0644_only_warns_in_stdio_mode(tmp_path, monkeypatch, caplog):
    import logging as _logging

    from fwanalyst_server.__main__ import _load_creds

    monkeypatch.setenv("CREDENTIALS_FILE", str(_write_creds(tmp_path, 0o644)))
    with caplog.at_level(_logging.WARNING, logger="fwanalyst_server.__main__"):
        assert _load_creds() == {"server": {"auth_token": "tok"}}
    assert "chmod 600" in caplog.text


def test_missing_creds_file_is_not_a_permission_error(tmp_path, monkeypatch):
    from fwanalyst_server.__main__ import _load_creds

    monkeypatch.setenv("CREDENTIALS_FILE", str(tmp_path / "absent.yaml"))
    assert _load_creds(http_mode=True) == {}


# ---------------------------------------------------------------------------
# Direct uvicorn TLS configuration
# ---------------------------------------------------------------------------

def test_ssl_files_none_when_unconfigured(monkeypatch):
    from fwanalyst_server.__main__ import _ssl_files

    monkeypatch.delenv("FW_ANALYST_SSL_CERTFILE", raising=False)
    monkeypatch.delenv("FW_ANALYST_SSL_KEYFILE", raising=False)
    assert _ssl_files({}) is None
    assert _ssl_files({"server": {"auth_token": "x"}}) is None


def test_ssl_files_from_env(monkeypatch):
    from fwanalyst_server.__main__ import _ssl_files

    monkeypatch.setenv("FW_ANALYST_SSL_CERTFILE", "/tls/server.crt")
    monkeypatch.setenv("FW_ANALYST_SSL_KEYFILE", "/tls/server.key")
    assert _ssl_files({}) == ("/tls/server.crt", "/tls/server.key")


def test_ssl_files_env_wins_over_credentials(monkeypatch):
    from fwanalyst_server.__main__ import _ssl_files

    monkeypatch.setenv("FW_ANALYST_SSL_CERTFILE", "/env/server.crt")
    monkeypatch.setenv("FW_ANALYST_SSL_KEYFILE", "/env/server.key")
    creds = {"server": {"ssl_certfile": "/yaml/c.crt", "ssl_keyfile": "/yaml/c.key"}}
    assert _ssl_files(creds) == ("/env/server.crt", "/env/server.key")


def test_ssl_files_from_credentials(monkeypatch):
    from fwanalyst_server.__main__ import _ssl_files

    monkeypatch.delenv("FW_ANALYST_SSL_CERTFILE", raising=False)
    monkeypatch.delenv("FW_ANALYST_SSL_KEYFILE", raising=False)
    creds = {"server": {"ssl_certfile": "/yaml/c.crt", "ssl_keyfile": "/yaml/c.key"}}
    assert _ssl_files(creds) == ("/yaml/c.crt", "/yaml/c.key")


def test_ssl_files_half_configured_exits(monkeypatch):
    from fwanalyst_server.__main__ import _ssl_files

    monkeypatch.setenv("FW_ANALYST_SSL_CERTFILE", "/tls/server.crt")
    monkeypatch.delenv("FW_ANALYST_SSL_KEYFILE", raising=False)
    with pytest.raises(SystemExit) as exc:
        _ssl_files({})
    assert "FW_ANALYST_SSL_KEYFILE" in str(exc.value)

    monkeypatch.delenv("FW_ANALYST_SSL_CERTFILE", raising=False)
    monkeypatch.setenv("FW_ANALYST_SSL_KEYFILE", "/tls/server.key")
    with pytest.raises(SystemExit) as exc:
        _ssl_files({})
    assert "FW_ANALYST_SSL_CERTFILE" in str(exc.value)
