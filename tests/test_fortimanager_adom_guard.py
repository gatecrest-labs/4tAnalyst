"""
Unit tests for per-ADOM access control in fortimanager_mcp/server.py.
All tests set allowed_adoms_var directly — no HTTP stack needed.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fwanalyst_server.context import allowed_adoms_var


def test_require_adom_permitted():
    from fortimanager_mcp.server import _require_adom
    token = allowed_adoms_var.set({"OT-ADOM", "GAS-ADOM"})
    try:
        assert _require_adom("OT-ADOM") is None
    finally:
        allowed_adoms_var.reset(token)


def test_require_adom_denied():
    from fortimanager_mcp.server import _require_adom
    token = allowed_adoms_var.set({"OT-ADOM"})
    try:
        result = _require_adom("IT-ADOM")
        assert result is not None
        assert "IT-ADOM" in result["error"]
        assert "allowed list" in result["error"]
    finally:
        allowed_adoms_var.reset(token)


def test_require_adom_wildcard_permits_any():
    from fortimanager_mcp.server import _require_adom
    token = allowed_adoms_var.set({"*"})
    try:
        assert _require_adom("any-adom-name") is None
    finally:
        allowed_adoms_var.reset(token)


def test_require_adom_stdio_default_full_access():
    """No ContextVar set (stdio/dev mode) → defaults to full access."""
    from fortimanager_mcp.server import _require_adom
    # Do NOT set the ContextVar — simulate stdio mode
    assert _require_adom("any-adom") is None


def test_get_adoms_filters_to_allowed(monkeypatch):
    """get_adoms() returns only ADOMs in the allowed set."""
    from fortimanager_mcp import query as _query
    from fortimanager_mcp import server as fmg_server

    fake_adoms = [
        {"name": "OT-ADOM", "status": "1", "os_type": "fos", "desc": ""},
        {"name": "IT-ADOM", "status": "1", "os_type": "fos", "desc": ""},
        {"name": "GAS-ADOM", "status": "1", "os_type": "fos", "desc": ""},
    ]

    class _FakeClient:
        def __enter__(self): return self
        def __exit__(self, *a): pass

    monkeypatch.setattr(fmg_server, "_fortimanager_client", lambda: _FakeClient())
    monkeypatch.setattr(_query, "list_adoms", lambda c: fake_adoms)

    token = allowed_adoms_var.set({"OT-ADOM", "GAS-ADOM"})
    try:
        result = fmg_server.get_adoms()
        names = [a["name"] for a in result]
        assert names == ["OT-ADOM", "GAS-ADOM"]
        assert "IT-ADOM" not in names
    finally:
        allowed_adoms_var.reset(token)


def test_get_adoms_wildcard_returns_all(monkeypatch):
    from fortimanager_mcp import query as _query
    from fortimanager_mcp import server as fmg_server

    fake_adoms = [
        {"name": "OT-ADOM", "status": "1", "os_type": "fos", "desc": ""},
        {"name": "IT-ADOM", "status": "1", "os_type": "fos", "desc": ""},
    ]

    class _FakeClient:
        def __enter__(self): return self
        def __exit__(self, *a): pass

    monkeypatch.setattr(fmg_server, "_fortimanager_client", lambda: _FakeClient())
    monkeypatch.setattr(_query, "list_adoms", lambda c: fake_adoms)

    token = allowed_adoms_var.set({"*"})
    try:
        result = fmg_server.get_adoms()
        assert len(result) == 2
    finally:
        allowed_adoms_var.reset(token)


def test_search_fqdn_rules_enforces_adom_guard(monkeypatch):
    """search_fqdn_rules must reject tokens that are not allowed for the ADOM."""
    from fortimanager_mcp import server as fmg_server

    # Restrict to OT-ADOM only
    token = allowed_adoms_var.set({"OT-ADOM"})
    try:
        result = fmg_server.search_fqdn_rules(
            adom="IT-ADOM", device="FW1", fqdns=["*.example.com"]
        )
    finally:
        allowed_adoms_var.reset(token)

    assert "error" in result
    assert "IT-ADOM" in result["error"]
    assert result.get("error_code") == "forbidden"


def test_search_fqdn_rules_permitted_adom(monkeypatch):
    """search_fqdn_rules passes through when the token allows the ADOM."""
    from fortimanager_mcp import query as _query
    from fortimanager_mcp import server as fmg_server

    class _FakeClient:
        def __enter__(self): return self
        def __exit__(self, *a): pass

    monkeypatch.setattr(fmg_server, "_fortimanager_client", lambda: _FakeClient())
    # Return a minimal valid result from search_fqdn_rules
    monkeypatch.setattr(
        _query, "search_fqdn_rules",
        lambda client, adom, device, fqdns: {
            "results": [], "degraded": False, "partial_group_match": None
        },
    )

    token = allowed_adoms_var.set({"OT-ADOM"})
    try:
        result = fmg_server.search_fqdn_rules(
            adom="OT-ADOM", device="FW1", fqdns=["*.example.com"]
        )
    finally:
        allowed_adoms_var.reset(token)

    assert "error" not in result
    assert result["degraded"] is False
