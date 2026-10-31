"""zone_mcp tools return structured errors instead of raising.

mcp 2.x reduces an uncaught tool exception to a bare "Error executing tool X",
so the zone tools catch failures and return {"error", "error_code",
"error_source"} (same shape family as fortimanager_mcp / plan_change).
"""

import asyncio

import pytest

from zone_mcp import server
from zone_mcp.client import ZonePolicyError


class _FailingClient:
    def __init__(self, exc):
        self._exc = exc

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def query(self, **kw):
        raise self._exc

    def zones(self):
        raise self._exc

    def policies(self):
        raise self._exc


class _OkClient(_FailingClient):
    def __init__(self):
        pass

    def query(self, **kw):
        return [{"verdict": "ALLOWED", "src_zones": ["A"], "dst_zones": ["B"],
                 "governing": [], "all_policies": []}]


def _patch(monkeypatch, client):
    monkeypatch.setattr(server, "_zone_client", lambda: client)


CALLS = [
    ("query_zone_policy", {"src": "10.0.0.1", "dst": "10.0.0.2"}),
    ("get_zones", {}),
    ("get_policies", {}),
    ("find_zone_for_ip", {"ip": "10.0.0.1"}),
    ("check_ip_traffic", {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}),
]


@pytest.mark.parametrize("name,args", CALLS)
def test_zone_api_error_is_structured(monkeypatch, name, args):
    _patch(monkeypatch, _FailingClient(ZonePolicyError("4THealth API unavailable: External API is disabled")))
    out = getattr(server, name)(**args)
    assert out["error_code"] == "upstream_error"
    assert out["error_source"] == "4thealth"
    assert "External API is disabled" in out["error"]


def test_unexpected_error_is_structured_and_sanitized(monkeypatch):
    _patch(monkeypatch, _FailingClient(RuntimeError("boom at https://zone.internal.example.com/external/api/zone/query")))
    out = server.get_zones()
    assert out["error_code"] == "internal_error"
    assert "internal.example.com" not in out["error"]
    assert "/external/api" not in out["error"]


def test_success_path_unchanged(monkeypatch):
    _patch(monkeypatch, _OkClient())
    out = server.check_ip_traffic("10.0.0.1", "10.0.0.2", "443")
    assert out["verdict"] == "ALLOWED"
    assert "error" not in out


def test_error_dispatches_without_is_error_through_server(monkeypatch):
    """Through the real MCPServer dispatch (output-schema validation included)."""
    _patch(monkeypatch, _FailingClient(ZonePolicyError("down")))
    for name, args in CALLS:
        result = asyncio.run(server.mcp.call_tool(name, args))
        text = str(result)
        assert "upstream_error" in text, name
