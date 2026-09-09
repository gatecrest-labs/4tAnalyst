import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fortimanager_mcp.client import FortiManagerAPIError
from hygiene_mcp.server import parse_hygiene_findings


def test_parse_hygiene_findings_from_pasted_json():
    text = '[{"policy_id": "1", "policy_name": "P1", "seq": 1, "check": "unhit", "detail": "d"}]'
    result = parse_hygiene_findings(text=text, file_type="json")
    assert "error" not in result
    assert result["findings"][0]["policy_id"] == "1"


def test_parse_hygiene_findings_file_content_wins_over_text():
    text_findings = '[{"policy_id": "1", "policy_name": "P1", "seq": 1, "check": "unhit", "detail": "d"}]'
    file_findings = '[{"policy_id": "2", "policy_name": "P2", "seq": 2, "check": "unlogged", "detail": "d"}]'
    result = parse_hygiene_findings(text=text_findings, file_content=file_findings, file_type="json")
    assert result["findings"][0]["policy_id"] == "2"


def test_parse_hygiene_findings_malformed_returns_error_not_exception():
    result = parse_hygiene_findings(text="not json", file_type="json")
    assert result["error_code"] == "parse_error"


def test_parse_hygiene_findings_no_input_returns_error():
    result = parse_hygiene_findings(text="", file_content="", file_type="json")
    assert result["error_code"] == "invalid_input"


def test_parse_hygiene_findings_invalid_file_type_returns_error():
    result = parse_hygiene_findings(text="[]", file_type="xml")
    assert result["error_code"] == "invalid_input"


def test_parse_hygiene_findings_csv():
    text = "Policy ID,Policy Name,Seq,Check,Detail\r\n1,P1,1,unhit,no hits\r\n"
    result = parse_hygiene_findings(text=text, file_type="csv")
    assert result["findings"][0]["check"] == "unhit"


from fwanalyst_server.context import allowed_adoms_var
from hygiene_mcp import server as hygiene_server

_LIVE = [
    {"policyid": 1, "name": "P1", "comments": "", "srcaddr": ["S1"], "dstaddr": ["D1"], "action": "accept"},
]


class _FakeClient:
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def get_policy_packages(self, adom): return []  # no-op; no underscore→slash translation
    def get_policies(self, adom, pkg): return _LIVE


class _FakeClientWithFailingPolicies(_FakeClient):
    """Simulates FortiManager returning an error for the policy fetch."""
    def get_policies(self, adom, pkg):
        raise FortiManagerAPIError("Object does not exist")


def _one_finding():
    return [{"policy_id": "1", "policy_name": "P1", "seq": 1, "check": "unhit", "detail": "no hits"}]


def test_assess_hygiene_fixes_blocked_by_adom_guard():
    token = allowed_adoms_var.set({"OTHER-ADOM"})
    try:
        result = hygiene_server.assess_hygiene_fixes(
            adom="OT-ADOM", device="FW1", pkg="pkg1", findings=_one_finding(),
        )
    finally:
        allowed_adoms_var.reset(token)
    assert result["error_code"] == "forbidden"


def test_assess_hygiene_fixes_happy_path(monkeypatch):
    monkeypatch.setattr(hygiene_server, "_fortimanager_client", lambda: _FakeClient())

    token = allowed_adoms_var.set({"*"})
    try:
        result = hygiene_server.assess_hygiene_fixes(
            adom="OT-ADOM", device="FW1", pkg="pkg1", findings=_one_finding(),
        )
    finally:
        allowed_adoms_var.reset(token)

    assert "error" not in result
    assert result["fixes"][0]["policy_id"] == "1"
    assert result["html_content"] is not None
    assert result["html_error"] is None


def test_assess_hygiene_fixes_missing_pkg_returns_error():
    token = allowed_adoms_var.set({"*"})
    try:
        result = hygiene_server.assess_hygiene_fixes(
            adom="OT-ADOM", device="FW1", pkg="", findings=_one_finding(),
        )
    finally:
        allowed_adoms_var.reset(token)
    assert result["error_code"] == "invalid_input"


def test_assess_hygiene_fixes_fetch_failure_surfaces_error(monkeypatch):
    monkeypatch.setattr(
        hygiene_server, "_fortimanager_client", lambda: _FakeClientWithFailingPolicies()
    )

    token = allowed_adoms_var.set({"*"})
    try:
        result = hygiene_server.assess_hygiene_fixes(
            adom="OT-ADOM", device="FW1", pkg="pkg1", findings=_one_finding(),
        )
    finally:
        allowed_adoms_var.reset(token)
    assert result["error_code"] == "upstream_error"
    assert "Object does not exist" in result["error"]


def test_assess_hygiene_fixes_non_numeric_seq_returns_error_not_exception():
    findings = [{"policy_id": "1", "policy_name": "P1", "seq": "not-a-number", "check": "unhit", "detail": "d"}]
    token = allowed_adoms_var.set({"*"})
    try:
        result = hygiene_server.assess_hygiene_fixes(
            adom="OT-ADOM", device="FW1", pkg="pkg1", findings=findings,
        )
    finally:
        allowed_adoms_var.reset(token)
    assert result["error_code"] == "invalid_input"
    assert "error" in result


def test_render_hygiene_report_rebuilds_html_from_assessment_dict():
    assessment = {
        "device": "FW1", "adom": "OT-ADOM", "pkg": "pkg1",
        "generated_at": "2026-09-03T12:00:00+00:00",
        "fixes": [{
            "policy_id": "1", "policy_name": "P1", "check": "unhit",
            "options": [{
                "option_id": "A", "label": "Disable", "description": "disable it",
                "cli": ["config firewall policy\n    edit 1\nend"],
                "new_comment": None, "irreversible": False,
            }],
        }],
        "stale_findings": [],
    }
    result = hygiene_server.render_hygiene_report(assessment)
    assert "error" not in result
    assert "P1" in result["html_content"]


def test_render_hygiene_report_malformed_input_returns_error():
    result = hygiene_server.render_hygiene_report({"device": "FW1"})  # missing required keys
    assert "error" in result


# ---------------------------------------------------------------------------
# Fix 1: underscore→slash pkg normalization
# ---------------------------------------------------------------------------

class _FakeClientWithPackages(_FakeClient):
    """Fake client that advertises one per-VDOM package in slash form."""
    def get_policy_packages(self, adom):
        return [{"name": "SITEFW01/PROD99", "type": "pkg"}]


def test_assess_hygiene_fixes_underscore_pkg_resolved_to_slash(monkeypatch):
    """Display-form pkg (DEVICE_VDOM) is translated to FMG path (DEVICE/VDOM)."""
    captured_pkgs: list[str] = []

    class _CapturingClient(_FakeClientWithPackages):
        def get_policies(self, adom, pkg):
            captured_pkgs.append(pkg)
            return _LIVE

    monkeypatch.setattr(hygiene_server, "_fortimanager_client", lambda: _CapturingClient())

    token = allowed_adoms_var.set({"*"})
    try:
        result = hygiene_server.assess_hygiene_fixes(
            adom="TEST-ADOM",
            device="SITEFW01",
            pkg="SITEFW01_PROD99",  # underscore (display form from export)
            findings=_one_finding(),
        )
    finally:
        allowed_adoms_var.reset(token)

    assert "error" not in result
    assert captured_pkgs == ["SITEFW01/PROD99"]  # slash (canonical) sent to FMG


def test_assess_hygiene_fixes_slash_pkg_passes_unchanged(monkeypatch):
    """Canonical slash-form pkg bypasses the package-list lookup and is used as-is."""
    captured_pkgs: list[str] = []

    class _CapturingClient(_FakeClient):
        def get_policies(self, adom, pkg):
            captured_pkgs.append(pkg)
            return _LIVE

    monkeypatch.setattr(hygiene_server, "_fortimanager_client", lambda: _CapturingClient())

    token = allowed_adoms_var.set({"*"})
    try:
        result = hygiene_server.assess_hygiene_fixes(
            adom="TEST-ADOM",
            device="SITEFW01",
            pkg="SITEFW01/PROD99",  # already canonical
            findings=_one_finding(),
        )
    finally:
        allowed_adoms_var.reset(token)

    assert "error" not in result
    assert captured_pkgs == ["SITEFW01/PROD99"]


# ---------------------------------------------------------------------------
# Fix 2: parse_hygiene_findings returns meta from JSON export
# ---------------------------------------------------------------------------

def test_parse_hygiene_findings_returns_meta_from_json_export():
    """meta dict from the hygiene export is included in the parse response."""
    export = json.dumps({
        "meta": {
            "package": "SITEFW01_PROD99",
            "adom": "TEST-ADOM",
            "generated": "2026-09-09T00:00:00Z",
        },
        "findings": [
            {"policy_id": "1", "policy_name": "P1", "seq": 1, "check": "unhit", "detail": "d"}
        ],
    })
    result = parse_hygiene_findings(text=export, file_type="json")
    assert "error" not in result
    assert result["findings"][0]["policy_id"] == "1"
    assert result["meta"]["package"] == "SITEFW01_PROD99"
    assert result["meta"]["adom"] == "TEST-ADOM"


def test_parse_hygiene_findings_meta_empty_for_list_form_json():
    """List-form JSON (no metadata envelope) returns an empty meta dict."""
    text = '[{"policy_id": "1", "policy_name": "P1", "seq": 1, "check": "unhit", "detail": "d"}]'
    result = parse_hygiene_findings(text=text, file_type="json")
    assert "error" not in result
    assert result.get("meta") == {}
