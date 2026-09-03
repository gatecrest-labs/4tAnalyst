import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

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
    from fortimanager_mcp import query as _query

    monkeypatch.setattr(hygiene_server, "_fortimanager_client", lambda: _FakeClient())
    monkeypatch.setattr(_query, "get_device_policies", lambda c, adom, pkgs: {"pkg1": _LIVE})

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
    from fortimanager_mcp import query as _query

    monkeypatch.setattr(hygiene_server, "_fortimanager_client", lambda: _FakeClient())
    monkeypatch.setattr(_query, "get_device_policies", lambda c, adom, pkgs: {"pkg1": None})

    token = allowed_adoms_var.set({"*"})
    try:
        result = hygiene_server.assess_hygiene_fixes(
            adom="OT-ADOM", device="FW1", pkg="pkg1", findings=_one_finding(),
        )
    finally:
        allowed_adoms_var.reset(token)
    assert result["error_code"] == "upstream_error"


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
