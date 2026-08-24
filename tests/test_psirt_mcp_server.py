"""
Tests for psirt_mcp.server tool functions. parse_advisory's own extraction
is done by the calling LLM, not this code — these tests exercise the
shape-validation psirt_mcp applies to whatever structured dict it's given,
plus assess_fleet_exposure/render_psirt_report wiring against fakes.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from psirt_mcp import server


def test_parse_advisory_rejects_missing_advisory_id():
    result = server.parse_advisory(
        email_text="some email text",
        extracted={"cve_ids": ["CVE-2024-12345"]},
    )
    assert "error" in result


def test_parse_advisory_accepts_well_formed_extraction():
    result = server.parse_advisory(
        email_text="some email text",
        extracted={
            "advisory_id": "FG-IR-24-001",
            "cve_ids": ["CVE-2024-12345"],
            "affected_ranges": [
                {"product": "FortiOS", "min_version": "7.4.0", "max_version": "7.4.4",
                 "fixed_version": "7.4.5"},
            ],
        },
    )
    assert result["advisory_id"] == "FG-IR-24-001"
    assert result["affected_ranges"][0]["product"] == "FortiOS"


def test_parse_advisory_rejects_malformed_cve_id():
    result = server.parse_advisory(
        email_text="x",
        extracted={"advisory_id": "FG-IR-24-001", "cve_ids": ["not-a-cve"]},
    )
    assert "error" in result


class _FakeFMGClient:
    def get_adoms(self):
        return [{"name": "OT-ADOM"}]

    def get_devices(self, adom):
        return [{"name": "FW01", "os_ver": "7", "mr": 4, "patch": 2}]

    def get_system_status(self):
        return {"Version": "7.4.5"}


def test_assess_fleet_exposure_returns_assessment_dict(monkeypatch):
    monkeypatch.setattr(server, "_build_fmg_client", lambda: _FakeFMGClient())
    monkeypatch.setattr(server, "_build_http_client", lambda: None)
    advisory = {
        "advisory_id": "FG-IR-24-001",
        "cve_ids": ["CVE-2024-12345"],
        "cvss_score": 9.8,
        "affected_ranges": [
            {"product": "FortiOS", "min_version": "7.4.0", "max_version": "7.4.4",
             "fixed_version": "7.4.5"},
        ],
    }
    result = server.assess_fleet_exposure(advisory)
    assert result["priority"] in ("critical", "high", "medium", "low", "informational", "unknown")
    assert "total_findings" in result
    assert "verdict_counts" in result
    # HTML is returned as a string for the caller to write locally — no server paths
    assert "html_content" in result
    assert "assessment_json" not in result


def test_render_psirt_report_returns_html_content():
    assessment = {
        "plan_type": "psirt_advisory",
        "advisory": {
            "advisory_id": "FG-IR-24-001", "advisory_url": "", "cve_ids": ["CVE-2024-12345"],
            "published_date": "", "fortinet_severity": "Critical", "cvss_score": 9.8,
            "description": "", "affected_ranges": [], "workaround_text": "",
            "exploited_in_wild_text": "", "enrichment_degraded": False,
        },
        "findings": [],
        "out_of_scope_products": [],
        "priority": "critical",
        "priority_rationale": "CVSS 9.8",
        "kev_hit": False,
        "degraded": False,
        "warnings": [],
    }
    result = server.render_psirt_report(assessment=assessment)
    assert "html_content" in result
    assert "FG-IR-24-001" in result["html_content"]
    # Server never writes files — no html_path key
    assert "html_path" not in result
