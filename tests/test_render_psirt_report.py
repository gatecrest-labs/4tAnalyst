"""Tests for scripts/render_report.py's psirt_advisory plan_type support."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

import pytest
from render_report import PayloadError, render_psirt_html, validate_psirt_payload


def _payload(**overrides):
    base = {
        "plan_type": "psirt_advisory",
        "advisory": {
            "advisory_id": "FG-IR-24-001",
            "advisory_url": "https://fortiguard.com/psirt/FG-IR-24-001",
            "cve_ids": ["CVE-2024-12345"],
            "published_date": "2024-01-15",
            "fortinet_severity": "Critical",
            "cvss_score": 9.8,
            "description": "Heap overflow in sslvpnd",
            "affected_ranges": [
                {"product": "FortiOS", "min_version": "7.4.0", "max_version": "7.4.4",
                 "fixed_version": "7.4.5", "notes": ""},
            ],
            "workaround_text": "Disable SSL-VPN",
            "exploited_in_wild_text": "Fortinet is aware of an instance where this was exploited",
            "enrichment_degraded": False,
        },
        "findings": [
            {"device": "FW01", "adom": "OT-ADOM", "product": "FortiOS",
             "current_version": "7.4.2", "in_range": True,
             "workaround_status": "not_in_place", "verdict": "config_change_required",
             "reason": "Firmware 7.4.2 is affected and the workaround is NOT in place."},
        ],
        "out_of_scope_products": ["FortiAP"],
        "priority": "critical",
        "priority_rationale": "CVSS 9.8; forced to at least High because exploited in the wild",
        "kev_hit": True,
        "degraded": False,
        "warnings": [],
    }
    base.update(overrides)
    return base


def test_validate_psirt_payload_accepts_well_formed_payload():
    validate_psirt_payload(_payload())  # must not raise


def test_validate_psirt_payload_rejects_missing_keys():
    payload = _payload()
    del payload["findings"]
    with pytest.raises(PayloadError):
        validate_psirt_payload(payload)


def test_validate_psirt_payload_rejects_wrong_plan_type():
    payload = _payload(plan_type="ip_change")
    with pytest.raises(PayloadError):
        validate_psirt_payload(payload)


def test_render_psirt_html_includes_advisory_and_findings():
    html = render_psirt_html(_payload())
    assert "FG-IR-24-001" in html
    assert "CVE-2024-12345" in html
    assert "FW01" in html
    assert "config_change_required" in html or "Configuration change required" in html


def test_render_psirt_html_flags_kev_hit():
    html = render_psirt_html(_payload())
    assert "KEV" in html


def test_render_psirt_html_lists_out_of_scope_products():
    html = render_psirt_html(_payload())
    assert "FortiAP" in html


def test_render_psirt_html_shows_feature_section_when_features_present():
    payload = _payload(affected_features=["ssl_vpn", "ztna"])
    html = render_psirt_html(payload)
    assert "Affected Services / Features" in html
    assert "SSL-VPN" in html
    assert "ZTNA" in html
    assert "Features" in html  # table header column added


def test_render_psirt_html_no_feature_section_when_features_empty():
    payload = _payload(affected_features=[])
    html = render_psirt_html(payload)
    assert "Affected Services / Features" not in html
    # Features column header still present (always shown for layout consistency)
    assert "Features" in html


def test_render_psirt_html_feature_column_not_exposed_badge():
    payload = _payload(
        affected_features=["ssl_vpn"],
        findings=[{
            "device": "FW01", "adom": "OT-ADOM", "product": "FortiOS",
            "current_version": "7.4.2", "in_range": True,
            "workaround_status": "not_applicable", "verdict": "no_action",
            "reason": "Feature inactive.",
            "feature_status": "inactive",
            "features_checked": ["ssl_vpn"],
        }],
    )
    html = render_psirt_html(payload)
    assert "Not exposed" in html
    assert "feat-not-exposed" in html


def test_render_psirt_html_feature_column_exposed_badge():
    payload = _payload(
        affected_features=["ssl_vpn"],
        findings=[{
            "device": "FW01", "adom": "OT-ADOM", "product": "FortiOS",
            "current_version": "7.4.2", "in_range": True,
            "workaround_status": "not_in_place", "verdict": "upgrade_required",
            "reason": "Feature active.",
            "feature_status": "active",
            "features_checked": ["ssl_vpn"],
        }],
    )
    html = render_psirt_html(payload)
    assert "Exposed" in html
    assert "feat-exposed" in html


def test_render_psirt_html_feature_column_dash_when_not_checked():
    # Out-of-range device (features_checked is absent/empty) — cell should be "—"
    payload = _payload(
        affected_features=["ssl_vpn"],
        findings=[{
            "device": "FW99", "adom": "OT-ADOM", "product": "FortiOS",
            "current_version": "7.6.0", "in_range": False,
            "workaround_status": "not_applicable", "verdict": "no_action",
            "reason": "Out of range.",
        }],
    )
    html = render_psirt_html(payload)
    assert "—" in html
