"""Tests for psirt.models: dataclasses and to_dict() round-tripping."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from psirt.models import (
    Advisory,
    AffectedRange,
    DeviceFinding,
    PsirtAssessment,
    PsirtDataError,
)


def test_advisory_to_dict_roundtrip():
    adv = Advisory(
        advisory_id="FG-IR-24-001",
        advisory_url="https://fortiguard.com/psirt/FG-IR-24-001",
        cve_ids=["CVE-2024-12345"],
        published_date="2024-01-15",
        fortinet_severity="Critical",
        cvss_score=9.8,
        description="Heap overflow in sslvpnd",
        affected_ranges=[
            AffectedRange(product="FortiOS", min_version="7.4.0",
                          max_version="7.4.4", fixed_version="7.4.5"),
        ],
        workaround_text="Disable SSL-VPN",
        exploited_in_wild_text="Fortinet is aware of an instance where this was exploited",
    )
    d = adv.to_dict()
    assert d["advisory_id"] == "FG-IR-24-001"
    assert d["affected_ranges"][0]["min_version"] == "7.4.0"
    assert d["affected_ranges"][0]["fixed_version"] == "7.4.5"
    assert d["cve_ids"] == ["CVE-2024-12345"]


def test_device_finding_to_dict():
    f = DeviceFinding(
        device="FW01", adom="OT-ADOM", product="FortiOS",
        current_version="7.4.2", in_range=True,
        workaround_status="not_in_place", verdict="config_change_required",
        reason="SSL-VPN is enabled and no workaround is applied",
    )
    d = f.to_dict()
    assert d["device"] == "FW01"
    assert d["verdict"] == "config_change_required"


def test_psirt_assessment_to_dict_nests_advisory_and_findings():
    adv = Advisory(advisory_id="FG-IR-24-001")
    finding = DeviceFinding(
        device="FW01", adom="OT-ADOM", product="FortiOS",
        current_version="7.4.2", in_range=True,
        workaround_status="not_applicable", verdict="upgrade_required",
        reason="No workaround published; upgrade to 7.4.5",
    )
    assessment = PsirtAssessment(
        advisory=adv, findings=[finding], priority="critical",
        priority_rationale="CVSS 9.8, exploited in the wild",
        kev_hit=True,
    )
    d = assessment.to_dict()
    assert d["advisory"]["advisory_id"] == "FG-IR-24-001"
    assert d["findings"][0]["device"] == "FW01"
    assert d["kev_hit"] is True


def test_psirt_data_error_fields():
    err = PsirtDataError("fortimanager", "all hosts unreachable")
    assert err.source == "fortimanager"
    assert "unreachable" in err.detail
    assert "[fortimanager]" in str(err)
