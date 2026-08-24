"""Tests for psirt.scoring: deterministic priority computation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from psirt.scoring import _indicates_exploitation, compute_priority


def test_zero_fleet_exposure_is_informational_regardless_of_cvss():
    priority, rationale = compute_priority(
        cvss_score=9.8, fortinet_severity="Critical",
        exploited_in_wild_text="", kev_hit=False, any_device_in_range=False,
    )
    assert priority == "informational"
    assert "no" in rationale.lower() and "exposed" in rationale.lower() or "range" in rationale.lower()


def test_cvss_band_critical():
    priority, _ = compute_priority(
        cvss_score=9.8, fortinet_severity="Critical",
        exploited_in_wild_text="", kev_hit=False, any_device_in_range=True,
    )
    assert priority == "critical"


def test_cvss_band_high():
    priority, _ = compute_priority(
        cvss_score=7.5, fortinet_severity="High",
        exploited_in_wild_text="", kev_hit=False, any_device_in_range=True,
    )
    assert priority == "high"


def test_cvss_band_medium():
    priority, _ = compute_priority(
        cvss_score=5.0, fortinet_severity="Medium",
        exploited_in_wild_text="", kev_hit=False, any_device_in_range=True,
    )
    assert priority == "medium"


def test_cvss_band_low():
    priority, _ = compute_priority(
        cvss_score=2.0, fortinet_severity="Low",
        exploited_in_wild_text="", kev_hit=False, any_device_in_range=True,
    )
    assert priority == "low"


def test_kev_hit_forces_at_least_high_even_with_low_cvss():
    priority, rationale = compute_priority(
        cvss_score=4.5, fortinet_severity="Medium",
        exploited_in_wild_text="", kev_hit=True, any_device_in_range=True,
    )
    assert priority == "high"
    assert "kev" in rationale.lower()


def test_exploited_in_wild_text_forces_at_least_high():
    priority, rationale = compute_priority(
        cvss_score=6.8, fortinet_severity="Medium",
        exploited_in_wild_text="Fortinet is aware of an instance where this was exploited",
        kev_hit=False, any_device_in_range=True,
    )
    assert priority == "high"
    assert "exploit" in rationale.lower()


# --- _indicates_exploitation keyword detection ---

def test_indicates_exploitation_empty_is_false():
    assert _indicates_exploitation("") is False
    assert _indicates_exploitation(None) is False


def test_indicates_exploitation_positive_phrase():
    assert _indicates_exploitation("Exploitation in the wild has been reported.") is True
    assert _indicates_exploitation("This vulnerability is actively exploited.") is True


def test_indicates_exploitation_negative_qualifier_suppresses_escalation():
    # "Known Exploited: No" style — common advisory phrasing
    assert _indicates_exploitation("Fortinet is not aware of exploitation in the wild.") is False
    assert _indicates_exploitation("No known exploitation of this vulnerability.") is False
    assert _indicates_exploitation("Known Exploited: No") is False


def test_negative_text_does_not_force_high_priority():
    # This was the reported bug: CVSS 5.0 Medium advisory with "Known Exploited: No"
    # text was escalated to HIGH because the string was non-empty.
    priority, _ = compute_priority(
        cvss_score=5.0, fortinet_severity="Medium",
        exploited_in_wild_text="Fortinet is not aware of exploitation in the wild.",
        kev_hit=False, any_device_in_range=True,
    )
    assert priority == "medium"


def test_kev_never_downgrades_an_already_critical_score():
    priority, _ = compute_priority(
        cvss_score=9.8, fortinet_severity="Critical",
        exploited_in_wild_text="", kev_hit=True, any_device_in_range=True,
    )
    assert priority == "critical"


def test_missing_cvss_falls_back_to_fortinet_severity():
    priority, rationale = compute_priority(
        cvss_score=None, fortinet_severity="Critical",
        exploited_in_wild_text="", kev_hit=False, any_device_in_range=True,
    )
    assert priority == "critical"
    assert "fortinet" in rationale.lower() or "severity" in rationale.lower()
