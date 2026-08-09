"""
Tests for planner/standards.py — deterministic naming, risk, logging, and
approval lookups. Pure logic; YAML dicts injected where possible, real repo
YAML files exercised for the loaders.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from fortimanager_mcp.matching import parse_service_request
from planner.standards import (
    load_naming,
    object_name,
    policy_name,
    risk_level,
    rule_type_for,
    log_settings,
    review_requirements,
)


# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------

def test_object_name_host():
    assert object_name("host", ip="10.1.2.3") == "H_10.1.2.3"


def test_object_name_network():
    assert object_name("network", ip="10.8.0.0/16") == "N_10.8.0.0_16"


def test_object_name_service():
    assert object_name("service", proto="tcp", port="8443") == "SVC_TCP_8443"


def test_policy_name_with_ticket():
    assert policy_name("CHG0012345", "OT_LAN", "IT", seq=1) == "CHG0012345_OT_LAN_TO_IT_001"


def test_policy_name_placeholder_without_ticket():
    assert policy_name("", "WAN", "DMZ") == "<TICKET_ID>_WAN_TO_DMZ_001"


def test_load_naming_reads_repo_yaml():
    naming = load_naming()
    assert "fortigate" in naming["platforms"]
    assert "log_settings" in naming


# ---------------------------------------------------------------------------
# Risk level (SKILL.md Step 5 logic, deterministic)
# ---------------------------------------------------------------------------

_DOMAINS = {
    "NSS OT-All": "OT",
    "NSS CIP-H-All": "CIP-H",
    "NSS IT DMZ": "IT",
    "NSS Corp Internal": "IT",
    "Users Networks": "Users",
    "Internet": "Internet",
}


def test_risk_ot_zone_is_critical():
    assert risk_level(["NSS OT-All"], ["NSS Corp Internal"], _DOMAINS) == "critical"


def test_risk_internet_destination_is_critical():
    assert risk_level(["NSS Corp Internal"], ["Internet"], _DOMAINS) == "critical"


def test_risk_internet_source_is_critical():
    assert risk_level(["Internet"], ["NSS Corp Internal"], _DOMAINS) == "critical"


def test_risk_internet_zone_name_is_critical_regardless_of_domain():
    # A catalogue may label the Internet zone's domain "Default" — the zone
    # NAME is authoritative for the catch-all.
    domains = {"Internet": "Default", "Internal-Wifi": "Default"}
    assert risk_level(["Internet"], ["Internal-Wifi"], domains) == "critical"
    assert risk_level(["Internal-Wifi"], ["Internet"], domains) == "critical"


def test_risk_cross_domain_is_high():
    assert risk_level(["Users Networks"], ["NSS IT DMZ"], _DOMAINS) == "high"


def test_risk_same_domain_is_medium():
    assert risk_level(["NSS Corp Internal"], ["NSS IT DMZ"], _DOMAINS) == "medium"


def test_risk_unknown_zone_is_critical():
    assert risk_level([], ["NSS IT DMZ"], _DOMAINS) == "critical"
    assert risk_level(["Mystery Zone"], ["NSS IT DMZ"], _DOMAINS) == "critical"


# ---------------------------------------------------------------------------
# Rule type for logging
# ---------------------------------------------------------------------------

def test_rule_type_ot_to_it():
    assert rule_type_for("ALLOWED", {"OT"}, {"IT"},
                         parse_service_request("443")) == "allow_ot_to_it"


def test_rule_type_it_to_ot():
    assert rule_type_for("ALLOWED", {"IT"}, {"OT"},
                         parse_service_request("443")) == "allow_it_to_ot"


def test_rule_type_internet_outbound():
    assert rule_type_for("ALLOWED", {"IT"}, {"Internet"},
                         parse_service_request("443")) == "allow_internet_outbound"


def test_rule_type_internet_inbound():
    assert rule_type_for("ALLOWED", {"Internet"}, {"IT"},
                         parse_service_request("443")) == "allow_internet_inbound"


def test_rule_type_internet_inbound_wins_over_management_ports():
    assert rule_type_for("ALLOWED", {"Internet"}, {"IT"},
                         parse_service_request("ssh")) == "allow_internet_inbound"


def test_rule_type_management_ports():
    assert rule_type_for("ALLOWED", {"IT"}, {"IT"},
                         parse_service_request("ssh")) == "management_access"
    assert rule_type_for("ALLOWED", {"IT"}, {"IT"},
                         parse_service_request("3389")) == "management_access"


def test_rule_type_internal_default():
    assert rule_type_for("ALLOWED", {"IT"}, {"IT"},
                         parse_service_request("8443")) == "allow_internal"


def test_rule_type_blocked_exception_uses_dst_domain():
    # a blocked flow still gets the logging profile of its zone pair
    assert rule_type_for("BLOCKED", {"IT"}, {"OT"},
                         parse_service_request("443")) == "allow_it_to_ot"


# ---------------------------------------------------------------------------
# YAML-backed lookups
# ---------------------------------------------------------------------------

def test_log_settings_known_type():
    s = log_settings("allow_it_to_ot")
    assert s["log_start"] is True
    assert s["siem_forward"] is True
    assert s["retention_days"] == 365


def test_log_settings_unknown_type_raises():
    with pytest.raises(KeyError):
        log_settings("no_such_rule_type")


def test_review_requirements_critical():
    r = review_requirements("critical")
    assert r["peer_review"] is True
    assert any("CISO" in a for a in r["approvers"])
    assert r["sla_hours"] == 96


# ---------------------------------------------------------------------------
# Least-privilege / permissiveness checks
# ---------------------------------------------------------------------------

from planner.standards import permissiveness_warnings


def _warns(srcs, dsts, service):
    return permissiveness_warnings(srcs, dsts, parse_service_request(service))


def test_specific_flow_has_no_permissiveness_warnings():
    assert _warns(["10.1.2.3"], ["10.9.8.7"], "tcp/443") == []


def test_slash24_networks_are_fine():
    assert _warns(["10.1.2.0/24"], ["10.9.8.0/24"], "tcp/443") == []


def test_any_source_flagged():
    warns = _warns(["0.0.0.0/0"], ["10.9.8.7"], "tcp/443")
    assert any("ANY source" in w for w in warns)


def test_any_destination_flagged():
    warns = _warns(["10.1.2.3"], ["0.0.0.0/0"], "tcp/443")
    assert any("ANY destination" in w for w in warns)


def test_broad_source_network_flagged():
    warns = _warns(["10.0.0.0/8"], ["10.9.8.7"], "tcp/443")
    assert any("10.0.0.0/8" in w and "broad" in w.lower() for w in warns)


def test_slash16_not_flagged_as_broad():
    assert _warns(["10.1.0.0/16"], ["10.9.8.7"], "tcp/443") == []


def test_any_service_flagged():
    warns = _warns(["10.1.2.3"], ["10.9.8.7"], "any")
    assert any("ANY service" in w for w in warns)


def test_wide_port_range_flagged():
    warns = _warns(["10.1.2.3"], ["10.9.8.7"], "tcp/1000-9000")
    assert any("1000-9000" in w and "port" in w.lower() for w in warns)


def test_moderate_port_range_not_flagged():
    assert _warns(["10.1.2.3"], ["10.9.8.7"], "tcp/8000-8100") == []


def test_any_any_any_escalated():
    warns = _warns(["0.0.0.0/0"], ["0.0.0.0/0"], "any")
    assert any("least-privilege" in w for w in warns)


def test_invalid_token_ignored_not_crash():
    # non-IP tokens (e.g. an FQDN) are skipped, never a crash
    assert _warns(["app.example.com"], ["10.9.8.7"], "tcp/443") == []
