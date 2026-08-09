"""
Tests for planner/insertion.py — first-match shadowing analysis.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fortimanager_mcp.matching import (
    AddressCatalog,
    PolicyMatcher,
    ServiceCatalog,
    parse_service_request,
)
from planner.insertion import plan_insertion


def _matcher():
    addr = AddressCatalog(
        [{"name": "NET_10_1", "type": "ipmask", "subnet": "10.1.0.0/16"},
         {"name": "H_DST", "type": "ipmask", "subnet": "10.9.8.7/32"},
         {"name": "NET_172", "type": "ipmask", "subnet": "172.16.0.0/16"},
         {"name": "H_INSIDE", "type": "ipmask", "subnet": "10.1.5.5/32"}],
        [],
    )
    svc = ServiceCatalog(
        [{"name": "HTTPS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"},
         {"name": "SSH", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "22"}],
        [],
    )
    return PolicyMatcher(addr, svc)


def _pol(pid, srcaddr, dstaddr, service, action=1, status="enable",
         srcintf=("port1",), dstintf=("port2",)):
    return {
        "policyid": pid, "name": f"pol{pid}", "status": status, "action": action,
        "schedule": ["always"], "srcaddr": list(srcaddr), "dstaddr": list(dstaddr),
        "service": list(service), "srcintf": list(srcintf), "dstintf": list(dstintf),
    }


HTTPS = parse_service_request("443")


def _plan(policies, src="10.1.2.3", dst="10.9.8.7", ranges=HTTPS,
          srcintf="port1", dstintf="port2"):
    return plan_insertion("pkgA", policies, _matcher(), src, dst, ranges,
                          srcintf, dstintf)


def test_insert_before_first_overlapping_deny():
    policies = [
        _pol(1, ["NET_172"], ["H_DST"], ["HTTPS"]),          # unrelated
        _pol(2, ["NET_10_1"], ["H_DST"], ["HTTPS"], action=0),  # overlapping deny
        _pol(3, ["all"], ["all"], ["ALL"], action=0),
    ]
    plan = _plan(policies)
    assert plan.insert_before_policy_id == 2
    assert "pol2" in plan.rationale or "2" in plan.rationale


def test_insert_before_broad_any_accept():
    # a broad accept would also swallow the flow first — the new, more
    # specific rule must precede it to be meaningful
    policies = [
        _pol(1, ["NET_172"], ["H_DST"], ["HTTPS"]),
        _pol(2, ["all"], ["all"], ["ALL"], action=1),
    ]
    plan = _plan(policies)
    assert plan.insert_before_policy_id == 2


def test_no_overlap_appends_before_catchall_deny():
    policies = [
        _pol(1, ["NET_172"], ["H_DST"], ["SSH"]),
        _pol(9, ["all"], ["all"], ["ALL"], action=0),   # final deny-all
    ]
    # src 192.168/24 overlaps nothing except the catch-all
    plan = _plan(policies, src="192.168.1.1")
    assert plan.insert_before_policy_id == 9


def test_no_overlap_no_catchall_appends_at_end():
    policies = [_pol(1, ["NET_172"], ["H_DST"], ["SSH"])]
    plan = _plan(policies, src="192.168.1.1")
    assert plan.insert_before_policy_id is None
    assert "append" in plan.rationale.lower()


def test_fully_shadowed_reported():
    policies = [
        _pol(1, ["NET_10_1"], ["H_DST"], ["HTTPS"], action=1),  # covers fully
        _pol(2, ["all"], ["all"], ["ALL"], action=0),
    ]
    plan = _plan(policies)
    assert 1 in plan.shadowed_by


def test_would_shadow_reported():
    # candidate 10.1.0.0/16 -> H_DST any-service fully covers pol2 (H_INSIDE)
    policies = [
        _pol(2, ["H_INSIDE"], ["H_DST"], ["HTTPS"]),
        _pol(3, ["all"], ["all"], ["ALL"], action=0),
    ]
    plan = _plan(policies, src="10.1.0.0/16", ranges=parse_service_request("any"))
    assert 2 in plan.would_shadow


def test_disabled_policies_ignored_for_frontier():
    policies = [
        _pol(1, ["NET_10_1"], ["H_DST"], ["HTTPS"], action=0, status="disable"),
        _pol(2, ["NET_10_1"], ["H_DST"], ["HTTPS"], action=0),
    ]
    plan = _plan(policies)
    assert plan.insert_before_policy_id == 2


def test_interface_scoping():
    # overlapping rule on different interfaces is not a frontier
    policies = [
        _pol(1, ["NET_10_1"], ["H_DST"], ["HTTPS"], action=0,
             srcintf=("port7",), dstintf=("port8",)),
    ]
    plan = _plan(policies)
    assert plan.insert_before_policy_id is None
