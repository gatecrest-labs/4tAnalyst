"""
Tests for the planner package: models, fetch layer, and the plan_change
engine (fully faked clients — no live FMG/4THealth).
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from fortimanager_mcp.matching import PortRange
from planner.models import (
    ChangePlan,
    FirewallPlan,
    InsertionPlan,
    NormalizedFlow,
    ObjectPlan,
    PlannerDataError,
)

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

def test_models_roundtrip():
    plan = ChangePlan(
        ticket_id="CHG1",
        flow=NormalizedFlow(src="10.1.1.1", dst="10.2.2.2", service="443",
                            service_ranges=[PortRange("tcp", 443, 443)]),
        zone_verdict={"verdict": "ALLOWED"},
        risk_level="high",
        firewalls=[FirewallPlan(
            firewall="FW1", adom="root", status="new_rule",
            objects=[ObjectPlan(role="source", action="create",
                                name="H_10.1.1.1", obj_type="host",
                                value="10.1.1.1/32", cli="config ...")],
            insertion=InsertionPlan(package="pkgA", insert_before_policy_id=7,
                                    rationale="precede deny"),
        )],
        cli_status="new_rule",
        recommendation="ok",
    )
    d = plan.to_dict()
    assert d["firewalls"][0]["insertion"]["insert_before_policy_id"] == 7
    assert d["flow"]["service_ranges"][0]["protocol"] == "tcp"


def test_planner_data_error_fields():
    err = PlannerDataError("fortimanager", "all hosts unreachable")
    assert err.source == "fortimanager"
    assert "unreachable" in err.detail
    assert "[fortimanager]" in str(err)


# ---------------------------------------------------------------------------
# Fetch layer
# ---------------------------------------------------------------------------

from fortimanager_mcp.client import FortiManagerAPIError
from planner.fetch import (
    fetch_device_snapshot,
    fetch_zone_domains,
    fetch_zone_verdict,
    resolve_interfaces,
)


class FakeFMGClient:
    def __init__(self, fail_pkgs=(), devices=("FW1",)):
        self._fail = set(fail_pkgs)
        self._devices = devices

    def get_devices(self, adom):
        return [{"name": d} for d in self._devices]

    def get_policy_packages(self, adom):
        return [{"name": "pkgA", "scope member": [{"name": "FW1"}]},
                {"name": "pkgB", "scope member": [{"name": "FW1"}]}]

    def get_policies(self, adom, pkg):
        if pkg in self._fail:
            raise FortiManagerAPIError("timeout", code=-1)
        return [{"policyid": 1, "name": f"{pkg}-p1", "status": "enable",
                 "action": 1, "srcaddr": ["all"], "dstaddr": ["all"],
                 "service": ["ALL"], "srcintf": ["any"], "dstintf": ["any"],
                 "schedule": ["always"]}]

    def get_address_objects(self, adom):
        return []

    def get_address_groups(self, adom):
        return []

    def get_global_address_objects(self):
        return []

    def get_global_address_groups(self):
        return []

    def get_service_objects(self, adom):
        return []

    def get_service_groups(self, adom):
        return []

    def get_device_interfaces(self, adom, device):
        return [
            {"name": "port1", "ip": "10.1.0.1 255.255.0.0", "type": "physical",
             "status": "up"},
            {"name": "port2", "ip": ["10.9.8.1", "255.255.255.0"], "type": "physical",
             "status": "up"},
        ]

    def get_device_meta(self, adom, device):
        return {"os_ver": "7", "mr": 4, "patch": 2}


def test_snapshot_happy_path():
    snap = fetch_device_snapshot(FakeFMGClient(), "root", "FW1")
    assert snap.packages == ["pkgA", "pkgB"]
    assert not snap.degraded
    assert len(snap.policies_by_package["pkgA"]) == 1
    assert len(snap.interfaces) == 2


def test_snapshot_unknown_device_raises():
    from planner.models import PlannerDataError
    with pytest.raises(PlannerDataError) as exc:
        fetch_device_snapshot(FakeFMGClient(devices=("OTHER",)), "root", "FW1")
    assert exc.value.source == "fortimanager"


def test_snapshot_degraded_on_package_failure():
    snap = fetch_device_snapshot(FakeFMGClient(fail_pkgs={"pkgB"}), "root", "FW1")
    assert snap.degraded
    assert any("pkgB" in f for f in snap.failures)
    assert "pkgA" in snap.policies_by_package
    assert "pkgB" not in snap.policies_by_package


def test_resolve_interfaces_by_subnet():
    snap = fetch_device_snapshot(FakeFMGClient(), "root", "FW1")
    srcintf, dstintf, warnings = resolve_interfaces(snap, "10.1.2.3", "10.9.8.7")
    assert srcintf == "port1"
    assert dstintf == "port2"
    assert warnings == []


def test_resolve_interfaces_ambiguous_warns():
    snap = fetch_device_snapshot(FakeFMGClient(), "root", "FW1")
    srcintf, dstintf, warnings = resolve_interfaces(snap, "192.168.1.1", "10.9.8.7")
    assert srcintf == ""
    assert dstintf == "port2"
    assert any("192.168.1.1" in w for w in warnings)


class FakeZoneClient:
    def __init__(self, results=None, zones=None, boom=False, policies=None):
        self._results = results
        self._zones = zones or {"zones": [
            {"name": "NSS OT-All", "domain": "OT"},
            {"name": "NSS Corp Internal", "domain": "IT"},
        ]}
        self._boom = boom
        self._policies = policies or []

    def query(self, src, dst, service="", verbose=True):
        from zone_mcp.client import ZonePolicyError
        if self._boom:
            raise ZonePolicyError("api down")
        return self._results if self._results is not None else [{
            "src": src, "dst": dst, "service": service,
            "verdict": "ALLOWED", "src_zones": ["NSS OT-All"],
            "dst_zones": ["NSS Corp Internal"], "governing": [],
            "all_policies": [],
        }]

    def zones(self):
        from zone_mcp.client import ZonePolicyError
        if self._boom:
            raise ZonePolicyError("api down")
        return self._zones

    def policies(self):
        from zone_mcp.client import ZonePolicyError
        if self._boom:
            raise ZonePolicyError("api down")
        return list(self._policies)


def test_zone_verdict_happy():
    v = fetch_zone_verdict(FakeZoneClient(), "10.1.1.1", "10.2.2.2", "443")
    assert v["verdict"] == "ALLOWED"
    assert v["src_zones"] == ["NSS OT-All"]


_INTERNET_CATALOGUE = {"zones": [
    {"name": "Internet", "domain": "Internet", "subnets": [], "parents": []},
    {"name": "Internal-Wifi", "domain": "Default",
     "subnets": [{"subnet": "10.1.1.0/24"}], "parents": []},
]}


def _unresolved_src_client(policies):
    return FakeZoneClient(
        results=[{"src": "192.168.40.147", "dst": "10.1.1.7", "service": "tcp/443",
                  "verdict": "UNKNOWN", "src_zones": [],
                  "dst_zones": ["Internal-Wifi"], "governing": [],
                  "all_policies": []}],
        zones=_INTERNET_CATALOGUE,
        policies=policies,
    )


def test_unresolved_ip_defaults_to_internet_zone_and_reevaluates():
    zc = _unresolved_src_client([
        {"policy_set": "Corp", "from_zone": "Internet", "to_zone": "Internal-Wifi",
         "access_type": "block only", "services": ["telnet"], "severity": "high"},
    ])
    v = fetch_zone_verdict(zc, "192.168.40.147", "10.1.1.7", "tcp/443")
    assert v["src_zones"] == ["Internet"]
    assert v["verdict"] == "ALLOWED"      # block-only telnet → 443 permitted
    assert v["governing"]
    assert any("Internet" in n for n in v["notes"])


def test_unresolved_ip_internet_default_can_block():
    zc = _unresolved_src_client([
        {"policy_set": "Corp", "from_zone": "Internet", "to_zone": "Internal-Wifi",
         "access_type": "block all", "services": [], "severity": "critical"},
    ])
    v = fetch_zone_verdict(zc, "192.168.40.147", "10.1.1.7", "tcp/443")
    assert v["verdict"] == "BLOCKED"


def test_unresolved_ip_stays_unknown_without_internet_zone():
    zc = FakeZoneClient(
        results=[{"src": "192.168.40.147", "dst": "10.1.1.7", "service": "tcp/443",
                  "verdict": "UNKNOWN", "src_zones": [],
                  "dst_zones": ["Internal-Wifi"], "governing": [],
                  "all_policies": []}],
        zones={"zones": [{"name": "Internal-Wifi", "domain": "Default",
                          "subnets": [{"subnet": "10.1.1.0/24"}]}]},
    )
    v = fetch_zone_verdict(zc, "192.168.40.147", "10.1.1.7", "tcp/443")
    assert v["verdict"] == "UNKNOWN"
    assert v["src_zones"] == []
    assert any("no 'Internet' zone" in n for n in v["notes"])


def test_unresolved_ip_no_governing_policy_stays_unknown():
    zc = _unresolved_src_client([])
    v = fetch_zone_verdict(zc, "192.168.40.147", "10.1.1.7", "tcp/443")
    assert v["src_zones"] == ["Internet"]
    assert v["verdict"] == "UNKNOWN"


def test_zone_verdict_error_raises_typed():
    from planner.models import PlannerDataError
    with pytest.raises(PlannerDataError) as exc:
        fetch_zone_verdict(FakeZoneClient(boom=True), "10.1.1.1", "10.2.2.2", "443")
    assert exc.value.source == "4thealth"


def test_zone_verdict_empty_result_raises_typed():
    from planner.models import PlannerDataError
    with pytest.raises(PlannerDataError):
        fetch_zone_verdict(FakeZoneClient(results=[]), "10.1.1.1", "10.2.2.2", "443")


def test_zone_domains_map():
    domains = fetch_zone_domains(FakeZoneClient())
    assert domains["NSS OT-All"] == "OT"


# ---------------------------------------------------------------------------
# Engine — plan_change end to end with fake clients
# ---------------------------------------------------------------------------

from planner.engine import plan_change, to_report_payload
from planner.models import TargetFirewall as TF

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from render_report import validate_payload  # noqa: E402


class EngineFMG:
    """Richer fake FMG for engine tests."""

    def __init__(self, policies=None, fail_pkgs=(), addr_groups=None):
        self._addr_groups = addr_groups or []
        self._policies = policies if policies is not None else [
            {"policyid": 10, "name": "existing-allow", "status": "enable",
             "action": 1, "schedule": ["always"],
             "srcaddr": ["NET_10_1"], "dstaddr": ["NET_DST"],
             "service": ["HTTPS"], "srcintf": ["port1"], "dstintf": ["port2"],
             "logtraffic": 2},
            {"policyid": 99, "name": "deny-all", "status": "enable",
             "action": 0, "schedule": ["always"],
             "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"],
             "srcintf": ["any"], "dstintf": ["any"], "logtraffic": 2},
        ]
        self._fail = set(fail_pkgs)

    def get_devices(self, adom):
        return [{"name": "FW1"}]

    def get_policy_packages(self, adom):
        pkgs = [{"name": "pkgA", "scope member": [{"name": "FW1"}]}]
        if self._fail:
            pkgs.append({"name": "pkgBAD", "scope member": [{"name": "FW1"}]})
        return pkgs

    def get_policies(self, adom, pkg):
        if pkg in self._fail:
            raise FortiManagerAPIError("timeout", code=-1)
        return list(self._policies)

    def get_address_objects(self, adom):
        return [
            {"name": "NET_10_1", "type": "ipmask", "subnet": "10.1.0.0/16"},
            {"name": "NET_DST", "type": "ipmask", "subnet": "10.9.8.0/24"},
            {"name": "H_EXIST", "type": "ipmask", "subnet": "10.1.2.3/32"},
        ]

    def get_address_groups(self, adom):
        return list(self._addr_groups)

    def get_global_address_objects(self):
        return []

    def get_global_address_groups(self):
        return []

    def get_service_objects(self, adom):
        return [
            {"name": "HTTPS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"},
            {"name": "SVC_TCP_8443", "protocol": "TCP/UDP/SCTP",
             "tcp-portrange": "8443"},
        ]

    def get_service_groups(self, adom):
        return []

    def get_device_interfaces(self, adom, device):
        return [
            {"name": "port1", "ip": "10.1.0.1 255.255.0.0", "status": "up"},
            {"name": "port2", "ip": "10.9.8.1 255.255.255.0", "status": "up"},
        ]

    def get_device_meta(self, adom, device):
        return {}


class EngineZone:
    def __init__(self, verdict="ALLOWED", src_zones=("NSS Corp Internal",),
                 dst_zones=("NSS IT DMZ",)):
        self._verdict = verdict
        self._src = list(src_zones)
        self._dst = list(dst_zones)

    def query(self, src, dst, service="", verbose=True):
        return [{"src": src, "dst": dst, "service": service,
                 "verdict": self._verdict, "src_zones": self._src,
                 "dst_zones": self._dst,
                 "governing": [{"policy_set": "PS", "access_type": "allow all",
                                "severity": "high"}],
                 "all_policies": []}]

    def zones(self):
        return {"zones": [
            {"name": "NSS Corp Internal", "domain": "IT"},
            {"name": "NSS IT DMZ", "domain": "IT"},
            {"name": "NSS OT-All", "domain": "OT"},
        ]}


def _run(src="10.1.2.3", dst="10.9.8.7", service="443", verdict="ALLOWED",
         fmg=None, zone=None, ticket="CHG0042"):
    return plan_change(
        src=src, dst=dst, service=service,
        firewalls=[TF(device="FW1", adom="root")],
        justification="test flow", ticket_id=ticket,
        fmg_client=fmg or EngineFMG(),
        zone_client=zone or EngineZone(verdict=verdict),
    )


def test_already_covered_end_to_end():
    plan = _run()
    assert plan.cli_status == "already_covered"
    fw = plan.firewalls[0]
    assert fw.status == "already_covered"
    assert fw.covering_rules and fw.covering_rules[0]["policy_id"] == 10
    assert plan.risk_level == "medium"


def test_to_report_payload_splits_covering_and_partial():
    """to_report_payload must emit separate covering_rules and partial_matches keys."""
    plan = _run()
    payload = to_report_payload(plan)
    validate_payload(payload)

    fw_name = list(payload["existing_rules"].keys())[0]
    info = payload["existing_rules"][fw_name]

    # Both new keys must be present
    assert "covering_rules" in info, "covering_rules key missing from payload"
    assert "partial_matches" in info, "partial_matches key missing from payload"

    # Legacy rules key must still be present (backward compat)
    assert "rules" in info

    # covering_rules should be non-empty when status is already_covered
    if info["status"] == "ALREADY COVERED":
        assert len(info["covering_rules"]) > 0

    # covering_rules + partial_matches must equal rules (same content, split)
    assert len(info["covering_rules"]) + len(info["partial_matches"]) == len(info["rules"])


def test_new_rule_generates_objects_and_policy():
    plan = _run(service="tcp/8443")
    assert plan.cli_status == "new_rule"
    fw = plan.firewalls[0]
    assert fw.status == "new_rule"
    roles = {(o.role, o.action) for o in fw.objects}
    # src 10.1.2.3 matches H_EXIST exactly -> reuse; dst 10.9.8.7 has no exact
    # object -> create; service tcp/8443 matches SVC_TCP_8443 -> reuse
    assert ("source", "reuse") in roles
    assert ("destination", "create") in roles
    assert ("service", "reuse") in roles
    assert fw.policy_cli
    assert 'set srcintf "port1"' in fw.policy_cli
    assert fw.insertion is not None
    # deny-all catch-all is the frontier for this uncovered flow
    assert fw.insertion.insert_before_policy_id == 99


def test_full_cover_on_other_interfaces_is_not_coverage():
    # A broad LAN->WAN accept rule (internal->wan1) fully matches the flow's
    # addresses/service, but the flow traverses port1->port2 — a real FortiGate
    # would never apply that rule, so it must not count as "already covered".
    fmg = EngineFMG(policies=[
        {"policyid": 1, "name": "lan-to-wan", "status": "enable",
         "action": 1, "schedule": ["always"],
         "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"],
         "srcintf": ["internal"], "dstintf": ["wan1"], "logtraffic": 2},
    ])
    plan = _run(fmg=fmg)
    fw = plan.firewalls[0]
    assert fw.status == "new_rule"
    assert not fw.covering_rules
    # still surfaced as an overlapping rule for the engineer to see
    assert any(r["policy_id"] == 1 for r in fw.partial_matches)


def test_new_rule_creates_service_object_when_missing():
    plan = _run(service="tcp/9000")
    fw = plan.firewalls[0]
    svc = [o for o in fw.objects if o.role == "service"][0]
    assert svc.action == "create"
    assert svc.name == "SVC_TCP_9000"
    assert "set tcp-portrange 9000" in svc.cli


def test_blocked_exception_adds_comment():
    plan = _run(verdict="BLOCKED", service="tcp/8443")
    assert plan.cli_status == "blocked_exception"
    fw = plan.firewalls[0]
    assert "EXCEPTION" in fw.policy_cli or "exception" in fw.policy_cli.lower()


def test_unknown_zone_no_action():
    plan = _run(verdict="UNKNOWN")
    assert plan.cli_status == "unknown_no_action"
    assert plan.firewalls[0].status == "no_action"
    assert plan.firewalls[0].policy_cli == ""


def test_degraded_never_already_covered():
    plan = _run(fmg=EngineFMG(fail_pkgs={"pkgBAD"}))
    assert plan.cli_status == "new_rule"
    assert any("pkgBAD" in w or "incomplete" in w.lower() for w in plan.warnings)


def test_device_not_found_flagged():
    plan = plan_change(
        src="10.1.2.3", dst="10.9.8.7", service="443",
        firewalls=[TF(device="NOPE", adom="root")],
        fmg_client=EngineFMG(), zone_client=EngineZone(),
    )
    assert plan.firewalls[0].status == "not_found"
    assert plan.cli_status == "new_rule"  # cannot prove coverage


def test_payload_passes_render_validate():
    for kwargs in ({}, {"service": "tcp/8443"}, {"verdict": "BLOCKED"},
                   {"verdict": "UNKNOWN"}):
        plan = _run(**kwargs)
        payload = to_report_payload(plan)
        validate_payload(payload)  # raises on contract violation
        assert payload["ticket_id"] == "CHG0042"
        assert payload["request"]["src"] == "10.1.2.3"


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

from planner.__main__ import parse_args


def test_cli_arg_parsing():
    args = parse_args([
        "--src", "10.1.2.3", "--dst", "10.9.8.7", "--service", "tcp/8443",
        "--firewall", "FW1:root", "--firewall", "FW2:ot-adom",
        "--ticket", "CHG9",
    ])
    assert [(t.device, t.adom) for t in args.targets] == [
        ("FW1", "root"), ("FW2", "ot-adom")]
    assert args.ticket == "CHG9"


def test_cli_malformed_firewall_exits():
    with pytest.raises(SystemExit):
        parse_args(["--src", "a", "--dst", "b", "--service", "443",
                    "--firewall", "no-adom-given"])


def test_cli_json_only_end_to_end(monkeypatch, capsys):
    import planner.__main__ as cli
    import planner.engine as eng

    monkeypatch.setattr(eng, "_default_fmg_client", lambda: EngineFMG())
    monkeypatch.setattr(eng, "_default_zone_client", lambda: EngineZone())
    rc = cli.main(["--src", "10.1.2.3", "--dst", "10.9.8.7", "--service", "443",
                   "--firewall", "FW1:root", "--json-only"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["cli"]["status"] == "already_covered"


import json  # noqa: E402

# ---------------------------------------------------------------------------
# Group-append alternative
# ---------------------------------------------------------------------------

_NEAR_MISS_POLICIES = [
    # near-miss: src fully covers 10.1.2.3, service SVC_TCP_8443 exact,
    # dst group GRP_PUB does NOT contain 10.9.8.7 -> append candidate
    {"policyid": 20, "name": "publish-hosts", "status": "enable",
     "action": 1, "schedule": ["always"],
     "srcaddr": ["NET_10_1"], "dstaddr": ["GRP_PUB"],
     "service": ["SVC_TCP_8443"], "srcintf": ["port1"], "dstintf": ["port2"],
     "logtraffic": 2},
    # another rule referencing the same group directly -> blast radius
    {"policyid": 30, "name": "other-user-of-group", "status": "enable",
     "action": 1, "schedule": ["always"],
     "srcaddr": ["GRP_PUB"], "dstaddr": ["all"], "service": ["ALL"],
     "srcintf": ["any"], "dstintf": ["any"], "logtraffic": 2},
    # references the group via a parent group -> blast radius (nested)
    {"policyid": 40, "name": "parent-group-user", "status": "enable",
     "action": 1, "schedule": ["always"],
     "srcaddr": ["all"], "dstaddr": ["GRP_PARENT"], "service": ["ALL"],
     "srcintf": ["any"], "dstintf": ["any"], "logtraffic": 2},
]

_GROUPS = [
    {"name": "GRP_PUB", "member": ["H_OTHER"]},
    {"name": "GRP_PARENT", "member": ["GRP_PUB"]},
]


def _near_miss_fmg(policies=None):
    fmg = EngineFMG(policies=policies or [dict(p) for p in _NEAR_MISS_POLICIES],
                    addr_groups=_GROUPS)
    base_objects = fmg.get_address_objects("root")
    fmg.get_address_objects = lambda adom: base_objects + [
        {"name": "H_OTHER", "type": "ipmask", "subnet": "10.99.0.5/32"},
    ]
    return fmg


def test_group_append_alternative_detected():
    plan = _run(service="tcp/8443", fmg=_near_miss_fmg())
    fw = plan.firewalls[0]
    assert fw.status == "new_rule"          # new-policy plan still primary
    alt = fw.alternative
    assert alt is not None
    assert alt.policy_id == 20 and alt.group == "GRP_PUB" and alt.side == "destination"
    assert 'append member' in alt.group_cli and 'GRP_PUB' in alt.group_cli
    # dst 10.9.8.7 has no existing object -> member must be created
    assert alt.members[0].action == "create" and alt.members[0].cli
    # blast radius: both the direct and the nested-parent user, not rule 20
    affected_ids = {a["policy_id"] for a in alt.affected_policies}
    assert affected_ids == {30, 40}
    assert any("2 other rule" in w for w in alt.warnings)


def test_group_append_alternative_in_payload():
    plan = _run(service="tcp/8443", fmg=_near_miss_fmg())
    payload = to_report_payload(plan)
    validate_payload(payload)
    entry = payload["cli"]["per_firewall"][0]
    alt = entry["alternative"]

    # identity fields — to_report_payload must not drop or rename these
    assert alt["group"] == "GRP_PUB"
    assert alt["policy_id"] == 20
    assert alt["policy_name"] == "publish-hosts"
    assert alt["package"] == "pkgA"
    assert alt["side"] == "destination"

    # summary is constructed at serialisation time from the fields above
    assert "20" in alt["summary"]
    assert "GRP_PUB" in alt["summary"]
    assert "destination" in alt["summary"]

    # CLI correctness — append member, not set member (set would wipe existing members)
    assert "append member" in alt["group_cli"]
    assert "GRP_PUB" in alt["group_cli"]
    assert "set member" not in alt["group_cli"]

    # new address object CLI must be present and come before the group append
    assert alt["member_cli"]
    assert alt["member_names"]

    # blast radius: both direct (30) and nested-via-GRP_PARENT (40) are present;
    # the triggering rule itself (20) must be excluded
    assert {a["policy_id"] for a in alt["affected_rules"]} == {30, 40}

    # each affected-rule dict must carry the keys render_report.py reads
    for ar in alt["affected_rules"]:
        assert "policy_id" in ar
        assert "name" in ar
        assert "package" in ar
        assert "side" in ar
        assert "via" in ar
        assert "status" in ar

    # at least one warning about the blast radius must survive serialisation
    assert any("other rule" in w for w in alt["warnings"])


def test_group_append_not_offered_for_negated_side():
    pols = [dict(_NEAR_MISS_POLICIES[0], **{"dstaddr-negate": "enable"})]
    # negated group contains the dst -> rule doesn't match; appending would
    # REMOVE access, so no alternative may be offered
    fmg = EngineFMG(policies=pols, addr_groups=[{"name": "GRP_PUB", "member": ["H_DST_NET"]}])
    base_objects = fmg.get_address_objects("root")
    fmg.get_address_objects = lambda adom: base_objects + [
        {"name": "H_DST_NET", "type": "ipmask", "subnet": "10.9.8.0 255.255.255.0"},
    ]
    plan = _run(service="tcp/8443", fmg=fmg)
    assert plan.firewalls[0].alternative is None


def test_direct_append_offered_when_no_group_on_failing_side():
    # Direct-object dst (no group) — should now propose a direct policy append
    # instead of silently skipping.  H_EXIST resolves to 10.1.2.3/32 which does
    # not contain the requested dst 10.9.8.7 → dst is the failing side.
    pols = [dict(_NEAR_MISS_POLICIES[0], dstaddr=["H_EXIST"])]
    plan = _run(service="tcp/8443", fmg=EngineFMG(policies=pols))
    alt = plan.firewalls[0].alternative
    assert alt is not None
    assert alt.group is None                   # direct-append, not group-append
    assert alt.side == "destination"
    assert alt.policy_id == 20
    assert "append dstaddr" in alt.direct_cli
    assert alt.group_cli == ""                 # no group CLI for direct-append
    assert not alt.affected_policies           # only one rule affected


def _seeburger_fmg():
    """Fake FMG mimicking the SEEBURGER / RITM0892999 scenario:
    a specific near-miss rule (exact dst + svc, direct host src) alongside a
    broad catch-all rule (group src, dst=all).  The specific rule must win.

    GRP_BROAD contains H_SOMEOTHER (10.99.0.5/32) — NOT the request src
    10.1.2.3 — so the catch-all does not fully cover the flow and both rules
    become near-miss candidates that the ranker must choose between."""
    pols = [
        # Specific near-miss: H_OLD_SRC ≠ 10.1.2.3, but dst and svc are exact
        {"policyid": 110221, "name": "SEEBURGER - ESB Support", "status": "enable",
         "action": 1, "schedule": ["always"],
         "srcaddr": ["H_OLD_SRC"], "dstaddr": ["H_EXACT_DST"],
         "service": ["SVC_TCP_8443"], "srcintf": ["port1"], "dstintf": ["port2"],
         "logtraffic": 2},
        # Catch-all: group src (doesn't contain request src), any dst — qualifies
        # but is less specific (dst=all → specificity 0)
        {"policyid": 110154, "name": "T3 - CatchAll", "status": "enable",
         "action": 1, "schedule": ["always"],
         "srcaddr": ["GRP_BROAD"], "dstaddr": ["all"],
         "service": ["SVC_TCP_8443"], "srcintf": ["port1"], "dstintf": ["port2"],
         "logtraffic": 2},
    ]
    groups = [{"name": "GRP_BROAD", "member": ["H_SOMEOTHER"]}]
    fmg = EngineFMG(policies=pols, addr_groups=groups)
    base = fmg.get_address_objects("root")
    fmg.get_address_objects = lambda adom: base + [
        # H_OLD_SRC: prior host on same subnet, not 10.1.2.3 (the new request src)
        {"name": "H_OLD_SRC", "type": "ipmask", "subnet": "10.1.2.99/32"},
        # H_EXACT_DST: exact requested destination
        {"name": "H_EXACT_DST", "type": "ipmask", "subnet": "10.9.8.7/32"},
        # H_SOMEOTHER: occupant of GRP_BROAD — must not be the request src
        {"name": "H_SOMEOTHER", "type": "ipmask", "subnet": "10.99.0.5/32"},
    ]
    return fmg


def test_direct_append_preferred_over_group_catch_all():
    # The specific rule (exact dst + svc, direct src) should be chosen over the
    # catch-all group-append rule.  This is the SEEBURGER/RITM0892999 scenario.
    plan = _run(service="tcp/8443", fmg=_seeburger_fmg())
    fw = plan.firewalls[0]
    alt = fw.alternative
    assert alt is not None
    # must point to the specific rule, not the catch-all
    assert alt.policy_id == 110221
    assert alt.policy_name == "SEEBURGER - ESB Support"
    assert alt.group is None                   # direct-append
    assert alt.side == "source"
    assert "append srcaddr" in alt.direct_cli
    assert "110221" in alt.direct_cli
    assert not alt.affected_policies


def test_direct_append_alternative_in_payload():
    plan = _run(service="tcp/8443", fmg=_seeburger_fmg())
    payload = to_report_payload(plan)
    validate_payload(payload)
    entry = payload["cli"]["per_firewall"][0]
    alt = entry["alternative"]
    assert alt["policy_id"] == 110221
    assert alt["group"] is None
    assert alt["direct_cli"]
    assert "append srcaddr" in alt["direct_cli"]
    assert alt["group_cli"] == ""
    assert "direct_cli" in alt              # field must be serialised
    assert "adding" in alt["summary"].lower()
    assert "source address list" in alt["summary"]


def _wind_farms_fmg():
    """Two near-miss candidates where Wind Farms has more dst refs than SEEBURGER.
    SEEBURGER (1 exact dst ref) must beat Wind Farms (4 dst refs) because fewer
    non-failing-side refs means the rule is more targeted at this specific flow."""
    pols = [
        {"policyid": 110221, "name": "SEEBURGER - ESB Support", "status": "enable",
         "action": 1, "schedule": ["always"],
         "srcaddr": ["H_OLD_SRC"], "dstaddr": ["H_EXACT_DST"],
         "service": ["SVC_TCP_8443"], "srcintf": ["port1"], "dstintf": ["port2"],
         "logtraffic": 2},
        {"policyid": 10110, "name": "Wind Farms", "status": "enable",
         "action": 1, "schedule": ["always"],
         "srcaddr": ["H_WF1", "H_WF2", "H_WF3"],
         "dstaddr": ["H_EXACT_DST", "H_OTHER1", "H_OTHER2", "H_OTHER3"],
         "service": ["SVC_TCP_8443"], "srcintf": ["port1"], "dstintf": ["port2"],
         "logtraffic": 2},
    ]
    fmg = EngineFMG(policies=pols)
    base = fmg.get_address_objects("root")
    fmg.get_address_objects = lambda adom: base + [
        {"name": "H_OLD_SRC",   "type": "ipmask", "subnet": "10.1.2.99/32"},
        {"name": "H_EXACT_DST", "type": "ipmask", "subnet": "10.9.8.7/32"},
        {"name": "H_WF1",       "type": "ipmask", "subnet": "10.50.0.1/32"},
        {"name": "H_WF2",       "type": "ipmask", "subnet": "10.50.0.2/32"},
        {"name": "H_WF3",       "type": "ipmask", "subnet": "10.50.0.3/32"},
        {"name": "H_OTHER1",    "type": "ipmask", "subnet": "10.60.0.1/32"},
        {"name": "H_OTHER2",    "type": "ipmask", "subnet": "10.60.0.2/32"},
        {"name": "H_OTHER3",    "type": "ipmask", "subnet": "10.60.0.3/32"},
    ]
    return fmg


def test_targeted_rule_preferred_over_broad_many_refs():
    # SEEBURGER has exactly 1 dst ref matching our flow; Wind Farms has 4 dst refs
    # (ours + 3 others).  The rule with fewer non-failing-side refs must win —
    # more refs means the rule covers many unrelated flows, not this one specifically.
    plan = _run(service="tcp/8443", fmg=_wind_farms_fmg())
    fw = plan.firewalls[0]
    alt = fw.alternative
    assert alt is not None, "expected a near-miss alternative"
    assert alt.policy_id == 110221, (
        f"expected SEEBURGER (110221), got rule #{alt.policy_id} '{alt.policy_name}'"
    )
    assert alt.policy_name == "SEEBURGER - ESB Support"
    assert alt.group is None    # direct-append, no group
    assert alt.side == "source"


# ---------------------------------------------------------------------------
# Consolidated multi-value planning
# ---------------------------------------------------------------------------

class MultiZone(EngineZone):
    """Zone fake whose verdict can vary by destination."""

    def __init__(self, verdict_by_dst=None, **kw):
        super().__init__(**kw)
        self._by_dst = verdict_by_dst or {}

    def query(self, src, dst, service="", verbose=True):
        v = self._by_dst.get(dst, self._verdict)
        return [{"src": src, "dst": dst, "service": service,
                 "verdict": v, "src_zones": self._src, "dst_zones": self._dst,
                 "governing": [{"policy_set": "PS", "access_type": "allow all",
                                "severity": "high"}],
                 "all_policies": []}]


def _run_multi(src, dst, service, fmg=None, zone=None, ticket="CHG0042", **kw):
    return plan_change(
        src=src, dst=dst, service=service,
        firewalls=[TF(device="FW1", adom="root")],
        justification="test flow", ticket_id=ticket,
        fmg_client=fmg or EngineFMG(),
        zone_client=zone or EngineZone(),
        **kw,
    )


def test_consolidated_two_sources_one_policy():
    plan = _run_multi(["10.1.2.3", "10.1.2.4"], "10.9.8.7", "tcp/8443")
    assert plan.cli_status == "new_rule"
    fw = plan.firewalls[0]
    # exactly one policy block, listing both source objects
    assert fw.policy_cli.count("config firewall policy") == 1
    assert 'set srcaddr "H_EXIST" "H_10.1.2.4"' in fw.policy_cli
    roles = [(o.role, o.action, o.name) for o in fw.objects]
    assert ("source", "reuse", "H_EXIST") in roles          # 10.1.2.3 exists
    assert ("source", "create", "H_10.1.2.4") in roles      # 10.1.2.4 is new
    assert plan.flow.src == "10.1.2.3, 10.1.2.4"


def test_consolidated_comma_string_input():
    plan = _run_multi("10.1.2.3, 10.1.2.4", "10.9.8.7", "tcp/8443")
    assert plan.flow.srcs == ["10.1.2.3", "10.1.2.4"]
    assert 'set srcaddr "H_EXIST" "H_10.1.2.4"' in plan.firewalls[0].policy_cli


def test_consolidated_multi_service_members():
    plan = _run_multi("10.1.2.3", "10.9.8.7", ["tcp/8443", "tcp/9000"])
    fw = plan.firewalls[0]
    assert 'set service "SVC_TCP_8443" "SVC_TCP_9000"' in fw.policy_cli
    svc_actions = {(o.name, o.action) for o in fw.objects if o.obj_type == "service"}
    assert ("SVC_TCP_8443", "reuse") in svc_actions
    assert ("SVC_TCP_9000", "create") in svc_actions


def test_mixed_zone_verdicts_refuse_consolidation():
    from planner.models import PlannerDataError
    zone = MultiZone(verdict_by_dst={"10.9.8.7": "ALLOWED", "10.9.8.8": "BLOCKED"})
    with pytest.raises(PlannerDataError) as exc:
        _run_multi("10.1.2.3", ["10.9.8.7", "10.9.8.8"], "tcp/8443", zone=zone)
    assert exc.value.source == "request"
    assert "split" in exc.value.detail.lower()


def test_any_unknown_pair_means_unknown_no_action():
    zone = MultiZone(verdict_by_dst={"10.9.8.7": "ALLOWED", "10.9.8.8": "UNKNOWN"})
    plan = _run_multi("10.1.2.3", ["10.9.8.7", "10.9.8.8"], "tcp/8443", zone=zone)
    assert plan.cli_status == "unknown_no_action"


def test_already_covered_requires_every_pair():
    # default EngineFMG policy 10 covers NET_10_1 -> NET_DST (10.9.8.0/24) on 443
    # 10.99.0.9 is outside NET_DST, so only one of the two pairs is covered
    plan = _run_multi("10.1.2.3", ["10.9.8.7", "10.99.0.9"], "443")
    assert plan.cli_status == "new_rule"
    fw = plan.firewalls[0]
    assert fw.status == "new_rule"
    assert any("already covered" in w.lower() for w in fw.warnings)


def test_all_pairs_covered_is_already_covered():
    plan = _run_multi("10.1.2.3", ["10.9.8.7", "10.9.8.9"], "443")
    assert plan.cli_status == "already_covered"


def test_auto_group_above_threshold():
    srcs = ["10.1.2.3", "10.1.2.4", "10.1.2.5", "10.1.2.6"]
    plan = _run_multi(srcs, "10.9.8.7", "tcp/8443")
    fw = plan.firewalls[0]
    groups = [o for o in fw.objects if o.obj_type == "group"]
    assert len(groups) == 1 and groups[0].name == "GRP_CHG0042_SRC"
    assert "set member" in groups[0].cli
    assert 'set srcaddr "GRP_CHG0042_SRC"' in fw.policy_cli


def test_named_group_used_even_below_threshold():
    plan = _run_multi(["10.1.2.3", "10.1.2.4"], "10.9.8.7", "tcp/8443",
                      src_group="GRP_VENDOR_X")
    fw = plan.firewalls[0]
    assert 'set srcaddr "GRP_VENDOR_X"' in fw.policy_cli
    groups = [o for o in fw.objects if o.obj_type == "group"]
    assert groups and groups[0].name == "GRP_VENDOR_X"
    payload = to_report_payload(plan)
    validate_payload(payload)
    assert payload["request"]["src"] == "10.1.2.3, 10.1.2.4"


def test_group_append_alternative_multi_missing_members():
    plan = _run_multi("10.1.2.3", ["10.9.8.7", "10.99.0.9"], "tcp/8443",
                      fmg=_near_miss_fmg())
    fw = plan.firewalls[0]
    # near-miss rule 20's dst group GRP_PUB misses both destinations
    alt = fw.alternative
    assert alt is not None and alt.group == "GRP_PUB"
    names = [m.name for m in alt.members]
    assert "H_10.9.8.7" in names and "H_10.99.0.9" in names
    assert alt.group_cli.count("append member") == 2


def test_permissive_request_warned_in_plan():
    # service "any" on an otherwise-normal flow must surface a
    # least-privilege warning on the plan (and in the report payload)
    plan = _run(service="any")
    assert any("ANY service" in w for w in plan.warnings)
    payload = to_report_payload(plan)
    validate_payload(payload)


# ---------------------------------------------------------------------------
# Bug-fix regression: disabled rules and ICMP noise in partial_matches
# ---------------------------------------------------------------------------

def _make_icmp_proto_svc():
    return {"name": "icmp-proto", "protocol": "IP", "protocol-number": 1}


def test_disabled_rule_not_in_partial_matches():
    """A disabled rule that overlaps the request must be excluded from
    partial_matches — disabled rules have no traffic effect."""
    fmg = EngineFMG(policies=[
        {"policyid": 5, "name": "disabled-overlap", "status": "disable",
         "action": 1, "schedule": ["always"],
         "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"],
         "srcintf": ["port1"], "dstintf": ["port2"], "logtraffic": 2},
    ])
    plan = _run(service="tcp/22", fmg=fmg)
    fw = plan.firewalls[0]
    assert not any(r["policy_id"] == 5 for r in fw.partial_matches), (
        "disabled rule must not appear in partial_matches"
    )
    assert not any(r["policy_id"] == 5 for r in fw.covering_rules), (
        "disabled rule must not appear in covering_rules"
    )


def test_non_overlapping_service_rule_not_in_partial_matches():
    """A rule whose service has no overlap with the requested service must not
    appear in partial_matches (e.g. an HTTPS-only rule when ssh/tcp-22 is requested)."""
    fmg = EngineFMG(policies=[
        # HTTPS-only rule — no tcp/22 overlap
        {"policyid": 8, "name": "https-only-rule", "status": "enable",
         "action": 1, "schedule": ["always"],
         "srcaddr": ["all"], "dstaddr": ["all"], "service": ["HTTPS"],
         "srcintf": ["port1"], "dstintf": ["port2"], "logtraffic": 2},
    ])
    plan = _run(service="tcp/22", fmg=fmg)
    fw = plan.firewalls[0]
    assert not any(r["policy_id"] == 8 for r in fw.partial_matches), (
        "HTTPS-only rule must not appear in partial_matches for a tcp/22 request"
    )


def test_blocked_recommendation_names_governing_policy():
    """When zone verdict is BLOCKED, the recommendation must name the blocking
    policy so engineers know which rule is the source of the block."""
    zone = EngineZone(
        verdict="BLOCKED",
        src_zones=["NSS Corp Internal"],
        dst_zones=["NSS OT-All"],
    )
    # Patch the query method to return a blocking governing policy
    orig_query = zone.query

    def _query_with_block(src, dst, service="", verbose=True):
        result = orig_query(src, dst, service, verbose)
        result[0]["governing"] = [
            {"policy_set": "OT and CIP-H Block All", "access_type": "block all",
             "severity": "high"}
        ]
        return result

    zone.query = _query_with_block

    plan = _run(verdict="BLOCKED", zone=zone, service="tcp/22")
    assert plan.cli_status == "blocked_exception"
    assert "OT and CIP-H Block All" in plan.recommendation, (
        "Blocking policy name must appear in the recommendation text"
    )
