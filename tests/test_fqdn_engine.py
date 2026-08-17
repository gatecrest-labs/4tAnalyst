import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


from intake_mcp.fqdn_parser import FQDNAllowlistRequest, FQDNEntry
from planner.engine import plan_fqdn_change, to_fqdn_report_payload
from planner.models import FQDNChangePlan

# ---- Fake clients ----

class FakeZoneClientFQDN:
    def __init__(self, verdict="ALLOWED", src_zone="OT-LAN", boom=False):
        self._verdict = verdict
        self._src_zone = src_zone
        self._boom = boom

    def query(self, src, dst, service="", verbose=True):
        from zone_mcp.client import ZonePolicyError
        if self._boom:
            raise ZonePolicyError("api down")
        return [{"src": src, "dst": dst, "service": service,
                 "verdict": self._verdict,
                 "src_zones": [self._src_zone], "dst_zones": ["Internet"],
                 "governing": [], "all_policies": []}]

    def zones(self):
        return {"zones": [
            {"name": "OT-LAN", "domain": "OT"},
            {"name": "Internet", "domain": "Internet"},
        ]}

    def policies(self):
        return []


class FakeFMGFQDN:
    def __init__(self, devices=("FW1",), fqdn_objects=None,
                 fqdn_groups=None, policies=None):
        self._devices = list(devices)
        self._fqdn_objs = fqdn_objects or []
        self._fqdn_grps = fqdn_groups or []
        self._policies = policies or []

    def get_devices(self, adom):
        return [{"name": d} for d in self._devices]

    def get_policy_packages(self, adom):
        return [{"name": "pkgA", "scope member": [{"name": "FW1"}]}]

    def get_policies(self, adom, pkg):
        return list(self._policies)

    def get_address_objects(self, adom):
        return list(self._fqdn_objs)

    def get_address_groups(self, adom):
        return list(self._fqdn_grps)

    def get_global_address_objects(self):
        return []

    def get_global_address_groups(self):
        return []

    def get_service_objects(self, adom):
        return []

    def get_service_groups(self, adom):
        return []

    def get_device_interfaces(self, adom, device):
        return [{"name": "port1", "ip": "10.1.0.1 255.255.0.0",
                 "type": "physical", "status": "up"}]

    def get_device_vdoms(self, adom, device):
        return [{"name": "root"}]

    def get_routing_table(self, adom, device):
        return []

    def get_routing_table_live(self, adom, device):
        from fortimanager_mcp.client import FortiManagerAPIError
        raise FortiManagerAPIError("unavailable in test", code=-6)

    def get_device_meta(self, adom, device):
        return {"os_ver": "7", "mr": 4, "patch": 2}


def _basic_request():
    return FQDNAllowlistRequest(
        vendor="Apple",
        category="APNs",
        src_ip="10.1.2.3",
        ticket_id="CHG001",
        firewalls=["FW1:OT-ADOM"],
        entries=[
            FQDNEntry(fqdn="*.push.apple.com", is_wildcard=True,
                      ports=[443, 5223], protocol="TCP",
                      required=True, comment="APNs push"),
            FQDNEntry(fqdn="axm-adm-scep.apple.com", is_wildcard=False,
                      ports=[443], protocol="TCP",
                      required=True, comment="SCEP"),
        ],
    )


# ---- Tests ----

def test_new_rule_plan():
    plan = plan_fqdn_change(
        _basic_request(),
        fmg_client=FakeFMGFQDN(),
        zone_client=FakeZoneClientFQDN(),
    )
    assert isinstance(plan, FQDNChangePlan)
    assert len(plan.per_firewall) == 1
    fw = plan.per_firewall[0]
    assert fw.firewall == "FW1"
    assert fw.verdict == "new_rule"
    assert fw.coverage == "new_rule"
    assert len(fw.uncovered_entries) == 2
    assert fw.proposed_group is not None
    assert fw.proposed_group.name == "GRP-Apple-APNs-DST"
    assert fw.proposed_policy is not None
    assert len(fw.proposed_objects) == 2
    # Wildcard FQDN gets WFQDN- prefix
    names = [o.name for o in fw.proposed_objects]
    assert any(n.startswith("WFQDN-") for n in names)
    assert any(n.startswith("FQDN-") for n in names)


def test_already_covered_plan():
    objs = [{"name": "WFQDN-push", "type": "wildcard-fqdn",
             "wildcard-fqdn": "*.push.apple.com"},
            {"name": "FQDN-axm-scep", "type": "fqdn",
             "fqdn": "axm-adm-scep.apple.com"}]
    grps = [{"name": "GRP-Apple-APNs-DST",
             "member": [{"name": "WFQDN-push"}, {"name": "FQDN-axm-scep"}]}]
    pols = [{"policyid": 5, "name": "Existing-Rule", "status": "enable",
             "action": 1, "srcaddr": ["any"],
             "dstaddr": ["GRP-Apple-APNs-DST"],
             "service": ["HTTPS"], "srcintf": ["any"], "dstintf": ["any"],
             "schedule": ["always"]}]
    fmg = FakeFMGFQDN(fqdn_objects=objs, fqdn_groups=grps, policies=pols)
    plan = plan_fqdn_change(
        _basic_request(), fmg_client=fmg,
        zone_client=FakeZoneClientFQDN(),
    )
    fw = plan.per_firewall[0]
    assert fw.verdict == "already_covered"
    assert fw.coverage == "already_covered"
    assert fw.proposed_group is None
    assert fw.proposed_policy is None


def test_unknown_zone_verdict_no_action():
    plan = plan_fqdn_change(
        _basic_request(),
        fmg_client=FakeFMGFQDN(),
        zone_client=FakeZoneClientFQDN(verdict="UNKNOWN"),
    )
    fw = plan.per_firewall[0]
    assert fw.verdict == "unknown_no_action"
    assert fw.proposed_group is None


def test_blocked_verdict():
    plan = plan_fqdn_change(
        _basic_request(),
        fmg_client=FakeFMGFQDN(),
        zone_client=FakeZoneClientFQDN(verdict="BLOCKED"),
    )
    fw = plan.per_firewall[0]
    assert fw.verdict == "blocked_exception"
    assert fw.proposed_group is not None  # still propose objects for the exception


def test_degraded_fmg_client():
    from fortimanager_mcp.client import FortiManagerAPIError

    class DeadFMG(FakeFMGFQDN):
        def get_policy_packages(self, adom):
            raise FortiManagerAPIError("timeout", code=-1)

    plan = plan_fqdn_change(
        _basic_request(), fmg_client=DeadFMG(),
        zone_client=FakeZoneClientFQDN(),
    )
    fw = plan.per_firewall[0]
    assert fw.degraded is True


def test_object_name_truncation_warning():
    long_fqdn = "a" * 80 + ".example.com"
    req = FQDNAllowlistRequest(
        vendor="Test", category="Long",
        src_ip="10.0.0.1", ticket_id="CHG999",
        firewalls=["FW1:OT-ADOM"],
        entries=[FQDNEntry(fqdn=long_fqdn, is_wildcard=False,
                           ports=[443], protocol="TCP",
                           required=True, comment="")],
    )
    plan = plan_fqdn_change(req, fmg_client=FakeFMGFQDN(),
                            zone_client=FakeZoneClientFQDN())
    fw = plan.per_firewall[0]
    obj = fw.proposed_objects[0]
    assert len(obj.name) <= 79
    assert any("truncated" in w.lower() or "79" in w for w in fw.warnings)


def test_to_fqdn_report_payload():
    plan = plan_fqdn_change(
        _basic_request(),
        fmg_client=FakeFMGFQDN(),
        zone_client=FakeZoneClientFQDN(),
    )
    payload = to_fqdn_report_payload(plan)
    assert payload["plan_type"] == "fqdn_allowlist"
    assert payload["vendor"] == "Apple"
    assert payload["category"] == "APNs"
    assert "per_firewall" in payload
    assert len(payload["per_firewall"]) == 1
