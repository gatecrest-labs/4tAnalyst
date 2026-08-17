import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fortimanager_mcp.matching import FQDNCatalog


def _objs():
    return [
        {"name": "WFQDN-push.apple.com", "type": "wildcard-fqdn",
         "wildcard-fqdn": "*.push.apple.com"},
        {"name": "FQDN-axm-scep", "type": "fqdn",
         "fqdn": "axm-adm-scep.apple.com"},
        {"name": "H_10.1.1.1", "type": "ipmask",
         "subnet": ["10.1.1.1", "255.255.255.255"]},
    ]


def _grps():
    return [
        {"name": "GRP-Apple-APNs-DST", "member": [
            {"name": "WFQDN-push.apple.com"},
            {"name": "FQDN-axm-scep"},
        ]},
        {"name": "GRP-IP-Only", "member": [{"name": "H_10.1.1.1"}]},
    ]


def test_fqdns_for_fqdn_object():
    cat = FQDNCatalog(_objs(), [])
    result = cat.fqdns_for_ref("FQDN-axm-scep")
    assert result == {"axm-adm-scep.apple.com"}


def test_fqdns_for_wildcard_fqdn_object():
    cat = FQDNCatalog(_objs(), [])
    result = cat.fqdns_for_ref("WFQDN-push.apple.com")
    assert result == {"*.push.apple.com"}


def test_ip_only_object_returns_empty_set():
    cat = FQDNCatalog(_objs(), [])
    result = cat.fqdns_for_ref("H_10.1.1.1")
    assert result == set()  # known, but no FQDNs


def test_unknown_ref_returns_none():
    cat = FQDNCatalog(_objs(), [])
    result = cat.fqdns_for_ref("nonexistent")
    assert result is None


def test_group_recursion():
    cat = FQDNCatalog(_objs(), _grps())
    result = cat.fqdns_for_ref("GRP-Apple-APNs-DST")
    assert result == {"*.push.apple.com", "axm-adm-scep.apple.com"}


def test_ip_only_group_returns_empty_set():
    cat = FQDNCatalog(_objs(), _grps())
    result = cat.fqdns_for_ref("GRP-IP-Only")
    assert result == set()


def test_cycle_guard():
    objs = [{"name": "obj-a", "type": "fqdn", "fqdn": "a.example.com"}]
    grps = [
        {"name": "grp-1", "member": [{"name": "grp-2"}]},
        {"name": "grp-2", "member": [{"name": "grp-1"}]},
    ]
    cat = FQDNCatalog(objs, grps)
    result = cat.fqdns_for_ref("grp-1")
    assert result is not None  # cycle guard prevents infinite loop; may be empty set


def test_exact_match_name_fqdn():
    cat = FQDNCatalog(_objs(), [])
    assert cat.exact_match_name("axm-adm-scep.apple.com") == "FQDN-axm-scep"


def test_exact_match_name_wildcard():
    cat = FQDNCatalog(_objs(), [])
    assert cat.exact_match_name("*.push.apple.com") == "WFQDN-push.apple.com"


def test_exact_match_name_not_found():
    cat = FQDNCatalog(_objs(), [])
    assert cat.exact_match_name("other.example.com") is None


def test_groups_containing_fqdn():
    cat = FQDNCatalog(_objs(), _grps())
    groups = cat.groups_containing_fqdn("*.push.apple.com")
    assert "GRP-Apple-APNs-DST" in groups


# ---- search_fqdn_rules ----

from fortimanager_mcp.client import FortiManagerAPIError
from fortimanager_mcp.query import search_fqdn_rules


class FakeFMGForFQDN:
    def __init__(self, addr_objects=None, addr_groups=None,
                 packages=None, policies=None, fail_pkg=None):
        self._objects = addr_objects or []
        self._groups = addr_groups or []
        self._packages = packages or [{"name": "pkgA",
                                        "scope member": [{"name": "FW1"}]}]
        self._policies = policies or []
        self._fail_pkg = fail_pkg

    def get_address_objects(self, adom):
        return list(self._objects)

    def get_address_groups(self, adom):
        return list(self._groups)

    def get_policy_packages(self, adom):
        return list(self._packages)

    def get_policies(self, adom, pkg):
        if self._fail_pkg and pkg == self._fail_pkg:
            raise FortiManagerAPIError("timeout", code=-1)
        return list(self._policies)

    def get_devices(self, adom):
        return [{"name": "FW1"}]


def _make_fmg(covered_fqdn="*.push.apple.com"):
    objs = [
        {"name": "WFQDN-push", "type": "wildcard-fqdn",
         "wildcard-fqdn": covered_fqdn},
    ]
    grps = [
        {"name": "GRP-Apple-APNs-DST", "member": [{"name": "WFQDN-push"}]},
    ]
    pols = [
        {"policyid": 10, "name": "Allow-Apple-Outbound", "status": "enable",
         "action": 1, "srcaddr": ["any"], "dstaddr": ["GRP-Apple-APNs-DST"],
         "service": ["HTTPS"], "srcintf": ["any"], "dstintf": ["any"],
         "schedule": ["always"]},
    ]
    return FakeFMGForFQDN(addr_objects=objs, addr_groups=grps, policies=pols)


def test_search_fqdn_covered():
    fmg = _make_fmg()
    result = search_fqdn_rules(fmg, "OT-ADOM", "FW1", ["*.push.apple.com"])
    assert not result["degraded"]
    assert len(result["results"]) == 1
    r = result["results"][0]
    assert r["fqdn"] == "*.push.apple.com"
    assert r["covered"] is True
    assert r["rule_id"] == 10
    assert r["via_group"] == "GRP-Apple-APNs-DST"


def test_search_fqdn_not_covered():
    fmg = FakeFMGForFQDN()  # no policies, no objects
    result = search_fqdn_rules(fmg, "OT-ADOM", "FW1", ["*.push.apple.com"])
    assert not result["degraded"]
    r = result["results"][0]
    assert r["covered"] is False


def test_search_fqdn_partial_group_match():
    objs = [
        {"name": "WFQDN-push", "type": "wildcard-fqdn",
         "wildcard-fqdn": "*.push.apple.com"},
    ]
    grps = [{"name": "GRP-Apple-APNs-DST", "member": [{"name": "WFQDN-push"}]}]
    pols = [{"policyid": 10, "name": "Allow-Apple", "status": "enable",
             "action": 1, "srcaddr": ["any"], "dstaddr": ["GRP-Apple-APNs-DST"],
             "service": ["HTTPS"], "srcintf": ["any"], "dstintf": ["any"],
             "schedule": ["always"]}]
    fmg = FakeFMGForFQDN(addr_objects=objs, addr_groups=grps, policies=pols)
    result = search_fqdn_rules(fmg, "OT-ADOM", "FW1",
                               ["*.push.apple.com", "axm-adm-scep.apple.com"])
    assert result["partial_group_match"] is not None
    pm = result["partial_group_match"]
    assert pm["group_name"] == "GRP-Apple-APNs-DST"
    assert "*.push.apple.com" in pm["covered"]
    assert "axm-adm-scep.apple.com" in pm["uncovered"]


def test_search_fqdn_degraded_on_package_failure():
    fmg = _make_fmg()
    fmg._fail_pkg = "pkgA"
    result = search_fqdn_rules(fmg, "OT-ADOM", "FW1", ["*.push.apple.com"])
    assert result["degraded"] is True
    assert len(result["packages_failed"]) == 1
