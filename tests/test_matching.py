"""
Unit tests for fortimanager_mcp/matching.py — pure logic, no I/O.

Covers PortRange semantics, service request parsing, and catalog resolution
of FortiManager service/address objects into numeric sets.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from fortimanager_mcp.matching import (
    PortRange,
    ServiceCatalog,
    parse_service_request,
)

# ---------------------------------------------------------------------------
# PortRange
# ---------------------------------------------------------------------------

def test_portrange_contains_and_overlaps():
    broad = PortRange("tcp", 8000, 8100)
    narrow = PortRange("tcp", 8080, 8080)
    other_proto = PortRange("udp", 8080, 8080)
    disjoint = PortRange("tcp", 9000, 9100)

    assert broad.contains(narrow)
    assert not narrow.contains(broad)
    assert broad.overlaps(narrow)
    assert not broad.contains(other_proto)
    assert not broad.overlaps(other_proto)
    assert not broad.overlaps(disjoint)


def test_portrange_ip_wildcard_matches_everything():
    wildcard = PortRange("ip", 0, 65535)
    assert wildcard.contains(PortRange("tcp", 443, 443))
    assert wildcard.overlaps(PortRange("udp", 53, 53))


# ---------------------------------------------------------------------------
# parse_service_request
# ---------------------------------------------------------------------------

def test_parse_port_number():
    assert parse_service_request("443") == [PortRange("tcp", 443, 443)]


def test_parse_port_number_with_udp_hint():
    assert parse_service_request("162", protocol_hint="udp") == [
        PortRange("udp", 162, 162)
    ]


def test_parse_proto_slash_port():
    assert parse_service_request("tcp/8443") == [PortRange("tcp", 8443, 8443)]
    assert parse_service_request("udp/514") == [PortRange("udp", 514, 514)]


def test_parse_port_range():
    assert parse_service_request("tcp/8000-8100") == [PortRange("tcp", 8000, 8100)]


def test_parse_well_known_ssh():
    assert parse_service_request("ssh") == [PortRange("tcp", 22, 22)]


def test_parse_well_known_dns_is_tcp_and_udp():
    result = parse_service_request("dns")
    assert PortRange("tcp", 53, 53) in result
    assert PortRange("udp", 53, 53) in result


def test_parse_any_is_wildcard():
    for raw in ("any", "ALL", ""):
        result = parse_service_request(raw)
        assert result == [PortRange("ip", 0, 65535)]


def test_parse_unknown_raises():
    with pytest.raises(ValueError):
        parse_service_request("no-such-service-xyz")


# ---------------------------------------------------------------------------
# ServiceCatalog
# ---------------------------------------------------------------------------

def _catalog(objects=None, groups=None):
    return ServiceCatalog(objects or [], groups or [])


def test_catalog_resolves_tcp_portrange():
    cat = _catalog([{"name": "SVC_TCP_8443", "protocol": "TCP/UDP/SCTP",
                     "tcp-portrange": "8443"}])
    assert cat.ranges_for_ref("SVC_TCP_8443") == [PortRange("tcp", 8443, 8443)]


def test_catalog_resolves_multi_and_dash_ranges():
    cat = _catalog([{"name": "WEB", "protocol": "TCP/UDP/SCTP",
                     "tcp-portrange": "80 8000-8100"}])
    ranges = cat.ranges_for_ref("WEB")
    assert PortRange("tcp", 80, 80) in ranges
    assert PortRange("tcp", 8000, 8100) in ranges


def test_catalog_resolves_range_with_source_port_suffix():
    # FMG syntax "443:1024-65535" — destination 443, source part after ':' ignored
    cat = _catalog([{"name": "HTTPS_SRC", "protocol": "TCP/UDP/SCTP",
                     "tcp-portrange": "443:1024-65535"}])
    assert cat.ranges_for_ref("HTTPS_SRC") == [PortRange("tcp", 443, 443)]


def test_catalog_udp_and_tcp_combined():
    cat = _catalog([{"name": "DNS", "protocol": "TCP/UDP/SCTP",
                     "tcp-portrange": "53", "udp-portrange": "53"}])
    ranges = cat.ranges_for_ref("DNS")
    assert PortRange("tcp", 53, 53) in ranges
    assert PortRange("udp", 53, 53) in ranges


def test_catalog_icmp_protocol_resolves_to_icmp_range():
    cat = _catalog([{"name": "PING", "protocol": "ICMP"}])
    assert cat.ranges_for_ref("PING") == [PortRange("icmp", 0, 65535)]


def test_catalog_ip_protocol_no_number_is_wildcard():
    # An IP-typed service object without protocol-number is the ALL service.
    cat = _catalog([{"name": "ALL_IP", "protocol": "IP"}])
    assert cat.ranges_for_ref("ALL_IP") == [PortRange("ip", 0, 65535)]


def test_catalog_ip_protocol_with_icmp_number_resolves_to_icmp():
    # protocol=IP + protocol-number=1 is icmp-proto — must resolve to ICMP,
    # not the IP wildcard, so it can never match TCP/UDP requests.
    cat = _catalog([{"name": "icmp-proto", "protocol": "IP", "protocol-number": 1}])
    assert cat.ranges_for_ref("icmp-proto") == [PortRange("icmp", 0, 65535)]


def test_catalog_ip_protocol_with_unknown_number_is_unresolvable():
    # protocol=IP + protocol-number=47 (GRE) is not in our map; return None.
    cat = _catalog([{"name": "GRE", "protocol": "IP", "protocol-number": 47}])
    assert cat.ranges_for_ref("GRE") is None


def test_icmp_proto_service_does_not_match_tcp22():
    # A policy carrying icmp-proto (protocol=IP, protocol-number=1) must not
    # report a match against a tcp/22 request — icmp PortRange does not
    # overlap tcp PortRange.
    from fortimanager_mcp.matching import AddressCatalog, PolicyMatcher
    svc_cat = _catalog([{"name": "icmp-proto", "protocol": "IP", "protocol-number": 1}])
    addr_cat = AddressCatalog([], [])
    matcher = PolicyMatcher(addr_cat, svc_cat)
    pol = {
        "policyid": 1, "action": 1, "status": "enable",
        "srcaddr": ["all"], "dstaddr": ["all"], "service": ["icmp-proto"],
        "srcintf": ["any"], "dstintf": ["any"], "schedule": ["always"],
    }
    result = matcher.evaluate(pol, "10.1.1.1", "10.9.9.9",
                              [PortRange("tcp", 22, 22)])
    assert not result.matched, "icmp-proto must not match tcp/22"
    assert "icmp-proto" not in result.unknown_refs, (
        "icmp-proto should resolve cleanly to ICMP range, not be unknown"
    )


def test_catalog_all_name_is_wildcard():
    cat = _catalog()
    assert cat.ranges_for_ref("ALL") == [PortRange("ip", 0, 65535)]
    assert cat.ranges_for_ref("any") == [PortRange("ip", 0, 65535)]


def test_catalog_group_recursion_with_cycle():
    cat = ServiceCatalog(
        [{"name": "SSH", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "22"}],
        [
            {"name": "G1", "member": ["SSH", "G2"]},
            {"name": "G2", "member": ["G1"]},  # cycle back to G1
        ],
    )
    assert cat.ranges_for_ref("G1") == [PortRange("tcp", 22, 22)]


def test_catalog_unknown_ref_returns_none():
    assert _catalog().ranges_for_ref("MYSTERY_OBJECT") is None


def test_80_does_not_match_8080():
    """The bug this layer exists to fix: substring matching false positives."""
    cat = _catalog([{"name": "TCP_8080", "protocol": "TCP/UDP/SCTP",
                     "tcp-portrange": "8080"}])
    requested = parse_service_request("80")
    resolved = cat.ranges_for_ref("TCP_8080")
    assert not any(obj.contains(req) for obj in resolved for req in requested)
    assert not any(obj.overlaps(req) for obj in resolved for req in requested)


# ---------------------------------------------------------------------------
# AddressCatalog
# ---------------------------------------------------------------------------

import ipaddress

from fortimanager_mcp.matching import AddressCatalog


def _nets(*cidrs):
    return [ipaddress.ip_network(c) for c in cidrs]


def test_addr_ipmask_space_form():
    cat = AddressCatalog([{"name": "NET_A", "type": "ipmask",
                           "subnet": "10.8.0.0 255.255.0.0"}], [])
    assert cat.networks_for_ref("NET_A") == _nets("10.8.0.0/16")


def test_addr_ipmask_list_form():
    cat = AddressCatalog([{"name": "NET_B", "type": "ipmask",
                           "subnet": ["10.9.0.0", "255.255.255.0"]}], [])
    assert cat.networks_for_ref("NET_B") == _nets("10.9.0.0/24")


def test_addr_iprange():
    cat = AddressCatalog([{"name": "R1", "type": "iprange",
                           "start-ip": "10.1.1.10", "end-ip": "10.1.1.11"}], [])
    nets = cat.networks_for_ref("R1")
    covered = set()
    for n in nets:
        covered.update(n.hosts() if n.prefixlen < 31 else n)
        covered.update([n.network_address, n.broadcast_address])
    assert ipaddress.ip_address("10.1.1.10") in covered
    assert ipaddress.ip_address("10.1.1.11") in covered


def test_addr_group_recursion():
    cat = AddressCatalog(
        [{"name": "H1", "type": "ipmask", "subnet": "10.1.1.1 255.255.255.255"},
         {"name": "H2", "type": "ipmask", "subnet": "10.1.1.2/32"}],
        [{"name": "G_OUTER", "member": ["G_INNER"]},
         {"name": "G_INNER", "member": ["H1", "H2"]}],
    )
    nets = cat.networks_for_ref("G_OUTER")
    assert set(nets) == set(_nets("10.1.1.1/32", "10.1.1.2/32"))


def test_addr_group_cycle_guard():
    cat = AddressCatalog(
        [{"name": "H1", "type": "ipmask", "subnet": "10.1.1.1/32"}],
        [{"name": "GA", "member": ["GB", "H1"]},
         {"name": "GB", "member": ["GA"]}],
    )
    assert cat.networks_for_ref("GA") == _nets("10.1.1.1/32")


def test_addr_all_is_default_route():
    cat = AddressCatalog([], [])
    assert cat.networks_for_ref("all") == _nets("0.0.0.0/0")
    assert cat.networks_for_ref("ANY") == _nets("0.0.0.0/0")


def test_addr_fqdn_unresolvable_returns_none():
    cat = AddressCatalog([{"name": "WEBSITE", "type": "fqdn",
                           "fqdn": "example.com"}], [])
    assert cat.networks_for_ref("WEBSITE") is None


def test_addr_unknown_name_returns_none():
    assert AddressCatalog([], []).networks_for_ref("NOPE") is None


def test_global_group_lookup_and_adom_precedence():
    cat = AddressCatalog(
        objects=[{"name": "DUP", "type": "ipmask", "subnet": "10.1.0.0/24"}],
        groups=[],
        global_objects=[
            {"name": "DUP", "type": "ipmask", "subnet": "10.99.0.0/24"},
            {"name": "GLOB_H", "type": "ipmask", "subnet": "10.50.0.1/32"},
        ],
        global_groups=[{"name": "GLOB_G", "member": ["GLOB_H"]}],
    )
    # per-ADOM name shadows global
    assert cat.networks_for_ref("DUP") == _nets("10.1.0.0/24")
    assert cat.networks_for_ref("GLOB_G") == _nets("10.50.0.1/32")


# ---------------------------------------------------------------------------
# PolicyMatcher — semantics table from the plan
# ---------------------------------------------------------------------------

from fortimanager_mcp.matching import PolicyMatcher


def _matcher():
    addr = AddressCatalog(
        [{"name": "NET_10_1", "type": "ipmask", "subnet": "10.1.0.0/16"},
         {"name": "H_10_9_8_7", "type": "ipmask", "subnet": "10.9.8.7/32"}],
        [],
    )
    svc = ServiceCatalog(
        [{"name": "HTTPS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"},
         {"name": "TCP_85", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "85"}],
        [],
    )
    return PolicyMatcher(addr, svc)


def _pol(**over):
    base = {
        "policyid": 1, "name": "P", "status": "enable", "action": 1,
        "schedule": ["always"],
        "srcaddr": ["NET_10_1"], "dstaddr": ["H_10_9_8_7"],
        "service": ["HTTPS"],
        "srcintf": ["port1"], "dstintf": ["port2"],
    }
    base.update(over)
    return base


def _https():
    return parse_service_request("443")


def test_matcher_full_cover_host_in_subnet():
    r = _matcher().evaluate(_pol(), "10.1.2.3", "10.9.8.7", _https())
    assert r.matched and r.full_cover
    assert r.action == "accept" and not r.disabled and not r.conditional_schedule
    assert r.unknown_refs == []


def test_matcher_cidr_overlap_not_contained():
    # requested source 10.0.0.0/8 is wider than the policy's 10.1.0.0/16
    r = _matcher().evaluate(_pol(), "10.0.0.0/8", "10.9.8.7", _https())
    assert r.matched and not r.full_cover


def test_matcher_service_overlap_not_contained():
    # request tcp/80-90; policy only covers tcp/85
    r = _matcher().evaluate(_pol(service=["TCP_85"]), "10.1.2.3", "10.9.8.7",
                            parse_service_request("tcp/80-90"))
    assert r.matched and not r.full_cover


def test_matcher_all_refs_full_cover():
    r = _matcher().evaluate(
        _pol(srcaddr=["all"], dstaddr=["all"], service=["ALL"]),
        "192.168.1.1", "8.8.8.8", _https())
    assert r.matched and r.full_cover


def test_matcher_negate_target_inside_refs():
    r = _matcher().evaluate(_pol(**{"srcaddr-negate": "enable"}),
                            "10.1.2.3", "10.9.8.7", _https())
    assert not r.matched and not r.full_cover


def test_matcher_negate_target_disjoint():
    r = _matcher().evaluate(_pol(**{"srcaddr-negate": "enable"}),
                            "192.168.5.5", "10.9.8.7", _https())
    assert r.matched and r.full_cover


def test_matcher_disabled_policy_flagged():
    r = _matcher().evaluate(_pol(status="disable"), "10.1.2.3", "10.9.8.7", _https())
    assert r.matched and r.full_cover and r.disabled


def test_matcher_conditional_schedule_flagged():
    r = _matcher().evaluate(_pol(schedule=["weekend-only"]),
                            "10.1.2.3", "10.9.8.7", _https())
    assert r.matched and r.conditional_schedule


def test_matcher_unknown_ref_conservative():
    r = _matcher().evaluate(_pol(dstaddr=["FQDN_THING"]),
                            "10.1.2.3", "10.9.8.7", _https())
    assert r.matched and not r.full_cover
    assert "FQDN_THING" in r.unknown_refs


def test_matcher_no_overlap_no_match():
    r = _matcher().evaluate(_pol(), "172.16.0.1", "10.9.8.7", _https())
    assert not r.matched


def test_matcher_deny_action_mapped():
    r = _matcher().evaluate(_pol(action=0), "10.1.2.3", "10.9.8.7", _https())
    assert r.action == "deny"


def test_matcher_wildcard_request_src():
    # empty src means "engineer didn't constrain it" — treat as wildcard
    r = _matcher().evaluate(_pol(), "", "10.9.8.7", _https())
    assert r.matched and not r.full_cover


# ---------------------------------------------------------------------------
# Group-introspection helpers (for the planner's group-append alternative)
# ---------------------------------------------------------------------------

def _nested_catalog():
    return AddressCatalog(
        objects=[{"name": "H_A", "type": "ipmask", "subnet": "10.1.1.7 255.255.255.255"}],
        groups=[
            {"name": "G_INNER", "member": ["H_A"]},
            {"name": "G_OUTER", "member": ["G_INNER"]},
            {"name": "G_OTHER", "member": ["H_A"]},
        ],
    )


def test_is_group():
    cat = _nested_catalog()
    assert cat.is_group("G_INNER")
    assert not cat.is_group("H_A")
    assert not cat.is_group("NOPE")


def test_groups_containing_transitive():
    cat = _nested_catalog()
    assert cat.groups_containing("G_INNER") == {"G_OUTER"}
    assert cat.groups_containing("H_A") == {"G_INNER", "G_OUTER", "G_OTHER"}
    assert cat.groups_containing("G_OUTER") == set()


def test_groups_containing_cycle_safe():
    cat = AddressCatalog([], [
        {"name": "G1", "member": ["G2"]},
        {"name": "G2", "member": ["G1"]},
    ])
    assert cat.groups_containing("G1") == {"G2", "G1"}


def test_matcher_public_side_helpers():
    m = _matcher()
    pol = _pol()
    # src inside NET_10_1, dst inside NET_DST (matches _pol fixture semantics)
    src_m, src_f = m.addr_side(pol, "srcaddr", "10.1.2.3")
    assert src_m and src_f
    svc_m, svc_f = m.svc_side(pol, _https())
    assert svc_m and svc_f


# ---------------------------------------------------------------------------
# addr_ip_overlap
# ---------------------------------------------------------------------------

def test_addr_ip_overlap_returns_true_when_ip_in_resolved_subnet():
    m = _matcher()
    pol = _pol()  # srcaddr=["NET_10_1"] which is 10.1.0.0/16
    assert m.addr_ip_overlap(pol, "srcaddr", "10.1.2.3")


def test_addr_ip_overlap_returns_false_when_ip_outside_resolved_subnet():
    m = _matcher()
    pol = _pol()  # srcaddr=["NET_10_1"] which is 10.1.0.0/16
    assert not m.addr_ip_overlap(pol, "srcaddr", "10.2.0.1")


def test_addr_ip_overlap_ignores_fqdn_refs():
    """A policy whose only dst refs are FQDNs (unresolvable) must return False,
    even though the conservative matcher would say matched=True."""
    addr = AddressCatalog(
        [{"name": "H_192_168_1_1", "type": "ipmask", "subnet": "192.168.1.1/32"}],
        [],
    )
    svc = ServiceCatalog([], [])
    m = PolicyMatcher(addr, svc)
    # FQDN_AVAYA resolves to None (unknown/FQDN type not in catalog)
    pol = _pol(dstaddr=["FQDN_AVAYA"])
    assert not m.addr_ip_overlap(pol, "dstaddr", "52.116.196.54")


def test_addr_ip_overlap_true_when_any_ref_overlaps_even_if_others_are_fqdn():
    """If at least one ref resolves and overlaps, return True despite other FQDNs."""
    addr = AddressCatalog(
        [{"name": "H_52", "type": "ipmask", "subnet": "52.116.196.0/24"}],
        [],
    )
    m = PolicyMatcher(addr, ServiceCatalog([], []))
    pol = _pol(dstaddr=["FQDN_UNKNOWN", "H_52"])
    assert m.addr_ip_overlap(pol, "dstaddr", "52.116.196.54")


# ---------------------------------------------------------------------------
# uncovered_services
# ---------------------------------------------------------------------------

def test_uncovered_services_empty_when_all_covered():
    m = _matcher()
    pol = _pol()  # service=["HTTPS"] which is tcp/443
    assert m.uncovered_services(pol, parse_service_request("443")) == []


def test_uncovered_services_returns_missing_proto():
    """UDP side of a tcp/udp request not covered by a TCP-only service object."""
    m = _matcher()
    pol = _pol()  # service=["HTTPS"] — TCP/443 only
    requested = parse_service_request("tcp/443") + parse_service_request("udp/443")
    gap = m.uncovered_services(pol, requested)
    assert len(gap) == 1
    assert gap[0].protocol == "udp" and gap[0].start == 443


def test_uncovered_services_empty_for_broad_range():
    """A service object covering tcp/20000-59999 fully contains tcp/33001."""
    addr = AddressCatalog([], [])
    svc = ServiceCatalog(
        [{"name": "BIG", "protocol": "TCP/UDP/SCTP",
          "tcp-portrange": "20000-59999", "udp-portrange": "20000-59999"}],
        [],
    )
    m = PolicyMatcher(addr, svc)
    pol = {"service": ["BIG"]}
    requested = parse_service_request("tcp/33001") + parse_service_request("udp/33001")
    assert m.uncovered_services(pol, requested) == []
