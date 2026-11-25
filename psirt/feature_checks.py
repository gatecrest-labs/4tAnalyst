"""
Feature exposure checks for PSIRT advisory assessment.

Keyword-based detection of which services/features a PSIRT advisory mentions,
followed by deterministic FortiManager config reads to determine whether each
feature is actually active on a given device.

A device where ALL detected features are confirmed inactive gets its verdict
downgraded from upgrade_required / config_change_required to no_action — the
vulnerable attack surface does not exist on that device.

A check returning "unknown" is treated conservatively: it does not cause a
downgrade. The registry grows one pattern at a time as new advisory types are
encountered (same discipline as workaround_checks.py).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

# ---------------------------------------------------------------------------
# Keyword → feature key mapping
# ---------------------------------------------------------------------------
# Each entry is (advisory_text_keyword, feature_key). Keywords are matched
# whole-word, case-insensitive in the advisory text.
# Multiple entries may share the same feature_key (many-to-one).
# One keyword may appear multiple times with different feature_keys when it
# implies more than one feature (e.g. "VPN" implies both ssl_vpn and ipsec).
#
# Source: fortinet-vuln-agent _SERVICE_KEYWORDS list, extended with aliases
# and additional services (DHCP, IPv6).
# ---------------------------------------------------------------------------

_KEYWORD_TO_FEATURE: list[tuple[str, str]] = [
    # SSL-VPN
    ("SSL-VPN",             "ssl_vpn"),
    ("SSL VPN",             "ssl_vpn"),
    ("SSLVPN",              "ssl_vpn"),
    # IPsec
    ("IPsec",               "ipsec"),
    ("IKE",                 "ipsec"),
    # Generic "VPN" is ambiguous — check both SSL-VPN and IPsec
    ("VPN",                 "ssl_vpn"),
    ("VPN",                 "ipsec"),
    # ZTNA
    ("ZTNA",                "ztna"),
    # Routing protocols
    ("BGP",                 "bgp"),
    ("OSPF",                "ospf"),
    ("multicast",           "multicast"),
    # Authentication services
    ("RADIUS",              "radius"),
    ("LDAP",                "ldap"),
    ("SAML",                "saml"),
    # Network services
    ("SD-WAN",              "sdwan"),
    ("SNMP",                "snmp"),
    ("SSH",                 "ssh"),
    ("DHCP",                "dhcp"),
    ("DHCPv6",              "dhcp"),
    ("IPv6",                "ipv6"),
    # Management interface — no dedicated check (handled by workaround_checks
    # for specific workaround advisories); registered so it surfaces in the
    # affected_features list but always returns "unknown" from check_feature_active.
    ("web management",      "web_management"),
    ("GUI",                 "web_management"),
    ("admin",               "web_management"),
    # Additional keywords from fortinet-vuln-agent — no check implemented yet;
    # all return "unknown" and do not affect the verdict.
    ("NTP",                 "ntp"),
    ("DNS",                 "dns"),
    ("HA",                  "ha"),
    ("FGFM",                "fgfm"),
    ("FortiGuard",          "fortiguard"),
    ("captive portal",      "captive_portal"),
    ("2FA",                 "two_fa"),
    ("WAD",                 "wad"),
    ("IPS",                 "ips"),
    ("antivirus",           "antivirus"),
    ("webfilter",           "webfilter"),
    ("application control", "app_control"),
    ("VDOM",                "vdom"),
    ("LLDP",                "lldp"),
    ("ARP",                 "arp"),
]


# Custom regex overrides for keywords that need more precise matching than
# the default `\b{keyword}\b`. The hyphen in "SSL-VPN" is a non-word char,
# so \bVPN\b matches the "VPN" inside "SSL-VPN". The override adds a
# negative lookbehind so standalone "VPN" is detected without triggering
# on the more-specific "SSL-VPN" / "IPsec" entries already above it.
_KEYWORD_RE_OVERRIDE: dict[str, str] = {
    "VPN": r"(?<![A-Za-z-])\bVPN\b",
}


def detect_affected_features(text: str) -> list[str]:
    """
    Scan advisory text for known service/feature keywords.

    Returns a deduplicated list of feature keys in the order first matched.
    Matching is whole-word and case-insensitive — "SSL-VPN" matches "ssl-vpn"
    but not "SSLVPN" (a separate entry handles that variant).
    """
    seen: set[str] = set()
    result: list[str] = []
    t = text or ""
    for keyword, feature_key in _KEYWORD_TO_FEATURE:
        if feature_key in seen:
            continue
        pattern = _KEYWORD_RE_OVERRIDE.get(keyword, rf"\b{re.escape(keyword)}\b")
        if re.search(pattern, t, re.IGNORECASE):
            seen.add(feature_key)
            result.append(feature_key)
    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_vdoms(client: Any, adom: str, device: str) -> list[str]:
    """Return the VDOM names for a device, falling back to ['root']."""
    try:
        vdoms = client.get_device_vdoms(adom, device)
        names = [v.get("name", "") for v in vdoms if isinstance(v, dict) and v.get("name")]
        return names if names else ["root"]
    except Exception:
        return ["root"]


def _aggregate(per_vdom: list[str]) -> str:
    """
    Collapse per-VDOM status strings to a device-level verdict.

    active   — any VDOM confirmed the feature is running
    inactive — every VDOM confirmed the feature is off/not configured
    unknown  — could not confirm any VDOM, or mix of inactive + unknown
    """
    if "active" in per_vdom:
        return "active"
    if per_vdom and all(s == "inactive" for s in per_vdom):
        return "inactive"
    return "unknown"


# ---------------------------------------------------------------------------
# Per-feature check functions
# Signature: (client, adom, device) -> "active" | "inactive" | "unknown"
# Each function iterates all VDOMs and returns "active" if any VDOM has the
# feature running. Exceptions are caught and mapped to "unknown" so that a
# single failing VDOM never silently clears an "active" result.
# ---------------------------------------------------------------------------

def _check_ssl_vpn(client: Any, adom: str, device: str) -> str:
    results = []
    for vdom in _get_vdoms(client, adom, device):
        try:
            cfg = client.get_ssl_vpn_settings(device, vdom)
            status = str(cfg.get("status", "")).lower()
            if status == "enable":
                results.append("active")
            elif status in ("disable", "disabled"):
                results.append("inactive")
            else:
                results.append("unknown")
        except Exception:
            results.append("unknown")
    return _aggregate(results)


def _check_ipsec(client: Any, adom: str, device: str) -> str:
    results = []
    for vdom in _get_vdoms(client, adom, device):
        try:
            tunnels = client.get_ipsec_phase1(device, vdom)
            results.append("active" if tunnels else "inactive")
        except Exception:
            results.append("unknown")
    return _aggregate(results)


def _check_bgp(client: Any, adom: str, device: str) -> str:
    results = []
    for vdom in _get_vdoms(client, adom, device):
        try:
            cfg = client.get_bgp_config(device, vdom)
            as_num = cfg.get("as", 0)
            try:
                active = int(str(as_num)) != 0
            except (TypeError, ValueError):
                active = bool(as_num)
            results.append("active" if active else "inactive")
        except Exception:
            results.append("unknown")
    return _aggregate(results)


def _check_ospf(client: Any, adom: str, device: str) -> str:
    results = []
    for vdom in _get_vdoms(client, adom, device):
        try:
            cfg = client.get_ospf_config(device, vdom)
            areas = cfg.get("area", []) or []
            results.append("active" if isinstance(areas, list) and areas else "inactive")
        except Exception:
            results.append("unknown")
    return _aggregate(results)


def _check_radius(client: Any, adom: str, device: str) -> str:
    results = []
    for vdom in _get_vdoms(client, adom, device):
        try:
            servers = client.get_radius_servers(device, vdom)
            results.append("active" if servers else "inactive")
        except Exception:
            results.append("unknown")
    return _aggregate(results)


def _check_ldap(client: Any, adom: str, device: str) -> str:
    results = []
    for vdom in _get_vdoms(client, adom, device):
        try:
            servers = client.get_ldap_servers(device, vdom)
            results.append("active" if servers else "inactive")
        except Exception:
            results.append("unknown")
    return _aggregate(results)


def _check_saml(client: Any, adom: str, device: str) -> str:
    results = []
    for vdom in _get_vdoms(client, adom, device):
        try:
            servers = client.get_saml_servers(device, vdom)
            results.append("active" if servers else "inactive")
        except Exception:
            results.append("unknown")
    return _aggregate(results)


def _check_ztna(client: Any, adom: str, device: str) -> str:
    results = []
    for vdom in _get_vdoms(client, adom, device):
        try:
            proxies = client.get_ztna_access_proxy(device, vdom)
            results.append("active" if proxies else "inactive")
        except Exception:
            results.append("unknown")
    return _aggregate(results)


def _check_multicast(client: Any, adom: str, device: str) -> str:
    results = []
    for vdom in _get_vdoms(client, adom, device):
        try:
            cfg = client.get_multicast_config(device, vdom)
            pim_global = cfg.get("pim-sm-global", {}) or {}
            if isinstance(pim_global, dict):
                if str(pim_global.get("status", "")).lower() == "enable":
                    results.append("active")
                    continue
            interfaces = cfg.get("interface", []) or []
            results.append("active" if interfaces else "inactive")
        except Exception:
            results.append("unknown")
    return _aggregate(results)


def _check_sdwan(client: Any, adom: str, device: str) -> str:
    # SD-WAN is per-VDOM but typically only configured on root; check root only.
    try:
        raw = client.get_device_sdwan(device, vdom="root")
        if not isinstance(raw, dict):
            return "unknown"
        members_raw = raw.get("members", {})
        if isinstance(members_raw, dict):
            member_list = members_raw.get("member", [])
        elif isinstance(members_raw, list):
            member_list = members_raw
        else:
            member_list = []
        return "active" if member_list else "inactive"
    except Exception:
        return "unknown"


def _check_snmp(client: Any, adom: str, device: str) -> str:
    results = []
    for vdom in _get_vdoms(client, adom, device):
        try:
            cfg = client.get_snmp_sysinfo(device, vdom)
            status = str(cfg.get("status", "")).lower()
            if status == "enable":
                results.append("active")
            elif status in ("disable", "disabled"):
                results.append("inactive")
            else:
                results.append("unknown")
        except Exception:
            results.append("unknown")
    return _aggregate(results)


def _check_ssh(client: Any, adom: str, device: str) -> str:
    """Check whether SSH admin access is enabled on any interface."""
    try:
        result = client.get_device_interface_config(device)
        raw = (
            result if isinstance(result, list)
            else result.get("interfaces", []) if isinstance(result, dict)
            else []
        )
        raw_list = raw if isinstance(raw, list) else [raw]
        found_any = False
        for iface in raw_list:
            if not isinstance(iface, dict):
                continue
            found_any = True
            allowaccess = iface.get("allowaccess", []) or []
            if isinstance(allowaccess, str):
                allowaccess = allowaccess.split()
            if "ssh" in {str(a).lower() for a in allowaccess}:
                return "active"
        return "inactive" if found_any else "unknown"
    except Exception:
        return "unknown"


def _check_dhcp(client: Any, adom: str, device: str) -> str:
    """Check whether a DHCP server is configured on any VDOM."""
    results = []
    for vdom in _get_vdoms(client, adom, device):
        try:
            servers = client.get_dhcp_servers(device, vdom)
            results.append("active" if servers else "inactive")
        except Exception:
            results.append("unknown")
    return _aggregate(results)


def _check_ipv6(client: Any, adom: str, device: str) -> str:
    """
    Check whether IPv6 is configured on any interface.

    Reads the device-DB interface config and looks for any interface with an
    IPv6 block that has a non-empty ip6-address or ip6-status == "enable".
    """
    try:
        result = client.get_device_interface_config(device)
        raw = (
            result if isinstance(result, list)
            else result.get("interfaces", []) if isinstance(result, dict)
            else []
        )
        raw_list = raw if isinstance(raw, list) else [raw]
        found_any = False
        for iface in raw_list:
            if not isinstance(iface, dict):
                continue
            found_any = True
            ipv6 = iface.get("ipv6", {}) or {}
            if not isinstance(ipv6, dict):
                continue
            ip6_status = str(ipv6.get("ip6-mode", "") or ipv6.get("ip6-status", "")).lower()
            ip6_addr = str(ipv6.get("ip6-address", "") or "").strip()
            # ip6-address "::/0" means not configured; any other non-empty value means active
            if ip6_addr and ip6_addr != "::/0":
                return "active"
            if ip6_status in ("static", "dhcp", "pppoe", "delegated"):
                return "active"
        return "inactive" if found_any else "unknown"
    except Exception:
        return "unknown"


def _check_ntp(client: Any, adom: str, device: str) -> str:
    try:
        cfg = client.get_ntp_config(device)
        status = str(cfg.get("ntpsync", "")).lower()
        if status == "enable":
            return "active"
        if status in ("disable", "disabled"):
            return "inactive"
        return "unknown"
    except Exception:
        return "unknown"


def _check_dns(client: Any, adom: str, device: str) -> str:
    try:
        cfg = client.get_dns_config(device)
        primary = str(cfg.get("primary", "") or "").strip()
        if primary and primary != "0.0.0.0":
            return "active"
        secondary = str(cfg.get("secondary", "") or "").strip()
        if secondary and secondary != "0.0.0.0":
            return "active"
        # Both addresses are 0.0.0.0 or absent. This happens when DNS servers
        # are assigned by DHCP/PPPoE — the device IS resolving names but the
        # static config fields are empty. Return "unknown" (conservative) rather
        # than "inactive" to avoid incorrectly downgrading a DNS-advisory verdict.
        return "unknown"
    except Exception:
        return "unknown"


def _check_ha(client: Any, adom: str, device: str) -> str:
    try:
        cfg = client.get_ha_config(device)
        mode = str(cfg.get("mode", "")).lower()
        if mode in ("a-a", "a-p", "active-active", "active-passive"):
            return "active"
        if mode == "standalone":
            return "inactive"
        return "unknown"
    except Exception:
        return "unknown"


def _check_fortiguard(client: Any, adom: str, device: str) -> str:
    try:
        cfg = client.get_fortiguard_config(device)
        status = str(cfg.get("status", "") or "").lower()
        if status == "disable":
            return "inactive"
        loc = str(cfg.get("update-server-location", "") or "").strip()
        if loc:
            return "active"
        return "unknown"
    except Exception:
        return "unknown"


def _check_fgfm(client: Any, adom: str, device: str) -> str:
    try:
        cfg = client.get_central_management(device)
        mgmt_type = str(cfg.get("type", "")).lower()
        if mgmt_type == "fortimanager":
            return "active"
        if mgmt_type == "none":
            return "inactive"
        return "unknown"
    except Exception:
        return "unknown"


def _check_vdom(client: Any, adom: str, device: str) -> str:
    """Active when the device has more than one VDOM configured (multi-VDOM mode)."""
    try:
        vdoms = client.get_device_vdoms(adom, device)
        names = [v.get("name", "") for v in vdoms if isinstance(v, dict) and v.get("name")]
        return "active" if len(names) > 1 else "inactive"
    except Exception:
        return "unknown"


def _check_two_fa(client: Any, adom: str, device: str) -> str:
    results = []
    for vdom in _get_vdoms(client, adom, device):
        try:
            users = client.get_local_users(device, vdom)
            has_2fa = any(
                str(u.get("two-factor", "disable")).lower() not in ("disable", "")
                for u in users if isinstance(u, dict)
            )
            results.append("active" if has_2fa else "inactive")
        except Exception:
            results.append("unknown")
    return _aggregate(results)


def _check_captive_portal(client: Any, adom: str, device: str) -> str:
    results = []
    for vdom in _get_vdoms(client, adom, device):
        try:
            cfg = client.get_user_settings(device, vdom)
            portal_ip = str(cfg.get("captive-portal-ip", "") or "").strip()
            if portal_ip and portal_ip != "0.0.0.0":
                results.append("active")
                continue
            auth_type = cfg.get("auth-type", []) or []
            if isinstance(auth_type, str):
                auth_type = [auth_type]
            if any("captive" in str(a).lower() for a in auth_type):
                results.append("active")
            else:
                results.append("inactive")
        except Exception:
            results.append("unknown")
    return _aggregate(results)


def _check_lldp(client: Any, adom: str, device: str) -> str:
    """Check whether LLDP reception or transmission is enabled on any interface."""
    try:
        result = client.get_device_interface_config(device)
        raw = (
            result if isinstance(result, list)
            else result.get("interfaces", []) if isinstance(result, dict)
            else []
        )
        raw_list = raw if isinstance(raw, list) else [raw]
        found_any = False
        for iface in raw_list:
            if not isinstance(iface, dict):
                continue
            found_any = True
            rx = str(iface.get("lldp-reception", "")).lower()
            tx = str(iface.get("lldp-transmission", "")).lower()
            if "enable" in (rx, tx):
                return "active"
        return "inactive" if found_any else "unknown"
    except Exception:
        return "unknown"


def _check_ips(client: Any, adom: str, device: str) -> str:
    # NOTE: FortiOS ships with non-deletable factory IPS sensors ("default",
    # "protect_client", etc.). This check returns "active" whenever any sensor
    # profile exists in the Device-DB — including those factory profiles — so
    # it cannot distinguish "IPS engine in use" from "factory profiles only,
    # no policy references them". It is intentionally conservative (false-active
    # rather than false-inactive) for an advisory targeting the IPS engine.
    results = []
    for vdom in _get_vdoms(client, adom, device):
        try:
            sensors = client.get_ips_sensors(device, vdom)
            results.append("active" if sensors else "inactive")
        except Exception:
            results.append("unknown")
    return _aggregate(results)


def _check_antivirus(client: Any, adom: str, device: str) -> str:
    # NOTE: Factory AV profiles ("default") are always present. Same caveat
    # as _check_ips — this is conservatively true-positive biased.
    results = []
    for vdom in _get_vdoms(client, adom, device):
        try:
            profiles = client.get_av_profiles(device, vdom)
            results.append("active" if profiles else "inactive")
        except Exception:
            results.append("unknown")
    return _aggregate(results)


def _check_webfilter(client: Any, adom: str, device: str) -> str:
    # NOTE: Factory web filter profiles are always present. Same caveat as
    # _check_ips — conservatively true-positive biased.
    results = []
    for vdom in _get_vdoms(client, adom, device):
        try:
            profiles = client.get_webfilter_profiles(device, vdom)
            results.append("active" if profiles else "inactive")
        except Exception:
            results.append("unknown")
    return _aggregate(results)


def _check_app_control(client: Any, adom: str, device: str) -> str:
    # NOTE: Factory application sensor profiles are always present. Same caveat
    # as _check_ips — conservatively true-positive biased.
    results = []
    for vdom in _get_vdoms(client, adom, device):
        try:
            sensors = client.get_app_sensors(device, vdom)
            results.append("active" if sensors else "inactive")
        except Exception:
            results.append("unknown")
    return _aggregate(results)


# ---------------------------------------------------------------------------
# Feature check registry
# Maps feature_key -> (human-readable description, check_fn or None)
# None means no automated check is implemented — always returns "unknown".
# ---------------------------------------------------------------------------

_FEATURE_REGISTRY: dict[str, tuple[str, Callable[[Any, str, str], str] | None]] = {
    "ssl_vpn":        ("SSL-VPN",                         _check_ssl_vpn),
    "ipsec":          ("IPsec VPN",                       _check_ipsec),
    "ztna":           ("ZTNA",                            _check_ztna),
    "bgp":            ("BGP routing",                     _check_bgp),
    "ospf":           ("OSPF routing",                    _check_ospf),
    "radius":         ("RADIUS authentication",           _check_radius),
    "ldap":           ("LDAP authentication",             _check_ldap),
    "saml":           ("SAML authentication",             _check_saml),
    "multicast":      ("Multicast routing",               _check_multicast),
    "sdwan":          ("SD-WAN",                          _check_sdwan),
    "snmp":           ("SNMP",                            _check_snmp),
    "ssh":            ("SSH admin access",                _check_ssh),
    "dhcp":           ("DHCP server",                     _check_dhcp),
    "ipv6":           ("IPv6",                            _check_ipv6),
    # Handled by workaround_checks for workaround advisories; no feature check.
    "web_management": ("Web/HTTP/HTTPS management",       None),
    # Global system features (no VDOM iteration; check global config directly).
    "ntp":            ("NTP",                             _check_ntp),
    "dns":            ("DNS",                             _check_dns),
    "ha":             ("High Availability",               _check_ha),
    "fgfm":           ("FortiGate-FortiManager protocol", _check_fgfm),
    "fortiguard":     ("FortiGuard services",             _check_fortiguard),
    "vdom":           ("VDOM (multi-VDOM mode)",          _check_vdom),
    # Per-VDOM features with implemented checks.
    "captive_portal": ("Captive portal",                  _check_captive_portal),
    "two_fa":         ("Two-factor authentication",       _check_two_fa),
    "ips":            ("IPS/IDPS",                        _check_ips),
    "antivirus":      ("Antivirus",                       _check_antivirus),
    "webfilter":      ("Web filtering",                   _check_webfilter),
    "app_control":    ("Application control",             _check_app_control),
    "lldp":           ("LLDP",                            _check_lldp),
    # No clean deterministic check — always returns "unknown".
    "wad":            ("Web Application Daemon",          None),
    "arp":            ("ARP",                             None),
}


def check_feature_active(feature_key: str, client: Any, adom: str, device: str) -> str:
    """
    Check whether a named feature is active on a device.

    Returns:
        "active"   — feature is confirmed running/enabled on at least one VDOM
        "inactive" — feature is confirmed off/not configured on all VDOMs
        "unknown"  — no check function registered, check failed, or status
                     could not be determined from the config data
    """
    entry = _FEATURE_REGISTRY.get(feature_key)
    if entry is None or entry[1] is None:
        return "unknown"
    _, check_fn = entry
    try:
        return check_fn(client, adom, device)
    except Exception:
        return "unknown"


def feature_description(feature_key: str) -> str:
    """Return a human-readable label for a feature key."""
    entry = _FEATURE_REGISTRY.get(feature_key)
    return entry[0] if entry else feature_key
