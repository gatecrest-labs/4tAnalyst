"""Tests for psirt.feature_checks: keyword detection + config-based feature checks."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from psirt.feature_checks import (
    check_feature_active,
    detect_affected_features,
    feature_description,
)

# ---------------------------------------------------------------------------
# Helpers — fake FortiManager clients
# ---------------------------------------------------------------------------

class _FakeClient:
    """Configurable stub: each method returns the value you pass at construction."""

    def __init__(
        self,
        vdoms=None,
        ssl_vpn=None,
        ipsec=None,
        bgp=None,
        ospf=None,
        radius=None,
        ldap=None,
        saml=None,
        ztna=None,
        multicast=None,
        sdwan=None,
        snmp=None,
        interfaces=None,
        dhcp=None,
        # Global system features
        ntp=None,
        dns=None,
        ha=None,
        fortiguard=None,
        central_mgmt=None,
        # Per-VDOM user/security-profile features
        local_users=None,
        user_settings=None,
        ips_sensors=None,
        av_profiles=None,
        webfilter_profiles=None,
        app_sensors=None,
    ):
        self._vdoms = vdoms or [{"name": "root"}]
        self._ssl_vpn = ssl_vpn if ssl_vpn is not None else {}
        self._ipsec = ipsec if ipsec is not None else []
        self._bgp = bgp if bgp is not None else {}
        self._ospf = ospf if ospf is not None else {}
        self._radius = radius if radius is not None else []
        self._ldap = ldap if ldap is not None else []
        self._saml = saml if saml is not None else []
        self._ztna = ztna if ztna is not None else []
        self._multicast = multicast if multicast is not None else {}
        self._sdwan = sdwan if sdwan is not None else {}
        self._snmp = snmp if snmp is not None else {}
        self._interfaces = interfaces if interfaces is not None else []
        self._dhcp = dhcp if dhcp is not None else []
        self._ntp = ntp if ntp is not None else {}
        self._dns = dns if dns is not None else {}
        self._ha = ha if ha is not None else {}
        self._fortiguard = fortiguard if fortiguard is not None else {}
        self._central_mgmt = central_mgmt if central_mgmt is not None else {}
        self._local_users = local_users if local_users is not None else []
        self._user_settings = user_settings if user_settings is not None else {}
        self._ips_sensors = ips_sensors if ips_sensors is not None else []
        self._av_profiles = av_profiles if av_profiles is not None else []
        self._webfilter_profiles = webfilter_profiles if webfilter_profiles is not None else []
        self._app_sensors = app_sensors if app_sensors is not None else []

    def get_device_vdoms(self, adom, device):
        return self._vdoms

    def get_ssl_vpn_settings(self, device, vdom="root"):
        return self._ssl_vpn

    def get_ipsec_phase1(self, device, vdom="root"):
        return self._ipsec

    def get_bgp_config(self, device, vdom="root"):
        return self._bgp

    def get_ospf_config(self, device, vdom="root"):
        return self._ospf

    def get_radius_servers(self, device, vdom="root"):
        return self._radius

    def get_ldap_servers(self, device, vdom="root"):
        return self._ldap

    def get_saml_servers(self, device, vdom="root"):
        return self._saml

    def get_ztna_access_proxy(self, device, vdom="root"):
        return self._ztna

    def get_multicast_config(self, device, vdom="root"):
        return self._multicast

    def get_device_sdwan(self, device, vdom="root"):
        return self._sdwan

    def get_snmp_sysinfo(self, device, vdom="root"):
        return self._snmp

    def get_device_interface_config(self, device, vlanids=None, name=None):
        return self._interfaces

    def get_dhcp_servers(self, device, vdom="root"):
        return self._dhcp

    def get_ntp_config(self, device):
        return self._ntp

    def get_dns_config(self, device):
        return self._dns

    def get_ha_config(self, device):
        return self._ha

    def get_fortiguard_config(self, device):
        return self._fortiguard

    def get_central_management(self, device):
        return self._central_mgmt

    def get_local_users(self, device, vdom="root"):
        return self._local_users

    def get_user_settings(self, device, vdom="root"):
        return self._user_settings

    def get_ips_sensors(self, device, vdom="root"):
        return self._ips_sensors

    def get_av_profiles(self, device, vdom="root"):
        return self._av_profiles

    def get_webfilter_profiles(self, device, vdom="root"):
        return self._webfilter_profiles

    def get_app_sensors(self, device, vdom="root"):
        return self._app_sensors


class _RaisingClient(_FakeClient):
    """Client that raises on every call — simulates a down device."""
    def get_ssl_vpn_settings(self, *a, **kw): raise RuntimeError("unreachable")
    def get_ipsec_phase1(self, *a, **kw): raise RuntimeError("unreachable")
    def get_bgp_config(self, *a, **kw): raise RuntimeError("unreachable")
    def get_ospf_config(self, *a, **kw): raise RuntimeError("unreachable")
    def get_radius_servers(self, *a, **kw): raise RuntimeError("unreachable")
    def get_ldap_servers(self, *a, **kw): raise RuntimeError("unreachable")
    def get_saml_servers(self, *a, **kw): raise RuntimeError("unreachable")
    def get_ztna_access_proxy(self, *a, **kw): raise RuntimeError("unreachable")
    def get_multicast_config(self, *a, **kw): raise RuntimeError("unreachable")
    def get_device_sdwan(self, *a, **kw): raise RuntimeError("unreachable")
    def get_snmp_sysinfo(self, *a, **kw): raise RuntimeError("unreachable")
    def get_device_interface_config(self, *a, **kw): raise RuntimeError("unreachable")
    def get_dhcp_servers(self, *a, **kw): raise RuntimeError("unreachable")
    def get_ntp_config(self, *a, **kw): raise RuntimeError("unreachable")
    def get_dns_config(self, *a, **kw): raise RuntimeError("unreachable")
    def get_ha_config(self, *a, **kw): raise RuntimeError("unreachable")
    def get_fortiguard_config(self, *a, **kw): raise RuntimeError("unreachable")
    def get_central_management(self, *a, **kw): raise RuntimeError("unreachable")
    def get_local_users(self, *a, **kw): raise RuntimeError("unreachable")
    def get_user_settings(self, *a, **kw): raise RuntimeError("unreachable")
    def get_ips_sensors(self, *a, **kw): raise RuntimeError("unreachable")
    def get_av_profiles(self, *a, **kw): raise RuntimeError("unreachable")
    def get_webfilter_profiles(self, *a, **kw): raise RuntimeError("unreachable")
    def get_app_sensors(self, *a, **kw): raise RuntimeError("unreachable")


# ---------------------------------------------------------------------------
# detect_affected_features
# ---------------------------------------------------------------------------

def test_detects_ssl_vpn_keyword():
    features = detect_affected_features("An improper authentication vulnerability in SSL-VPN")
    assert "ssl_vpn" in features


def test_detects_ssl_vpn_case_insensitive():
    features = detect_affected_features("vulnerability in ssl-vpn web management interface")
    assert "ssl_vpn" in features


def test_generic_vpn_maps_to_both_ssl_vpn_and_ipsec():
    features = detect_affected_features("A buffer overflow in the VPN daemon")
    assert "ssl_vpn" in features
    assert "ipsec" in features


def test_ipsec_keyword_maps_to_ipsec_only():
    features = detect_affected_features("IPsec IKE negotiation flaw")
    assert "ipsec" in features
    # "ike" also maps to ipsec — no double entry
    assert features.count("ipsec") == 1


def test_detects_bgp():
    features = detect_affected_features("Out-of-bounds read in the BGP routing daemon")
    assert "bgp" in features


def test_detects_radius():
    features = detect_affected_features("Authentication bypass via RADIUS protocol")
    assert "radius" in features


def test_detects_dhcp():
    features = detect_affected_features("Heap overflow in DHCP server processing")
    assert "dhcp" in features


def test_detects_ipv6():
    features = detect_affected_features("Use-after-free in IPv6 packet processing")
    assert "ipv6" in features


def test_detects_multiple_features():
    text = "Vulnerability affects BGP routing and OSPF neighbors"
    features = detect_affected_features(text)
    assert "bgp" in features
    assert "ospf" in features


def test_unknown_keyword_returns_empty():
    features = detect_affected_features("Memory corruption in proprietary protocol XYZ")
    assert features == []


def test_no_duplicates_in_result():
    # Both "SSL-VPN" and "VPN" match ssl_vpn — should only appear once
    features = detect_affected_features("SSL-VPN VPN daemon overflow")
    assert features.count("ssl_vpn") == 1


# ---------------------------------------------------------------------------
# SSL-VPN check
# ---------------------------------------------------------------------------

def test_ssl_vpn_active_when_enabled():
    client = _FakeClient(ssl_vpn={"status": "enable"})
    assert check_feature_active("ssl_vpn", client, "ADOM", "FW01") == "active"


def test_ssl_vpn_inactive_when_disabled():
    client = _FakeClient(ssl_vpn={"status": "disable"})
    assert check_feature_active("ssl_vpn", client, "ADOM", "FW01") == "inactive"


def test_ssl_vpn_unknown_when_status_absent():
    client = _FakeClient(ssl_vpn={})
    assert check_feature_active("ssl_vpn", client, "ADOM", "FW01") == "unknown"


def test_ssl_vpn_unknown_when_client_raises():
    assert check_feature_active("ssl_vpn", _RaisingClient(), "ADOM", "FW01") == "unknown"


# ---------------------------------------------------------------------------
# IPsec check
# ---------------------------------------------------------------------------

def test_ipsec_active_when_phase1_entries_exist():
    client = _FakeClient(ipsec=[{"name": "VPN-to-Branch"}])
    assert check_feature_active("ipsec", client, "ADOM", "FW01") == "active"


def test_ipsec_inactive_when_no_phase1_entries():
    client = _FakeClient(ipsec=[])
    assert check_feature_active("ipsec", client, "ADOM", "FW01") == "inactive"


# ---------------------------------------------------------------------------
# BGP check
# ---------------------------------------------------------------------------

def test_bgp_active_when_as_nonzero():
    client = _FakeClient(bgp={"as": 65001})
    assert check_feature_active("bgp", client, "ADOM", "FW01") == "active"


def test_bgp_inactive_when_as_zero():
    client = _FakeClient(bgp={"as": 0})
    assert check_feature_active("bgp", client, "ADOM", "FW01") == "inactive"


def test_bgp_inactive_when_as_absent():
    client = _FakeClient(bgp={})
    assert check_feature_active("bgp", client, "ADOM", "FW01") == "inactive"


# ---------------------------------------------------------------------------
# OSPF check
# ---------------------------------------------------------------------------

def test_ospf_active_when_areas_configured():
    client = _FakeClient(ospf={"area": [{"id": "0.0.0.0"}]})
    assert check_feature_active("ospf", client, "ADOM", "FW01") == "active"


def test_ospf_inactive_when_no_areas():
    client = _FakeClient(ospf={"area": []})
    assert check_feature_active("ospf", client, "ADOM", "FW01") == "inactive"


# ---------------------------------------------------------------------------
# RADIUS / LDAP / SAML check
# ---------------------------------------------------------------------------

def test_radius_active_when_servers_configured():
    client = _FakeClient(radius=[{"name": "FAC-Primary"}])
    assert check_feature_active("radius", client, "ADOM", "FW01") == "active"


def test_radius_inactive_when_no_servers():
    client = _FakeClient(radius=[])
    assert check_feature_active("radius", client, "ADOM", "FW01") == "inactive"


def test_ldap_active_when_servers_configured():
    client = _FakeClient(ldap=[{"name": "corp-ldap"}])
    assert check_feature_active("ldap", client, "ADOM", "FW01") == "active"


def test_saml_inactive_when_no_servers():
    client = _FakeClient(saml=[])
    assert check_feature_active("saml", client, "ADOM", "FW01") == "inactive"


# ---------------------------------------------------------------------------
# ZTNA check
# ---------------------------------------------------------------------------

def test_ztna_active_when_proxies_configured():
    client = _FakeClient(ztna=[{"name": "ztna-proxy"}])
    assert check_feature_active("ztna", client, "ADOM", "FW01") == "active"


def test_ztna_inactive_when_no_proxies():
    client = _FakeClient(ztna=[])
    assert check_feature_active("ztna", client, "ADOM", "FW01") == "inactive"


# ---------------------------------------------------------------------------
# Multicast check
# ---------------------------------------------------------------------------

def test_multicast_active_when_pim_enabled():
    client = _FakeClient(multicast={"pim-sm-global": {"status": "enable"}})
    assert check_feature_active("multicast", client, "ADOM", "FW01") == "active"


def test_multicast_active_when_interface_configured():
    client = _FakeClient(multicast={"interface": [{"name": "port1"}]})
    assert check_feature_active("multicast", client, "ADOM", "FW01") == "active"


def test_multicast_inactive_when_empty_config():
    client = _FakeClient(multicast={})
    assert check_feature_active("multicast", client, "ADOM", "FW01") == "inactive"


# ---------------------------------------------------------------------------
# SD-WAN check
# ---------------------------------------------------------------------------

def test_sdwan_active_when_members_present():
    client = _FakeClient(sdwan={"members": {"member": [{"interface": "wan1"}]}})
    assert check_feature_active("sdwan", client, "ADOM", "FW01") == "active"


def test_sdwan_inactive_when_no_members():
    client = _FakeClient(sdwan={"members": {"member": []}})
    assert check_feature_active("sdwan", client, "ADOM", "FW01") == "inactive"


# ---------------------------------------------------------------------------
# SNMP check
# ---------------------------------------------------------------------------

def test_snmp_active_when_enabled():
    client = _FakeClient(snmp={"status": "enable"})
    assert check_feature_active("snmp", client, "ADOM", "FW01") == "active"


def test_snmp_inactive_when_disabled():
    client = _FakeClient(snmp={"status": "disable"})
    assert check_feature_active("snmp", client, "ADOM", "FW01") == "inactive"


# ---------------------------------------------------------------------------
# SSH check
# ---------------------------------------------------------------------------

def test_ssh_active_when_interface_allows_ssh():
    client = _FakeClient(interfaces=[
        {"name": "port1", "allowaccess": ["ping", "ssh"]},
    ])
    assert check_feature_active("ssh", client, "ADOM", "FW01") == "active"


def test_ssh_inactive_when_no_interface_allows_ssh():
    client = _FakeClient(interfaces=[
        {"name": "port1", "allowaccess": ["ping", "https"]},
    ])
    assert check_feature_active("ssh", client, "ADOM", "FW01") == "inactive"


def test_ssh_unknown_when_no_interfaces():
    client = _FakeClient(interfaces=[])
    assert check_feature_active("ssh", client, "ADOM", "FW01") == "unknown"


# ---------------------------------------------------------------------------
# DHCP check
# ---------------------------------------------------------------------------

def test_dhcp_active_when_servers_configured():
    client = _FakeClient(dhcp=[{"id": 1, "interface": "port2"}])
    assert check_feature_active("dhcp", client, "ADOM", "FW01") == "active"


def test_dhcp_inactive_when_no_servers():
    client = _FakeClient(dhcp=[])
    assert check_feature_active("dhcp", client, "ADOM", "FW01") == "inactive"


# ---------------------------------------------------------------------------
# IPv6 check
# ---------------------------------------------------------------------------

def test_ipv6_active_when_interface_has_address():
    client = _FakeClient(interfaces=[
        {"name": "port1", "ipv6": {"ip6-address": "2001:db8::1/64"}},
    ])
    assert check_feature_active("ipv6", client, "ADOM", "FW01") == "active"


def test_ipv6_inactive_when_all_interfaces_have_default_address():
    client = _FakeClient(interfaces=[
        {"name": "port1", "ipv6": {"ip6-address": "::/0"}},
    ])
    assert check_feature_active("ipv6", client, "ADOM", "FW01") == "inactive"


def test_ipv6_inactive_when_no_ipv6_block():
    client = _FakeClient(interfaces=[{"name": "port1"}])
    assert check_feature_active("ipv6", client, "ADOM", "FW01") == "inactive"


# ---------------------------------------------------------------------------
# Multi-VDOM scenarios
# ---------------------------------------------------------------------------

def test_active_on_any_vdom_returns_active():
    # root: disabled, vdom2: enabled → device is active
    class _MultiVdomClient(_FakeClient):
        def get_ssl_vpn_settings(self, device, vdom="root"):
            if vdom == "vdom2":
                return {"status": "enable"}
            return {"status": "disable"}

    client = _MultiVdomClient(vdoms=[{"name": "root"}, {"name": "vdom2"}])
    assert check_feature_active("ssl_vpn", client, "ADOM", "FW01") == "active"


def test_all_vdoms_inactive_returns_inactive():
    class _MultiVdomClient(_FakeClient):
        def get_ssl_vpn_settings(self, device, vdom="root"):
            return {"status": "disable"}

    client = _MultiVdomClient(vdoms=[{"name": "root"}, {"name": "vdom2"}])
    assert check_feature_active("ssl_vpn", client, "ADOM", "FW01") == "inactive"


def test_mix_of_inactive_and_unknown_returns_unknown():
    # One VDOM returns disable, one raises — conservative: unknown
    class _MixedClient(_FakeClient):
        def get_ssl_vpn_settings(self, device, vdom="root"):
            if vdom == "vdom2":
                raise RuntimeError("query failed")
            return {"status": "disable"}

    client = _MixedClient(vdoms=[{"name": "root"}, {"name": "vdom2"}])
    assert check_feature_active("ssl_vpn", client, "ADOM", "FW01") == "unknown"


# ---------------------------------------------------------------------------
# Features with no check registered (always unknown)
# ---------------------------------------------------------------------------

def test_unregistered_feature_key_returns_unknown():
    assert check_feature_active("totally_made_up", _FakeClient(), "ADOM", "FW01") == "unknown"


def test_ips_inactive_when_no_sensors_configured():
    assert check_feature_active("ips", _FakeClient(), "ADOM", "FW01") == "inactive"


def test_web_management_returns_unknown_deferred_to_workaround_checks():
    assert check_feature_active("web_management", _FakeClient(), "ADOM", "FW01") == "unknown"


# ---------------------------------------------------------------------------
# feature_description
# ---------------------------------------------------------------------------

def test_feature_description_known_key():
    assert feature_description("ssl_vpn") == "SSL-VPN"
    assert feature_description("bgp") == "BGP routing"
    assert feature_description("dhcp") == "DHCP server"
    assert feature_description("ipv6") == "IPv6"


def test_feature_description_unknown_key_returns_key():
    assert feature_description("some_unknown_thing") == "some_unknown_thing"


# ---------------------------------------------------------------------------
# NTP check
# ---------------------------------------------------------------------------

def test_ntp_active_when_ntpsync_enabled():
    client = _FakeClient(ntp={"ntpsync": "enable"})
    assert check_feature_active("ntp", client, "ADOM", "FW01") == "active"


def test_ntp_inactive_when_ntpsync_disabled():
    client = _FakeClient(ntp={"ntpsync": "disable"})
    assert check_feature_active("ntp", client, "ADOM", "FW01") == "inactive"


def test_ntp_unknown_when_config_empty():
    client = _FakeClient(ntp={})
    assert check_feature_active("ntp", client, "ADOM", "FW01") == "unknown"


def test_ntp_unknown_when_client_raises():
    assert check_feature_active("ntp", _RaisingClient(), "ADOM", "FW01") == "unknown"


# ---------------------------------------------------------------------------
# DNS check
# ---------------------------------------------------------------------------

def test_dns_active_when_primary_set():
    client = _FakeClient(dns={"primary": "8.8.8.8"})
    assert check_feature_active("dns", client, "ADOM", "FW01") == "active"


def test_dns_active_when_secondary_set():
    client = _FakeClient(dns={"primary": "0.0.0.0", "secondary": "1.1.1.1"})
    assert check_feature_active("dns", client, "ADOM", "FW01") == "active"


def test_dns_unknown_when_both_zero():
    # Both addresses 0.0.0.0 may mean DHCP-assigned DNS — cannot confirm inactive.
    client = _FakeClient(dns={"primary": "0.0.0.0", "secondary": "0.0.0.0"})
    assert check_feature_active("dns", client, "ADOM", "FW01") == "unknown"


def test_dns_unknown_when_config_empty():
    # Empty config means addresses may come from DHCP — cannot confirm inactive.
    client = _FakeClient(dns={})
    assert check_feature_active("dns", client, "ADOM", "FW01") == "unknown"


# ---------------------------------------------------------------------------
# HA check
# ---------------------------------------------------------------------------

def test_ha_active_when_active_passive():
    client = _FakeClient(ha={"mode": "a-p"})
    assert check_feature_active("ha", client, "ADOM", "FW01") == "active"


def test_ha_active_when_active_active():
    client = _FakeClient(ha={"mode": "a-a"})
    assert check_feature_active("ha", client, "ADOM", "FW01") == "active"


def test_ha_inactive_when_standalone():
    client = _FakeClient(ha={"mode": "standalone"})
    assert check_feature_active("ha", client, "ADOM", "FW01") == "inactive"


def test_ha_unknown_when_mode_absent():
    client = _FakeClient(ha={})
    assert check_feature_active("ha", client, "ADOM", "FW01") == "unknown"


# ---------------------------------------------------------------------------
# FortiGuard check
# ---------------------------------------------------------------------------

def test_fortiguard_active_when_server_location_set():
    client = _FakeClient(fortiguard={"update-server-location": "any"})
    assert check_feature_active("fortiguard", client, "ADOM", "FW01") == "active"


def test_fortiguard_unknown_when_location_absent():
    client = _FakeClient(fortiguard={})
    assert check_feature_active("fortiguard", client, "ADOM", "FW01") == "unknown"


# ---------------------------------------------------------------------------
# FGFM (central-management) check
# ---------------------------------------------------------------------------

def test_fgfm_active_when_type_fortimanager():
    client = _FakeClient(central_mgmt={"type": "fortimanager"})
    assert check_feature_active("fgfm", client, "ADOM", "FW01") == "active"


def test_fgfm_inactive_when_type_none():
    client = _FakeClient(central_mgmt={"type": "none"})
    assert check_feature_active("fgfm", client, "ADOM", "FW01") == "inactive"


def test_fgfm_unknown_when_config_empty():
    client = _FakeClient(central_mgmt={})
    assert check_feature_active("fgfm", client, "ADOM", "FW01") == "unknown"


# ---------------------------------------------------------------------------
# VDOM (multi-VDOM mode) check
# ---------------------------------------------------------------------------

def test_vdom_active_when_multiple_vdoms():
    client = _FakeClient(vdoms=[{"name": "root"}, {"name": "vdom2"}])
    assert check_feature_active("vdom", client, "ADOM", "FW01") == "active"


def test_vdom_inactive_when_only_root():
    client = _FakeClient(vdoms=[{"name": "root"}])
    assert check_feature_active("vdom", client, "ADOM", "FW01") == "inactive"


# ---------------------------------------------------------------------------
# Two-factor authentication check
# ---------------------------------------------------------------------------

def test_two_fa_active_when_user_has_fortitoken():
    client = _FakeClient(local_users=[
        {"name": "alice", "two-factor": "fortitoken"},
    ])
    assert check_feature_active("two_fa", client, "ADOM", "FW01") == "active"


def test_two_fa_inactive_when_all_users_disabled():
    client = _FakeClient(local_users=[
        {"name": "alice", "two-factor": "disable"},
        {"name": "bob", "two-factor": "disable"},
    ])
    assert check_feature_active("two_fa", client, "ADOM", "FW01") == "inactive"


def test_two_fa_inactive_when_no_users():
    client = _FakeClient(local_users=[])
    assert check_feature_active("two_fa", client, "ADOM", "FW01") == "inactive"


def test_two_fa_unknown_when_client_raises():
    assert check_feature_active("two_fa", _RaisingClient(), "ADOM", "FW01") == "unknown"


# ---------------------------------------------------------------------------
# Captive portal check
# ---------------------------------------------------------------------------

def test_captive_portal_active_when_portal_ip_set():
    client = _FakeClient(user_settings={"captive-portal-ip": "192.168.1.1"})
    assert check_feature_active("captive_portal", client, "ADOM", "FW01") == "active"


def test_captive_portal_active_when_auth_type_includes_captive():
    client = _FakeClient(user_settings={"auth-type": ["captive-portal"]})
    assert check_feature_active("captive_portal", client, "ADOM", "FW01") == "active"


def test_captive_portal_inactive_when_no_portal_configured():
    client = _FakeClient(user_settings={"captive-portal-ip": "0.0.0.0", "auth-type": []})
    assert check_feature_active("captive_portal", client, "ADOM", "FW01") == "inactive"


# ---------------------------------------------------------------------------
# LLDP check
# ---------------------------------------------------------------------------

def test_lldp_active_when_reception_enabled():
    client = _FakeClient(interfaces=[
        {"name": "port1", "lldp-reception": "enable", "lldp-transmission": "disable"},
    ])
    assert check_feature_active("lldp", client, "ADOM", "FW01") == "active"


def test_lldp_active_when_transmission_enabled():
    client = _FakeClient(interfaces=[
        {"name": "port1", "lldp-reception": "disable", "lldp-transmission": "enable"},
    ])
    assert check_feature_active("lldp", client, "ADOM", "FW01") == "active"


def test_lldp_inactive_when_both_disabled():
    client = _FakeClient(interfaces=[
        {"name": "port1", "lldp-reception": "disable", "lldp-transmission": "disable"},
    ])
    assert check_feature_active("lldp", client, "ADOM", "FW01") == "inactive"


def test_lldp_inactive_when_no_lldp_fields():
    client = _FakeClient(interfaces=[{"name": "port1"}])
    assert check_feature_active("lldp", client, "ADOM", "FW01") == "inactive"


def test_lldp_unknown_when_no_interfaces():
    client = _FakeClient(interfaces=[])
    assert check_feature_active("lldp", client, "ADOM", "FW01") == "unknown"


# ---------------------------------------------------------------------------
# IPS check
# ---------------------------------------------------------------------------

def test_ips_active_when_sensors_configured():
    client = _FakeClient(ips_sensors=[{"name": "default"}, {"name": "strict"}])
    assert check_feature_active("ips", client, "ADOM", "FW01") == "active"


def test_ips_inactive_when_no_sensors():
    client = _FakeClient(ips_sensors=[])
    assert check_feature_active("ips", client, "ADOM", "FW01") == "inactive"


# ---------------------------------------------------------------------------
# Antivirus check
# ---------------------------------------------------------------------------

def test_antivirus_active_when_profiles_configured():
    client = _FakeClient(av_profiles=[{"name": "default"}])
    assert check_feature_active("antivirus", client, "ADOM", "FW01") == "active"


def test_antivirus_inactive_when_no_profiles():
    client = _FakeClient(av_profiles=[])
    assert check_feature_active("antivirus", client, "ADOM", "FW01") == "inactive"


# ---------------------------------------------------------------------------
# Web filter check
# ---------------------------------------------------------------------------

def test_webfilter_active_when_profiles_configured():
    client = _FakeClient(webfilter_profiles=[{"name": "default"}])
    assert check_feature_active("webfilter", client, "ADOM", "FW01") == "active"


def test_webfilter_inactive_when_no_profiles():
    client = _FakeClient(webfilter_profiles=[])
    assert check_feature_active("webfilter", client, "ADOM", "FW01") == "inactive"


# ---------------------------------------------------------------------------
# Application control check
# ---------------------------------------------------------------------------

def test_app_control_active_when_sensors_configured():
    client = _FakeClient(app_sensors=[{"name": "default"}])
    assert check_feature_active("app_control", client, "ADOM", "FW01") == "active"


def test_app_control_inactive_when_no_sensors():
    client = _FakeClient(app_sensors=[])
    assert check_feature_active("app_control", client, "ADOM", "FW01") == "inactive"


# ---------------------------------------------------------------------------
# feature_description for new features
# ---------------------------------------------------------------------------

def test_feature_description_new_features():
    assert feature_description("ntp") == "NTP"
    assert feature_description("ha") == "High Availability"
    assert feature_description("fgfm") == "FortiGate-FortiManager protocol"
    assert feature_description("two_fa") == "Two-factor authentication"
    assert feature_description("lldp") == "LLDP"
    assert feature_description("ips") == "IPS/IDPS"
    assert feature_description("antivirus") == "Antivirus"
    assert feature_description("webfilter") == "Web filtering"
    assert feature_description("app_control") == "Application control"
