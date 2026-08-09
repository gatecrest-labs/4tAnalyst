from fortimanager_mcp.client import FortiManagerClient


def test_get_adoms_monkeypatch():
    c = FortiManagerClient(primary_host='h', primary_key='k')

    # Monkeypatch _rpc to return a batch
    def fake_rpc(method, path, params):
        return [{'name': 'root_adom'}]

    c._rpc = fake_rpc
    adoms = c.get_adoms()
    assert isinstance(adoms, list)
    assert adoms[0].get('name') == 'root_adom'


def test_get_device_meta_monkeypatch():
    c = FortiManagerClient(primary_host='h', primary_key='k')

    def fake_rpc(method, path, params):
        return {'version': '7.6'}

    c._rpc = fake_rpc
    meta = c.get_device_meta('adom', 'device1')
    assert meta.get('version') == '7.6'


def test_get_system_status_monkeypatch():
    c = FortiManagerClient(primary_host='h', primary_key='k')

    def fake_rpc(method, path, params):
        assert path == '/sys/status'
        return {'Version': '7.4.5', 'Host Name': 'FMG-SITE-A'}

    c._rpc = fake_rpc
    status = c.get_system_status()
    assert status['Version'] == '7.4.5'


def test_get_ha_status_monkeypatch():
    c = FortiManagerClient(primary_host='h', primary_key='k')

    def fake_rpc(method, path, params):
        assert path == '/sys/ha/status'
        return {'HA mode': 'standalone'}

    c._rpc = fake_rpc
    status = c.get_ha_status()
    assert status['HA mode'] == 'standalone'


def test_get_device_vdoms_monkeypatch():
    c = FortiManagerClient(primary_host='h', primary_key='k')

    def fake_rpc(method, path, params):
        return [{'name': 'root'}, {'name': 'vdom2'}]

    c._rpc = fake_rpc
    vdoms = c.get_device_vdoms('adom', 'device1')
    assert [v['name'] for v in vdoms] == ['root', 'vdom2']


# ---------------------------------------------------------------------------
# query.search_policies — structured return, set-semantics matching
# ---------------------------------------------------------------------------

from fortimanager_mcp import query
from fortimanager_mcp.client import FortiManagerAPIError


class FakeFMG:
    """Duck-typed stand-in for FortiManagerClient."""

    def __init__(self, packages, policies_by_pkg, addrs=None, fail_pkgs=()):
        self._packages = packages
        self._policies = policies_by_pkg
        self._addrs = addrs or [
            {"name": "NET_10_1", "type": "ipmask", "subnet": "10.1.0.0/16"},
            {"name": "H_10_9_8_7", "type": "ipmask", "subnet": "10.9.8.7/32"},
        ]
        self._fail = set(fail_pkgs)

    def get_policy_packages(self, adom):
        return self._packages

    def get_policies(self, adom, pkg):
        if pkg in self._fail:
            raise FortiManagerAPIError("boom", code=-6)
        return self._policies.get(pkg, [])

    def get_address_objects(self, adom):
        return self._addrs

    def get_address_groups(self, adom):
        return []

    def get_global_address_objects(self):
        return []

    def get_global_address_groups(self):
        return []

    def get_service_objects(self, adom):
        return [
            {"name": "HTTPS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"},
            {"name": "TCP_8080", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "8080"},
        ]

    def get_service_groups(self, adom):
        return []


def _pkg(name, device="FW1"):
    return {"name": name, "scope member": [{"name": device}]}


def _policy(pid, srcaddr, dstaddr, service, action=1, **over):
    pol = {
        "policyid": pid, "name": f"pol{pid}", "status": "enable",
        "action": action, "schedule": ["always"],
        "srcaddr": srcaddr, "dstaddr": dstaddr, "service": service,
        "srcintf": ["port1"], "dstintf": ["port2"],
        "logtraffic": 2,
    }
    pol.update(over)
    return pol


def test_search_policies_structured_return():
    fake = FakeFMG(
        [_pkg("pkgA")],
        {"pkgA": [_policy(1, ["NET_10_1"], ["H_10_9_8_7"], ["HTTPS"])]},
    )
    out = query.search_policies(fake, "adom1", "FW1", "10.1.2.3", "10.9.8.7", "443")
    assert out["packages_searched"] == ["pkgA"]
    assert out["packages_failed"] == []
    assert out["degraded"] is False
    assert len(out["policies"]) == 1
    p = out["policies"][0]
    assert p["policy_id"] == 1
    assert p["full_cover"] is True
    assert p["disabled"] is False
    assert p["schedule"] == ["always"]


def test_search_policies_package_failure_sets_degraded():
    fake = FakeFMG(
        [_pkg("okpkg"), _pkg("badpkg")],
        {"okpkg": []},
        fail_pkgs={"badpkg"},
    )
    out = query.search_policies(fake, "adom1", "FW1", "10.1.2.3", "", "")
    assert out["degraded"] is True
    assert out["packages_failed"][0]["package"] == "badpkg"
    assert "okpkg" in out["packages_searched"]


def test_search_policies_no_substring_false_positive():
    fake = FakeFMG(
        [_pkg("pkgA")],
        {"pkgA": [_policy(2, ["all"], ["all"], ["TCP_8080"])]},
    )
    out = query.search_policies(fake, "adom1", "FW1", "", "", "80")
    assert out["policies"] == []


def test_search_policies_partial_not_full_cover():
    fake = FakeFMG(
        [_pkg("pkgA")],
        {"pkgA": [_policy(3, ["NET_10_1"], ["H_10_9_8_7"], ["HTTPS"])]},
    )
    # requested source wider than the policy's subnet
    out = query.search_policies(fake, "adom1", "FW1", "10.0.0.0/8", "10.9.8.7", "443")
    assert len(out["policies"]) == 1
    assert out["policies"][0]["full_cover"] is False


def test_search_policies_bad_service_reports_error():
    fake = FakeFMG([_pkg("pkgA")], {"pkgA": []})
    out = query.search_policies(fake, "adom1", "FW1", "", "", "gibberish-svc")
    assert out["degraded"] is True
    assert "error" in out


# ---------------------------------------------------------------------------
# query.get_system_status / get_ha_status / list_device_vdoms / search_devices
# ---------------------------------------------------------------------------

class FakeStatusFMG:
    def __init__(self, status=None, ha=None, vdoms=None, devices=None):
        self._status = status or {}
        self._ha = ha or {}
        self._vdoms = vdoms or []
        self._devices = devices or []

    def get_system_status(self):
        return self._status

    def get_ha_status(self):
        return self._ha

    def get_device_vdoms(self, adom, device):
        return self._vdoms

    def get_devices(self, adom):
        return self._devices


def test_get_system_status_normalises_known_fields_and_keeps_raw():
    fake = FakeStatusFMG(status={"Version": "7.4.5", "Host Name": "FMG-SITE-A",
                                  "Serial Number": "FMG-VM123", "Platform Type": "FMG-VM"})
    out = query.get_system_status(fake)
    assert out["version"] == "7.4.5"
    assert out["hostname"] == "FMG-SITE-A"
    assert out["serial_number"] == "FMG-VM123"
    assert out["platform"] == "FMG-VM"
    assert out["raw"]["Version"] == "7.4.5"


def test_get_ha_status_passes_through_raw():
    fake = FakeStatusFMG(ha={"HA mode": "standalone"})
    assert query.get_ha_status(fake) == {"HA mode": "standalone"}


def test_list_device_vdoms():
    fake = FakeStatusFMG(vdoms=[
        {"name": "root", "vdom_type": "traffic", "opmode": "nat", "status": "1"},
    ])
    out = query.list_device_vdoms(fake, "adom1", "FW1")
    assert out == [{"name": "root", "vdom_type": "traffic", "opmode": "nat", "status": "1"}]


def test_search_devices_filters_combine_with_and():
    fake = FakeStatusFMG(devices=[
        {"name": "MNHQ-FW01", "ip": "10.1.1.1", "platform_str": "FortiGate-VM64",
         "os_ver": "7.4", "conn_status": 1, "db_status": "modified"},
        {"name": "MNHQ-FW02", "ip": "10.1.1.2", "platform_str": "FortiGate-100F",
         "os_ver": "7.2", "conn_status": 2, "db_status": "insync"},
    ])
    out = query.search_devices(fake, "adom1", name_filter="MNHQ", platform_filter="VM",
                                connection_status="up")
    assert out["count"] == 1
    assert out["devices"][0]["name"] == "MNHQ-FW01"
    assert out["devices"][0]["conn_status"] == "up"


def test_search_devices_bad_connection_status_reports_error():
    fake = FakeStatusFMG(devices=[])
    out = query.search_devices(fake, "adom1", connection_status="sideways")
    assert "error" in out
