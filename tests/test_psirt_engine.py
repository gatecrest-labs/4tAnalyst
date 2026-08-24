"""
End-to-end tests for psirt.engine.assess() with a fully faked FortiManager
client and HTTP client — no live systems.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from psirt.engine import assess
from psirt.models import Advisory, AffectedRange


class FakeFMGClient:
    def __init__(self, adoms=("OT-ADOM",), devices_by_adom=None, fail_adoms=()):
        self._adoms = adoms
        self._devices_by_adom = devices_by_adom or {}
        self._fail_adoms = set(fail_adoms)

    def get_adoms(self):
        return [{"name": a} for a in self._adoms]

    def get_devices(self, adom):
        if adom in self._fail_adoms:
            raise RuntimeError("FMG timeout")
        return self._devices_by_adom.get(adom, [])

    def get_system_status(self):
        return {"Version": "7.4.5", "Host Name": "FMG-SITE-A"}

    def get_device_interface_config(self, device, vlanids=None, name=None):
        return [{"name": "port1", "allowaccess": ["ping"]}]


class _FakeHTTPClient:
    def get(self, url, timeout=None):
        class _Resp:
            status_code = 404
        return _Resp()


def _advisory():
    return Advisory(
        advisory_id="FG-IR-24-001",
        cve_ids=["CVE-2024-12345"],
        cvss_score=9.8,
        fortinet_severity="Critical",
        affected_ranges=[
            AffectedRange(product="FortiOS", min_version="7.4.0",
                          max_version="7.4.4", fixed_version="7.4.5"),
        ],
        workaround_text="",
    )


def test_assess_flags_in_range_device_as_upgrade_required_with_no_workaround():
    client = FakeFMGClient(devices_by_adom={
        "OT-ADOM": [{"name": "FW01", "os_ver": "7", "mr": 4, "patch": 2}],
    })
    result = assess(_advisory(), client, _FakeHTTPClient(), kev_url="")
    assert result.priority == "critical"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.device == "FW01"
    assert finding.in_range is True
    assert finding.verdict == "upgrade_required"


def test_assess_out_of_range_device_is_no_action():
    client = FakeFMGClient(devices_by_adom={
        "OT-ADOM": [{"name": "FW02", "os_ver": "7", "mr": 6, "patch": 0}],
    })
    result = assess(_advisory(), client, _FakeHTTPClient(), kev_url="")
    finding = result.findings[0]
    assert finding.in_range is False
    assert finding.verdict == "no_action"


def test_assess_zero_fleet_exposure_is_informational_priority():
    client = FakeFMGClient(devices_by_adom={
        "OT-ADOM": [{"name": "FW02", "os_ver": "7", "mr": 6, "patch": 0}],
    })
    result = assess(_advisory(), client, _FakeHTTPClient(), kev_url="")
    assert result.priority == "informational"


def test_assess_with_recognized_workaround_and_not_in_place_gives_config_change():
    adv = _advisory()
    adv.workaround_text = "Disable HTTPS admin access on all interfaces"
    client = FakeFMGClient(devices_by_adom={
        "OT-ADOM": [{"name": "FW01", "os_ver": "7", "mr": 4, "patch": 2}],
    })

    class _ClientWithHTTPSOpen(FakeFMGClient):
        def get_device_interface_config(self, device, vlanids=None, name=None):
            return [{"name": "port1", "allowaccess": ["https"]}]

    client = _ClientWithHTTPSOpen(devices_by_adom={
        "OT-ADOM": [{"name": "FW01", "os_ver": "7", "mr": 4, "patch": 2}],
    })
    result = assess(adv, client, _FakeHTTPClient(), kev_url="")
    finding = result.findings[0]
    assert finding.workaround_status == "not_in_place"
    assert finding.verdict == "config_change_required"


def test_assess_with_workaround_already_in_place_is_no_action():
    adv = _advisory()
    adv.workaround_text = "Disable HTTPS admin access on all interfaces"
    client = FakeFMGClient(devices_by_adom={
        "OT-ADOM": [{"name": "FW01", "os_ver": "7", "mr": 4, "patch": 2}],
    })  # default get_device_interface_config only allows "ping"
    result = assess(adv, client, _FakeHTTPClient(), kev_url="")
    finding = result.findings[0]
    assert finding.workaround_status == "in_place"
    assert finding.verdict == "no_action"


def test_assess_degraded_adom_query_marks_devices_unknown():
    client = FakeFMGClient(adoms=("OT-ADOM",), fail_adoms=("OT-ADOM",))
    result = assess(_advisory(), client, _FakeHTTPClient(), kev_url="")
    assert result.degraded is True
    assert any(w for w in result.warnings)
    assert result.priority == "unknown"


def test_assess_matches_fortimanager_itself_against_advisory():
    adv = Advisory(
        advisory_id="FG-IR-24-002",
        cve_ids=["CVE-2024-99999"],
        cvss_score=8.0,
        affected_ranges=[
            AffectedRange(product="FortiManager", min_version="7.4.0",
                          max_version="7.4.5", fixed_version="7.4.6"),
        ],
    )
    client = FakeFMGClient(devices_by_adom={"OT-ADOM": []})
    result = assess(adv, client, _FakeHTTPClient(), kev_url="")
    fmg_findings = [f for f in result.findings if f.product == "FortiManager"]
    assert len(fmg_findings) == 1
    assert fmg_findings[0].current_version == "7.4.5"
    assert fmg_findings[0].in_range is True
