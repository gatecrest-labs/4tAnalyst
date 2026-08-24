"""Tests for psirt.workaround_checks: pattern matching + config checks."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from psirt.workaround_checks import check_workaround, match_workaround_pattern


class _StubClient:
    def __init__(self, interfaces):
        self._interfaces = interfaces

    def get_device_interface_config(self, device, vlanids=None, name=None):
        return self._interfaces


def test_match_workaround_pattern_recognizes_admin_access_text():
    key = match_workaround_pattern(
        "Disable HTTP/HTTPS administrative access on the interface facing the internet"
    )
    assert key == "disable_http_https_admin_access"


def test_match_workaround_pattern_case_insensitive():
    key = match_workaround_pattern("DISABLE HTTPS ADMIN ACCESS immediately")
    assert key == "disable_http_https_admin_access"


def test_match_workaround_pattern_unrecognized_returns_none():
    key = match_workaround_pattern("Rotate the API key used by the integration")
    assert key is None


def test_check_workaround_in_place_when_no_interface_allows_http_or_https():
    client = _StubClient([
        {"name": "port1", "allowaccess": ["ping", "ssh"]},
        {"name": "port2", "allowaccess": ["ping"]},
    ])
    status = check_workaround("disable_http_https_admin_access", client, "OT-ADOM", "FW01")
    assert status == "in_place"


def test_check_workaround_not_in_place_when_an_interface_allows_https():
    client = _StubClient([
        {"name": "port1", "allowaccess": ["ping", "https", "ssh"]},
    ])
    status = check_workaround("disable_http_https_admin_access", client, "OT-ADOM", "FW01")
    assert status == "not_in_place"


def test_check_workaround_unknown_key_returns_manual_verification():
    client = _StubClient([])
    status = check_workaround("some_unregistered_key", client, "OT-ADOM", "FW01")
    assert status == "manual_verification_required"


def test_check_workaround_in_place_when_allowaccess_is_null():
    client = _StubClient([
        {"name": "port1", "allowaccess": None},
    ])
    status = check_workaround("disable_http_https_admin_access", client, "OT-ADOM", "FW01")
    assert status == "in_place"


def test_check_workaround_in_place_when_allowaccess_key_absent():
    client = _StubClient([
        {"name": "port1"},
    ])
    status = check_workaround("disable_http_https_admin_access", client, "OT-ADOM", "FW01")
    assert status == "in_place"


def test_check_workaround_manual_when_empty_interface_list():
    client = _StubClient([])
    status = check_workaround("disable_http_https_admin_access", client, "OT-ADOM", "FW01")
    assert status == "manual_verification_required"
