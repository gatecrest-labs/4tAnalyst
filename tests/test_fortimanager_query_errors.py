"""
Sanitized error surfacing for fortimanager_mcp.query — raw FortiManager
error strings (including internal /pm/config/... URL paths) must never be
returned verbatim to MCP tool callers.
"""

from fortimanager_mcp import query
from fortimanager_mcp.client import FortiManagerAPIError


class _FailingClient:
    def get_address_object(self, adom, name_or_ip):
        raise FortiManagerAPIError(
            "FortiManager API error on /pm/config/adom/OT-ADOM/obj/firewall/address: [-11] No permission",
            code=-11,
        )


def test_get_address_object_non_not_found_error_is_sanitized():
    # A non-"-9" error (here: permission denied) must return the sanitized
    # error directly and must NOT attempt the IP-search fallback.
    result = query.get_address_object(_FailingClient(), "OT-ADOM", "H_10.1.2.3")
    assert "error" in result
    assert "/pm/config" not in result["error"]
    assert result.get("error_code") == "internal_error"


class _NotFoundThenFallbackClient:
    """Exact-name lookup misses (-9); fallback IP search succeeds."""

    def get_address_object(self, adom, name_or_ip):
        raise FortiManagerAPIError(
            "FortiManager API error on /pm/config/adom/OT-ADOM/obj/firewall/address: [-9] Object not found",
            code=-9,
        )

    def get_address_objects(self, adom):
        return [
            {"name": "H_10.1.2.3", "subnet": ["10.1.2.3", "255.255.255.255"]},
        ]

    def get_global_address_objects(self):
        return []


def test_get_address_object_not_found_falls_back_to_ip_search():
    # -9 ("not found") on the exact-name lookup must fall through to the
    # IP-search fallback rather than short-circuiting to an error — a raw
    # IP is virtually never also a valid FortiManager object name.
    result = query.get_address_object(_NotFoundThenFallbackClient(), "OT-ADOM", "10.1.2.3")
    assert "error" not in result
    assert result["name"] == "H_10.1.2.3"
    assert result["subnet"] == "10.1.2.3/255.255.255.255"


class _NotFoundNoMatchClient:
    """Exact-name lookup misses (-9); fallback IP search finds nothing."""

    def get_address_object(self, adom, name_or_ip):
        raise FortiManagerAPIError(
            "FortiManager API error on /pm/config/adom/OT-ADOM/obj/firewall/address: [-9] Object not found",
            code=-9,
        )

    def get_address_objects(self, adom):
        return []

    def get_global_address_objects(self):
        return []


def test_get_address_object_not_found_falls_back_and_reports_no_match():
    result = query.get_address_object(_NotFoundNoMatchClient(), "OT-ADOM", "10.9.9.9")
    assert "error" in result
    assert "No address object found" in result["error"]


class _FailingServiceClient:
    def get_service_object(self, adom, name_or_port):
        raise FortiManagerAPIError(
            "FortiManager API error on /pm/config/adom/OT-ADOM/obj/firewall/service/custom/HTTPS: [-6] Object does not exist",
            code=-6,
        )


def test_get_service_object_non_not_found_error_is_sanitized():
    # A non-"-9" error must return the sanitized error directly and must
    # NOT attempt the port-substring-search fallback.
    result = query.get_service_object(_FailingServiceClient(), "OT-ADOM", "HTTPS")
    assert "error" in result
    assert "/pm/config" not in result["error"]
    assert result.get("error_code") == "internal_error"


class _ServiceNotFoundThenFallbackClient:
    """Exact-name lookup misses (-9); fallback port-substring search succeeds."""

    def get_service_object(self, adom, name_or_port):
        raise FortiManagerAPIError(
            "FortiManager API error on /pm/config/adom/OT-ADOM/obj/firewall/service/custom/8443: [-9] Object not found",
            code=-9,
        )

    def get_service_objects(self, adom):
        return [
            {"name": "TCP_8443", "tcp-portrange": "8443", "protocol": "TCP"},
        ]


def test_get_service_object_not_found_falls_back_to_port_search():
    # -9 ("not found") on the exact-name lookup must fall through to the
    # port-substring-search fallback rather than short-circuiting to an error
    # — a raw port is virtually never also a valid FortiManager object name.
    result = query.get_service_object(_ServiceNotFoundThenFallbackClient(), "OT-ADOM", "8443")
    assert "error" not in result
    assert result["name"] == "TCP_8443"
    assert result["tcp_portrange"] == "8443"


class _ServiceNotFoundNoMatchClient:
    """Exact-name lookup misses (-9); fallback port search finds nothing."""

    def get_service_object(self, adom, name_or_port):
        raise FortiManagerAPIError(
            "FortiManager API error on /pm/config/adom/OT-ADOM/obj/firewall/service/custom/9999: [-9] Object not found",
            code=-9,
        )

    def get_service_objects(self, adom):
        return []


def test_get_service_object_not_found_falls_back_and_reports_no_match():
    result = query.get_service_object(_ServiceNotFoundNoMatchClient(), "OT-ADOM", "9999")
    assert "error" in result
    assert "No service object found" in result["error"]


class _FailingAddressSearchClient:
    def get_address_objects(self, adom):
        raise FortiManagerAPIError(
            "FortiManager API error on /pm/config/adom/OT-ADOM/obj/firewall/address: [-11] No permission",
            code=-11,
        )


def test_search_address_objects_error_is_sanitized():
    result = query.search_address_objects(_FailingAddressSearchClient(), "OT-ADOM", "10.1.2.3")
    assert len(result) == 1
    assert "/pm/config" not in result[0]["error"]
    assert result[0].get("error_code") == "internal_error"


class _FailingPolicySearchClient:
    def get_policy_packages(self, adom):
        return [{"name": "pkgA", "scope member": [{"name": "FW1"}]}]

    def get_policies(self, adom, pkg):
        raise FortiManagerAPIError(
            f"FortiManager API error on /pm/config/adom/{adom}/pkg/{pkg}/firewall/policy: [-3] Internal error",
            code=-3,
        )

    def get_address_objects(self, adom):
        return []

    def get_address_groups(self, adom):
        return []

    def get_global_address_objects(self):
        return []

    def get_global_address_groups(self):
        return []

    def get_central_dnat_rules(self, adom, pkg):
        return []

    def get_service_objects(self, adom):
        return []

    def get_service_groups(self, adom):
        return []


def test_search_policies_packages_failed_error_is_sanitized():
    result = query.search_policies(_FailingPolicySearchClient(), "OT-ADOM", "FW1")
    assert result["degraded"] is True
    assert len(result["packages_failed"]) == 1
    assert "/pm/config" not in result["packages_failed"][0]["error"]
    assert result["packages_failed"][0].get("error_code") == "internal_error"
