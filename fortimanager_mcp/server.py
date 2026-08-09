"""
FortiManager MCP Server (7.4.x / 7.6.x compatible)

Exposes seventeen read-only tools to Claude:
  - get_system_status           : FortiManager version, hostname, serial, platform
  - get_ha_status               : FortiManager HA cluster status
  - get_adoms                   : List all administrative domains
  - get_devices                 : List FortiGates managed in an ADOM
  - search_devices              : Filter devices by name/platform/OS/connection status
  - search_policies             : Find policies matching a src/dst/service flow
  - get_address_object          : Look up an address object by name or IP
  - search_address_objects      : Find all objects containing a given IP
  - get_service_object          : Look up a service object by name or port
  - get_policy                  : Full details for a specific policy ID
  - get_interface_map           : Interface-to-zone mapping for a device
  - get_device_interface_config : Device-DB interface config with VLAN filtering
  - get_routing_table           : Static routing table for a device
  - list_device_vdoms           : VDOMs configured on a device
  - get_device_client_location  : Locate a client on detected-client inventory
  - get_device_sdwan            : Device-DB SD-WAN config (zones, members, health-checks)
  - get_device_sdwan_monitor    : Live SD-WAN runtime status (link state, bandwidth, SLA)

Connection parameters (two hosts + API keys) are loaded from credentials.yaml
(gitignored).  Set CREDENTIALS_FILE env var to override the path.

Run locally (stdio):
  python -m fortimanager_mcp.server

Run as SSE server (production):
  mcp run fortimanager_mcp/server.py --transport sse --port 8002
"""

import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from fortimanager_mcp import client as _client_module
from fortimanager_mcp import query as _query
from fwanalyst_server.context import allowed_adoms_var
from mcp_common.errors import safe_error
from mcp_common.validation import (
    ValidationError,
    validate_adom,
    validate_device_name,
    validate_object_name,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Credentials loading
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parent.parent
_DEFAULT_CREDS = _REPO_ROOT / "credentials.yaml"


@lru_cache(maxsize=1)
def _load_creds() -> dict:
    creds_path = Path(os.getenv("CREDENTIALS_FILE", str(_DEFAULT_CREDS)))
    if not creds_path.exists():
        raise FileNotFoundError(
            f"credentials.yaml not found at {creds_path}. "
            "Copy credentials.yaml.example to credentials.yaml and fill in values."
        )
    with open(creds_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _fortimanager_client() -> _client_module.FortiManagerClient:
    """Build a connected FortiManagerClient from credentials.yaml."""
    cfg = _load_creds().get("fortimanager", {})

    raw_hosts = cfg.get("hosts", [])
    if not raw_hosts:
        raise ValueError(
            "fortimanager.hosts is empty in credentials.yaml. "
            "Add at least one entry with host and api_key."
        )

    hosts = []
    for entry in raw_hosts:
        h = entry.get("host", "").strip()
        k = entry.get("api_key", "").strip()
        if not h or not k:
            raise ValueError(
                f"Each fortimanager.hosts entry needs a non-empty host and api_key. "
                f"Bad entry: {entry}"
            )
        hosts.append((h, k))

    primary_host, primary_key = hosts[0]
    secondary_host, secondary_key = hosts[1] if len(hosts) > 1 else ("", "")

    c = _client_module.FortiManagerClient(
        primary_host=primary_host,
        primary_key=primary_key,
        secondary_host=secondary_host,
        secondary_key=secondary_key,
        port=int(cfg.get("port", 443)),
        verify_ssl=bool(cfg.get("verify_ssl", True)),
        version=str(cfg.get("version", "7.4")),
        session_timeout=int(cfg.get("session_timeout", 300)),
    )
    c.login()
    return c


def _require_adom(adom: str) -> dict | None:
    """Return error dict if the caller's token does not allow this ADOM, else None.

    Defaults to {"*"} (full access) when the ContextVar has no value — this
    preserves existing behaviour in stdio/dev mode where no auth middleware runs.
    """
    allowed = allowed_adoms_var.get({"*"})
    if "*" in allowed or adom in allowed:
        return None
    return {
        "error": f"ADOM '{adom}' is not in your allowed list.",
        "error_code": "forbidden",
    }


def _validate_or_error(
    adom: str, device: str | None = None
) -> tuple[str | None, str | None, dict | None]:
    """Validate `adom` (and optionally `device`), then check ADOM access.

    Returns (adom, device, None) on success, or (None, None, error_dict) on
    failure. `error_dict` is always the bare {"error", "error_code"} shape —
    callers that return `list[dict]` must wrap it themselves (`return [err]`).
    """
    try:
        adom = validate_adom(adom)
        if device is not None:
            device = validate_device_name(device)
    except ValidationError as e:
        message, code = safe_error(e)
        return None, None, {"error": message, "error_code": code}
    if err := _require_adom(adom):
        return None, None, err
    return adom, device, None


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="fortimanager",
    instructions=(
        "FortiManager read-only query server (7.4.x). "
        "Use get_adoms to discover administrative domains, get_devices to list FortiGates, "
        "search_policies to find rules matching a traffic flow, "
        "search_address_objects to find objects by IP (searches both per-ADOM and global ADOM), "
        "get_interface_map for zone assignments, and get_routing_table for path analysis. "
        "get_device_client_location locates a client on a device's detected-inventory, and "
        "get_device_sdwan/get_device_sdwan_monitor return SD-WAN config and live link status. "
        "All operations are read-only — no changes are made to policy."
    ),
)


# ---------------------------------------------------------------------------
# Tool: get_system_status
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_system_status() -> dict[str, Any]:
    """
    Return FortiManager system status and version information.

    Returns version, hostname, serial number, and platform as normalised
    top-level fields, plus the full raw response under 'raw' (field names
    vary slightly by FortiManager version).
    """
    try:
        with _fortimanager_client() as c:
            return _query.get_system_status(c)
    except Exception as e:
        message, code = safe_error(e)
        return {"error": message, "error_code": code}


# ---------------------------------------------------------------------------
# Tool: get_ha_status
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_ha_status() -> dict[str, Any]:
    """
    Return FortiManager High Availability (HA) cluster status.

    Response shape (standalone vs cluster, member list) varies by topology,
    so the raw FortiManager response is returned as-is.
    """
    try:
        with _fortimanager_client() as c:
            return _query.get_ha_status(c)
    except Exception as e:
        message, code = safe_error(e)
        return {"error": message, "error_code": code}


# ---------------------------------------------------------------------------
# Tool: get_adoms
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_adoms() -> list[dict[str, Any]]:
    """
    List administrative domains (ADOMs) managed by FortiManager.

    Returns only ADOMs the caller's token is permitted to access.
    Returns a list of objects, each with:
      name      : str  — ADOM name
      status    : str  — operational status
      os_type   : str  — device OS family managed (FortiOS, etc.)
      desc      : str  — description
    """
    allowed = allowed_adoms_var.get({"*"})
    try:
        with _fortimanager_client() as c:
            adoms = _query.list_adoms(c)
    except Exception as e:
        message, code = safe_error(e)
        return [{"error": message, "error_code": code}]
    if "*" in allowed:
        return adoms
    return [a for a in adoms if a["name"] in allowed]


# ---------------------------------------------------------------------------
# Tool: get_devices
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_devices(adom: str) -> list[dict[str, Any]]:
    """
    List FortiGate devices managed within an ADOM.

    Parameters
    ----------
    adom : str
        ADOM name (from get_adoms).

    Returns device name, management IP, firmware version, HA mode,
    connection status, and database sync status.
    """
    adom, _, err = _validate_or_error(adom)
    if err:
        return [err]
    try:
        with _fortimanager_client() as c:
            return _query.list_devices(c, adom)
    except Exception as e:
        message, code = safe_error(e)
        return [{"error": message, "error_code": code}]


# ---------------------------------------------------------------------------
# Tool: search_devices
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def search_devices(
    adom: str,
    name_filter: str = "",
    platform_filter: str = "",
    os_version_filter: str = "",
    connection_status: str = "",
) -> dict[str, Any]:
    """
    Filter FortiGate devices in an ADOM by name, platform, OS version,
    and/or connection status.

    Parameters
    ----------
    adom               : str  — ADOM name (from get_adoms)
    name_filter        : str  — Substring match on device name (optional)
    platform_filter    : str  — Substring match on platform (e.g. "FortiGate-VM") (optional)
    os_version_filter  : str  — Substring match on OS version (e.g. "7.4") (optional)
    connection_status  : str  — "up" or "down" (optional)

    All filters combine with AND. Filtering is client-side over get_devices —
    no additional FortiManager query is issued. Returns {count, devices}.
    """
    adom, _, err = _validate_or_error(adom)
    if err:
        return err
    try:
        with _fortimanager_client() as c:
            return _query.search_devices(c, adom, name_filter, platform_filter,
                                          os_version_filter, connection_status)
    except Exception as e:
        message, code = safe_error(e)
        return {"error": message, "error_code": code}


# ---------------------------------------------------------------------------
# Tool: search_policies
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def search_policies(
    adom: str,
    device: str,
    src_ip: str = "",
    dst_ip: str = "",
    service: str = "",
) -> dict[str, Any]:
    """
    Find firewall policies that could match the given traffic parameters.

    Parameters
    ----------
    adom    : str  — ADOM name (from get_adoms)
    device  : str  — FortiGate device name (from get_devices)
    src_ip  : str  — Source IP or CIDR (optional, e.g. "10.1.2.3" or "10.1.0.0/16")
    dst_ip  : str  — Destination IP or CIDR (optional)
    service : str  — Port, proto/port, or service name (e.g. "443", "tcp/8443", "ssh")

    Matching is set-based: service objects are resolved to numeric proto/port
    ranges and address groups are recursed, so e.g. "80" never matches an
    object named TCP_8080. Searches all policy packages installed on the
    target device, including global-ADOM inherited objects.

    Returns a structured dict:
      policies          : matching policies sorted by package then policy ID,
                          each with full_cover / disabled / conditional_schedule /
                          unknown_refs flags in addition to the usual summary
      packages_searched : packages successfully queried
      packages_failed   : [{package, error}] for fetch failures
      degraded          : True if any package failed — an empty `policies`
                          list is then NOT proof that no rule exists
    """
    adom, device, err = _validate_or_error(adom, device)
    if err:
        return err
    try:
        with _fortimanager_client() as c:
            return _query.search_policies(c, adom, device, src_ip, dst_ip, service)
    except Exception as e:
        message, code = safe_error(e)
        return {"error": message, "error_code": code}


# ---------------------------------------------------------------------------
# Tool: get_address_object
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_address_object(adom: str, name_or_ip: str) -> dict[str, Any]:
    """
    Look up an address object by name or IP address.

    Parameters
    ----------
    adom       : str  — ADOM name
    name_or_ip : str  — Exact object name (e.g. "H_10.1.2.3") or raw IP/CIDR.
                        Falls back to IP search if name lookup returns not-found.

    Returns the object's name, type, subnet, FQDN (if set), comment, and UUID.
    """
    adom, _, err = _validate_or_error(adom)
    if err:
        return err
    try:
        with _fortimanager_client() as c:
            return _query.get_address_object(c, adom, name_or_ip)
    except Exception as e:
        message, code = safe_error(e)
        return {"error": message, "error_code": code}


# ---------------------------------------------------------------------------
# Tool: search_address_objects
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def search_address_objects(adom: str, ip: str) -> list[dict[str, Any]]:
    """
    Find all address objects that contain the given IP address or CIDR.

    Parameters
    ----------
    adom : str  — ADOM name
    ip   : str  — IP address (e.g. "10.1.2.3") or CIDR (e.g. "10.1.0.0/16")

    Searches both the per-ADOM object database and the global ADOM (for
    inherited objects). Use this before recommending creating a new object —
    an equivalent one may already exist.

    Returns a list of matching objects with their subnet, type, comment, and scope.
    """
    adom, _, err = _validate_or_error(adom)
    if err:
        return [err]
    try:
        with _fortimanager_client() as c:
            return _query.search_address_objects(c, adom, ip)
    except Exception as e:
        message, code = safe_error(e)
        return [{"error": message, "error_code": code}]


# ---------------------------------------------------------------------------
# Tool: get_service_object
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_service_object(adom: str, name_or_port: str) -> dict[str, Any]:
    """
    Look up a service object by name or port number.

    Parameters
    ----------
    adom         : str  — ADOM name
    name_or_port : str  — Service name (e.g. "HTTPS") or port number (e.g. "443").
                          Falls back to substring search if exact name not found.

    Returns the service object's name, protocol, TCP/UDP port ranges, and comment.
    """
    adom, _, err = _validate_or_error(adom)
    if err:
        return err
    try:
        with _fortimanager_client() as c:
            return _query.get_service_object(c, adom, name_or_port)
    except Exception as e:
        message, code = safe_error(e)
        return {"error": message, "error_code": code}


# ---------------------------------------------------------------------------
# Tool: get_policy
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_policy(adom: str, pkg: str, policy_id: int) -> dict[str, Any]:
    """
    Return full details for a specific firewall policy.

    Parameters
    ----------
    adom      : str  — ADOM name
    pkg       : str  — Policy package name
    policy_id : int  — Policy ID (from search_policies results)

    Returns all policy fields: source/destination interfaces and addresses,
    service, action, logging, NAT, and UUID.
    """
    adom, _, err = _validate_or_error(adom)
    if err:
        return err
    try:
        with _fortimanager_client() as c:
            return _query.get_policy(c, adom, pkg, policy_id)
    except Exception as e:
        message, code = safe_error(e)
        return {"error": message, "error_code": code}


# ---------------------------------------------------------------------------
# Tool: get_interface_map
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_interface_map(adom: str, device: str) -> dict[str, Any]:
    """
    Return interface-to-zone assignments for a FortiGate device.

    Parameters
    ----------
    adom   : str  — ADOM name
    device : str  — FortiGate device name (from get_devices)

    Returns a list of interfaces with IP, zone membership, VLAN ID, alias,
    and admin status. Also returns device firmware version and HA mode.
    Use this to determine which zone an IP belongs to on a specific firewall.
    """
    adom, device, err = _validate_or_error(adom, device)
    if err:
        return err
    try:
        with _fortimanager_client() as c:
            return _query.get_interface_map(c, adom, device)
    except Exception as e:
        message, code = safe_error(e)
        return {"error": message, "error_code": code}


# ---------------------------------------------------------------------------
# Tool: get_device_interface_config
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_device_interface_config(
    adom: str,
    device: str,
    vlanids: list[int] | None = None,
    name: str | None = None,
) -> dict[str, Any]:
    """
    Return a FortiGate's device-DB interface configuration, optionally
    filtered by VLAN id(s) and/or exact interface name.

    Parameters
    ----------
    adom    : str  — ADOM name (used for the access-control check only; the
                      underlying FortiManager query is device-scoped)
    device  : str  — FortiGate device name (from get_devices)
    vlanids : list[int]  — Optional VLAN ids to filter on (optional)
    name    : str  — Optional exact interface name to filter on (optional)

    Unlike get_interface_map (live monitor proxy, no filtering), this reads
    FortiManager's stored device-DB config — works even when the device is
    offline, and supports server-side VLAN filtering. Use it to answer
    "which interface/port is VLAN 20 on" directly.
    """
    adom, device, err = _validate_or_error(adom, device)
    if err:
        return err
    try:
        with _fortimanager_client() as c:
            return _query.get_device_interface_config(c, device, vlanids=vlanids, name=name)
    except Exception as e:
        message, code = safe_error(e)
        return {"error": message, "error_code": code}


# ---------------------------------------------------------------------------
# Tool: get_routing_table
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_routing_table(adom: str, device: str) -> list[dict[str, Any]]:
    """
    Return the static routing table configured on a FortiGate device.

    Parameters
    ----------
    adom   : str  — ADOM name
    device : str  — FortiGate device name (from get_devices)

    Returns static routes sorted by sequence number, each with destination
    prefix, gateway, egress interface, administrative distance, and priority.
    Use this for path analysis when determining which firewall is in the
    forwarding path between two IP addresses.
    """
    adom, device, err = _validate_or_error(adom, device)
    if err:
        return [err]
    try:
        with _fortimanager_client() as c:
            return _query.get_routing_table(c, adom, device)
    except Exception as e:
        message, code = safe_error(e)
        return [{"error": message, "error_code": code}]


# ---------------------------------------------------------------------------
# Tool: list_device_vdoms
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def list_device_vdoms(adom: str, device: str) -> list[dict[str, Any]]:
    """
    List VDOMs (virtual domains) configured on a FortiGate device.

    Parameters
    ----------
    adom   : str  — ADOM name
    device : str  — FortiGate device name (from get_devices)

    Returns each VDOM's name, type, operating mode, and status. Most
    4tAnalyst flows target "root" implicitly (see get_interface_map /
    get_routing_table), but multi-VDOM devices route traffic per-VDOM —
    use this to confirm which VDOM a flow actually traverses.
    """
    adom, device, err = _validate_or_error(adom, device)
    if err:
        return [err]
    try:
        with _fortimanager_client() as c:
            return _query.list_device_vdoms(c, adom, device)
    except Exception as e:
        message, code = safe_error(e)
        return [{"error": message, "error_code": code}]


# ---------------------------------------------------------------------------
# Tool: get_device_client_location
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_device_client_location(
    adom: str,
    device: str,
    ip: str = "",
    mac: str = "",
    hostname: str = "",
) -> dict[str, Any]:
    """
    Locate a client on a device's detected-inventory: which FortiAP/FortiSwitch
    port and VLAN it's connected through, plus hostname/vendor/online state.

    Parameters
    ----------
    adom     : str — ADOM name
    device   : str — FortiGate device name (from get_devices)
    ip       : str — Filter to one client by IPv4 address (exact match, optional)
    mac      : str — Filter to one client by MAC address (case-insensitive, optional)
    hostname : str — Filter by hostname substring (case-insensitive, optional)

    With no filter, returns the full detected-client inventory (summarized).
    Use this to answer "where does this endpoint actually sit" during
    request triage.
    """
    adom, device, err = _validate_or_error(adom, device)
    if err:
        return err
    try:
        with _fortimanager_client() as c:
            return _query.get_device_client_location(
                c, adom, device,
                ip=ip or None, mac=mac or None, hostname=hostname or None,
            )
    except Exception as e:
        message, code = safe_error(e)
        return {"error": message, "error_code": code}


# ---------------------------------------------------------------------------
# Tool: get_device_sdwan
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_device_sdwan(adom: str, device: str, vdom: str = "root") -> dict[str, Any]:
    """
    Return a FortiGate's device-DB SD-WAN configuration: zones, members,
    and health-checks.

    Parameters
    ----------
    adom   : str — ADOM name (access-control check only)
    device : str — FortiGate device name (from get_devices)
    vdom   : str — VDOM to query (default "root")

    Use when a device runs SD-WAN but has no assigned wanprof template —
    this reads the local device-DB config directly. Relevant when
    segmentation/routing decisions touch an SD-WAN-connected site.
    """
    adom, device, err = _validate_or_error(adom, device)
    if err:
        return err
    try:
        vdom = validate_object_name(vdom, kind="vdom")
    except ValidationError as e:
        message, code = safe_error(e)
        return {"error": message, "error_code": code}
    try:
        with _fortimanager_client() as c:
            return _query.get_device_sdwan(c, device, vdom=vdom)
    except Exception as e:
        message, code = safe_error(e)
        return {"error": message, "error_code": code}


# ---------------------------------------------------------------------------
# Tool: get_device_sdwan_monitor
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_device_sdwan_monitor(adom: str, device: str) -> dict[str, Any]:
    """
    Return LIVE SD-WAN runtime status for a device: per-member link state
    and bandwidth, plus per-health-check SLA (latency/packet loss) per member.

    Parameters
    ----------
    adom   : str — ADOM name (access-control check only)
    device : str — FortiGate device name (from get_devices)

    Pairs with get_device_sdwan (config); this answers "how are the uplinks
    doing right now / is any member breaching SLA".
    """
    adom, device, err = _validate_or_error(adom, device)
    if err:
        return err
    try:
        with _fortimanager_client() as c:
            return _query.get_device_sdwan_monitor(c, adom, device)
    except Exception as e:
        message, code = safe_error(e)
        return {"error": message, "error_code": code}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
