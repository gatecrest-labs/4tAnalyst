"""
Zone Policy MCP Server (4THealth external API)

Exposes five read-only tools to Claude:
  - query_zone_policy     : Verdict for one or more src→dst IP/CIDR pairs
  - get_zones             : Full zone catalogue (subnets, hierarchy, domain)
  - get_policies          : Raw policy table (zone pairs, access types, services)
  - find_zone_for_ip      : Which zone(s) an IP or CIDR belongs to
  - check_ip_traffic      : Combined IP→zone resolution + policy verdict

Connection parameters are loaded from credentials.yaml (gitignored).
Set CREDENTIALS_FILE env var to override the default path.

Run locally (stdio):
  uv run python -m zone_mcp.server

Run as SSE server (production):
  uv run mcp run zone_mcp/server.py --transport sse --port 8005
"""

import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from zone_mcp.client import ZonePolicyClient

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


def _zone_client() -> ZonePolicyClient:
    """Build a ZonePolicyClient from credentials.yaml."""
    cfg = _load_creds().get("zone_policy", {})

    base_url = cfg.get("base_url", "").strip()
    if not base_url:
        raise ValueError(
            "zone_policy.base_url is missing in credentials.yaml. "
            "Example: https://4thealth.internal.example.com"
        )

    token = cfg.get("token", "").strip()
    if not token:
        raise ValueError(
            "zone_policy.token is missing in credentials.yaml. "
            "Set it to the 4th_... Bearer token."
        )

    verify_ssl = cfg.get("verify_ssl", False)
    if isinstance(verify_ssl, str):
        # A CA bundle path — pass through as-is (requests accepts str or bool).
        pass
    else:
        verify_ssl = bool(verify_ssl)

    return ZonePolicyClient(
        base_url=base_url,
        token=token,
        verify_ssl=verify_ssl,
        timeout=float(cfg.get("timeout", 30.0)),
    )


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="zone_policy",
    instructions=(
        "4THealth zone policy server — read-only IP-to-zone and zone-to-zone "
        "traffic analysis. "
        "Use query_zone_policy to check whether traffic between specific IPs is "
        "ALLOWED, BLOCKED, or UNKNOWN. "
        "Use get_zones to see all zones and their subnets. "
        "Use get_policies to inspect the full zone-pair rule table. "
        "Use find_zone_for_ip to resolve an IP to its zone(s). "
        "Use check_ip_traffic for a combined IP-lookup + verdict in a single call. "
        "All operations are read-only — no changes are made."
    ),
)


# ---------------------------------------------------------------------------
# Tool: query_zone_policy
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def query_zone_policy(
    src: str,
    dst: str,
    service: str = "",
) -> list[dict[str, Any]]:
    """
    Query the 4THealth zone policy API for a src→dst traffic verdict.

    Parameters
    ----------
    src : str
        Source IP, CIDR, or comma/newline-separated list of either.
        Examples: "10.1.0.5", "10.1.0.0/24", "10.1.0.5,10.1.0.6"
    dst : str
        Destination IP, CIDR, or comma/newline-separated list of either.
    service : str, optional
        Port number, port name, or proto/port string.
        Examples: "443", "ssh", "tcp/8443"
        If omitted, the query checks zone-level access without a service filter.

    Returns a list — one entry per src×dst combination — each containing:
      src        : str   — source address evaluated
      dst        : str   — destination address evaluated
      service    : str   — service evaluated (if supplied)
      verdict    : str   — "ALLOWED" | "BLOCKED" | "UNKNOWN"
      src_zones  : list  — zone names that contain src
      dst_zones  : list  — zone names that contain dst
      governing  : list  — policy rules that determined the verdict
      all_policies: list — all policies evaluated (full context)

    UNKNOWN means neither IP matched any configured zone — treat as denied.
    """
    with _zone_client() as c:
        return c.query(src=src, dst=dst, service=service, verbose=True)


# ---------------------------------------------------------------------------
# Tool: get_zones
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_zones() -> dict[str, Any]:
    """
    Return the full zone catalogue from the 4THealth zone policy database.

    Each zone entry contains:
      name        : str   — zone identifier
      domain      : str   — security domain (e.g. OT, IT, CIP-H, Gas, Internet)
      is_shared   : bool  — whether the zone spans multiple domains
      description : str
      subnets     : list of { subnet: str, description: str }
      children    : list of child zone names
      parents     : list of parent zone names

    Also returns total_subnets: total subnet count across all zones.
    """
    with _zone_client() as c:
        return c.zones()


# ---------------------------------------------------------------------------
# Tool: get_policies
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_policies() -> list[dict[str, Any]]:
    """
    Return the complete zone-pair policy table from 4THealth.

    Each policy entry contains:
      index       : int    — rule index / priority
      policy_set  : str    — named rule set this belongs to
      from_zone   : str    — source zone
      to_zone     : str    — destination zone
      access_type : str    — "allow all" | "block all" | "block only"
      severity    : str    — "high" | "critical"
      services    : list   — services blocked (for "block only" rules)
      description : str

    Use this to understand the full rule set before recommending changes.
    """
    with _zone_client() as c:
        return c.policies()


# ---------------------------------------------------------------------------
# Tool: find_zone_for_ip
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def find_zone_for_ip(ip: str) -> dict[str, Any]:
    """
    Resolve an IP address or CIDR to the zone(s) it belongs to.

    Uses a dummy self-query (src==dst==ip) so the 4THealth engine performs
    the subnet-to-zone lookup without needing a separate endpoint.

    Parameters
    ----------
    ip : str
        A single IP address or CIDR (e.g. "10.1.2.3", "10.1.0.0/24").

    Returns:
      ip         : str        — the IP/CIDR queried
      zones      : list[str]  — zone names that contain this IP
      found      : bool       — False if no zone matched (IP is unclassified)
    """
    with _zone_client() as c:
        results = c.query(src=ip, dst=ip, service="", verbose=False)

    if not results:
        return {"ip": ip, "zones": [], "found": False}

    # src_zones and dst_zones should be identical for a self-query
    zones = results[0].get("src_zones", [])
    return {"ip": ip, "zones": zones, "found": bool(zones)}


# ---------------------------------------------------------------------------
# Tool: check_ip_traffic
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def check_ip_traffic(
    src_ip: str,
    dst_ip: str,
    service: str = "",
) -> dict[str, Any]:
    """
    One-call IP-to-zone resolution + policy verdict.

    This is the primary tool for firewall request analysis when the engineer
    provides raw IP addresses rather than zone names.  It queries the
    4THealth API and returns the full decision context in a single response.

    Parameters
    ----------
    src_ip  : str
        Source IP or CIDR (single address — use query_zone_policy for bulk).
    dst_ip  : str
        Destination IP or CIDR.
    service : str, optional
        Port, port name, or proto/port (e.g. "443", "ssh", "tcp/8443").

    Returns:
      src_ip         : str
      dst_ip         : str
      service        : str
      src_zones      : list[str]   — zone(s) that contain src_ip
      dst_zones      : list[str]   — zone(s) that contain dst_ip
      verdict        : str         — "ALLOWED" | "BLOCKED" | "UNKNOWN"
      governing      : list        — rules that determined the verdict
      all_policies   : list        — full set of evaluated policies
      note           : str         — plain-English guidance
    """
    with _zone_client() as c:
        results = c.query(src=src_ip, dst=dst_ip, service=service, verbose=True)

    if not results:
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "service": service,
            "src_zones": [],
            "dst_zones": [],
            "verdict": "UNKNOWN",
            "governing": [],
            "all_policies": [],
            "note": "No result returned from the zone policy API.",
        }

    r = results[0]
    verdict = r.get("verdict", "UNKNOWN")

    if verdict == "ALLOWED":
        note = "Traffic is explicitly permitted by zone policy."
    elif verdict == "BLOCKED":
        note = (
            "Traffic is explicitly blocked. "
            "An exception requires security team approval."
        )
    else:
        note = (
            "One or both IPs did not match any configured zone. "
            "Treat as implicitly denied — a new rule may be required, "
            "or the IP may be outside the organization's managed address space."
        )

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "service": service,
        "src_zones": r.get("src_zones", []),
        "dst_zones": r.get("dst_zones", []),
        "verdict": verdict,
        "governing": r.get("governing", []),
        "all_policies": r.get("all_policies", []),
        "note": note,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
