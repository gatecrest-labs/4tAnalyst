"""
Standards MCP Server

Exposes five tools to Claude:
  - get_zone_matrix       : Full zone-pair policy table
  - check_traffic         : Zone-level allow/block verdict for a src→dst flow
  - get_naming_convention : Object naming patterns per type and platform
  - get_required_log_settings : Required logging for a given rule category
  - get_review_requirements   : Approval chain based on risk level

Data sources:
  - policy_db.json   : Zone definitions + USP policy rules (from zone-script)
  - naming.yaml      : Object naming conventions per platform
  - review_requirements.yaml : Approval chain by risk score

Run locally (stdio):
  python -m standards_mcp.server

Run as SSE server (for central deployment):
  mcp run standards_mcp/server.py --transport sse --port 8000
"""

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

# ---------------------------------------------------------------------------
# Paths — all relative to this file's directory
# ---------------------------------------------------------------------------

_HERE = Path(__file__).parent
_POLICY_DB_PATH = _HERE / "policy_db.json"
_NAMING_PATH = _HERE / "naming.yaml"
_REVIEW_PATH = _HERE / "review_requirements.yaml"

# Allow overrides via environment variables for containerised deployments
_POLICY_DB_PATH = Path(os.getenv("STANDARDS_POLICY_DB", str(_POLICY_DB_PATH)))
_NAMING_PATH = Path(os.getenv("STANDARDS_NAMING_YAML", str(_NAMING_PATH)))
_REVIEW_PATH = Path(os.getenv("STANDARDS_REVIEW_YAML", str(_REVIEW_PATH)))

# ---------------------------------------------------------------------------
# Data loading (cached — files are read once per process lifetime)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _load_policy_db() -> dict:
    with open(_POLICY_DB_PATH, encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def _load_naming() -> dict:
    with open(_NAMING_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


@lru_cache(maxsize=1)
def _load_review() -> dict:
    with open(_REVIEW_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="standards",
    instructions=(
        "Network segmentation standards server. "
        "Use get_zone_matrix to see all zone-pair policies, "
        "check_traffic to evaluate a specific src→dst flow, "
        "get_naming_convention for object naming patterns, "
        "get_required_log_settings for logging requirements, and "
        "get_review_requirements for the approval chain based on risk level."
    ),
)


# ---------------------------------------------------------------------------
# Tool: get_zone_matrix
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_zone_matrix() -> list[dict[str, Any]]:
    """
    Return the complete zone-pair policy matrix derived from the USP policy
    export.  Each entry describes whether traffic between two zones is
    ALLOWED, BLOCKED, or has no explicit rule (UNKNOWN / implicit deny).

    Returns a list of objects, each with:
      src_zone        : source zone name
      dst_zone        : destination zone name
      verdict         : "ALLOWED" | "BLOCKED" | "UNKNOWN"
      policy_sets     : which named policy sets govern this pair
      severity        : highest severity level (high / critical)
      services_blocked: services explicitly blocked by block-only rules (if any)
    """
    from standards_mcp.policy_engine import build_zone_matrix
    return build_zone_matrix(_load_policy_db())


# ---------------------------------------------------------------------------
# Tool: check_traffic
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def check_traffic(
    src_zone: str,
    dst_zone: str,
    service: str = "",
) -> dict[str, Any]:
    """
    Evaluate whether traffic from src_zone to dst_zone is permitted by the
    network segmentation policy.

    Parameters
    ----------
    src_zone : str
        Source zone name (e.g. "NETZONE OT-All", "Users Networks", "Internet").
        Use get_zone_matrix to see valid zone names.
    dst_zone : str
        Destination zone name.
    service : str, optional
        Service or port to check.  Accepts:
          - named service : "ssh", "RDP", "telnet", "https"
          - bare port     : "22", "3389", "443"
          - proto/port    : "tcp/22", "udp/514"
          - multiple      : "ssh 3389" or "ssh,3389"
        If omitted, only block-all rules are considered.

    Returns a dict with:
      src_zone        : str
      dst_zone        : str
      services        : list[str]  (parsed tokens)
      verdict         : "ALLOWED" | "BLOCKED" | "UNKNOWN"
      governing_rules : list of matching policy rule objects
      note            : str  (guidance when verdict is UNKNOWN)
    """
    import re as _re

    from standards_mcp.policy_engine import (
        evaluate,
        find_matching_policies,
    )

    db = _load_policy_db()
    zones = db["zones"]
    policies = db["policies"]

    # Parse service tokens
    services = [t.strip() for t in _re.split(r"[\s,]+", service.strip()) if t.strip()]

    matched = find_matching_policies([src_zone], [dst_zone], zones, policies)
    verdict, governing = evaluate(matched, services)

    result: dict[str, Any] = {
        "src_zone": src_zone,
        "dst_zone": dst_zone,
        "services": services,
        "verdict": verdict,
        "governing_rules": governing,
    }

    if verdict == "UNKNOWN":
        result["note"] = (
            "No explicit policy covers this zone pair. "
            "Treat as implicitly denied — a new rule will be required."
        )
    elif verdict == "BLOCKED":
        result["note"] = (
            "This traffic is explicitly blocked. "
            "An exception requires security team approval."
        )
    else:
        result["note"] = "Traffic is explicitly permitted by policy."

    return result


# ---------------------------------------------------------------------------
# Tool: get_naming_convention
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_naming_convention(
    object_type: str,
    platform: str,
) -> dict[str, Any]:
    """
    Return the naming convention for a firewall object type on a given platform.

    Parameters
    ----------
    object_type : str
        One of: "host", "network", "range", "service", "service_group",
                "address_group", "policy", "nat_rule", "vip"
    platform : str
        Currently: "fortigate" (case-insensitive)

    Returns a dict with:
      object_type  : str
      platform     : str
      pattern      : str   (the naming pattern / template)
      examples     : list[str]
      notes        : str
    """
    naming = _load_naming()
    plat_key = platform.lower()

    if plat_key not in naming.get("platforms", {}):
        available = list(naming.get("platforms", {}).keys())
        return {
            "error": f"Unknown platform '{platform}'.",
            "available_platforms": available,
        }

    obj_key = object_type.lower()
    conventions = naming["platforms"][plat_key].get("conventions", {})

    if obj_key not in conventions:
        available = list(conventions.keys())
        return {
            "error": f"Unknown object_type '{object_type}' for platform '{platform}'.",
            "available_object_types": available,
        }

    entry = conventions[obj_key]
    return {
        "object_type": object_type,
        "platform": platform,
        "pattern": entry.get("pattern", ""),
        "examples": entry.get("examples", []),
        "notes": entry.get("notes", ""),
    }


# ---------------------------------------------------------------------------
# Tool: get_required_log_settings
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_required_log_settings(rule_type: str) -> dict[str, Any]:
    """
    Return the required logging configuration for a firewall rule of the given type.

    Parameters
    ----------
    rule_type : str
        Category of the rule.  Common values:
          "allow_internet_outbound", "allow_internal", "block_all",
          "block_specific_service", "nat", "management_access"

    Returns a dict with:
      rule_type           : str
      log_start           : bool  (log when session starts)
      log_end             : bool  (log when session ends)
      alert_on_match      : bool
      retention_days      : int
      siem_forward        : bool
      notes               : str
    """
    naming = _load_naming()
    log_settings = naming.get("log_settings", {})
    key = rule_type.lower()

    if key not in log_settings:
        available = list(log_settings.keys())
        return {
            "error": f"Unknown rule_type '{rule_type}'.",
            "available_rule_types": available,
        }

    entry = log_settings[key]
    return {"rule_type": rule_type, **entry}


# ---------------------------------------------------------------------------
# Tool: get_review_requirements
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_review_requirements(risk_level: str) -> dict[str, Any]:
    """
    Return the approval chain and review requirements for a proposed firewall
    change based on its risk level.

    Parameters
    ----------
    risk_level : str
        One of: "low", "medium", "high", "critical"
        Risk level is determined by the recommendation engine based on
        factors such as zone pair classification, service exposure, and
        blast radius.

    Returns a dict with:
      risk_level       : str
      approvers        : list[str]  (roles required to approve)
      peer_review      : bool       (independent engineer peer review required)
      security_review  : bool       (security team sign-off required)
      change_window    : str        (when changes can be implemented)
      sla_hours        : int        (target turnaround time)
      notes            : str
    """
    review = _load_review()
    key = risk_level.lower()

    if key not in review.get("risk_levels", {}):
        available = list(review.get("risk_levels", {}).keys())
        return {
            "error": f"Unknown risk_level '{risk_level}'.",
            "available_risk_levels": available,
        }

    entry = review["risk_levels"][key]
    return {"risk_level": risk_level, **entry}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
