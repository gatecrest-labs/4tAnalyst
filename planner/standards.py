"""
Deterministic standards lookups for the change planner.

Loads the same team-maintained YAML files the standards MCP serves
(standards_mcp/naming.yaml, review_requirements.yaml) and encodes the
risk/logging decision rules that previously lived as prose in
.claude/skills/analyze-request/SKILL.md Steps 4-5.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path

import yaml

from fortimanager_mcp.matching import PortRange

_REPO_ROOT = Path(__file__).parent.parent
_NAMING_FILE = _REPO_ROOT / "standards_mcp" / "naming.yaml"
_REVIEW_FILE = _REPO_ROOT / "standards_mcp" / "review_requirements.yaml"

# Destination ports that make a rule "management access" per naming.yaml
# (interactive access logging — a common regulated-environment requirement,
# e.g. NERC CIP-005 in a regulated deployment).
_MANAGEMENT_PORTS = {("tcp", 22), ("tcp", 3389), ("tcp", 23)}


@lru_cache(maxsize=4)
def _load_yaml(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_naming(path: Path | None = None) -> dict:
    return _load_yaml(str(path or _NAMING_FILE))


def object_name(obj_type: str, *, ip: str = "", proto: str = "",
                port: str = "", naming: dict | None = None) -> str:
    """Generate an object name per the FortiGate conventions in naming.yaml."""
    if obj_type == "host":
        return f"H_{ip.split('/')[0]}"
    if obj_type == "network":
        addr, _, prefix = ip.partition("/")
        return f"N_{addr}_{prefix or '32'}"
    if obj_type == "service":
        return f"SVC_{proto.upper()}_{port}"
    raise ValueError(f"No naming convention for object type {obj_type!r}")


def policy_name(ticket_id: str, srcintf: str, dstintf: str, seq: int = 1) -> str:
    ticket = ticket_id or "<TICKET_ID>"
    return f"{ticket}_{srcintf.upper()}_TO_{dstintf.upper()}_{seq:03d}"


def _domains_for(zones: list[str], zone_domains: dict[str, str]) -> set[str] | None:
    """Resolve zone names to domains. None if any zone is unknown/missing."""
    if not zones:
        return None
    domains = set()
    for z in zones:
        d = zone_domains.get(z)
        if d is None:
            return None
        domains.add(d)
    return domains


def risk_level(src_zones: list[str], dst_zones: list[str],
               zone_domains: dict[str, str]) -> str:
    """
    Deterministic version of SKILL.md Step 5:
      critical — any CIP-H/OT/Nuclear zone, Internet on either side, or any
                 unresolvable zone (fail safe)
      high     — cross-domain flow
      medium   — same-domain flow between known zones
    """
    # The zone NAME "Internet" is the catch-all for unresolved IPs — it is
    # the internet regardless of what domain label the catalogue gives it.
    if "Internet" in src_zones or "Internet" in dst_zones:
        return "critical"

    src_domains = _domains_for(src_zones, zone_domains)
    dst_domains = _domains_for(dst_zones, zone_domains)
    if src_domains is None or dst_domains is None:
        return "critical"  # unknown zone: cannot bound the blast radius

    sensitive = {"CIP-H", "OT", "Nuclear", "Gas"}
    if (src_domains | dst_domains) & sensitive:
        return "critical"
    if "Internet" in src_domains or "Internet" in dst_domains:
        return "critical"
    if src_domains != dst_domains:
        return "high"
    return "medium"


def rule_type_for(verdict: str, src_domains: set[str], dst_domains: set[str],
                  service_ranges: list[PortRange]) -> str:
    """Map a flow onto a naming.yaml log_settings key.

    The zone pair decides the profile even for BLOCKED flows — an approved
    exception must log like any other rule between those zones.
    """
    ot_like = {"OT", "CIP-H", "Gas", "Nuclear"}
    if src_domains & ot_like and not (dst_domains & ot_like):
        return "allow_ot_to_it"
    if dst_domains & ot_like and not (src_domains & ot_like):
        return "allow_it_to_ot"
    if "Internet" in src_domains and "Internet" not in dst_domains:
        return "allow_internet_inbound"
    if "Internet" in dst_domains:
        return "allow_internet_outbound"
    for r in service_ranges:
        for proto, port in _MANAGEMENT_PORTS:
            if r.protocol == proto and r.start <= port <= r.end:
                return "management_access"
    return "allow_internal"


def log_settings(rule_type: str, naming: dict | None = None) -> dict:
    settings = (naming or load_naming())["log_settings"]
    if rule_type not in settings:
        raise KeyError(
            f"rule_type {rule_type!r} not present in naming.yaml log_settings"
        )
    return dict(settings[rule_type], rule_type=rule_type)


# Least-privilege thresholds. An IPv4 prefix shorter than /16 (IPv6 /48) is
# "very broad"; a tcp/udp/sctp request spanning more than this many ports is
# a wide-open service. Both are review flags, not hard blocks.
_BROAD_PREFIX_V4 = 16
_BROAD_PREFIX_V6 = 48
_WIDE_PORT_SPAN = 1024


def permissiveness_warnings(
    srcs: list[str], dsts: list[str], service_ranges: list[PortRange],
) -> list[str]:
    """Least-privilege review of the *request itself* (NIST SP 800-41):
    flag any-source/any-destination, very broad CIDRs, any-service, and
    wide port ranges. Non-IP tokens are skipped — other layers validate
    them. Returns warnings only; the engineer decides."""
    warnings: list[str] = []
    any_side = {"source": False, "destination": False}

    for label, values in (("source", srcs), ("destination", dsts)):
        for v in values:
            try:
                net = ipaddress.ip_network(v, strict=False)
            except ValueError:
                continue
            broad_at = _BROAD_PREFIX_V4 if net.version == 4 else _BROAD_PREFIX_V6
            if net.prefixlen == 0:
                any_side[label] = True
                warnings.append(
                    f"Request matches ANY {label} ({v}) — least-privilege "
                    "requires scoping to the actual endpoints."
                )
            elif net.prefixlen < broad_at:
                warnings.append(
                    f"{label.capitalize()} {v} is very broad "
                    f"(wider than /{broad_at}) — confirm the whole range "
                    "genuinely needs this access."
                )

    any_service = any(r.protocol == "ip" for r in service_ranges)
    if any_service:
        warnings.append(
            "Request is for ANY service (all protocols/ports) — "
            "least-privilege requires naming the specific service(s)."
        )
    else:
        for r in service_ranges:
            if r.protocol in ("tcp", "udp", "sctp") and \
                    (r.end - r.start + 1) > _WIDE_PORT_SPAN:
                warnings.append(
                    f"Service {r.protocol}/{r.start}-{r.end} spans "
                    f"{r.end - r.start + 1} ports — confirm the application "
                    "really needs the full range."
                )

    if any_side["source"] and any_side["destination"] and any_service:
        warnings.append(
            "ANY-source to ANY-destination on ANY service is a least-privilege "
            "violation — this request should be rejected or re-scoped, not "
            "implemented as written."
        )
    return warnings


def review_requirements(risk: str, path: Path | None = None) -> dict:
    levels = _load_yaml(str(path or _REVIEW_FILE))["risk_levels"]
    if risk not in levels:
        raise KeyError(f"risk level {risk!r} not present in review_requirements.yaml")
    return dict(levels[risk], risk_level=risk)
