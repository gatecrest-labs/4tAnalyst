"""
Core policy evaluation logic adapted from zone-script/query_flow.py.

This module is stateless — callers load the DB once and pass it in.
All public functions are pure (no side effects, no file I/O).
"""

import ipaddress
import re
from typing import Any

# ---------------------------------------------------------------------------
# Port → service name aliases (used for "block only" service matching)
# ---------------------------------------------------------------------------

_PORT_TO_NAMES: dict[int, list[str]] = {
    20:   ["ftp-data", "ftp"],
    21:   ["ftp"],
    22:   ["ssh"],
    23:   ["telnet"],
    25:   ["smtp"],
    53:   ["dns"],
    80:   ["http"],
    110:  ["pop3"],
    143:  ["imap"],
    161:  ["snmp"],
    162:  ["snmp-trap", "snmp"],
    389:  ["ldap"],
    443:  ["https"],
    445:  ["smb", "cifs"],
    514:  ["syslog"],
    636:  ["ldaps"],
    1433: ["mssql", "sql"],
    1521: ["oracle"],
    3306: ["mysql"],
    3389: ["rdp", "RDP"],
    5432: ["postgresql", "postgres"],
    5900: ["vnc"],
    8080: ["http-alt", "http"],
    8443: ["https-alt", "https"],
}


def _service_aliases(token: str) -> list[str]:
    """
    Expand a service token to all names that should match against a policy
    service list.  Accepts: "ssh", "RDP", "22", "3389", "tcp/22", "udp/514".
    """
    aliases: list[str] = [token]
    m = re.fullmatch(r"(?:tcp|udp|icmp)/(\d+)", token, re.IGNORECASE)
    port_str = m.group(1) if m else (token if token.isdigit() else None)
    if port_str is not None:
        port = int(port_str)
        if m and str(port) not in aliases:
            aliases.append(str(port))
        for name in _PORT_TO_NAMES.get(port, []):
            if name not in aliases:
                aliases.append(name)
    return aliases


# ---------------------------------------------------------------------------
# IP / subnet helpers
# ---------------------------------------------------------------------------

def parse_endpoint(raw: str):
    """Return an ip_network or ip_address from a bare IP, CIDR, or dotted-decimal mask."""
    if "/" in raw:
        host, mask = raw.split("/", 1)
        if "." in mask:
            try:
                prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
                raw = f"{host}/{prefix_len}"
            except ValueError:
                pass
        return ipaddress.ip_network(raw, strict=False)
    return ipaddress.ip_address(raw)


def _overlaps(query, zone_net) -> bool:
    if isinstance(query, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return query in zone_net
    return query.overlaps(zone_net)


def zones_for_endpoint(raw: str, zones: dict) -> list[str]:
    """
    Return zone names (most-specific first) whose subnets overlap the given IP/CIDR.
    Public IPs with no match are assigned to the implicit "Internet" zone.
    Returns an empty list for private IPs with no subnet match.
    """
    endpoint = parse_endpoint(raw)
    matches: list[tuple[int, str]] = []
    for name, zone in zones.items():
        for entry in zone.get("subnets", []):
            try:
                network = ipaddress.ip_network(entry["subnet"], strict=False)
            except ValueError:
                continue
            if _overlaps(endpoint, network):
                matches.append((network.prefixlen, name))

    if not matches:
        if isinstance(endpoint, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            is_public = endpoint.is_global and not endpoint.is_private
        else:
            is_public = not endpoint.is_private
        return ["Internet"] if is_public else []

    matches.sort(key=lambda x: x[0], reverse=True)
    seen: set[str] = set()
    result: list[str] = []
    for _, name in matches:
        if name not in seen:
            seen.add(name)
            result.append(name)
    return result


# ---------------------------------------------------------------------------
# Zone hierarchy
# ---------------------------------------------------------------------------

def ancestor_zones(zone_name: str, zones: dict) -> list[str]:
    """Return the zone itself plus all ancestors (BFS)."""
    result: list[str] = []
    visited: set[str] = set()
    queue = [zone_name]
    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        result.append(current)
        for parent in zones.get(current, {}).get("parents", []):
            queue.append(parent)
    return result


# ---------------------------------------------------------------------------
# Policy matching
# ---------------------------------------------------------------------------

def find_matching_policies(
    src_zones: list[str],
    dst_zones: list[str],
    zones: dict,
    policies: list[dict],
) -> list[dict]:
    """
    Return all policies covering any (src_ancestor, dst_ancestor) pair.
    Each result is annotated with matched_from_zone and matched_to_zone.
    """
    src_candidates: list[str] = []
    for z in src_zones:
        for a in ancestor_zones(z, zones):
            if a not in src_candidates:
                src_candidates.append(a)

    dst_candidates: list[str] = []
    for z in dst_zones:
        for a in ancestor_zones(z, zones):
            if a not in dst_candidates:
                dst_candidates.append(a)

    matched: list[dict] = []
    seen: set[tuple] = set()
    for policy in policies:
        for src_name in src_candidates:
            if policy["from_zone"] != src_name:
                continue
            for dst_name in dst_candidates:
                if policy["to_zone"] != dst_name:
                    continue
                key = (policy["policy_set"], src_name, dst_name, policy["access_type"])
                if key in seen:
                    continue
                seen.add(key)
                matched.append({**policy, "matched_from_zone": src_name, "matched_to_zone": dst_name})
    return matched


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

def evaluate(policies: list[dict], services: list[str]) -> tuple[str, list[dict]]:
    """
    Return (verdict, governing_rules).

    verdict is one of:
      "ALLOWED"     — traffic is explicitly permitted
      "BLOCKED"     — traffic is explicitly denied
      "UNKNOWN"     — no policy covers this zone pair (treat as implicit deny)

    Precedence:
      1. block all   → BLOCKED
      2. block only + service matches → BLOCKED
      3. allow all   → ALLOWED
      4. allow only + service in list → ALLOWED
      5. allow only + service not in list → BLOCKED (allow-list is exhaustive)
      6. block only + service not in list → ALLOWED
      7. no rules    → UNKNOWN

    An "allow only" policy queried without a service counts as ALLOWED —
    the zone pair is at least partially open.
    """
    if not policies:
        return "UNKNOWN", []

    for p in policies:
        if p["access_type"] == "block all":
            return "BLOCKED", [p]

    alias_sets = [_service_aliases(t) for t in services] if services else []

    def _service_listed(p: dict) -> bool:
        rule_lower = [s.lower() for s in p["services"]]
        return any(alias.lower() in rule_lower
                   for aliases in alias_sets for alias in aliases)

    if services:
        for p in policies:
            if p["access_type"] == "block only" and _service_listed(p):
                return "BLOCKED", [p]

    for p in policies:
        if p["access_type"] == "allow all":
            return "ALLOWED", [p]

    allow_only = [p for p in policies if p["access_type"] == "allow only"]
    if allow_only:
        if not services:
            return "ALLOWED", allow_only
        for p in allow_only:
            if _service_listed(p):
                return "ALLOWED", [p]
        return "BLOCKED", allow_only

    return "ALLOWED", policies


# ---------------------------------------------------------------------------
# High-level convenience: check a traffic flow end-to-end
# ---------------------------------------------------------------------------

def check_traffic_flow(
    src: str,
    dst: str,
    services: list[str],
    db: dict,
) -> dict[str, Any]:
    """
    Given src/dst IPs or CIDRs, resolve zones and return a structured result:
    {
      "src": str,
      "dst": str,
      "src_zones": [str, ...],
      "dst_zones": [str, ...],
      "services": [str, ...],
      "verdict": "ALLOWED" | "BLOCKED" | "UNKNOWN",
      "governing_rules": [{...}, ...],
    }
    """
    zones = db["zones"]
    policies = db["policies"]

    src_zones = zones_for_endpoint(src, zones)
    dst_zones = zones_for_endpoint(dst, zones)
    all_matched = find_matching_policies(src_zones, dst_zones, zones, policies)
    verdict, governing = evaluate(all_matched, services)

    return {
        "src": src,
        "dst": dst,
        "src_zones": src_zones,
        "dst_zones": dst_zones,
        "services": services,
        "verdict": verdict,
        "governing_rules": governing,
    }


def build_zone_matrix(db: dict) -> list[dict[str, Any]]:
    """
    Return every zone pair that has at least one explicit policy rule, with its
    effective verdict (no service filter applied — use check_traffic for service-aware queries).

    Each entry:
    {
      "src_zone": str,
      "dst_zone": str,
      "verdict": "ALLOWED" | "BLOCKED" | "UNKNOWN",
      "policy_sets": [str, ...],   # which policy sets cover this pair
      "severity": str,             # highest severity seen
      "services_blocked": [str, ...]  # services named in block-only rules
    }
    """
    zones = db["zones"]
    policies = db["policies"]

    # Collect all (from_zone, to_zone) pairs that appear explicitly in policies
    pairs: set[tuple[str, str]] = set()
    for p in policies:
        pairs.add((p["from_zone"], p["to_zone"]))

    severity_rank = {"critical": 2, "high": 1, "": 0}

    matrix: list[dict] = []
    for src_zone, dst_zone in sorted(pairs):
        matched = find_matching_policies([src_zone], [dst_zone], zones, policies)
        verdict, _ = evaluate(matched, [])

        policy_sets = list({p["policy_set"] for p in matched})
        top_severity = max(
            (p.get("severity", "") for p in matched),
            key=lambda s: severity_rank.get(s, 0),
            default="",
        )
        blocked_services: list[str] = []
        for p in matched:
            if p["access_type"] == "block only":
                for svc in p["services"]:
                    if svc not in blocked_services:
                        blocked_services.append(svc)

        matrix.append({
            "src_zone": src_zone,
            "dst_zone": dst_zone,
            "verdict": verdict,
            "policy_sets": policy_sets,
            "severity": top_severity,
            "services_blocked": blocked_services,
        })

    return matrix
