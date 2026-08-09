"""
First-match insertion analysis.

Given the ordered policies of a package and a candidate new rule, compute
where the rule must sit so it actually takes effect: before the first
existing policy that would otherwise match the same traffic. Also reports
which earlier policies would fully shadow the candidate and which later
policies the candidate would fully shadow.
"""

from __future__ import annotations

import ipaddress

from fortimanager_mcp.matching import PolicyMatcher, PortRange
from planner.models import InsertionPlan


def _names(field) -> list[str]:
    if isinstance(field, list):
        return [x if isinstance(x, str) else x.get("name", str(x)) for x in field]
    if isinstance(field, str):
        return [field]
    return []


def _intf_scoped(pol: dict, srcintf: str, dstintf: str) -> bool:
    """True if the policy applies to the candidate's interface pair.
    'any'/empty on either side matches; unknown candidate intf ("") matches all."""

    def _side(refs: list[str], want: str) -> bool:
        if not want:
            return True
        return any(r in ("any", "") or r == want for r in refs)

    return _side(_names(pol.get("srcintf", [])), srcintf) and \
        _side(_names(pol.get("dstintf", [])), dstintf)


def _is_catchall_deny(pol: dict) -> bool:
    return (
        pol.get("action", 0) in (0, "deny")
        and set(_names(pol.get("srcaddr", []))) <= {"all", "any"}
        and set(_names(pol.get("dstaddr", []))) <= {"all", "any"}
        and {s.lower() for s in _names(pol.get("service", []))} <= {"all", "any"}
    )


def _candidate_nets(values: list[str]):
    nets = []
    for v in values:
        try:
            nets.append(ipaddress.ip_network(v or "0.0.0.0/0", strict=False))
        except ValueError:
            return None
    return nets


def _policy_within_candidate(
    pol: dict,
    matcher: PolicyMatcher,
    srcs: list[str],
    dsts: list[str],
    service_ranges: list[PortRange],
) -> bool:
    """True if the policy's resolved match set is fully inside the candidate's
    (the candidate placed earlier would shadow it). Unknown refs → False."""
    src_nets = _candidate_nets(srcs)
    dst_nets = _candidate_nets(dsts)
    if src_nets is None or dst_nets is None:
        return False

    for key, targets in (("srcaddr", src_nets), ("dstaddr", dst_nets)):
        if pol.get(f"{key}-negate", "disable") in ("enable", 1, True):
            return False
        nets = []
        for name in _names(pol.get(key, [])):
            resolved = matcher._addr.networks_for_ref(name)
            if resolved is None:
                return False
            nets.extend(resolved)
        if not nets:
            return False
        for n in nets:
            if not any(n.version == t.version and n.subnet_of(t) for t in targets):
                return False

    pol_ranges: list[PortRange] = []
    for name in _names(pol.get("service", [])):
        resolved = matcher._svc.ranges_for_ref(name)
        if resolved is None:
            return False
        pol_ranges.extend(resolved)
    if not pol_ranges:
        return False
    return all(
        any(req.contains(r) for req in service_ranges) for r in pol_ranges
    )


def plan_insertion(
    package: str,
    ordered_policies: list[dict],
    matcher: PolicyMatcher,
    src: str | list[str],
    dst: str | list[str],
    service_ranges: list[PortRange],
    srcintf: str,
    dstintf: str,
) -> InsertionPlan:
    srcs = [src] if isinstance(src, str) else list(src)
    dsts = [dst] if isinstance(dst, str) else list(dst)
    pairs = [(s, d) for s in srcs for d in dsts]
    notes: list[str] = []
    if not srcintf or not dstintf:
        notes.append(
            "candidate interfaces not fully resolved — analysis considered all policies"
        )

    scoped = [
        pol for pol in ordered_policies
        if isinstance(pol, dict) and _intf_scoped(pol, srcintf, dstintf)
    ]

    shadowed_by: list[int] = []
    would_shadow: list[int] = []
    frontier_id: int | None = None
    frontier_pol: dict | None = None

    for pol in scoped:
        results = [matcher.evaluate(pol, s, d, service_ranges) for s, d in pairs]
        if results[0].disabled:
            continue  # disabled rules never match traffic
        pid = pol.get("policyid", 0)

        if frontier_id is None:
            if not any(r.matched for r in results):
                continue
            frontier_id = pid
            frontier_pol = pol
            # only a rule covering EVERY pair truly shadows the candidate
            if all(r.full_cover for r in results):
                shadowed_by.append(pid)

        # every policy at or after the frontier that sits fully inside the
        # candidate's match set would be shadowed by the inserted rule
        if _policy_within_candidate(pol, matcher, srcs, dsts, service_ranges):
            would_shadow.append(pid)

    if frontier_id is not None:
        action = "deny" if frontier_pol.get("action", 0) in (0, "deny") else "accept"
        rationale = (
            f"Must precede policy {frontier_id} ({action}, "
            f"'{frontier_pol.get('name', '')}') in package '{package}' — it is the "
            "first enabled rule that would otherwise match this traffic."
        )
        if shadowed_by:
            rationale += (
                " NOTE: that rule fully covers the requested flow; placing the new"
                " rule after it would make the new rule dead."
            )
        insert_before = frontier_id
    else:
        # nothing overlaps — append, but stay above a final catch-all deny
        catchall = next((p for p in reversed(scoped) if _is_catchall_deny(p)), None)
        if catchall is not None:
            insert_before = catchall.get("policyid", 0)
            rationale = (
                f"No existing policy overlaps this flow; place before the final "
                f"catch-all deny (policy {insert_before}) in package '{package}'."
            )
        else:
            insert_before = None
            rationale = (
                f"No existing policy overlaps this flow and no catch-all deny found —"
                f" append at the end of package '{package}'."
            )

    if notes:
        rationale += " (" + "; ".join(notes) + ")"

    return InsertionPlan(
        package=package,
        insert_before_policy_id=insert_before,
        rationale=rationale,
        shadowed_by=shadowed_by,
        would_shadow=would_shadow,
    )
