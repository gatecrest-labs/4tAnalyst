"""
The change planning engine — the deterministic core of 4tAnalyst.

plan_change() takes a normalized flow plus named firewalls and computes the
entire change plan: zone verdict (live 4THealth), existing-rule coverage
(FortiManager, set semantics), object reuse vs. create, rule insertion point
(first-match shadowing analysis), naming/logging/approval requirements, and
the FortiGate CLI. to_report_payload() emits the exact schema
scripts/render_report.py validates.

The LLM layer must call this and relay the result; it must never recompute
or edit any part of the plan.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from functools import lru_cache
from pathlib import Path

import yaml

from fortimanager_mcp.client import FortiManagerAPIError, FortiManagerClient
from fortimanager_mcp.matching import PolicyMatcher, parse_service_request
from fortimanager_mcp.matching import _names as _ref_names
from planner import cli_gen, standards
from planner.fetch import (
    DeviceSnapshot,
    fetch_device_snapshot,
    fetch_zone_domains,
    fetch_zone_verdict,
)
from planner.insertion import plan_insertion
from planner.models import (
    ChangePlan,
    FirewallPlan,
    GroupAppendAlternative,
    InsertionPlan,
    NormalizedFlow,
    ObjectPlan,
    PlannerDataError,
    TargetFirewall,
)
from zone_mcp.client import ZonePolicyClient

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# Default client construction (credentials.yaml) — injected in tests
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _load_creds() -> dict:
    creds_path = Path(os.getenv("CREDENTIALS_FILE", str(_REPO_ROOT / "credentials.yaml")))
    if not creds_path.exists():
        raise PlannerDataError(
            "credentials",
            f"credentials.yaml not found at {creds_path} — copy credentials.yaml.example",
        )
    with open(creds_path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _default_fmg_client() -> FortiManagerClient:
    cfg = _load_creds().get("fortimanager", {})
    hosts = [(h.get("host", ""), h.get("api_key", "")) for h in cfg.get("hosts", [])]
    hosts = [(h, k) for h, k in hosts if h and k]
    if not hosts:
        raise PlannerDataError("credentials", "fortimanager.hosts is empty in credentials.yaml")
    primary = hosts[0]
    secondary = hosts[1] if len(hosts) > 1 else ("", "")
    client = FortiManagerClient(
        primary_host=primary[0], primary_key=primary[1],
        secondary_host=secondary[0], secondary_key=secondary[1],
        port=int(cfg.get("port", 443)),
        verify_ssl=bool(cfg.get("verify_ssl", True)),
        version=str(cfg.get("version", "7.4")),
    )
    client.login()
    return client


def _default_zone_client() -> ZonePolicyClient:
    cfg = _load_creds().get("zone_policy", {})
    if not cfg.get("base_url") or not cfg.get("token"):
        raise PlannerDataError("credentials", "zone_policy.base_url/token missing in credentials.yaml")
    return ZonePolicyClient(
        base_url=cfg["base_url"],
        token=cfg["token"],
        verify_ssl=bool(cfg.get("verify_ssl", False)),
        timeout=float(cfg.get("timeout", 30.0)),
    )


# ---------------------------------------------------------------------------
# Object planning
# ---------------------------------------------------------------------------

def _normalize_cidr(ip: str) -> str:
    net = ipaddress.ip_network(ip, strict=False)
    return str(net)


def _address_object_plan(role: str, ip: str, snapshot: DeviceSnapshot) -> ObjectPlan:
    cidr = _normalize_cidr(ip)
    existing = snapshot.addr_catalog.exact_match_name(cidr)
    if existing:
        return ObjectPlan(role=role, action="reuse", name=existing,
                          obj_type="host" if cidr.endswith("/32") else "network",
                          value=cidr)
    if cidr.endswith("/32"):
        name = standards.object_name("host", ip=cidr)
        obj_type = "host"
    else:
        name = standards.object_name("network", ip=cidr)
        obj_type = "network"
    return ObjectPlan(role=role, action="create", name=name, obj_type=obj_type,
                      value=cidr, cli=cli_gen.address_object_cli(name, cidr))


def _service_object_plan(token: str, snapshot: DeviceSnapshot) -> ObjectPlan:
    ranges = parse_service_request(token)
    if any(r.protocol == "ip" for r in ranges):
        # wildcard service — FortiGate's built-in ALL object, never created
        return ObjectPlan(role="service", action="reuse", name="ALL",
                          obj_type="service", value=token)
    existing = snapshot.svc_catalog.exact_match_name(ranges)
    if existing:
        return ObjectPlan(role="service", action="reuse", name=existing,
                          obj_type="service", value=token)
    r = ranges[0]
    port_expr = str(r.start) if r.start == r.end else f"{r.start}-{r.end}"
    name = standards.object_name("service", proto=r.protocol, port=port_expr)
    return ObjectPlan(role="service", action="create", name=name,
                      obj_type="service", value=f"{r.protocol}/{port_expr}",
                      cli=cli_gen.service_object_cli(name, r.protocol, port_expr))


# Sides with more members than this get a dedicated address group; smaller
# sets are inlined directly in the policy's srcaddr/dstaddr.
GROUP_THRESHOLD = 3


def _side_plan(
    objs: list[ObjectPlan], explicit_group: str, ticket_id: str, tag: str,
) -> tuple[list[str], list[ObjectPlan]]:
    """Return (policy member refs, extra group ObjectPlans) for one side."""
    names = [o.name for o in objs]
    if explicit_group or len(names) > GROUP_THRESHOLD:
        gname = explicit_group or f"GRP_{ticket_id or '<TICKET_ID>'}_{tag}"
        group = ObjectPlan(
            role=f"{'source' if tag == 'SRC' else 'destination'}-group",
            action="create", name=gname, obj_type="group",
            value=", ".join(names),
            cli=cli_gen.addrgrp_create_cli(gname, names),
        )
        return [gname], [group]
    return names, []


# ---------------------------------------------------------------------------
# Per-firewall planning
# ---------------------------------------------------------------------------

def _plan_firewall(
    target: TargetFirewall,
    flow: NormalizedFlow,
    zone_verdict: dict,
    log_cfg: dict,
    ticket_id: str,
    fmg_client,
    plan_warnings: list[str],
    src_group: str = "",
    dst_group: str = "",
) -> FirewallPlan:
    try:
        snapshot = fetch_device_snapshot(fmg_client, target.adom, target.device)
    except PlannerDataError as exc:
        status = "not_found" if "not found" in exc.detail else "error"
        return FirewallPlan(
            firewall=target.device, adom=target.adom, status=status,
            warnings=[str(exc)],
        )

    fw = FirewallPlan(firewall=target.device, adom=target.adom, status="new_rule")
    fw.warnings.extend(snapshot.zone_map_warnings)
    if snapshot.degraded:
        msg = (
            f"FortiManager data for {target.device} is incomplete "
            f"({'; '.join(snapshot.failures)}) — 'no existing rule' is NOT conclusive."
        )
        fw.warnings.append(msg)
        plan_warnings.append(msg)

    matcher = PolicyMatcher(snapshot.addr_catalog, snapshot.svc_catalog)

    # Interfaces are resolved up front: coverage must be judged only against
    # rules that apply to the flow's interface pair — a broad LAN->WAN accept
    # rule does not cover an east-west flow on a real FortiGate.
    fw.srcintf = _resolve_side_interface(
        snapshot, flow.srcs, zone_verdict.get("src_zones", []), "Source", fw.warnings)
    fw.dstintf = _resolve_side_interface(
        snapshot, flow.dsts, zone_verdict.get("dst_zones", []), "Destination", fw.warnings)

    # --- existing-rule coverage -------------------------------------------
    # A consolidated request is covered only if EVERY src×dst pair is fully
    # covered (possibly by different rules).
    from fortimanager_mcp.query import _summarise_policy
    from planner.insertion import _intf_scoped

    pairs = flow.pairs
    pair_covered: dict[tuple[str, str], list[int]] = {p: [] for p in pairs}
    for pkg, policies in snapshot.policies_by_package.items():
        for pol in policies:
            results = {p: matcher.evaluate(pol, p[0], p[1], flow.service_ranges)
                       for p in pairs}
            if not any(r.matched for r in results.values()):
                continue
            summary = _summarise_policy(pol, pkg)
            any_r = next(iter(results.values()))
            conditions_ok = (
                any_r.action == "accept" and not any_r.disabled
                and not any_r.conditional_schedule
                and not any(r.unknown_refs for r in results.values())
                and _intf_scoped(pol, fw.srcintf, fw.dstintf)
            )
            full_pairs = [p for p, r in results.items() if r.full_cover]
            summary["full_cover"] = conditions_ok and len(full_pairs) == len(pairs)
            if conditions_ok and full_pairs:
                for p in full_pairs:
                    pair_covered[p].append(pol.get("policyid", 0))
                if len(full_pairs) < len(pairs):
                    summary["covered_pairs"] = [f"{s} -> {d}" for s, d in full_pairs]
                fw.covering_rules.append(summary)
            else:
                # Skip disabled rules — they have no effect on traffic.
                # Skip rules where the service dimension has no overlap with
                # the requested service and no unknown service refs; those are
                # noise (e.g. an ICMP rule when tcp/22 was requested).
                if any_r.disabled:
                    continue
                svc_m, _ = matcher.svc_side(pol, flow.service_ranges)
                if not svc_m:
                    continue
                fw.partial_matches.append(summary)

    uncovered = [p for p in pairs if not pair_covered[p]]
    if not uncovered and not snapshot.degraded:
        fw.status = "already_covered"
        return fw
    if len(uncovered) < len(pairs):
        covered_ids = sorted({pid for ids in pair_covered.values() for pid in ids})
        fw.warnings.append(
            f"{len(pairs) - len(uncovered)} of {len(pairs)} flow pair(s) are "
            f"already covered by existing rule(s) {covered_ids} — the "
            "consolidated rule will overlap that coverage."
        )

    # --- new rule (or exception) -------------------------------------------

    src_objs = _dedupe_objects(
        [_address_object_plan("source", s, snapshot) for s in flow.srcs])
    dst_objs = _dedupe_objects(
        [_address_object_plan("destination", d, snapshot) for d in flow.dsts])
    svc_objs = _dedupe_objects(
        [_service_object_plan(tok, snapshot) for tok in flow.services])

    src_refs, src_groups = _side_plan(src_objs, src_group, ticket_id, "SRC")
    dst_refs, dst_groups = _side_plan(dst_objs, dst_group, ticket_id, "DST")
    fw.objects = src_objs + src_groups + dst_objs + dst_groups + svc_objs

    fw.policy_name = standards.policy_name(
        ticket_id,
        fw.srcintf or "<SET_SRC_INTERFACE>",
        fw.dstintf or "<SET_DST_INTERFACE>",
    )

    # insertion analysis on the package where the traffic would be evaluated:
    # the first package that has any overlapping policy, else the first fetched
    insertion: InsertionPlan | None = None
    pkg_for_insertion = None
    for pkg, policies in snapshot.policies_by_package.items():
        if any(matcher.evaluate(p, s, d, flow.service_ranges).matched
               for p in policies for s, d in pairs):
            pkg_for_insertion = pkg
            break
    if pkg_for_insertion is None and snapshot.policies_by_package:
        pkg_for_insertion = next(iter(snapshot.policies_by_package))
    if pkg_for_insertion is not None:
        insertion = plan_insertion(
            pkg_for_insertion,
            snapshot.policies_by_package[pkg_for_insertion],
            matcher, flow.srcs, flow.dsts, flow.service_ranges,
            fw.srcintf, fw.dstintf,
        )
        if insertion.shadowed_by:
            fw.warnings.append(
                f"Policies {insertion.shadowed_by} already fully match this flow "
                "(non-accept or conditional) — review before inserting."
            )
        if insertion.would_shadow:
            fw.warnings.append(
                f"The new rule would shadow existing policies {insertion.would_shadow} "
                "— consider consolidating instead of adding."
            )
    fw.insertion = insertion

    blocked = zone_verdict.get("verdict") == "BLOCKED"
    comments = cli_gen.exception_comment(ticket_id) if blocked else "Ticket <TICKET_ID>"

    fw.policy_cli = cli_gen.policy_cli(
        name=fw.policy_name,
        srcintf=fw.srcintf or "<SET_SRC_INTERFACE>",
        dstintf=fw.dstintf or "<SET_DST_INTERFACE>",
        srcaddr=src_refs,
        dstaddr=dst_refs,
        service=[o.name for o in svc_objs],
        logtraffic="all" if log_cfg.get("log_end", True) else "disable",
        logtraffic_start=bool(log_cfg.get("log_start", False)),
        comments=comments,
        insert_before=insertion.insert_before_policy_id if insertion else None,
    )

    fw.alternative = _group_append_alternative(fw, snapshot, matcher, flow, fmg_client)
    if fw.alternative:
        alt = fw.alternative
        member_names = ", ".join(m.name for m in alt.members)
        if alt.group:
            others = len(alt.affected_policies)
            fw.warnings.append(
                f"Alternative: rule #{alt.policy_id} {alt.policy_name!r} already covers "
                f"everything except the {alt.side} — appending {member_names} to "
                f"group {alt.group!r} would cover this flow without a new policy "
                f"({others} other rule(s) reference that group). Choose ONE option."
            )
        else:
            fw.warnings.append(
                f"Alternative: rule #{alt.policy_id} {alt.policy_name!r} already covers "
                f"everything except the {alt.side} — adding {member_names} directly to "
                "the rule's source address list would cover this flow without a new policy "
                "(only this rule is affected). Choose ONE option."
            )
    return fw


def _dedupe_objects(objs: list[ObjectPlan]) -> list[ObjectPlan]:
    seen: set[str] = set()
    out: list[ObjectPlan] = []
    for o in objs:
        if o.name not in seen:
            seen.add(o.name)
            out.append(o)
    return out


def _resolve_side_interface(
    snapshot, members: list[str], zones: list[str], label: str,
    warnings: list[str],
) -> str:
    """One interface for a whole side. All members must resolve to the same
    interface; a conflict yields "" plus a warning — never a silent pick."""
    from planner.fetch import resolve_interface

    resolved: dict[str, str] = {}
    for m in members:
        name, w = resolve_interface(snapshot, m, zones, label)
        warnings.extend(x for x in w if x not in warnings)
        resolved[m] = name
    distinct = sorted({v for v in resolved.values() if v})
    if len(distinct) > 1:
        detail = ", ".join(f"{m}→{v or '?'}" for m, v in resolved.items())
        warnings.append(
            f"{label} members resolve to different interfaces ({detail}) — a "
            "single consolidated rule cannot carry both; set the interface "
            "manually or split the request."
        )
        return ""
    return distinct[0] if distinct else ""


def _group_append_alternative(
    fw: FirewallPlan,
    snapshot,
    matcher: PolicyMatcher,
    flow: NormalizedFlow,
    client,
) -> GroupAppendAlternative | None:
    """Find the best near-miss rule where the only gap is one address side,
    and propose extending it instead of creating a new policy.

    Two extension modes are offered:
    - Group-append: the failing side references a named address group →
      append the missing endpoint to that group. Carries full blast radius.
    - Direct-append: the failing side is a concrete host/subnet list with no
      group → add the missing endpoint directly to the rule's address list.
      Only that one rule is affected (no blast radius).

    All qualifying candidates across every package are collected, then ranked
    by the specificity of the non-failing sides (count of non-"all" address
    refs). A direct-append candidate receives a +1 tiebreaker because it has
    a smaller blast radius than an equivalent group-append.

    Rules must be enabled, accept, unconditional, interface-scoped, and have
    no unknown refs. The failing side must be non-negated and non-empty (an
    unconstrained "all" source/destination is skipped for direct-append since
    the rule already matches anything).
    """
    from planner.insertion import _intf_scoped

    candidates: list[tuple[int, GroupAppendAlternative]] = []

    for pkg, policies in snapshot.policies_by_package.items():
        for pol in policies:
            results = [matcher.evaluate(pol, s, d, flow.service_ranges)
                       for s, d in flow.pairs]
            r = results[0]
            if (r.disabled or r.conditional_schedule or r.action != "accept"
                    or any(x.unknown_refs for x in results)
                    or all(x.full_cover for x in results)):
                continue
            if not _intf_scoped(pol, fw.srcintf, fw.dstintf):
                continue
            _, svc_full = matcher.svc_side(pol, flow.service_ranges)
            if not svc_full:
                continue
            src_fulls = {s: matcher.addr_side(pol, "srcaddr", s)[1] for s in flow.srcs}
            dst_fulls = {d: matcher.addr_side(pol, "dstaddr", d)[1] for d in flow.dsts}
            for side, key, other_key, missing, other_all_full in (
                ("destination", "dstaddr", "srcaddr",
                 [d for d, f in dst_fulls.items() if not f],
                 all(src_fulls.values())),
                ("source", "srcaddr", "dstaddr",
                 [s for s, f in src_fulls.items() if not f],
                 all(dst_fulls.values())),
            ):
                if not missing or not other_all_full:
                    continue
                if pol.get(f"{key}-negate", "disable") in ("enable", 1, True):
                    continue  # appending to a negated side REMOVES access

                # Specificity: how many non-"all" refs the non-failing side has.
                # A rule with an exact destination host scores higher than one
                # with destination "all", so we prefer the narrower match.
                other_refs = list(_ref_names(pol.get(other_key, [])))
                specificity = sum(1 for ref in other_refs if ref.lower() != "all")

                group = next(
                    (n for n in _ref_names(pol.get(key, []))
                     if snapshot.addr_catalog.is_group(n)), None,
                )
                members = [_address_object_plan(side, t, snapshot) for t in missing]

                if group is not None:
                    affected, scan_warnings = _group_blast_radius(
                        client, snapshot, group,
                        exclude=(pkg, pol.get("policyid", 0)),
                    )
                    warnings = list(scan_warnings)
                    if affected:
                        warnings.append(
                            f"Appending to group {group!r} also changes "
                            f"{len(affected)} other rule(s) — review each before "
                            "choosing this option."
                        )
                    else:
                        warnings.append(
                            f"No other rule references group {group!r} — the append "
                            "affects only the rule above."
                        )
                    candidates.append((specificity, GroupAppendAlternative(
                        package=pkg,
                        policy_id=pol.get("policyid", 0),
                        policy_name=pol.get("name", ""),
                        side=side,
                        group=group,
                        members=members,
                        group_cli=cli_gen.addrgrp_append_cli(
                            group, [m.name for m in members]),
                        affected_policies=affected,
                        warnings=warnings,
                    )))
                else:
                    # Direct-append: the failing side has concrete refs, no group.
                    # Skip if unconstrained ("all") — the rule would already match.
                    failing_refs = list(_ref_names(pol.get(key, [])))
                    if not failing_refs or failing_refs == ["all"]:
                        continue
                    member_names = [m.name for m in members]
                    # +1 tiebreaker: no blast radius beats an equal-specificity group
                    candidates.append((specificity + 1, GroupAppendAlternative(
                        package=pkg,
                        policy_id=pol.get("policyid", 0),
                        policy_name=pol.get("name", ""),
                        side=side,
                        group=None,
                        members=members,
                        direct_cli=cli_gen.policy_addr_append_cli(
                            pol.get("policyid", 0), key, member_names),
                        warnings=[
                            f"Adding {', '.join(member_names)} directly to rule "
                            f"#{pol.get('policyid', 0)} {side} address list — "
                            "only this rule is affected."
                        ],
                    )))

    if not candidates:
        return None
    return max(candidates, key=lambda c: c[0])[1]


def _group_blast_radius(
    client, snapshot, group: str, exclude: tuple[str, int],
) -> tuple[list[dict], list[str]]:
    """Every policy in the ADOM referencing `group` directly or through a
    parent group — the set of rules whose behaviour changes on append."""
    names = {group} | snapshot.addr_catalog.groups_containing(group)
    affected: list[dict] = []
    warnings: list[str] = []

    try:
        all_pkgs = [
            p.get("name", "") for p in client.get_policy_packages(snapshot.adom)
            if isinstance(p, dict)
        ]
    except FortiManagerAPIError as exc:
        return [], [f"Blast-radius scan incomplete — cannot list packages: {exc}"]

    for pkg in all_pkgs:
        policies = snapshot.policies_by_package.get(pkg)
        if policies is None:
            try:
                policies = [
                    p for p in client.get_policies(snapshot.adom, pkg)
                    if isinstance(p, dict)
                ]
            except FortiManagerAPIError as exc:
                warnings.append(
                    f"Blast-radius scan incomplete — package {pkg!r} could not "
                    f"be read: {exc}"
                )
                continue
        for pol in policies:
            pid = pol.get("policyid", 0)
            if (pkg, pid) == exclude:
                continue
            for key, label in (("srcaddr", "source"), ("dstaddr", "destination")):
                via = sorted(set(_ref_names(pol.get(key, []))) & names)
                if via:
                    affected.append({
                        "package": pkg,
                        "policy_id": pid,
                        "name": pol.get("name", ""),
                        "side": label,
                        "status": pol.get("status", "enable"),
                        "via": via,
                    })
    return affected, warnings


# ---------------------------------------------------------------------------
# Recommendation text (fixed templates — no free-form generation)
# ---------------------------------------------------------------------------

def _recommendation(plan_status: str, verdict: str, firewalls: list[FirewallPlan],
                    risk: str, warnings: list[str],
                    zone_verdict: dict | None = None) -> str:
    if plan_status == "unknown_no_action":
        return (
            "Zone verdict is UNKNOWN — at least one IP did not resolve to a known "
            "zone. Verify the IPs with the requester and/or update the 4THealth "
            "zone catalogue. No change should be implemented until resolved."
        )
    if plan_status == "already_covered":
        return (
            "Traffic is permitted by zone policy and every named firewall already "
            "has an enabled rule covering this exact flow. No change required — "
            "close the request citing the existing rules listed above."
        )
    lines = []
    if plan_status == "blocked_exception":
        governing = (zone_verdict or {}).get("governing", [])
        blocking_policy = next(
            (g.get("policy_set", "") for g in governing
             if g.get("access_type", "").startswith("block")),
            None,
        )
        block_detail = (
            f" Blocked by: \"{blocking_policy}\"." if blocking_policy else ""
        )
        lines.append(
            f"Zone policy BLOCKS this flow.{block_detail} The generated CLI "
            "implements an EXCEPTION and must not be pushed until the approval "
            f"chain (risk level: {risk}) has signed off."
        )
    else:
        lines.append(
            "Traffic is permitted by zone policy but not yet implemented on: "
            + ", ".join(f.firewall for f in firewalls if f.status == "new_rule")
            + f". Implement the generated objects and policy (risk level: {risk})."
        )
    not_found = [f.firewall for f in firewalls if f.status in ("not_found", "error")]
    if not_found:
        lines.append(
            "Could not analyse: " + ", ".join(not_found) + " — verify the device "
            "names/ADOM with FortiManager before proceeding."
        )
    if warnings:
        lines.append("Review the warnings section before implementation.")
    return " ".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _norm_list(value: str | list[str], label: str) -> list[str]:
    """Accept a comma-separated string or a list; return clean tokens."""
    if isinstance(value, str):
        tokens = [t.strip() for t in value.split(",") if t.strip()]
    else:
        tokens = [str(t).strip() for t in value if str(t).strip()]
    if not tokens:
        raise PlannerDataError("request", f"{label} must have at least one value")
    return tokens


def _consolidated_zone_verdict(
    zc: ZonePolicyClient, srcs: list[str], dsts: list[str], services: list[str],
) -> dict:
    """One aggregated verdict across every src×dst×service combination.

    Mixed ALLOWED+BLOCKED means the request cannot be one consolidated rule —
    that is a request problem, not a data problem, and the caller must split
    it. Any UNKNOWN combination makes the whole request UNKNOWN (fail safe).
    """
    verdicts: dict[str, list[str]] = {}
    src_zones: list[str] = []
    dst_zones: list[str] = []
    governing: list = []
    all_policies: list = []
    notes: list[str] = []
    seen_gov: set[str] = set()

    for s in srcs:
        for d in dsts:
            for svc in services:
                r = fetch_zone_verdict(zc, s, d, svc)
                v = r.get("verdict", "UNKNOWN")
                verdicts.setdefault(v, []).append(f"{s} -> {d} ({svc})")
                for z in r.get("src_zones", []):
                    if z not in src_zones:
                        src_zones.append(z)
                for z in r.get("dst_zones", []):
                    if z not in dst_zones:
                        dst_zones.append(z)
                for g in r.get("governing", []):
                    key = repr(g)
                    if key not in seen_gov:
                        seen_gov.add(key)
                        governing.append(g)
                all_policies.extend(r.get("all_policies", []))
                for n in r.get("notes", []):
                    if n not in notes:
                        notes.append(n)

    if "UNKNOWN" in verdicts:
        verdict = "UNKNOWN"
        notes.append(
            "Verdict UNKNOWN for: " + "; ".join(verdicts["UNKNOWN"])
            + " — no combination may be implemented until resolved."
        )
    elif "ALLOWED" in verdicts and "BLOCKED" in verdicts:
        raise PlannerDataError(
            "request",
            "Zone policy gives mixed verdicts — ALLOWED for "
            + "; ".join(verdicts["ALLOWED"]) + " but BLOCKED for "
            + "; ".join(verdicts["BLOCKED"])
            + ". A single consolidated rule cannot carry both: split the "
            "request into one per verdict and re-run.",
        )
    else:
        verdict = next(iter(verdicts))

    return {
        "src_ip": ", ".join(srcs),
        "dst_ip": ", ".join(dsts),
        "service": ", ".join(services),
        "verdict": verdict,
        "src_zones": src_zones,
        "dst_zones": dst_zones,
        "governing": governing,
        "all_policies": all_policies,
        "notes": notes,
    }


def plan_change(
    *,
    src: str | list[str],
    dst: str | list[str],
    service: str | list[str],
    firewalls: list[TargetFirewall],
    justification: str = "",
    ticket_id: str = "",
    src_group: str = "",
    dst_group: str = "",
    fmg_client: FortiManagerClient | None = None,
    zone_client: ZonePolicyClient | None = None,
) -> ChangePlan:
    """Compute the full deterministic change plan for one consolidated
    request. src/dst/service accept a single value, a comma-separated
    string, or a list; the plan emits ONE policy per firewall covering
    every combination."""
    srcs = _norm_list(src, "src")
    dsts = _norm_list(dst, "dst")
    services = _norm_list(service, "service")

    service_ranges = []
    for tok in services:
        try:
            service_ranges.extend(parse_service_request(tok))
        except ValueError as exc:
            raise PlannerDataError("request", str(exc)) from exc

    flow = NormalizedFlow(src=", ".join(srcs), dst=", ".join(dsts),
                          service=", ".join(services),
                          srcs=srcs, dsts=dsts, services=services,
                          service_ranges=service_ranges,
                          justification=justification)

    zc = zone_client or _default_zone_client()
    zone_verdict = _consolidated_zone_verdict(zc, srcs, dsts, services)
    zone_domains = fetch_zone_domains(zc)

    src_zones = zone_verdict.get("src_zones", [])
    dst_zones = zone_verdict.get("dst_zones", [])
    verdict = zone_verdict.get("verdict", "UNKNOWN")

    risk = standards.risk_level(src_zones, dst_zones, zone_domains)
    src_domains = {zone_domains.get(z, "") for z in src_zones} - {""}
    dst_domains = {zone_domains.get(z, "") for z in dst_zones} - {""}
    # The catch-all zone named "Internet" is the internet whatever domain
    # label the catalogue happens to give it.
    if "Internet" in src_zones:
        src_domains.add("Internet")
    if "Internet" in dst_zones:
        dst_domains.add("Internet")
    rule_type = standards.rule_type_for(verdict, src_domains, dst_domains, service_ranges)
    log_cfg = standards.log_settings(rule_type)
    approval = standards.review_requirements(risk)

    warnings: list[str] = list(zone_verdict.get("notes", []))
    warnings.extend(standards.permissiveness_warnings(srcs, dsts, service_ranges))
    fw_plans: list[FirewallPlan] = []

    if verdict == "UNKNOWN":
        for target in firewalls:
            fw_plans.append(FirewallPlan(
                firewall=target.device, adom=target.adom, status="no_action",
                warnings=["Zone verdict UNKNOWN — no analysis performed"],
            ))
        cli_status = "unknown_no_action"
    else:
        client = fmg_client or _default_fmg_client()
        for target in firewalls:
            fw_plans.append(_plan_firewall(
                target, flow, zone_verdict, log_cfg, ticket_id, client, warnings,
                src_group=src_group, dst_group=dst_group,
            ))
        for fw in fw_plans:
            warnings.extend(w for w in fw.warnings if w not in warnings)

        if verdict == "BLOCKED":
            cli_status = "blocked_exception"
        elif fw_plans and all(f.status == "already_covered" for f in fw_plans):
            cli_status = "already_covered"
        else:
            cli_status = "new_rule"

    recommendation = _recommendation(cli_status, verdict, fw_plans, risk, warnings,
                                      zone_verdict=zone_verdict)

    return ChangePlan(
        ticket_id=ticket_id,
        flow=flow,
        zone_verdict=zone_verdict,
        risk_level=risk,
        firewalls=fw_plans,
        cli_status=cli_status,
        recommendation=recommendation,
        warnings=warnings,
        naming=_naming_section(fw_plans),
        logging=log_cfg,
        approval=approval,
    )


def _naming_section(fw_plans: list[FirewallPlan]) -> dict:
    naming_yaml = standards.load_naming()
    conventions = naming_yaml.get("platforms", {}).get("fortigate", {}).get("conventions", {})
    objects = []
    seen = set()
    for fw in fw_plans:
        for obj in fw.objects:
            if obj.name in seen:
                continue
            seen.add(obj.name)
            pattern = conventions.get(obj.obj_type, {}).get("pattern", "")
            objects.append({
                "role": obj.role,
                "type": obj.obj_type,
                "name": obj.name,
                "pattern": pattern if obj.action == "create" else "(existing object — reused)",
            })
    return {"objects": objects}


# ---------------------------------------------------------------------------
# render_report.py payload
# ---------------------------------------------------------------------------

def to_report_payload(plan: ChangePlan) -> dict:
    """Emit the exact schema scripts/render_report.py validates."""
    existing_rules = {}
    for fw in plan.firewalls:
        if fw.status == "already_covered":
            note = "Existing enabled rule(s) fully cover this flow."
        elif fw.status == "new_rule":
            note = "No covering rule found — a new rule is required."
            if fw.partial_matches:
                note += f" ({len(fw.partial_matches)} partially-overlapping rule(s) noted.)"
        elif fw.status == "no_action":
            note = "Not analysed — zone verdict UNKNOWN."
        else:
            note = "; ".join(fw.warnings) or "Device could not be analysed."
        existing_rules[fw.firewall] = {
            "status": fw.status.upper().replace("_", " "),
            "rules": fw.covering_rules + fw.partial_matches,
            "covering_rules": fw.covering_rules,
            "partial_matches": fw.partial_matches,
            "note": note,
        }

    per_firewall = []
    for fw in plan.firewalls:
        if fw.status not in ("new_rule",):
            continue
        entry = {
            "firewall": fw.firewall,
            "warnings": list(fw.warnings),
            "address_objects": [
                {"cli": o.cli} for o in fw.objects if o.action == "create" and o.cli
            ],
            "policy": {"cli": fw.policy_cli},
        }
        if fw.insertion:
            entry["warnings"].append(f"Placement: {fw.insertion.rationale}")
        if fw.alternative:
            alt = fw.alternative
            member_names = ", ".join(m.name for m in alt.members)
            if alt.group:
                summary = (
                    f"Extend existing rule #{alt.policy_id} {alt.policy_name!r} "
                    f"(package {alt.package!r}) by appending {member_names} "
                    f"to its {alt.side} group {alt.group!r} instead of creating "
                    "a new policy. Choose ONE option, not both."
                )
            else:
                summary = (
                    f"Extend existing rule #{alt.policy_id} {alt.policy_name!r} "
                    f"(package {alt.package!r}) by adding {member_names} directly "
                    f"to its {alt.side} address list instead of creating "
                    "a new policy. Choose ONE option, not both."
                )
            entry["alternative"] = {
                "summary": summary,
                "package": alt.package,
                "policy_id": alt.policy_id,
                "policy_name": alt.policy_name,
                "side": alt.side,
                "group": alt.group,
                "member_names": [m.name for m in alt.members],
                "member_cli": "\n\n".join(m.cli for m in alt.members if m.cli),
                "group_cli": alt.group_cli,
                "direct_cli": alt.direct_cli,
                "affected_rules": alt.affected_policies,
                "warnings": alt.warnings,
            }
        per_firewall.append(entry)

    return {
        "ticket_id": plan.ticket_id,
        "request": {
            "src": plan.flow.src,
            "dst": plan.flow.dst,
            "service": plan.flow.service,
            "justification": plan.flow.justification,
            "firewalls": [f.firewall for f in plan.firewalls],
        },
        "zone_verdict": {
            "verdict": plan.zone_verdict.get("verdict", "UNKNOWN"),
            "src_zones": plan.zone_verdict.get("src_zones", []),
            "dst_zones": plan.zone_verdict.get("dst_zones", []),
            "governing": plan.zone_verdict.get("governing", []),
        },
        "existing_rules": existing_rules,
        "naming": plan.naming,
        "logging": {
            "rule_type": plan.logging.get("rule_type", ""),
            "log_start": plan.logging.get("log_start", ""),
            "log_end": plan.logging.get("log_end", ""),
            "alert_on_match": plan.logging.get("alert_on_match", ""),
            "retention_days": plan.logging.get("retention_days", ""),
            "siem_forward": plan.logging.get("siem_forward", ""),
            "notes": plan.logging.get("notes", ""),
        },
        "approval": {
            "risk_level": plan.risk_level,
            "approvers": plan.approval.get("approvers", []),
            "peer_review": plan.approval.get("peer_review", ""),
            "security_review": plan.approval.get("security_review", ""),
            "change_window": str(plan.approval.get("change_window", "")).strip(),
            "sla_hours": plan.approval.get("sla_hours", ""),
        },
        "recommendation": plan.recommendation,
        "cli": {
            "status": plan.cli_status,
            "per_firewall": per_firewall,
        },
    }
