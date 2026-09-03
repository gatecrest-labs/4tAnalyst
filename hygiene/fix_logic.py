"""
Per-check deterministic fix generators, ported from the 4thealth-plus
hygiene-fix-ai-assist design (docs/superpowers/specs/2026-09-03-
hygiene-fix-ai-assist-design.md in that repo). One `_fix_<check>()` per
check, dispatched via `_FIX_FNS`. Every generator has the signature
`(finding: Finding, live_policy: dict, ctx: FixContext) -> list[FixOption]`.

`live_policy` is a raw FortiManager policy dict (fields like `srcaddr`,
`dstaddr`, `comments`, `policyid` — the same shape fortimanager_mcp/query.py
already works with), never the normalized `search_policies` summary shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from hygiene.models import Finding, FixOption
from hygiene.tag import append_tag, find_tag


@dataclass
class FixContext:
    now: date
    redundant_policy_ids: set[str] = field(default_factory=set)


# ── Shared helpers ──────────────────────────────────────────────────────

def _addr_list(val) -> list[str]:
    """Normalize address fields: may be a list of strings or list of dicts."""
    if not val:
        return []
    if isinstance(val, str):
        return [val]
    out = []
    for item in val:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            out.append(item.get("name", str(item)))
    return out


def _is_any(val) -> bool:
    names = _addr_list(val)
    return not names or any(n.lower() in ("all", "any") for n in names)


def _comment(p: dict) -> str:
    return str(p.get("comments") or p.get("comment") or "")


def _safe(s: str) -> str:
    """Escape a string for a quoted FortiGate CLI field — same convention
    as planner/cli_gen.py::_safe_cli_str."""
    return s.replace('"', "''").replace("\n", "").replace("\r", "")


def _wrap_policy_block(policy_id: str, set_lines: list[str]) -> str:
    body = "\n".join(f"        {line}" for line in set_lines)
    return (
        "config firewall policy\n"
        f"    edit {policy_id}\n"
        f"{body}\n"
        "    next\n"
        "end"
    )


def _wrap_move(policy_id: str, before_id) -> str:
    return (
        "config firewall policy\n"
        f"    move {policy_id} before {before_id}\n"
        "end"
    )


def _wrap_delete(policy_id: str) -> str:
    return (
        "config firewall policy\n"
        f"    delete {policy_id}\n"
        "end"
    )


def _disable_and_tag_option(finding: Finding, live_policy: dict, ctx: FixContext,
                             option_id: str, label: str, description: str) -> FixOption:
    new_comment = append_tag(_comment(live_policy), ctx.now)
    cli = _wrap_policy_block(finding.policy_id, [
        "set status disable",
        f'set comments "{_safe(new_comment)}"',
    ])
    return FixOption(option_id, label, description, [cli], new_comment)


# ── Simple generators ───────────────────────────────────────────────────

def _fix_unhit(finding: Finding, live_policy: dict, ctx: FixContext) -> list[FixOption]:
    return [_disable_and_tag_option(
        finding, live_policy, ctx, "A", "Disable",
        "Disable the unused rule and record the fix date.",
    )]


def _fix_expired(finding: Finding, live_policy: dict, ctx: FixContext) -> list[FixOption]:
    return [_disable_and_tag_option(
        finding, live_policy, ctx, "A", "Disable",
        "Disable the expired-schedule rule and record the fix date.",
    )]


def _fix_unlogged(finding: Finding, live_policy: dict, ctx: FixContext) -> list[FixOption]:
    cli = _wrap_policy_block(finding.policy_id, ["set logtraffic all"])
    return [FixOption("A", "Enable logging", "Set logtraffic to all.", [cli], None)]


def _fix_missing_security_profile(finding: Finding, live_policy: dict, ctx: FixContext) -> list[FixOption]:
    return [FixOption(
        "A", "Manual review required",
        f"{finding.detail} No automated fix is offered for missing security profiles.",
        [], None,
    )]


def _fix_redundant(finding: Finding, live_policy: dict, ctx: FixContext) -> list[FixOption]:
    dup = finding.duplicate_of or {}
    dup_name = dup.get("name", "an earlier rule")
    dup_id = dup.get("policy_id", dup.get("id", "?"))
    return [_disable_and_tag_option(
        finding, live_policy, ctx, "A", "Disable",
        f"Redundant with rule '{dup_name}' (id {dup_id}); disable this later duplicate.",
    )]


def _fix_unnamed(finding: Finding, live_policy: dict, ctx: FixContext) -> list[FixOption]:
    src = _addr_list(live_policy.get("srcaddr"))
    dst = _addr_list(live_policy.get("dstaddr"))
    if src and dst and not _is_any(src) and not _is_any(dst):
        raw_name = f"Allow {src[0]} to {dst[0]}"
    else:
        raw_name = "Unknown -- Requires additional research"
    name = raw_name[:35]
    new_comment = append_tag(_comment(live_policy), ctx.now)
    cli = _wrap_policy_block(finding.policy_id, [
        f'set name "{_safe(name)}"',
        f'set comments "{_safe(new_comment)}"',
    ])
    return [FixOption(
        "A", "Rename and tag",
        f'Set policy name to "{name}" and record the fix date.',
        [cli], new_comment,
    )]


def _fix_over_permissive(finding: Finding, live_policy: dict, ctx: FixContext) -> list[FixOption]:
    comment = _comment(live_policy)
    disable = _disable_and_tag_option(
        finding, live_policy, ctx, "A", "Disable",
        "Disable the over-permissive rule and record the fix date.",
    )
    exempt_comment = append_tag(comment, ctx.now, exempt=True)
    exempt_cli = _wrap_policy_block(finding.policy_id, [
        f'set comments "{_safe(exempt_comment)}"',
    ])
    exempt = FixOption(
        "B", "Exempt (keep enabled)",
        "Mark reviewed-and-accepted; the rule stays enabled and is excluded "
        "from future hygiene runs (the EXEMPT tag is also what "
        "app/hygiene.py::_is_exempt matches on).",
        [exempt_cli], exempt_comment,
    )
    return [disable, exempt]


def _fix_disabled(finding: Finding, live_policy: dict, ctx: FixContext) -> list[FixOption]:
    comment = _comment(live_policy)
    tag_date = find_tag(comment)

    if tag_date is None:
        new_comment = append_tag(comment, ctx.now)
        cli = _wrap_policy_block(finding.policy_id, [f'set comments "{_safe(new_comment)}"'])
        return [FixOption(
            "A", "Tag for tracking",
            "No prior HygieneFix tag found; record today's date so the "
            "90-day deletion window can be tracked.",
            [cli], new_comment,
        )]

    age_days = (ctx.now - tag_date).days
    if age_days > 90:
        cli = _wrap_delete(finding.policy_id)
        return [FixOption(
            "A", "Delete",
            f"Disabled and tagged {age_days} days ago (>90); safe to delete.",
            [cli], None, irreversible=True,
        )]

    return [FixOption(
        "A", "No action needed yet",
        f"Tagged {age_days} days ago; eligible for deletion in "
        f"{90 - age_days} more day(s).",
        [], None,
    )]


def _fix_shadow(finding: Finding, live_policy: dict, ctx: FixContext) -> list[FixOption]:
    shadowing = finding.shadowing_rule or {}
    options = [_disable_and_tag_option(
        finding, live_policy, ctx, "A", "Disable shadowed rule",
        "This rule is fully shadowed by an earlier, broader rule; disable it.",
    )]

    shadowed_action = str(live_policy.get("action", "")).lower()
    shadowing_action = str(shadowing.get("action", "")).lower()
    shadowing_id = shadowing.get("policy_id") or shadowing.get("rule_id") or shadowing.get("id")

    if shadowing_id and shadowed_action and shadowing_action and shadowed_action != shadowing_action:
        move_cli = _wrap_move(finding.policy_id, shadowing_id)
        options.append(FixOption(
            "B", "Reorder above the shadowing rule",
            f"Actions differ ({shadowed_action} vs {shadowing_action}); "
            f"move this rule before policy {shadowing_id} instead of disabling it.",
            [move_cli], None,
        ))

    if finding.policy_id not in ctx.redundant_policy_ids:
        narrow = _shadow_narrow_option(finding, live_policy, shadowing)
        if narrow is not None:
            options.append(narrow)

    return options


def _shadow_narrow_option(finding: Finding, live_policy: dict, shadowing: dict) -> FixOption | None:
    shadowing_id = shadowing.get("policy_id") or shadowing.get("rule_id") or shadowing.get("id")
    if not shadowing_id:
        return None

    my_src = set(_addr_list(live_policy.get("srcaddr")))
    my_dst = set(_addr_list(live_policy.get("dstaddr")))
    shadowing_src = set(_addr_list(shadowing.get("srcaddr") or shadowing.get("source")))
    shadowing_dst = set(_addr_list(shadowing.get("dstaddr") or shadowing.get("destination")))

    if my_src == shadowing_src and my_dst == shadowing_dst:
        return None  # identical scope is redundant's territory, not shadow's

    # Best-effort only: never auto-generate group-membership CLI (removing a
    # member from a shared address group affects every other rule that
    # references it, and this engine doesn't resolve group nesting/blast
    # radius) — always describe the option with no CLI, per the spec's
    # explicit "empty cli + manual note" fallback.
    return FixOption(
        "C", "Narrow the shadowing rule's scope",
        f"This rule covers a subset of policy {shadowing_id}'s scope but "
        "isn't identical to it. Removing this rule's specific source/"
        "destination from the broader shadowing rule would let both stay "
        "enabled with distinct scopes, but group/address membership changes "
        "need manual review — no CLI is auto-generated for this option.",
        [], None,
    )


_FIX_FNS = {
    "unnamed": _fix_unnamed,
    "unlogged": _fix_unlogged,
    "shadow": _fix_shadow,
    "disabled": _fix_disabled,
    "expired": _fix_expired,
    "unhit": _fix_unhit,
    "missing_security_profile": _fix_missing_security_profile,
    "redundant": _fix_redundant,
    "over_permissive": _fix_over_permissive,
}


def build_fix(finding: Finding, live_policy: dict, ctx: FixContext) -> list[FixOption] | None:
    """Dispatch to the registered generator for finding.check, or None if the
    check isn't recognized (defensive — skipped by the caller, not an error)."""
    fn = _FIX_FNS.get(finding.check)
    if fn is None:
        return None
    return fn(finding, live_policy, ctx)
