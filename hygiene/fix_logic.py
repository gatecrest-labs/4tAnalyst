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
