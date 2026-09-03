"""
Single entry point for Rule Hygiene fix assessment, analogous to
planner.engine.plan_change() / psirt.engine.assess().
"""

from __future__ import annotations

from datetime import UTC, date, datetime

from hygiene.fix_logic import FixContext, build_fix
from hygiene.models import Finding, HygieneDataError, HygieneResult, PolicyFix


def assess(
    findings: list[Finding],
    live_policies_by_pkg: dict[str, list[dict] | None],
    device: str,
    adom: str,
    pkg: str,
    now: date | None = None,
) -> HygieneResult:
    if pkg not in live_policies_by_pkg:
        raise HygieneDataError(
            "fortimanager", f"policy package '{pkg}' not found in ADOM '{adom}'"
        )
    live_policies = live_policies_by_pkg[pkg]
    if live_policies is None:
        raise HygieneDataError(
            "fortimanager",
            f"failed to fetch policies for package '{pkg}' in ADOM '{adom}'",
        )

    now = now or datetime.now(UTC).date()
    by_id = {str(p.get("policyid")): p for p in live_policies}
    redundant_ids = {f.policy_id for f in findings if f.check == "redundant"}
    ctx = FixContext(now=now, redundant_policy_ids=redundant_ids)

    fixes: list[PolicyFix] = []
    stale: list[dict] = []
    for finding in findings:
        live_policy = by_id.get(finding.policy_id)
        if live_policy is None:
            stale.append({
                **finding.to_dict(),
                "reason": (
                    "policy_id not found in live package — may have been "
                    "deleted or renumbered since the hygiene run"
                ),
            })
            continue

        options = build_fix(finding, live_policy, ctx)
        if options is None:
            continue  # unrecognized check — defensive skip, not an error

        fixes.append(PolicyFix(
            policy_id=finding.policy_id,
            policy_name=finding.policy_name,
            check=finding.check,
            options=options,
        ))

    return HygieneResult(
        device=device,
        adom=adom,
        pkg=pkg,
        generated_at=datetime.now(UTC).isoformat(),
        fixes=fixes,
        stale_findings=stale,
    )
