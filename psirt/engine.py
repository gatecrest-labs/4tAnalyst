"""
The PSIRT assessment engine: given a structured Advisory, determines the
verdict for every FortiGate + the FortiManager itself. This is the
deterministic core other packages call — it never asks an LLM anything.

Fleet scan strategy: iterate every ADOM the caller's FortiManager client
can see, list every device in each, and evaluate FortiOS findings for each
device plus one FortiManager-itself finding (if the advisory names
FortiManager as a product). A per-ADOM device-list failure degrades the
assessment (those devices become unknown_needs_manual_check) rather than
being silently skipped — same discipline as planner/fetch.py.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from psirt.enrich import enrich_advisory
from psirt.models import Advisory, DeviceFinding, PsirtAssessment
from psirt.scoring import compute_priority
from psirt.version_match import VersionMatchError, version_in_range
from psirt.workaround_checks import check_workaround, match_workaround_pattern

_SUPPORTED_PRODUCTS = {"fortios", "fortigate", "fortimanager"}


def _device_firmware(device: dict) -> str:
    os_ver = str(device.get("os_ver", "")).strip()
    mr = str(device.get("mr", "")).strip()
    patch = str(device.get("patch", "")).strip()
    if not os_ver or not mr or not patch:
        return ""  # incomplete version → treat as unknown
    # FortiManager may return os_ver as "MAJOR.MINOR" (e.g. "7.0") rather than
    # just "MAJOR", making the assembled string 4 parts: "7.0.4.11". Advisory
    # ranges are always 3-part (MAJOR.MINOR.PATCH), so normalise to the first
    # three non-negative integer components and drop the build number.
    # A negative component (-1 = no build applied) stops the walk; anything
    # before it is still usable.
    raw = f"{os_ver}.{mr}.{patch}"
    parts: list[int] = []
    for seg in raw.split("."):
        try:
            val = int(seg)
        except ValueError:
            break
        if val < 0:
            break  # -1 build marker — stop, keep what we have
        parts.append(val)
        if len(parts) == 3:
            break
    if len(parts) < 3:
        return ""  # not enough components → treat as unknown
    return ".".join(str(p) for p in parts)


def _evaluate_device(
    advisory: Advisory,
    ranges: list,
    device_name: str,
    adom: str,
    product_label: str,
    firmware: str,
    fmg_client: Any,
) -> DeviceFinding:
    if not firmware:
        return DeviceFinding(
            device=device_name, adom=adom, product=product_label,
            current_version="", in_range=False,
            workaround_status="not_applicable", verdict="unknown_needs_manual_check",
            reason="No firmware version reported by FortiManager for this device.",
        )

    in_range = False
    matched_range = None
    try:
        for rng in ranges:
            if version_in_range(firmware, rng):
                in_range = True
                matched_range = rng
                break
    except VersionMatchError as exc:
        return DeviceFinding(
            device=device_name, adom=adom, product=product_label,
            current_version=firmware, in_range=False,
            workaround_status="not_applicable", verdict="unknown_needs_manual_check",
            reason=f"Could not compare firmware version: {exc}",
        )

    if not in_range:
        return DeviceFinding(
            device=device_name, adom=adom, product=product_label,
            current_version=firmware, in_range=False,
            workaround_status="not_applicable", verdict="no_action",
            reason=f"Firmware {firmware} is outside the advisory's affected range(s).",
        )

    pattern_key = match_workaround_pattern(advisory.workaround_text)
    if pattern_key is None:
        if advisory.workaround_text.strip():
            return DeviceFinding(
                device=device_name, adom=adom, product=product_label,
                current_version=firmware, in_range=True,
                workaround_status="manual_verification_required",
                verdict="config_change_required",
                reason=(
                    f"Firmware {firmware} is affected. A workaround is published "
                    f"but not automatically verifiable: {advisory.workaround_text!r}. "
                    "Manually confirm it's applied, or upgrade to "
                    f"{matched_range.fixed_version or 'the fixed version'}."
                ),
            )
        return DeviceFinding(
            device=device_name, adom=adom, product=product_label,
            current_version=firmware, in_range=True,
            workaround_status="not_applicable", verdict="upgrade_required",
            reason=(
                f"Firmware {firmware} is affected and no workaround is published. "
                f"Upgrade to {matched_range.fixed_version or 'the fixed version'}."
            ),
        )

    try:
        status = check_workaround(pattern_key, fmg_client, adom, device_name)
    except Exception as exc:
        return DeviceFinding(
            device=device_name, adom=adom, product=product_label,
            current_version=firmware, in_range=True,
            workaround_status="manual_verification_required",
            verdict="config_change_required",
            reason=f"Firmware {firmware} is affected. Workaround check failed: {exc}. Manual verification required.",
        )
    if status == "in_place":
        return DeviceFinding(
            device=device_name, adom=adom, product=product_label,
            current_version=firmware, in_range=True,
            workaround_status="in_place", verdict="no_action",
            reason=(
                f"Firmware {firmware} is affected, but the workaround is already "
                f"in place: {advisory.workaround_text}"
            ),
        )
    elif status == "not_in_place":
        return DeviceFinding(
            device=device_name, adom=adom, product=product_label,
            current_version=firmware, in_range=True,
            workaround_status="not_in_place",
            verdict="config_change_required",
            reason=(
                f"Firmware {firmware} is affected and the workaround is NOT in place: "
                f"{advisory.workaround_text}"
            ),
        )
    else:  # manual_verification_required
        return DeviceFinding(
            device=device_name, adom=adom, product=product_label,
            current_version=firmware, in_range=True,
            workaround_status="manual_verification_required",
            verdict="config_change_required",
            reason=(
                f"Firmware {firmware} is affected and the workaround status is unknown "
                f"(manual verification required): {advisory.workaround_text}"
            ),
        )


def assess(
    advisory: Advisory,
    fmg_client: Any,
    http_client: Any,
    kev_url: str,
) -> PsirtAssessment:
    """
    Main entry point. Enriches the advisory, scans every ADOM/device the
    FortiManager client can see, evaluates each against the advisory ranges,
    and returns a PsirtAssessment.

    Args:
        advisory:   Structured advisory (from the LLM parse step or tests).
        fmg_client: FortiManager client (live or fake).
        http_client: HTTP client for enrichment (httpx.Client or fake).
        kev_url:    CISA KEV catalog URL (empty string disables KEV check).

    Returns:
        PsirtAssessment with findings, priority, and warnings.
    """
    advisory = enrich_advisory(advisory, http_client, kev_url)
    kev_hit = getattr(advisory, "_kev_hit", False)

    out_of_scope = sorted({
        r.product for r in advisory.affected_ranges
        if r.product.strip().lower() not in _SUPPORTED_PRODUCTS
    })

    findings: list[DeviceFinding] = []
    warnings: list[str] = []
    degraded = advisory.enrichment_degraded

    fortios_ranges = [
        r for r in advisory.affected_ranges
        if r.product.strip().lower() in ("fortios", "fortigate")
    ]
    fmg_ranges = [
        r for r in advisory.affected_ranges
        if r.product.strip().lower() == "fortimanager"
    ]

    # Evaluate FortiManager itself if the advisory names it as a product.
    if fmg_ranges:
        status = fmg_client.get_system_status()
        fmg_version = str(status.get("Version", "")).strip()
        # FortiManager self-assessment: skip device-config workaround checks
        # (they use device-name queries that don't apply to the manager itself)
        fmg_advisory_no_workaround = dataclasses.replace(advisory, workaround_text="")
        findings.append(_evaluate_device(
            fmg_advisory_no_workaround, fmg_ranges,
            "FortiManager (this instance)", "-",
            "FortiManager", fmg_version, fmg_client,
        ))

    # Evaluate every FortiGate device in every ADOM.
    if fortios_ranges:
        try:
            adoms = [a.get("name", "") for a in fmg_client.get_adoms() if isinstance(a, dict)]
        except Exception as exc:
            degraded = True
            warnings.append(f"Could not list ADOMs: {exc}")
            adoms = []
        for adom in adoms:
            try:
                devices = fmg_client.get_devices(adom)
            except Exception as exc:
                degraded = True
                warnings.append(f"Could not list devices in ADOM {adom!r}: {exc}")
                continue
            for d in devices:
                if not isinstance(d, dict):
                    continue
                name = d.get("name", "")
                firmware = _device_firmware(d)
                findings.append(_evaluate_device(
                    advisory, fortios_ranges, name, adom, "FortiOS", firmware, fmg_client,
                ))

    any_in_range = any(f.in_range for f in findings)

    # If the assessment is degraded and no devices were successfully checked at all,
    # do not emit "informational" — nothing was checked, so we don't know.
    if degraded and not findings:
        return PsirtAssessment(
            advisory=advisory,
            findings=findings,
            out_of_scope_products=out_of_scope,
            priority="unknown",
            priority_rationale=(
                "Fleet assessment is degraded and no devices could be checked. "
                "Manual verification required."
            ),
            kev_hit=kev_hit,
            degraded=degraded,
            warnings=warnings,
        )

    priority, rationale = compute_priority(
        cvss_score=advisory.cvss_score,
        fortinet_severity=advisory.fortinet_severity,
        exploited_in_wild_text=advisory.exploited_in_wild_text,
        kev_hit=kev_hit,
        any_device_in_range=any_in_range,
    )

    return PsirtAssessment(
        advisory=advisory,
        findings=findings,
        out_of_scope_products=out_of_scope,
        priority=priority,
        priority_rationale=rationale,
        kev_hit=kev_hit,
        degraded=degraded,
        warnings=warnings,
    )
