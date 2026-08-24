"""
Deterministic PSIRT priority scoring.

Priority starts from a CVSS band (or Fortinet's own severity label when no
CVSS score was extracted), then is forced to at least "high" if the
advisory text states exploitation or the CVE is CISA KEV-listed — a
vulnerability being actively exploited outranks a merely high CVSS score.
A zero-exposure fleet always scores "informational" regardless of
severity, since there is nothing to act on.
"""

from __future__ import annotations

_PRIORITY_RANK = {"unknown": -1, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEVERITY_FALLBACK = {
    "critical": "critical", "high": "high", "medium": "medium", "low": "low",
}


def _cvss_band(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def compute_priority(
    cvss_score: float | None,
    fortinet_severity: str,
    exploited_in_wild_text: str,
    kev_hit: bool,
    any_device_in_range: bool,
) -> tuple[str, str]:
    if not any_device_in_range:
        return "informational", (
            "No devices in the fleet fall within the advisory's affected "
            "version range(s) — nothing to act on."
        )

    if cvss_score is not None:
        base = _cvss_band(cvss_score)
        base_reason = f"CVSS base score {cvss_score}"
    else:
        base = _SEVERITY_FALLBACK.get((fortinet_severity or "").strip().lower(), "medium")
        base_reason = f"no CVSS score extracted; used Fortinet's own severity rating ({fortinet_severity or 'unspecified'})"

    exploited = bool((exploited_in_wild_text or "").strip())
    forced_reasons = []
    if exploited:
        forced_reasons.append("advisory states exploitation in the wild")
    if kev_hit:
        forced_reasons.append("CVE is listed in the CISA KEV catalog")

    priority = base
    if forced_reasons and _PRIORITY_RANK[base] < _PRIORITY_RANK["high"]:
        priority = "high"

    rationale = base_reason
    if forced_reasons:
        rationale += f"; forced to at least High because: {', '.join(forced_reasons)}"

    return priority, rationale
