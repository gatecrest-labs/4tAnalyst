"""
Data models for the PSIRT advisory assessment engine.

Mirrors planner/models.py's dataclass + to_dict() pattern. PsirtDataError
means "a source failed", never "no results" — same discipline as
planner.models.PlannerDataError.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class PsirtDataError(Exception):
    """A data source (FortiManager, advisory enrichment) failed outright."""

    def __init__(self, source: str, detail: str):
        self.source = source
        self.detail = detail
        super().__init__(f"[{source}] {detail}")


@dataclass
class AffectedRange:
    product: str
    min_version: str = ""
    max_version: str = ""
    fixed_version: str = ""
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "product": self.product,
            "min_version": self.min_version,
            "max_version": self.max_version,
            "fixed_version": self.fixed_version,
            "notes": self.notes,
        }


@dataclass
class Advisory:
    advisory_id: str
    advisory_url: str = ""
    cve_ids: list[str] = field(default_factory=list)
    published_date: str = ""
    fortinet_severity: str = ""
    cvss_score: float | None = None
    description: str = ""
    affected_ranges: list[AffectedRange] = field(default_factory=list)
    workaround_text: str = ""
    exploited_in_wild_text: str = ""
    enrichment_degraded: bool = False

    def to_dict(self) -> dict:
        return {
            "advisory_id": self.advisory_id,
            "advisory_url": self.advisory_url,
            "cve_ids": list(self.cve_ids),
            "published_date": self.published_date,
            "fortinet_severity": self.fortinet_severity,
            "cvss_score": self.cvss_score,
            "description": self.description,
            "affected_ranges": [r.to_dict() for r in self.affected_ranges],
            "workaround_text": self.workaround_text,
            "exploited_in_wild_text": self.exploited_in_wild_text,
            "enrichment_degraded": self.enrichment_degraded,
        }


@dataclass
class DeviceFinding:
    device: str
    adom: str
    product: str
    current_version: str
    in_range: bool
    workaround_status: str  # in_place | not_in_place | manual_verification_required | not_applicable
    verdict: str  # no_action | config_change_required | upgrade_required | unknown_needs_manual_check
    reason: str

    def to_dict(self) -> dict:
        return {
            "device": self.device,
            "adom": self.adom,
            "product": self.product,
            "current_version": self.current_version,
            "in_range": self.in_range,
            "workaround_status": self.workaround_status,
            "verdict": self.verdict,
            "reason": self.reason,
        }


@dataclass
class PsirtAssessment:
    advisory: Advisory
    findings: list[DeviceFinding] = field(default_factory=list)
    out_of_scope_products: list[str] = field(default_factory=list)
    priority: str = ""
    priority_rationale: str = ""
    kev_hit: bool = False
    degraded: bool = False
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "advisory": self.advisory.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "out_of_scope_products": list(self.out_of_scope_products),
            "priority": self.priority,
            "priority_rationale": self.priority_rationale,
            "kev_hit": self.kev_hit,
            "degraded": self.degraded,
            "warnings": list(self.warnings),
        }
