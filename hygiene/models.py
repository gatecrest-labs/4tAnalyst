"""
Data models for the Rule Hygiene fix-generation engine.

Mirrors psirt/models.py's dataclass + to_dict() pattern. HygieneDataError
means "a source failed" (e.g. the live policy fetch), never "no results" —
same discipline as planner.models.PlannerDataError / psirt.models.PsirtDataError.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class HygieneParseError(Exception):
    """The pasted/uploaded findings text couldn't be parsed."""

    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


class HygieneDataError(Exception):
    """A data source (FortiManager) failed outright."""

    def __init__(self, source: str, detail: str):
        self.source = source
        self.detail = detail
        super().__init__(f"[{source}] {detail}")


@dataclass
class Finding:
    policy_id: str
    policy_name: str
    seq: int
    check: str
    detail: str
    severity: str = ""
    shadow_rule: dict | None = None
    shadowing_rule: dict | None = None
    duplicate_of: dict | None = None

    def to_dict(self) -> dict:
        return {
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "seq": self.seq,
            "check": self.check,
            "detail": self.detail,
            "severity": self.severity,
            "shadow_rule": self.shadow_rule,
            "shadowing_rule": self.shadowing_rule,
            "duplicate_of": self.duplicate_of,
        }


@dataclass
class FixOption:
    option_id: str
    label: str
    description: str
    cli: list[str] = field(default_factory=list)
    new_comment: str | None = None
    irreversible: bool = False

    def to_dict(self) -> dict:
        return {
            "option_id": self.option_id,
            "label": self.label,
            "description": self.description,
            "cli": list(self.cli),
            "new_comment": self.new_comment,
            "irreversible": self.irreversible,
        }


@dataclass
class PolicyFix:
    policy_id: str
    policy_name: str
    check: str
    options: list[FixOption] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "check": self.check,
            "options": [o.to_dict() for o in self.options],
            "detail": self.detail,
        }


@dataclass
class HygieneResult:
    device: str
    adom: str
    pkg: str
    generated_at: str
    fixes: list[PolicyFix] = field(default_factory=list)
    stale_findings: list[dict] = field(default_factory=list)
    skipped_findings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "device": self.device,
            "adom": self.adom,
            "pkg": self.pkg,
            "generated_at": self.generated_at,
            "fixes": [f.to_dict() for f in self.fixes],
            "stale_findings": list(self.stale_findings),
            "skipped_findings": list(self.skipped_findings),
        }
