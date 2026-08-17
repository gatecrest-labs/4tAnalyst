"""Data model for the deterministic change planner."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from fortimanager_mcp.matching import PortRange


class PlannerDataError(Exception):
    """A required data source failed — distinct from 'query ran, no results'.

    source identifies which system failed ("fortimanager" | "4thealth" |
    "credentials"), so callers can tell the engineer exactly what to check.
    """

    def __init__(self, source: str, detail: str) -> None:
        super().__init__(f"[{source}] {detail}")
        self.source = source
        self.detail = detail


@dataclass
class NormalizedFlow:
    """One consolidated request. src/dst/service are display strings
    (comma-joined); srcs/dsts/services are the member lists the engine
    plans over. service_ranges is the union of all service tokens."""
    src: str
    dst: str
    service: str
    srcs: list[str] = field(default_factory=list)
    dsts: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    service_ranges: list[PortRange] = field(default_factory=list)
    justification: str = ""

    def __post_init__(self) -> None:
        if not self.srcs:
            self.srcs = [t.strip() for t in self.src.split(",") if t.strip()]
        if not self.dsts:
            self.dsts = [t.strip() for t in self.dst.split(",") if t.strip()]
        if not self.services:
            self.services = [t.strip() for t in self.service.split(",") if t.strip()]

    @property
    def pairs(self) -> list[tuple[str, str]]:
        return [(s, d) for s in self.srcs for d in self.dsts]


@dataclass
class TargetFirewall:
    device: str
    adom: str


@dataclass
class ObjectPlan:
    role: str        # "source" | "destination" | "service"
    action: str      # "reuse" | "create"
    name: str
    obj_type: str    # "host" | "network" | "service"
    value: str       # "10.1.2.3/32" or "tcp/8443"
    cli: str = ""    # empty for reuse


@dataclass
class InsertionPlan:
    package: str
    insert_before_policy_id: int | None   # None → append at end
    rationale: str
    shadowed_by: list[int] = field(default_factory=list)
    would_shadow: list[int] = field(default_factory=list)


@dataclass
class GroupAppendAlternative:
    """Optional smaller change: extend a near-miss rule instead of creating
    a new policy.

    Two modes:
    - Group-append (group is not None): append the missing endpoint to an
      address group already referenced by the rule. group_cli carries the
      FortiGate CLI. Always carries the full blast radius (every other policy
      referencing the group directly or via group nesting).
    - Direct-append (group is None): add the missing endpoint directly to
      the rule's srcaddr/dstaddr list. direct_cli carries the CLI. Blast
      radius is trivially zero — only this rule is affected.

    The planner picks the best candidate by specificity: a rule that exactly
    matches on the non-failing sides (e.g. exact destination host + exact
    service) is preferred over a broad catch-all that merely qualifies."""
    package: str
    policy_id: int
    policy_name: str
    side: str                              # "source" | "destination"
    group: str | None                      # None for direct-append
    members: list[ObjectPlan]
    group_cli: str = ""                    # set for group-append; empty for direct
    direct_cli: str = ""                   # set for direct-append; empty for group
    affected_policies: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class FirewallPlan:
    firewall: str
    adom: str
    status: str                            # "already_covered" | "new_rule" | "not_found" | "error"
    covering_rules: list[dict] = field(default_factory=list)
    partial_matches: list[dict] = field(default_factory=list)
    objects: list[ObjectPlan] = field(default_factory=list)
    policy_name: str = ""
    policy_cli: str = ""
    srcintf: str = ""
    dstintf: str = ""
    insertion: InsertionPlan | None = None
    alternative: GroupAppendAlternative | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class ChangePlan:
    ticket_id: str
    flow: NormalizedFlow
    zone_verdict: dict                     # check_ip_traffic-shaped
    risk_level: str
    firewalls: list[FirewallPlan]
    cli_status: str                        # render_report VALID_CLI_STATUSES
    recommendation: str
    warnings: list[str] = field(default_factory=list)
    naming: dict = field(default_factory=dict)
    logging: dict = field(default_factory=dict)
    approval: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FQDNAddressObject:
    name: str         # e.g. "WFQDN-push.apple.com"
    obj_type: str     # "fqdn" | "wildcard-fqdn"
    value: str        # e.g. "*.push.apple.com"
    comment: str
    cli: str = ""


@dataclass
class FQDNAddrGroup:
    name: str           # "GRP-Apple-APNs-DST"
    members: list[str]  # object names
    comment: str
    cli: str = ""


@dataclass
class FQDNFirewallPlan:
    firewall: str
    adom: str
    verdict: str     # "blocked_exception" | "already_covered" | "new_rule" | "unknown_no_action" | "error"
    src_zone: str
    coverage: str    # "already_covered" | "partial_coverage" | "new_rule" | "n/a"
    covered_entries: list    # list of FQDNEntry objects from intake_mcp
    uncovered_entries: list  # list of FQDNEntry objects
    proposed_objects: list   # list[FQDNAddressObject]
    proposed_group: FQDNAddrGroup | None
    proposed_policy: dict | None
    group_append_alternative: GroupAppendAlternative | None
    degraded: bool
    warnings: list[str]


@dataclass
class FQDNChangePlan:
    request: Any     # FQDNAllowlistRequest from intake_mcp
    per_firewall: list[FQDNFirewallPlan]
