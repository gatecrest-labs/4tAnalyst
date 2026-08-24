"""
Unified 4tAnalyst MCP server.

Aggregates every read-only tool from the five per-domain packages onto one
FastMCP instance and adds plan_change — the deterministic change planner.
The per-package servers remain runnable individually for stdio development;
this is the production entry point (see __main__.py for transport/auth).
"""

from __future__ import annotations

import functools
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from fwanalyst_server.context import token_label_var

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Access logging
# ---------------------------------------------------------------------------

def _logged(fn):
    """Wrap a tool fn so every invocation emits one INFO access-log line.

    Logs the tool name and the caller's token label only — never arguments
    (they carry internal IPs) and never the token itself. functools.wraps keeps
    __name__/__doc__/__wrapped__ intact so FastMCP's schema generation
    (inspect.signature follows __wrapped__) sees the original function.
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        logger.info("tool_call tool=%s token=%s", fn.__name__, token_label_var.get())
        return fn(*args, **kwargs)

    return wrapper


mcp = FastMCP(
    name="fw-analyst",
    instructions=(
        "4tAnalyst unified server. For firewall change requests, prefer the "
        "plan_change tool: it computes the zone verdict, existing-rule "
        "coverage, object reuse, rule insertion point, and FortiGate CLI "
        "deterministically — relay its output verbatim, never recompute or "
        "edit it. The other tools are read-only lookups for ad-hoc questions. "
        "zone_* tools query the live 4THealth API (authoritative for "
        "verdicts); standards check_traffic uses static TUFIN-era data — do "
        "not use it for verdicts."
    ),
)


# ---------------------------------------------------------------------------
# plan_change — the deterministic planner
# ---------------------------------------------------------------------------

def plan_change(
    src: str,
    dst: str,
    service: str,
    firewalls: list[str],
    justification: str = "",
    ticket_id: str = "",
    src_group: str = "",
    dst_group: str = "",
) -> dict[str, Any]:
    """
    Compute a complete, deterministic firewall change plan for one
    consolidated request (single or multiple values per field).

    This is the primary tool for /analyze-request. Call it ONCE per request
    — pass ALL sources, destinations, and services together; the engine
    plans one policy per firewall covering every combination. It performs
    ALL analysis in tested code: 4THealth zone verdict per combination,
    FortiManager existing-rule search (set semantics), object reuse vs.
    create, auto-grouping, rule insertion point (first-match shadowing
    analysis), naming/logging standards, approval chain, and exact
    FortiGate CLI.

    Parameters
    ----------
    src           : Source IP(s)/CIDR(s), comma-separated for multiple
                    (e.g. "10.1.2.3" or "10.1.2.3, 10.1.2.4")
    dst           : Destination IP(s)/CIDR(s), comma-separated for multiple
    service       : Port(s), proto/port, or well-known names, comma-separated
                    ("443", "tcp/8443, tcp/22", "ssh")
    firewalls     : Target firewalls as "DEVICE:ADOM" strings
                    (e.g. ["MNHQ-FW01:OT-ADOM"]). The engineer names these;
                    path is never auto-discovered.
    justification : Business justification from the request
    ticket_id     : Change ticket ID if known
    src_group     : Optional name for a source address group — forces the
                    sources into a group even below the auto-group threshold
    dst_group     : Optional name for a destination address group

    Mixed zone verdicts (some combinations ALLOWED, some BLOCKED) return an
    error telling the engineer to split the request — relay it verbatim.

    Returns the render_report.py payload (request, zone_verdict,
    existing_rules, naming, logging, approval, recommendation, cli) plus a
    top-level "warnings" list. Present it verbatim: do not recompute
    verdicts, rename objects, or edit CLI text. If warnings mention degraded
    FortiManager data, lead with that when presenting.
    """
    from planner.engine import plan_change as _plan
    from planner.engine import to_report_payload
    from planner.models import PlannerDataError, TargetFirewall

    targets = []
    for raw in firewalls:
        device, sep, adom = raw.partition(":")
        if not sep or not device or not adom:
            return {"error": f"firewalls entries must be 'DEVICE:ADOM', got {raw!r}"}
        targets.append(TargetFirewall(device=device, adom=adom))

    try:
        plan = _plan(
            src=src, dst=dst, service=service, firewalls=targets,
            justification=justification, ticket_id=ticket_id,
            src_group=src_group, dst_group=dst_group,
        )
    except PlannerDataError as exc:
        return {"error": str(exc), "error_source": exc.source}

    payload = to_report_payload(plan)
    payload["warnings"] = plan.warnings
    return payload


mcp.add_tool(_logged(plan_change), annotations=ToolAnnotations(readOnlyHint=True))


# ---------------------------------------------------------------------------
# plan_fqdn_change — the FQDN allowlist planner
# ---------------------------------------------------------------------------

def plan_fqdn_change(
    src_ip: str,
    vendor: str,
    category: str,
    ticket_id: str,
    firewalls: list[str],
    entries: list[dict],
) -> dict:
    """
    Compute a deterministic FQDN allowlist change plan.

    Use this tool for requests where destinations are FQDNs or wildcard domains
    (e.g. *.push.apple.com) rather than IP addresses. plan_change will reject
    such inputs — use plan_fqdn_change instead.

    Parameters
    ----------
    src_ip      : Source IP/CIDR for the rule
    vendor      : Vendor name (e.g. "Apple") — used in address group naming
    category    : Vendor category (e.g. "APNs") — used in address group naming
    ticket_id   : Change ticket ID (e.g. CHG0012345)
    firewalls   : Target firewalls as "DEVICE:ADOM" strings
    entries     : List of FQDNEntry dicts with keys: fqdn, is_wildcard, ports,
                  protocol, required, comment. Use parse_fqdn_allowlist first
                  to produce these from a spreadsheet or conversation.

    Returns the FQDN change plan payload for render_report.py / display.
    Check per_firewall[*].warnings for degraded-data notices.
    """
    from intake_mcp.fqdn_parser import FQDNAllowlistRequest, FQDNEntry
    from planner.engine import plan_fqdn_change as _plan
    from planner.engine import to_fqdn_report_payload
    from planner.models import PlannerDataError

    try:
        parsed_entries = [
            FQDNEntry(
                fqdn=e["fqdn"],
                is_wildcard=e.get("is_wildcard", e["fqdn"].startswith("*.")),
                ports=[int(p) for p in e.get("ports", [443])],
                protocol=e.get("protocol", "TCP"),
                required=bool(e.get("required", True)),
                comment=e.get("comment", ""),
            )
            for e in entries
        ]
        request = FQDNAllowlistRequest(
            vendor=vendor, category=category, src_ip=src_ip,
            ticket_id=ticket_id, firewalls=firewalls, entries=parsed_entries,
        )
        plan = _plan(request)
        payload = to_fqdn_report_payload(plan)
        payload["warnings"] = [w for fw in plan.per_firewall for w in fw.warnings]
        return payload
    except PlannerDataError as exc:
        return {"error": str(exc), "error_source": exc.source}
    except Exception as exc:
        return {"error": str(exc)}


mcp.add_tool(_logged(plan_fqdn_change), annotations=ToolAnnotations(readOnlyHint=True))


# ---------------------------------------------------------------------------
# Aggregate the per-package tools
# ---------------------------------------------------------------------------

# The two feedback tools that write to the store; everything else aggregated
# here is read-only. Mirrors the annotations on the per-package servers, which
# add_tool does not carry over.
_ANNOTATIONS = {
    "record_feedback": ToolAnnotations(readOnlyHint=False, destructiveHint=False),
    "flag_for_review": ToolAnnotations(readOnlyHint=False, destructiveHint=False),
}


def _register_existing_tools() -> None:
    from feedback_mcp import server as feedback
    from fortimanager_mcp import server as fmg
    from intake_mcp import server as intake
    from psirt_mcp import server as psirt
    from standards_mcp import server as standards
    from zone_mcp import server as zone

    for fn in (
        # standards (static data — naming/logging/approvals; NOT verdicts)
        standards.get_zone_matrix,
        standards.check_traffic,
        standards.get_naming_convention,
        standards.get_required_log_settings,
        standards.get_review_requirements,
        # fortimanager (read-only)
        fmg.get_system_status,
        fmg.get_ha_status,
        fmg.get_adoms,
        fmg.get_devices,
        fmg.search_devices,
        fmg.search_policies,
        fmg.get_address_object,
        fmg.search_address_objects,
        fmg.get_service_object,
        fmg.get_policy,
        fmg.get_interface_map,
        fmg.get_routing_table,
        fmg.list_device_vdoms,
        fmg.get_device_interface_config,
        fmg.get_device_client_location,
        fmg.get_device_sdwan,
        fmg.get_device_sdwan_monitor,
        fmg.search_fqdn_rules,
        # feedback / audit
        feedback.record_feedback,
        feedback.get_similar_cases,
        feedback.get_feedback_summary,
        feedback.flag_for_review,
        feedback.get_audit_log,
        # intake
        intake.parse_spreadsheet_file,
        intake.parse_manual_entry_tool,
        intake.describe_template,
        intake.parse_fqdn_allowlist,
        # zone (live 4THealth — authoritative verdicts)
        zone.query_zone_policy,
        zone.get_zones,
        zone.get_policies,
        zone.find_zone_for_ip,
        zone.check_ip_traffic,
        # psirt advisory assessment
        psirt.parse_advisory,
        psirt.assess_fleet_exposure,
        psirt.render_psirt_report,
    ):
        mcp.add_tool(_logged(fn), annotations=_ANNOTATIONS.get(
            fn.__name__, ToolAnnotations(readOnlyHint=True)))


_register_existing_tools()


if __name__ == "__main__":
    mcp.run()
