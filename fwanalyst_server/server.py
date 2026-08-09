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
# fgplanner client wiring
# ---------------------------------------------------------------------------
#
# fgplanner ships no default clients and reads no credentials file (see
# fgplanner/clients.py) — callers must register zero-argument factories that
# build a FortiManagerClient / ZonePolicyClient from this repo's own
# credentials.yaml. This mirrors the deleted planner/engine.py
# _default_fmg_client()/_default_zone_client() helpers. Registration is
# idempotent (it's just an assignment) and happens lazily inside
# plan_change() below, since that's the one code path guaranteed to run
# regardless of entry point (stdio, HTTP, or a raw import).

def _load_credentials() -> dict:
    import os
    from pathlib import Path

    import yaml

    repo_root = Path(__file__).parent.parent
    creds_path = Path(os.getenv("CREDENTIALS_FILE", str(repo_root / "credentials.yaml")))
    if creds_path.exists():
        with open(creds_path, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    return {}


def _build_fmg_client():
    from fgplanner.models import PlannerDataError

    from fortimanager_mcp.client import FortiManagerClient

    cfg = _load_credentials().get("fortimanager", {})
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


def _build_zone_client():
    from fgplanner.models import PlannerDataError

    from zone_mcp.client import ZonePolicyClient

    cfg = _load_credentials().get("zone_policy", {})
    if not cfg.get("base_url") or not cfg.get("token"):
        raise PlannerDataError("credentials", "zone_policy.base_url/token missing in credentials.yaml")
    return ZonePolicyClient(
        base_url=cfg["base_url"],
        token=cfg["token"],
        verify_ssl=bool(cfg.get("verify_ssl", False)),
        timeout=float(cfg.get("timeout", 30.0)),
    )


def _register_fgplanner_clients() -> None:
    """Register fwanalyst_server's client factories with fgplanner.

    Safe to call repeatedly — registration is just an assignment, and the
    factories aren't invoked until plan_change() actually needs a client, so
    there's no I/O cost to calling this on every plan_change() invocation.
    """
    from fgplanner.clients import (
        register_fmg_client_factory,
        register_zone_client_factory,
    )

    register_fmg_client_factory(_build_fmg_client)
    register_zone_client_factory(_build_zone_client)


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
                    (e.g. ["SITE01-FW01:OT-ADOM"]). The engineer names these;
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
    from fgplanner.engine import plan_change as _plan
    from fgplanner.engine import to_report_payload
    from fgplanner.models import PlannerDataError, TargetFirewall

    _register_fgplanner_clients()

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
        # zone (live 4THealth — authoritative verdicts)
        zone.query_zone_policy,
        zone.get_zones,
        zone.get_policies,
        zone.find_zone_for_ip,
        zone.check_ip_traffic,
    ):
        mcp.add_tool(_logged(fn), annotations=_ANNOTATIONS.get(
            fn.__name__, ToolAnnotations(readOnlyHint=True)))


_register_existing_tools()


if __name__ == "__main__":
    mcp.run()
