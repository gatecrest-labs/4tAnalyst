#!/usr/bin/env python3
"""
Render an /analyze-request analysis (JSON payload) into two ticket-attachable
artifacts: an HTML report and a FortiGate CLI implementation/exception script.

Usage:
    uv run python scripts/render_report.py --data <path-to-json> --outdir output/

No external dependencies -- stdlib only, matching scripts/run_smoke.py's
"pure-Python, no external packages" convention.
"""
from __future__ import annotations

import argparse
import datetime
import html
import json
import sys
from pathlib import Path

REQUIRED_KEYS = {
    "request", "zone_verdict", "existing_rules", "naming", "logging",
    "approval", "recommendation", "cli",
}
REQUIRED_CLI_KEYS = {"status", "per_firewall"}
VALID_CLI_STATUSES = {
    "blocked_exception", "new_rule", "already_covered", "unknown_no_action",
}


class PayloadError(ValueError):
    """Raised when the input JSON payload is missing required data."""


def validate_payload(data: dict) -> None:
    if not isinstance(data, dict):
        raise PayloadError("payload must be a JSON object")
    missing = REQUIRED_KEYS - data.keys()
    if missing:
        raise PayloadError(f"payload missing required keys: {sorted(missing)}")
    cli = data["cli"]
    if not isinstance(cli, dict):
        raise PayloadError("payload['cli'] must be an object")
    missing_cli = REQUIRED_CLI_KEYS - cli.keys()
    if missing_cli:
        raise PayloadError(f"payload['cli'] missing required keys: {sorted(missing_cli)}")
    if cli["status"] not in VALID_CLI_STATUSES:
        raise PayloadError(
            f"payload['cli']['status'] must be one of {sorted(VALID_CLI_STATUSES)}, "
            f"got {cli['status']!r}"
        )
    if not isinstance(cli["per_firewall"], list):
        raise PayloadError("payload['cli']['per_firewall'] must be a list")


FQDN_REQUIRED_KEYS = {"plan_type", "vendor", "category", "src_ip", "per_firewall"}


def validate_fqdn_payload(data: dict) -> None:
    if not isinstance(data, dict):
        raise PayloadError("FQDN payload must be a JSON object")
    if data.get("plan_type") != "fqdn_allowlist":
        raise PayloadError("payload['plan_type'] must be 'fqdn_allowlist'")
    missing = FQDN_REQUIRED_KEYS - data.keys()
    if missing:
        raise PayloadError(f"FQDN payload missing required keys: {sorted(missing)}")
    if not isinstance(data["per_firewall"], list):
        raise PayloadError("payload['per_firewall'] must be a list")


def output_dir_name(data: dict) -> str:
    ticket_id = data.get("ticket_id")
    if ticket_id:
        return str(ticket_id)
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d_%H%M")


_STATUS_BANNERS = {
    "blocked_exception": (
        "# STATUS: BLOCKED -- this request is currently blocked by policy.\n"
        "# The commands below implement an EXCEPTION and must not be pushed\n"
        "# until the change has gone through approval (see approval chain in\n"
        "# the accompanying report.html) and any <TICKET_ID> / approver\n"
        "# placeholders below have been filled in.\n"
    ),
    "new_rule": (
        "# STATUS: ALLOWED -- no existing rule implements this flow yet.\n"
        "# The commands below create the required objects and policy.\n"
    ),
}


def render_conf(data: dict) -> str:
    cli = data["cli"]
    status = cli["status"]
    ticket = data.get("ticket_id") or "<TICKET_ID>"

    if status == "already_covered":
        return (
            "# STATUS: ALLOWED -- already covered by an existing rule.\n"
            "# No CLI changes are required. See report.html, section\n"
            "# 'Existing Rules on Named Firewalls', for the specific rule(s)\n"
            "# that already implement this flow.\n"
        )

    if status == "unknown_no_action":
        return (
            "# STATUS: UNKNOWN -- zone verdict could not be determined.\n"
            "# At least one of the source/destination IPs did not resolve to a\n"
            "# known zone. Nothing can be safely generated until the IP is\n"
            "# verified and/or the zone catalogue is updated. See report.html,\n"
            "# section 'Zone Policy Verdict', for details.\n"
        )

    parts = [_STATUS_BANNERS[status]]
    for fw in cli.get("per_firewall", []):
        parts.append(f"# {'=' * 77}")
        parts.append(f"# Firewall: {fw.get('firewall', '')}")
        parts.append(f"# {'=' * 77}")
        parts.append("")
        for w in fw.get("warnings", []):
            parts.append(f"# WARNING: {w}")
        if fw.get("warnings"):
            parts.append("")
        alt = fw.get("alternative")
        if alt:
            parts.append("# OPTION A -- new dedicated policy (default recommendation):")
            parts.append("")
        for obj in fw.get("address_objects", []):
            parts.append(obj.get("cli", "").replace("<TICKET_ID>", ticket))
            parts.append("")
        policy = fw.get("policy", {})
        if policy.get("cli"):
            parts.append(policy["cli"].replace("<TICKET_ID>", ticket))
            parts.append("")
        if alt:
            parts.append(f"# {'-' * 77}")
            parts.append("# OPTION B -- ALTERNATIVE: extend an existing rule instead.")
            parts.append(f"# {alt.get('summary', '')}")
            for w in alt.get("warnings", []):
                parts.append(f"# WARNING: {w}")
            for ar in alt.get("affected_rules", []):
                parts.append(
                    f"# ALSO AFFECTS: package {ar.get('package', '')!r} policy "
                    f"#{ar.get('policy_id', '')} {ar.get('name', '')!r} "
                    f"({ar.get('side', '')} via {'/'.join(ar.get('via', []))}, "
                    f"status {ar.get('status', '')})"
                )
            parts.append(f"# {'-' * 77}")
            parts.append("")
            if alt.get("member_cli"):
                parts.append(alt["member_cli"].replace("<TICKET_ID>", ticket))
                parts.append("")
            if alt.get("group_cli"):
                parts.append(alt["group_cli"].replace("<TICKET_ID>", ticket))
                parts.append("")
            elif alt.get("direct_cli"):
                parts.append(alt["direct_cli"].replace("<TICKET_ID>", ticket))
                parts.append("")
    return "\n".join(parts)


def render_fqdn_conf(data: dict) -> str:
    """Render FQDN allowlist plan as a FortiGate CLI implementation script."""
    ticket = data.get("ticket_id") or "<TICKET_ID>"
    parts: list[str] = []

    for fw in data.get("per_firewall", []):
        verdict = fw.get("verdict", "")
        parts.append(f"# {'=' * 77}")
        parts.append(f"# Firewall: {fw.get('firewall', '')} (ADOM: {fw.get('adom', '')})")
        parts.append(f"# Verdict:  {verdict}  |  Coverage: {fw.get('coverage', '')}")
        parts.append(f"# Source zone: {fw.get('src_zone', '')}  →  Internet (FQDN destination)")
        parts.append(f"# {'=' * 77}")
        parts.append("")

        for w in fw.get("warnings", []):
            parts.append(f"# WARNING: {w}")
        if fw.get("warnings"):
            parts.append("")

        if verdict == "already_covered":
            parts.append("# STATUS: already_covered — no CLI changes required.")
            parts.append("# All requested FQDNs are covered by existing rules.")
            parts.append("")
            continue

        if verdict == "unknown_no_action":
            parts.append("# STATUS: unknown_no_action — zone verdict could not be determined.")
            parts.append("# No CLI generated. Verify the source IP zone and re-run.")
            parts.append("")
            continue

        if verdict == "blocked_exception":
            parts.append(
                "# STATUS: blocked_exception — source zone is BLOCKED from Internet by policy.\n"
                "# The CLI below implements an EXCEPTION. Do not push until approved.\n"
            )

        # Coverage summary
        uncovered = fw.get("uncovered_entries", [])
        covered = fw.get("covered_entries", [])
        if covered:
            parts.append(f"# Already covered ({len(covered)} entries):")
            for e in covered:
                parts.append(f"#   {e['fqdn']}  ports={e['ports']}  protocol={e['protocol']}")
            parts.append("")
        if uncovered:
            parts.append(f"# New entries to implement ({len(uncovered)}):")
            for e in uncovered:
                parts.append(f"#   {e['fqdn']}  ports={e['ports']}  protocol={e['protocol']}")
            parts.append("")

        # Proposed address objects
        for obj in fw.get("proposed_objects", []):
            cli = obj.get("cli", "")
            if cli:
                parts.append(cli.replace("<TICKET_ID>", ticket))
                parts.append("")

        # Proposed group
        grp = fw.get("proposed_group")
        if grp and grp.get("cli"):
            parts.append(grp["cli"].replace("<TICKET_ID>", ticket))
            parts.append("")

        # Source / service objects + policy
        pol = fw.get("proposed_policy")
        if pol:
            if pol.get("src_object_cli"):
                parts.append(pol["src_object_cli"].replace("<TICKET_ID>", ticket))
                parts.append("")
            for svc_cli in pol.get("service_object_cli_blocks", []):
                parts.append(svc_cli.replace("<TICKET_ID>", ticket))
                parts.append("")
            if pol.get("cli"):
                parts.append(pol["cli"].replace("<TICKET_ID>", ticket))
                parts.append("")

        # Option B: group-append alternative
        alt = fw.get("group_append_alternative")
        if alt and alt.get("group_cli"):
            parts.append(f"# {'-' * 77}")
            parts.append(f"# OPTION B: append new FQDN objects to existing group {alt.get('group', '')!r}")
            parts.append(f"# {'-' * 77}")
            parts.append(alt["group_cli"].replace("<TICKET_ID>", ticket))
            parts.append("")

    return "\n".join(parts)


def esc(value) -> str:
    """HTML-escape a value, coercing to str first."""
    return html.escape(str(value))


def _render_meta_line(generated_at: str, model: str, cost_usd: str) -> str:
    parts = []
    if generated_at:
        parts.append(f"Generated: <code>{esc(generated_at)}</code>")
    if model:
        parts.append(f"AI model: <code>{esc(model)}</code>")
    if cost_usd:
        parts.append(f"Est. cost: <code>${esc(cost_usd)}</code>")
    return " &nbsp;·&nbsp; ".join(parts)


def render_html(
    data: dict,
    generated_at: str = "",
    model: str = "",
    cost_usd: str = "",
) -> str:
    request = data["request"]
    zone = data["zone_verdict"]
    existing = data["existing_rules"]
    naming = data["naming"]
    logging_ = data["logging"]
    approval = data["approval"]
    recommendation = data["recommendation"]
    ticket = data.get("ticket_id") or "(no ticket ID yet)"

    verdict = zone["verdict"]
    verdict_class = {
        "ALLOWED": "verdict-allowed",
        "BLOCKED": "verdict-blocked",
        "UNKNOWN": "verdict-unknown",
    }.get(verdict, "verdict-unknown")

    governing_html = "".join(
        f"<li><code>{esc(g.get('policy_set', ''))}</code> — {esc(g.get('access_type', ''))}, "
        f"severity: {esc(g.get('severity', ''))}</li>"
        for g in zone.get("governing", [])
    ) or "<li>No governing policy found</li>"

    def _rule_detail_table(r: dict) -> str:
        """Render one rule as a detail table row-group."""
        def csv(lst) -> str:
            if not lst:
                return "(none)"
            return ", ".join(esc(v) for v in lst)

        src_td = f"<code>{csv(r.get('source', []))}</code>"
        dst_td = f"<code>{csv(r.get('destination', []))}</code>"
        svc_td = f"<code>{csv(r.get('service', []))}</code>"
        pkg_td = esc(r.get('package', ''))
        raw_status = r.get('status', 'enable')
        disabled = raw_status in ('disable', 0)
        enabled = "Enabled" if not disabled else "<span style='color:var(--blocked)'>Disabled</span>"
        covered_pairs = r.get('covered_pairs', [])
        pairs_row = (
            f"<tr><th>Pairs covered</th><td><code>{esc(', '.join(covered_pairs))}</code></td></tr>"
            if covered_pairs else ""
        )
        unknown_refs = r.get('unknown_refs', [])
        unknown_row = (
            f"<tr><th>Unresolved refs</th><td><code>{esc(', '.join(unknown_refs))}</code> "
            f"<span class='note'>(coverage uncertain)</span></td></tr>"
            if unknown_refs else ""
        )
        svc_gap = r.get('svc_gap', [])
        gap_row = (
            f"<tr><th>Service gap</th><td><code>{esc(', '.join(svc_gap))}</code> "
            f"<span class='note'>— not covered by this rule</span></td></tr>"
            if svc_gap else ""
        )
        match_reason = r.get('match_reason', '')
        reason_row = (
            f"<tr><th>Near miss</th><td>{esc(match_reason)}</td></tr>"
            if match_reason else ""
        )
        return (
            f"<table class='rule-detail'>"
            f"<tr><th>Policy</th><td><strong>#{esc(r.get('policy_id', ''))}</strong> "
            f"\"{esc(r.get('name', ''))}\"</td></tr>"
            f"<tr><th>Package</th><td>{pkg_td}</td></tr>"
            f"<tr><th>Status</th><td>{enabled}</td></tr>"
            f"<tr><th>Source</th><td>{src_td}</td></tr>"
            f"<tr><th>Destination</th><td>{dst_td}</td></tr>"
            f"<tr><th>Service</th><td>{svc_td}</td></tr>"
            f"{pairs_row}{unknown_row}{gap_row}{reason_row}"
            f"</table>"
        )

    existing_html = ""
    for fw, info in existing.items():
        if "covering_rules" in info:
            covering = info["covering_rules"]
            partial = info.get("partial_matches", [])
        else:
            all_rules = info.get("rules", [])
            covering = [r for r in all_rules if r.get("full_cover", True)]
            partial = [r for r in all_rules if not r.get("full_cover", True)]

        covering_html = "".join(
            f"<div class='rule-card'>"
            f"<span class='tag tag-covering'>Covering</span>"
            f"{_rule_detail_table(r)}"
            f"</div>"
            for r in covering
        ) or ""

        partial_html = ""
        if partial:
            def _partial_card(r):
                if r.get('match_reason'):
                    tag = "Near miss"
                    note = esc(r['match_reason'])
                else:
                    tag = "Partial match"
                    note = ("This rule overlaps the request but does not fully "
                            "cover it — it is not sufficient on its own.")
                return (
                    f"<div class='rule-card'>"
                    f"<span class='tag tag-partial'>{esc(tag)}</span>"
                    f"{_rule_detail_table(r)}"
                    f"<div class='note'>{note}</div>"
                    f"</div>"
                )
            partial_cards = "".join(_partial_card(r) for r in partial)
            partial_html = (
                f"<div class='partial-section'>"
                f"<div class='partial-label'>Partial / overlapping matches</div>"
                f"{partial_cards}</div>"
            )

        if not covering_html and not partial_html:
            inner = "<div class='note'>(none)</div>"
        else:
            inner = covering_html + partial_html

        existing_html += (
            f"<div class='rule-card'><strong>{esc(fw)}</strong> "
            f"<span class='tag'>{esc(info.get('status', ''))}</span>"
            f"<div class='note'>{esc(info.get('note', ''))}</div>"
            f"{inner}</div>"
        )
    if not existing_html:
        existing_html = "<div class='note'>No firewalls were checked.</div>"

    naming_rows = "".join(
        f"<tr><th>{esc(o.get('role', ''))} ({esc(o.get('type', ''))})</th>"
        f"<td><code>{esc(o.get('name', ''))}</code> "
        f"<span class='note'>pattern: {esc(o.get('pattern', ''))}</span></td></tr>"
        for o in naming.get("objects", [])
    ) or "<tr><td colspan='2'>No new objects required</td></tr>"

    approvers_html = "".join(f"<span>{esc(a)}</span>" for a in approval.get("approvers", []))

    warnings_html = ""
    for fw_cli in data["cli"].get("per_firewall", []):
        for w in fw_cli.get("warnings", []):
            warnings_html += f"<li><strong>{esc(fw_cli.get('firewall', ''))}:</strong> {esc(w)}</li>"
    warnings_block = (
        f"<section><h2>Warnings</h2><ul>{warnings_html}</ul></section>"
        if warnings_html else ""
    )

    alt_html = ""
    for fw_cli in data["cli"].get("per_firewall", []):
        alt = fw_cli.get("alternative")
        if not alt:
            continue
        alt_warn_html = "".join(f"<li>{esc(w)}</li>" for w in alt.get("warnings", []))
        if alt.get("group"):
            affected_html = "".join(
                f"<li>package <code>{esc(a.get('package', ''))}</code> policy "
                f"#{esc(a.get('policy_id', ''))} \"{esc(a.get('name', ''))}\" "
                f"({esc(a.get('side', ''))} via {esc('/'.join(a.get('via', [])))}, "
                f"status {esc(a.get('status', ''))})</li>"
                for a in alt.get("affected_rules", [])
            ) or "<li>No other rules reference this group.</li>"
            scope_html = (
                f"<p><strong>Other rules referencing group "
                f"<code>{esc(alt.get('group', ''))}</code>:</strong></p>"
                f"<ul>{affected_html}</ul>"
            )
        else:
            scope_html = (
                "<p class='note'>Direct address-list change — only this rule is "
                "affected. No blast radius.</p>"
            )
        alt_html += (
            f"<div class='rule-card'><strong>{esc(fw_cli.get('firewall', ''))}</strong> "
            f"<span class='tag'>OPTION B</span>"
            f"<div class='note'>{esc(alt.get('summary', ''))}</div>"
            f"{scope_html}"
            f"<ul>{alt_warn_html}</ul></div>"
        )
    alt_block = (
        "<section><h2>Alternative: Extend Existing Rule</h2>"
        "<div class='note'>The generated CLI contains both options — "
        "implement ONE, not both.</div>"
        f"{alt_html}</section>"
        if alt_html else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Firewall Request Analysis — {esc(ticket)}</title>
<style>
  :root {{
    --bg: #0b0d12; --panel: #12151c; --border: #232733; --text: #e6e9ef;
    --muted: #8b94a7; --accent: #5b8cff;
    --blocked: #ef4444; --blocked-bg: #2a1215;
    --allowed: #22c55e; --allowed-bg: #122a18;
    --unknown: #eab308; --unknown-bg: #2a2512;
    --code-bg: #0e1015;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    line-height: 1.55; }}
  .wrap {{ max-width: 880px; margin: 0 auto; padding: 48px 24px 80px; }}
  header {{ margin-bottom: 32px; padding-bottom: 24px; border-bottom: 1px solid var(--border); }}
  header .kicker {{ color: var(--accent); font-size: 13px; font-weight: 600;
    letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 8px; }}
  h1 {{ font-size: 26px; margin: 0 0 8px; }}
  .meta {{ color: var(--muted); font-size: 14px; }}
  .meta code {{ color: var(--text); background: var(--code-bg); padding: 1px 6px; border-radius: 4px; }}
  section {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 20px 24px; margin-bottom: 20px; }}
  section h2 {{ font-size: 15px; text-transform: uppercase; letter-spacing: 0.04em;
    color: var(--muted); margin: 0 0 14px; }}
  .verdict-badge {{ display: inline-flex; align-items: center; gap: 8px; font-weight: 700;
    font-size: 16px; padding: 6px 14px; border-radius: 999px; margin-bottom: 16px; border: 1px solid; }}
  .verdict-blocked {{ background: var(--blocked-bg); color: var(--blocked); border-color: rgba(239,68,68,0.35); }}
  .verdict-allowed {{ background: var(--allowed-bg); color: var(--allowed); border-color: rgba(34,197,94,0.35); }}
  .verdict-unknown {{ background: var(--unknown-bg); color: var(--unknown); border-color: rgba(234,179,8,0.35); }}
  .verdict-badge .dot {{ width: 9px; height: 9px; border-radius: 50%; background: currentColor; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  table td, table th {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  table th {{ color: var(--muted); font-weight: 600; width: 220px; }}
  code, pre {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
  .rule-card {{ background: var(--code-bg); border: 1px solid var(--border); border-radius: 8px;
    padding: 12px 14px; margin-bottom: 10px; font-size: 14px; }}
  .rule-card .tag {{ display: inline-block; font-size: 11px; text-transform: uppercase;
    letter-spacing: 0.04em; color: var(--muted); border: 1px solid var(--border); border-radius: 4px;
    padding: 1px 6px; margin-left: 8px; }}
  .rule-detail {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 10px; }}
  .rule-detail td, .rule-detail th {{ padding: 5px 8px; border-bottom: 1px solid var(--border);
    vertical-align: top; }}
  .rule-detail th {{ color: var(--muted); font-weight: 600; width: 140px; white-space: nowrap; }}
  .rule-detail code {{ font-size: 12px; }}
  .partial-section {{ margin-top: 14px; border-top: 1px solid var(--border); padding-top: 10px; }}
  .partial-label {{ color: var(--unknown); font-size: 12px; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; }}
  .tag-partial {{ color: var(--unknown); border-color: rgba(234,179,8,0.35);
    background: var(--unknown-bg); }}
  .tag-covering {{ color: var(--allowed); border-color: rgba(34,197,94,0.35);
    background: var(--allowed-bg); }}
  .note {{ color: var(--muted); font-size: 13px; margin-top: 8px; }}
  .recommendation {{ border-left: 3px solid var(--accent); background: var(--code-bg);
    padding: 14px 18px; border-radius: 0 8px 8px 0; font-size: 14.5px; white-space: pre-wrap; }}
  .approver-list {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }}
  .approver-list span {{ background: var(--code-bg); border: 1px solid var(--border);
    border-radius: 999px; padding: 4px 12px; font-size: 13px; }}
  ul {{ margin: 8px 0 0; padding-left: 20px; }}
  li {{ margin-bottom: 4px; }}
  footer {{ color: var(--muted); font-size: 12px; margin-top: 40px; text-align: center; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="kicker">4tAnalyst · /analyze-request</div>
    <h1>Firewall Request Analysis</h1>
    <div class="meta">Ticket: <code>{esc(ticket)}</code></div>
    <div class="meta" style="margin-top:6px">{_render_meta_line(generated_at, model, cost_usd)}</div>
  </header>

  <section>
    <h2>Request Summary</h2>
    <table>
      <tr><th>Source</th><td><code>{esc(request.get('src', ''))}</code></td></tr>
      <tr><th>Destination</th><td><code>{esc(request.get('dst', ''))}</code></td></tr>
      <tr><th>Service</th><td>{esc(request.get('service', ''))}</td></tr>
      <tr><th>Business justification</th><td>{esc(request.get('justification', ''))}</td></tr>
      <tr><th>Firewalls</th><td>{esc(', '.join(request.get('firewalls', [])))}</td></tr>
    </table>
  </section>

  <section>
    <h2>Zone Policy Verdict</h2>
    <div class="verdict-badge {verdict_class}"><span class="dot"></span>{esc(verdict)}</div>
    <table>
      <tr><th>Source zones</th><td>{esc(', '.join(zone.get('src_zones', [])) or '(none)')}</td></tr>
      <tr><th>Destination zones</th><td>{esc(', '.join(zone.get('dst_zones', [])) or '(none)')}</td></tr>
    </table>
    <div class="note">Governing policies:</div>
    <ul>{governing_html}</ul>
  </section>

  <section>
    <h2>Existing Rules on Named Firewalls</h2>
    {existing_html}
  </section>

  <section>
    <h2>Object Naming</h2>
    <table>{naming_rows}</table>
  </section>

  <section>
    <h2>Logging Requirements</h2>
    <table>
      <tr><th>Rule type</th><td>{esc(logging_.get('rule_type', ''))}</td></tr>
      <tr><th>log_start</th><td>{esc(logging_.get('log_start', ''))}</td></tr>
      <tr><th>log_end</th><td>{esc(logging_.get('log_end', ''))}</td></tr>
      <tr><th>alert_on_match</th><td>{esc(logging_.get('alert_on_match', ''))}</td></tr>
      <tr><th>retention_days</th><td>{esc(logging_.get('retention_days', ''))}</td></tr>
      <tr><th>siem_forward</th><td>{esc(logging_.get('siem_forward', ''))}</td></tr>
    </table>
    <div class="note">{esc(logging_.get('notes', ''))}</div>
  </section>

  <section>
    <h2>Approval Requirements</h2>
    <table>
      <tr><th>Risk level</th><td><strong>{esc(approval.get('risk_level', ''))}</strong></td></tr>
      <tr><th>Peer review required</th><td>{esc(approval.get('peer_review', ''))}</td></tr>
      <tr><th>Security review required</th><td>{esc(approval.get('security_review', ''))}</td></tr>
      <tr><th>Change window</th><td>{esc(approval.get('change_window', ''))}</td></tr>
      <tr><th>SLA</th><td>{esc(approval.get('sla_hours', ''))} hours</td></tr>
    </table>
    <div class="approver-list">{approvers_html}</div>
  </section>

  {alt_block}

  {warnings_block}

  <section>
    <h2>Recommendation</h2>
    <div class="recommendation">{esc(recommendation)}</div>
  </section>

  <footer>Generated by scripts/render_report.py from an /analyze-request analysis.</footer>
</div>
</body>
</html>
"""


def render_fqdn_html(
    data: dict,
    generated_at: str = "",
    model: str = "",
    cost_usd: str = "",
) -> str:
    """Render FQDN allowlist plan as an HTML report."""
    ticket = data.get("ticket_id") or "(no ticket ID yet)"
    vendor = esc(data.get("vendor", ""))
    category = esc(data.get("category", ""))
    src_ip = esc(data.get("src_ip", ""))

    fw_sections = []
    for fw in data.get("per_firewall", []):
        verdict = fw.get("verdict", "")
        verdict_cls = {
            "new_rule": "verdict-allowed",
            "already_covered": "verdict-allowed",
            "blocked_exception": "verdict-blocked",
            "unknown_no_action": "verdict-unknown",
            "error": "verdict-unknown",
            "partial_coverage": "verdict-allowed",
        }.get(verdict, "verdict-unknown")

        uncovered_rows = "".join(
            f"<tr><td><code>{esc(e['fqdn'])}</code></td>"
            f"<td>{esc(', '.join(str(p) for p in e.get('ports', [])))}</td>"
            f"<td>{esc(e.get('protocol', ''))}</td>"
            f"<td>{'Yes' if e.get('required') else 'No'}</td>"
            f"<td>{esc(e.get('comment', ''))}</td></tr>"
            for e in fw.get("uncovered_entries", [])
        )
        covered_rows = "".join(
            f"<tr><td><code>{esc(e['fqdn'])}</code></td>"
            f"<td>{esc(', '.join(str(p) for p in e.get('ports', [])))}</td>"
            f"<td>{esc(e.get('protocol', ''))}</td>"
            f"<td>Already covered</td><td></td></tr>"
            for e in fw.get("covered_entries", [])
        )

        obj_rows = "".join(
            f"<tr><td><code>{esc(o['name'])}</code></td>"
            f"<td>{esc(o['obj_type'])}</td>"
            f"<td><code>{esc(o['value'])}</code></td></tr>"
            for o in fw.get("proposed_objects", [])
        )

        grp = fw.get("proposed_group") or {}
        pol = fw.get("proposed_policy") or {}

        fw_sections.append(f"""
<section class="firewall-section">
  <h2>Firewall: <code>{esc(fw.get('firewall', ''))}</code>
      &nbsp;<span class="badge {verdict_cls}">{esc(verdict)}</span>
      {' &nbsp;<span class="badge badge-warn">DEGRADED</span>' if fw.get('degraded') else ''}
  </h2>
  <p><strong>Source zone:</strong> <code>{esc(fw.get('src_zone', ''))}</code>
     &nbsp;→&nbsp; <strong>Internet</strong> (FQDN destination)</p>
  {f'<ul class="warnings">{"".join(f"<li>{esc(w)}</li>" for w in fw.get("warnings", []))}</ul>' if fw.get('warnings') else ''}

  <h3>FQDN Coverage</h3>
  <table>
    <thead><tr><th>FQDN</th><th>Ports</th><th>Protocol</th><th>Required</th><th>Notes</th></tr></thead>
    <tbody>{covered_rows}{uncovered_rows}</tbody>
  </table>

  {f'''<h3>Proposed Address Objects</h3>
  <table>
    <thead><tr><th>Name</th><th>Type</th><th>Value</th></tr></thead>
    <tbody>{obj_rows}</tbody>
  </table>''' if obj_rows else ''}

  {f'<h3>Proposed Group: <code>{esc(grp.get("name",""))}</code></h3><p>Members: {esc(", ".join(grp.get("members",[])))}</p>' if grp else ''}
  {f'<h3>Proposed Policy: <code>{esc(pol.get("name",""))}</code></h3><p><strong>Package:</strong> <code>{esc(pol.get("package",""))}</code></p>' if pol else ''}
</section>""")

    meta_line = _render_meta_line(generated_at, model, cost_usd)
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>FQDN Allowlist: {esc(ticket)}</title>
<style>
body{{font-family:sans-serif;max-width:1100px;margin:2em auto;padding:0 1em}}
code{{background:#f4f4f4;padding:2px 4px;border-radius:3px}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ddd;padding:6px 10px;text-align:left}}
th{{background:#f8f8f8}}
.verdict-allowed{{background:#d4edda;color:#155724;padding:2px 8px;border-radius:4px}}
.verdict-blocked{{background:#f8d7da;color:#721c24;padding:2px 8px;border-radius:4px}}
.verdict-unknown{{background:#fff3cd;color:#856404;padding:2px 8px;border-radius:4px}}
.badge-warn{{background:#ffc107;color:#000;padding:2px 8px;border-radius:4px}}
.warnings{{background:#fff3cd;border-left:4px solid #ffc107;padding:0.5em 1em;margin:1em 0}}
.firewall-section{{border:1px solid #ddd;border-radius:6px;padding:1.5em;margin:1.5em 0}}
</style>
</head><body>
<h1>FQDN Allowlist Change Plan</h1>
<p><strong>Ticket:</strong> <code>{esc(ticket)}</code>
   &nbsp; <strong>Vendor:</strong> {vendor} — {category}
   &nbsp; <strong>Source:</strong> <code>{src_ip}</code></p>
{f'<p class="meta">{meta_line}</p>' if meta_line else ''}
{''.join(fw_sections)}
</body></html>"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", required=True, help="Path to the JSON payload")
    parser.add_argument("--outdir", required=True, help="Base output directory")
    parser.add_argument("--model", default="", help="AI model name shown in report header")
    parser.add_argument("--cost-usd", default="", dest="cost_usd",
                        help="Estimated AI cost in USD shown in report header")
    args = parser.parse_args(argv)

    data_path = Path(args.data)
    try:
        with open(data_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: could not read/parse {data_path}: {exc}", file=sys.stderr)
        return 1

    plan_type = data.get("plan_type", "ip_change")
    generated_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    try:
        if plan_type == "fqdn_allowlist":
            validate_fqdn_payload(data)
            html = render_fqdn_html(
                data, generated_at=generated_at,
                model=args.model, cost_usd=args.cost_usd,
            )
            conf = render_fqdn_conf(data)
        else:
            validate_payload(data)
            html = render_html(
                data, generated_at=generated_at,
                model=args.model, cost_usd=args.cost_usd,
            )
            conf = render_conf(data)
    except PayloadError as exc:
        print(f"error: invalid payload: {exc}", file=sys.stderr)
        return 1

    folder_name = output_dir_name(data)
    outdir = Path(args.outdir) / folder_name
    outdir.mkdir(parents=True, exist_ok=True)

    html_path = outdir / f"report-{folder_name}.html"
    conf_path = outdir / "implementation.conf"
    data_path = outdir / "payload.json"

    html_path.write_text(html, encoding="utf-8")
    conf_path.write_text(conf, encoding="utf-8")
    data_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    print(str(html_path))
    print(str(conf_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
