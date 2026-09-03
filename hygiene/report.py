"""
Stdlib-only HTML report renderer for a HygieneResult — mirrors
scripts/render_report.py's zero-dependency convention. No third-party
templating; f-strings + html.escape().
"""

from __future__ import annotations

import html

from hygiene.models import HygieneResult, PolicyFix


def render_html(result: HygieneResult) -> str:
    banner = (
        f"<h1>Rule Hygiene Fixes — {html.escape(result.device)} / "
        f"{html.escape(result.pkg)} ({html.escape(result.adom)})</h1>"
        f"<p>Generated: {html.escape(result.generated_at)}</p>"
    )
    cards = "".join(_render_fix_card(fix) for fix in result.fixes)

    stale_html = ""
    if result.stale_findings:
        rows = "".join(
            f"<li>Policy {html.escape(str(f.get('policy_id')))} "
            f"({html.escape(str(f.get('policy_name')))}) — "
            f"{html.escape(str(f.get('reason')))}</li>"
            for f in result.stale_findings
        )
        stale_html = f"<h2>Stale findings</h2><ul>{rows}</ul>"

    title = f"Hygiene Fixes — {result.device}_{result.pkg}"
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>{html.escape(title)}</title>"
        "<style>"
        "body{font-family:sans-serif;margin:2rem;color:#111}"
        ".finding{border:1px solid #d1d5db;border-radius:6px;padding:1rem;margin-bottom:1rem}"
        ".option{margin-top:0.75rem}"
        ".irreversible{color:#991b1b;font-weight:700}"
        "pre{background:#f3f4f6;padding:0.75rem;overflow-x:auto}"
        "</style>"
        f"</head><body>{banner}{cards}{stale_html}</body></html>"
    )


def _render_fix_card(fix: PolicyFix) -> str:
    opts_html = []
    for opt in fix.options:
        flag = '<span class="irreversible">⚠ Irreversible</span> ' if opt.irreversible else ""
        if opt.cli:
            cli_html = "".join(f"<pre>{html.escape(block)}</pre>" for block in opt.cli)
        else:
            cli_html = "<p><em>No CLI — manual review required.</em></p>"
        opts_html.append(
            "<div class='option'>"
            f"{flag}<strong>Option {html.escape(opt.option_id)}: {html.escape(opt.label)}</strong>"
            f"<p>{html.escape(opt.description)}</p>{cli_html}"
            "</div>"
        )
    return (
        "<div class='finding'>"
        f"<h3>{html.escape(fix.check)} — {html.escape(fix.policy_name)} "
        f"(id {html.escape(fix.policy_id)})</h3>"
        f"{''.join(opts_html)}"
        "</div>"
    )
