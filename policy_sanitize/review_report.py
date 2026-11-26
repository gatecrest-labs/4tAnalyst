"""Self-contained HTML report for /review-policy findings (stdlib only).

The findings JSON is written by the model from SANITIZED data; it is still
treated as untrusted: validated strictly and every value html-escaped. The
output has inline CSS only, no JavaScript and no external resources.
"""
from __future__ import annotations

import html
import re

SEVERITIES = ("Critical", "High", "Medium", "Low")
UNVERIFIED_LABEL = "unverified — confirm with the hygiene checks"
BANNER = ("Values in this report are sanitized stand-ins — use the local map-back "
          "step to restore real names. Do not paste the mapped report into Claude.")
DEFAULT_SCOPE_LIMITS = (
    "no group membership in the export; findings on group references are limited",
    "sanitized values are fake",
)
CSP = "default-src 'none'; style-src 'unsafe-inline'"

MAX_FINDINGS = 500
MAX_TITLE = 200
MAX_TEXT = 2000  # why / fix
MAX_SHORT = 500  # rule_name, rule_seq/rule_id as text, each scope limit
MAX_SUMMARY = 5000
MAX_SCOPE = 50

_RUN_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_CLI_RE = re.compile(r"^\s*(?:(?:config|edit|set|unset)\s|(?:next|end)\s*$)", re.MULTILINE)

_MESSAGES = {
    "not_object": "findings document must be a JSON object",
    "run_id": "run_id must be 16 lowercase hex characters",
    "summary": "summary must be a string within the size limit",
    "generated_note": "generated_note must be a string within the size limit",
    "findings": "findings must be a list",
    "too_many": "too many findings",
    "finding": "each finding must be an object with severity, title, why and fix",
    "severity": "severity must be one of Critical, High, Medium, Low",
    "field_type": "a finding field has the wrong type",
    "too_long": "a finding field exceeds its size limit",
    "cli_not_allowed": "fix text must be words only, not CLI",
    "scope_limits": "scope_limits must be a list of short strings",
}


class ReportError(Exception):
    """Fixed message per code; never carries any value from the findings."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(f"{code}: {_MESSAGES.get(code, 'invalid findings')}")


def _str(v: object, limit: int, code: str = "field_type") -> None:
    if not isinstance(v, str):
        raise ReportError(code)
    if len(v) > limit:
        raise ReportError("too_long" if code == "field_type" else code)


def _ref(v: object) -> None:
    if isinstance(v, bool) or not isinstance(v, (int, str)):
        raise ReportError("field_type")
    if isinstance(v, str) and len(v) > MAX_SHORT:
        raise ReportError("too_long")


def validate_findings(findings: dict) -> None:
    if not isinstance(findings, dict):
        raise ReportError("not_object")
    rid = findings.get("run_id")
    if not isinstance(rid, str) or not _RUN_ID_RE.match(rid):
        raise ReportError("run_id")
    _str(findings.get("summary"), MAX_SUMMARY, "summary")
    if "generated_note" in findings:
        _str(findings["generated_note"], MAX_SHORT, "generated_note")
    items = findings.get("findings")
    if not isinstance(items, list):
        raise ReportError("findings")
    if len(items) > MAX_FINDINGS:
        raise ReportError("too_many")
    for f in items:
        if not isinstance(f, dict) or not all(k in f for k in ("severity", "title", "why", "fix")):
            raise ReportError("finding")
        if f["severity"] not in SEVERITIES:
            raise ReportError("severity")
        _str(f["title"], MAX_TITLE)
        _str(f["why"], MAX_TEXT)
        _str(f["fix"], MAX_TEXT)
        for k in ("rule_seq", "rule_id"):
            if k in f:
                _ref(f[k])
        if "rule_name" in f:
            _str(f["rule_name"], MAX_SHORT)
        if "unverified" in f and not isinstance(f["unverified"], bool):
            raise ReportError("field_type")
        if _CLI_RE.search(f["fix"]):
            raise ReportError("cli_not_allowed")
    limits = findings.get("scope_limits", [])
    if not isinstance(limits, list) or len(limits) > MAX_SCOPE or not all(
        isinstance(s, str) and len(s) <= MAX_SHORT for s in limits
    ):
        raise ReportError("scope_limits")


def _e(v: object) -> str:
    return html.escape("" if v is None else str(v), quote=True)


_CSS = """
body{font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;margin:2rem;color:#1d1d1f;line-height:1.45}
h1{font-size:1.5rem;margin-bottom:.25rem}h2{margin-top:2rem;border-bottom:2px solid #ddd;padding-bottom:.25rem}
.banner{background:#fff4e5;border:1px solid #f0a020;padding:.75rem 1rem;border-radius:4px;font-weight:600}
.note{color:#555;font-size:.9rem}
table{border-collapse:collapse;width:100%;margin-top:.5rem}
th,td{border:1px solid #ccc;padding:.4rem .5rem;text-align:left;vertical-align:top}
th{background:#f3f3f3}
.pre{white-space:pre-wrap}
.unverified{display:inline-block;background:#eef;border:1px solid #99c;border-radius:3px;padding:0 .3rem;font-size:.85rem}
.sev-critical h2{color:#a50e0e}.sev-high h2{color:#c2410c}.sev-medium h2{color:#a16207}.sev-low h2{color:#3f6212}
"""


def render_review_html(findings: dict) -> str:
    validate_findings(findings)
    rid = findings["run_id"]
    items = findings["findings"]
    by_sev = {s: [f for f in items if f["severity"] == s] for s in SEVERITIES}
    limits = list(DEFAULT_SCOPE_LIMITS) + [
        s for s in findings.get("scope_limits", []) if s not in DEFAULT_SCOPE_LIMITS
    ]
    out = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">',
        f"<title>Policy review {_e(rid)}</title>",
        f"<style>{_CSS}</style>",
        "</head>",
        "<body>",
        f"<h1>Policy review — run {_e(rid)}</h1>",
        f'<p class="banner">{_e(BANNER)}</p>',
    ]
    if findings.get("generated_note"):
        out.append(f'<p class="note">{_e(findings["generated_note"])}</p>')
    out += [
        "<h2>Summary</h2>",
        f'<p class="pre">{_e(findings["summary"])}</p>',
        "<table><thead><tr><th>Severity</th><th>Findings</th></tr></thead><tbody>",
    ]
    for s in SEVERITIES:
        out.append(f"<tr><td>{_e(s)}</td><td>{len(by_sev[s])}</td></tr>")
    out.append(f"<tr><td>Total</td><td>{len(items)}</td></tr></tbody></table>")
    for s in SEVERITIES:
        fs = by_sev[s]
        out.append(f'<section class="sev-{s.lower()}" id="sev-{s.lower()}">')
        out.append(f"<h2>{_e(s)} ({len(fs)})</h2>")
        if not fs:
            out.append("<p>None.</p></section>")
            continue
        out.append(
            "<table><thead><tr><th>Seq</th><th>ID</th><th>Rule</th><th>Finding</th>"
            "<th>Why it matters</th><th>Suggested fix</th></tr></thead><tbody>"
        )
        for f in fs:
            title = _e(f["title"])
            if f.get("unverified"):
                title += f' <span class="unverified">{_e(UNVERIFIED_LABEL)}</span>'
            out.append(
                f"<tr><td>{_e(f.get('rule_seq', ''))}</td><td>{_e(f.get('rule_id', ''))}</td>"
                f"<td>{_e(f.get('rule_name', ''))}</td><td>{title}</td>"
                f'<td class="pre">{_e(f["why"])}</td><td class="pre">{_e(f["fix"])}</td></tr>'
            )
        out.append("</tbody></table></section>")
    out.append("<h2>Scope limits</h2><ul>")
    out += [f"<li>{_e(s)}</li>" for s in limits]
    out += ["</ul>", "</body>", "</html>", ""]
    return "\n".join(out)
