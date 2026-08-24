"""
PSIRT advisory assessment MCP server.

Exposes three tools:
  - parse_advisory        : validate/shape the LLM's structured extraction
                             of a PSIRT email into an Advisory dict
  - assess_fleet_exposure : run the deterministic psirt.engine.assess()
                             against the live fleet
  - render_psirt_report   : render the assessment to an HTML report via
                             scripts/render_report.py

parse_advisory does NOT call an LLM itself — the calling model (Claude
Code, orchestrating via the /analyze-psirt skill) is expected to read the
raw email/eml text and pass its own structured extraction in `extracted`.
This mirrors intake_mcp.parse_manual_entry_tool, which normalises
conversationally-entered data rather than parsing it itself.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from psirt.engine import assess
from psirt.models import Advisory, AffectedRange

mcp = FastMCP(name="psirt")

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_REPO_ROOT = Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# Tool: parse_advisory
# ---------------------------------------------------------------------------

@mcp.tool()
def parse_advisory(
    email_text: str = "",
    eml_path: str = "",
    extracted: dict[str, Any] | None = None,
) -> dict:
    """
    Validate and shape a structured PSIRT advisory extraction.

    Parameters
    ----------
    email_text : str  — raw PSIRT email text (paste), for context/audit only
    eml_path    : str  — path to a saved .eml file, for context/audit only
    extracted   : dict — the structured fields YOU (the calling model) pulled
                  out of the email/eml. Required keys: advisory_id, cve_ids,
                  affected_ranges (list of {product, min_version, max_version,
                  fixed_version, notes}). Optional: advisory_url,
                  published_date, fortinet_severity, cvss_score, description,
                  workaround_text, exploited_in_wild_text.

    Returns the validated Advisory as a dict, or {"error": ...} if a
    required field is missing or malformed — ask the engineer to supply it
    rather than guessing.
    """
    if extracted is None:
        return {"error": "extracted is required — parse the email/eml text and pass structured fields"}

    advisory_id = str(extracted.get("advisory_id", "")).strip()
    if not advisory_id:
        return {"error": "extracted.advisory_id is required"}
    if not re.match(r'^[A-Za-z0-9._-]+$', advisory_id):
        return {"error": f"advisory_id contains invalid characters: {advisory_id!r} (allowed: A-Z a-z 0-9 . _ -)"}

    cve_ids = extracted.get("cve_ids", [])
    if not isinstance(cve_ids, list) or not cve_ids:
        return {"error": "extracted.cve_ids must be a non-empty list"}
    for cve in cve_ids:
        if not _CVE_RE.match(str(cve)):
            return {"error": f"malformed CVE id: {cve!r} (expected CVE-YYYY-NNNN)"}

    raw_ranges = extracted.get("affected_ranges", [])
    if not isinstance(raw_ranges, list) or not raw_ranges:
        return {"error": "extracted.affected_ranges must be a non-empty list"}
    ranges = []
    for r in raw_ranges:
        if not isinstance(r, dict) or not r.get("product"):
            return {"error": f"malformed affected_ranges entry: {r!r} (product is required)"}
        ranges.append(AffectedRange(
            product=str(r.get("product", "")),
            min_version=str(r.get("min_version", "")),
            max_version=str(r.get("max_version", "")),
            fixed_version=str(r.get("fixed_version", "")),
            notes=str(r.get("notes", "")),
        ))

    raw_cvss = extracted.get("cvss_score")
    cvss_score = None
    if raw_cvss is not None:
        try:
            cvss_score = float(raw_cvss)
        except (TypeError, ValueError):
            return {"error": f"cvss_score must be a number, got: {raw_cvss!r}"}

    advisory = Advisory(
        advisory_id=advisory_id,
        advisory_url=str(extracted.get("advisory_url", "")),
        cve_ids=[str(c) for c in cve_ids],
        published_date=str(extracted.get("published_date", "")),
        fortinet_severity=str(extracted.get("fortinet_severity", "")),
        cvss_score=cvss_score,
        description=str(extracted.get("description", "")),
        affected_ranges=ranges,
        workaround_text=str(extracted.get("workaround_text", "")),
        exploited_in_wild_text=str(extracted.get("exploited_in_wild_text", "")),
    )
    return advisory.to_dict()


# ---------------------------------------------------------------------------
# FortiManager / HTTP client wiring — mirrors fwanalyst_server's
# _build_fmg_client(): reads this repo's own credentials.yaml, no clients
# baked in by default.
# ---------------------------------------------------------------------------

def _load_credentials() -> dict:
    import os

    import yaml

    creds_path = Path(os.getenv("CREDENTIALS_FILE", str(_REPO_ROOT / "credentials.yaml")))
    if creds_path.exists():
        with open(creds_path, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    return {}


def _build_fmg_client():
    from fortimanager_mcp.client import FortiManagerClient

    cfg = _load_credentials().get("fortimanager", {})
    hosts = [(h.get("host", ""), h.get("api_key", "")) for h in cfg.get("hosts", [])]
    hosts = [(h, k) for h, k in hosts if h and k]
    if not hosts:
        raise RuntimeError("fortimanager.hosts is empty in credentials.yaml")
    primary = hosts[0]
    secondary = hosts[1] if len(hosts) > 1 else ("", "")
    client = FortiManagerClient(
        primary_host=primary[0], primary_key=primary[1],
        secondary_host=secondary[0], secondary_key=secondary[1],
        port=cfg.get("port", 443),
        verify_ssl=cfg.get("verify_ssl", True),
        version=str(cfg.get("version", "7.4")),
    )
    client.login()
    return client


def _build_http_client():
    import httpx

    return httpx.Client()


def _psirt_config() -> dict:
    return _load_credentials().get("psirt", {})


# ---------------------------------------------------------------------------
# Tool: assess_fleet_exposure
# ---------------------------------------------------------------------------

@mcp.tool()
def assess_fleet_exposure(advisory: dict[str, Any], output_dir: str = "") -> dict:
    """
    Assess the fleet's exposure to a PSIRT advisory.

    Parameters
    ----------
    advisory   : dict — the output of parse_advisory (or matching shape).
    output_dir : str  — base output directory for the saved assessment JSON and
                 HTML report; defaults to a PSIRT/ folder next to this repo.
                 Pass an absolute path to write to a specific location on the
                 engineer's machine.

    Always saves the full assessment JSON to
    <output_dir>/<advisory_id>/assessment.json and renders the HTML report to
    <output_dir>/<advisory_id>/<advisory_id>.html so large fleets never need
    to relay the full payload back through the model context.

    Returns a summary dict (advisory metadata + verdict counts + file paths)
    that is small enough to display regardless of fleet size.
    """
    import json

    ranges = [
        AffectedRange(
            product=r.get("product", ""),
            min_version=r.get("min_version", ""),
            max_version=r.get("max_version", ""),
            fixed_version=r.get("fixed_version", ""),
            notes=r.get("notes", ""),
        )
        for r in advisory.get("affected_ranges", [])
    ]
    adv = Advisory(
        advisory_id=advisory.get("advisory_id", ""),
        advisory_url=advisory.get("advisory_url", ""),
        cve_ids=advisory.get("cve_ids", []),
        published_date=advisory.get("published_date", ""),
        fortinet_severity=advisory.get("fortinet_severity", ""),
        cvss_score=advisory.get("cvss_score"),
        description=advisory.get("description", ""),
        affected_ranges=ranges,
        workaround_text=advisory.get("workaround_text", ""),
        exploited_in_wild_text=advisory.get("exploited_in_wild_text", ""),
    )

    advisory_id = adv.advisory_id or "unknown-advisory"
    if not re.match(r'^[A-Za-z0-9._-]+$', advisory_id):
        return {"error": f"advisory_id contains invalid characters: {advisory_id!r}"}

    cfg = _psirt_config()
    kev_url = cfg.get("kev_feed_url", "") if cfg.get("fortiguard_advisory_fetch", True) is not False else ""

    fmg_client = _build_fmg_client()
    http_client = _build_http_client()
    result = assess(adv, fmg_client, http_client, kev_url)
    payload = result.to_dict()
    payload["plan_type"] = "psirt_advisory"

    # --- Save full assessment to disk so render never needs the inline payload ---
    base = Path(output_dir).expanduser() if output_dir else (_REPO_ROOT / "PSIRT")
    outdir = (base / advisory_id).resolve()
    if not outdir.is_relative_to(base.resolve()):
        return {"error": f"advisory_id would escape output directory: {advisory_id!r}"}
    outdir.mkdir(parents=True, exist_ok=True)

    json_path = outdir / "assessment.json"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # Render HTML immediately — no second tool call needed for normal fleets
    sys.path.insert(0, str(_REPO_ROOT / "scripts"))
    html_path: Path | None = None
    html_error: str | None = None
    try:
        from render_report import render_psirt_html, validate_psirt_payload
        validate_psirt_payload(payload)
        html = render_psirt_html(payload)
        html_path = outdir / f"{advisory_id}.html"
        html_path.write_text(html, encoding="utf-8")
    except Exception as exc:
        html_error = str(exc)

    # --- Return a compact summary dict ---
    from collections import Counter
    verdict_counts = dict(Counter(f["verdict"] for f in payload.get("findings", [])))
    return {
        "advisory_id": advisory_id,
        "priority": payload.get("priority"),
        "priority_rationale": payload.get("priority_rationale"),
        "kev_hit": payload.get("kev_hit"),
        "degraded": payload.get("degraded"),
        "warnings": payload.get("warnings", []),
        "total_findings": len(payload.get("findings", [])),
        "verdict_counts": verdict_counts,
        "assessment_json": str(json_path),
        "html_report": str(html_path) if html_path else None,
        "html_error": html_error,
        "plan_type": "psirt_advisory",
    }


# ---------------------------------------------------------------------------
# Tool: render_psirt_report
# ---------------------------------------------------------------------------

@mcp.tool()
def render_psirt_report(
    assessment: dict[str, Any] | None = None,
    assessment_path: str = "",
    output_dir: str = "",
) -> dict:
    """
    Render a PsirtAssessment to an HTML report.

    For large fleets, pass assessment_path (the assessment.json path returned
    by assess_fleet_exposure) instead of the full assessment dict — this avoids
    relaying a large payload through the model context.

    Parameters
    ----------
    assessment      : dict — inline assessment dict (small fleets / re-render).
    assessment_path : str  — path to assessment.json saved by assess_fleet_exposure.
                      Takes precedence over assessment if both are provided.
    output_dir      : str  — base output directory; defaults to PSIRT/ next to
                      the repo root (same default as assess_fleet_exposure).
    """
    import json

    sys.path.insert(0, str(_REPO_ROOT / "scripts"))
    from render_report import PayloadError, render_psirt_html, validate_psirt_payload

    if assessment_path:
        p = Path(assessment_path).expanduser()
        if not p.exists():
            return {"error": f"assessment_path not found: {assessment_path!r}"}
        payload = json.loads(p.read_text(encoding="utf-8"))
    elif assessment is not None:
        payload = dict(assessment)
    else:
        return {"error": "provide either assessment or assessment_path"}

    payload.setdefault("plan_type", "psirt_advisory")

    try:
        validate_psirt_payload(payload)
    except PayloadError as exc:
        return {"error": str(exc)}

    advisory_id = payload.get("advisory", {}).get("advisory_id", "") or "unknown-advisory"
    if not re.match(r'^[A-Za-z0-9._-]+$', advisory_id):
        return {"error": f"advisory_id contains invalid characters: {advisory_id!r} (allowed: A-Z a-z 0-9 . _ -)"}
    base = Path(output_dir).expanduser() if output_dir else (_REPO_ROOT / "PSIRT")
    outdir = (base / advisory_id).resolve()
    if not outdir.is_relative_to(base.resolve()):
        return {"error": f"advisory_id would escape output directory: {advisory_id!r}"}
    outdir.mkdir(parents=True, exist_ok=True)

    html = render_psirt_html(payload)
    html_path = outdir / f"{advisory_id}.html"
    html_path.write_text(html, encoding="utf-8")

    return {"html_path": str(html_path)}
