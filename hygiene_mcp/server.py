"""
Rule Hygiene Fix MCP server.

Parses a completed Rule Hygiene run's findings (JSON/CSV, pasted or
uploaded) and computes deterministic FortiGate CLI remediation per finding,
cross-referenced against the live policy package. Read-only — no CLI is
ever applied to FortiManager or a device.

Run locally (stdio):
  python -m hygiene_mcp.server
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from fortimanager_mcp import query as _query
from fortimanager_mcp.client import FortiManagerClient
from fwanalyst_server.context import allowed_adoms_var
from hygiene.engine import assess as _assess
from hygiene.models import Finding, HygieneDataError, HygieneParseError, PolicyFix, FixOption, HygieneResult
from hygiene.parse import parse_csv, parse_json
from hygiene.report import render_html
from mcp_common.errors import safe_error
from mcp_common.validation import ValidationError, validate_adom, validate_device_name

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).parent.parent
_DEFAULT_CREDS = _REPO_ROOT / "credentials.yaml"

mcp = FastMCP(
    name="hygiene",
    instructions=(
        "Rule Hygiene fix assessment. Call parse_hygiene_findings on a "
        "pasted or uploaded Rule Hygiene export, then assess_hygiene_fixes "
        "with the resulting findings plus the ADOM/device/package the run "
        "was against."
    ),
)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def parse_hygiene_findings(
    text: str = "", file_content: str = "", file_type: str = "json"
) -> dict[str, Any]:
    """
    Parse a Rule Hygiene run's findings from pasted text or an uploaded file.

    Parameters
    ----------
    text         : str — pasted findings (JSON or CSV text)
    file_content : str — uploaded file's text content; wins over `text` when
                   both are given
    file_type    : str — "json" or "csv"

    Returns {"findings": [...]} or {"error": ..., "error_code": ...}.
    """
    raw = file_content if file_content.strip() else text
    if not raw.strip():
        return {"error": "no findings text or file content provided", "error_code": "invalid_input"}
    if file_type not in ("json", "csv"):
        return {"error": f"file_type must be 'json' or 'csv', got {file_type!r}", "error_code": "invalid_input"}
    try:
        findings = parse_json(raw) if file_type == "json" else parse_csv(raw)
    except HygieneParseError as e:
        return {"error": str(e), "error_code": "parse_error"}
    return {"findings": [f.to_dict() for f in findings]}


@lru_cache(maxsize=1)
def _load_creds() -> dict:
    creds_path = Path(os.getenv("CREDENTIALS_FILE", str(_DEFAULT_CREDS)))
    if not creds_path.exists():
        raise FileNotFoundError(
            f"credentials.yaml not found at {creds_path}. "
            "Copy credentials.yaml.example to credentials.yaml and fill in values."
        )
    with open(creds_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _fortimanager_client() -> FortiManagerClient:
    """Build a connected FortiManagerClient from credentials.yaml.

    Re-implemented here (mirrors fortimanager_mcp/server.py's private
    _fortimanager_client, and psirt_mcp/server.py's own equivalent) rather
    than importing fortimanager_mcp/server.py's underscore-prefixed name.
    """
    cfg = _load_creds().get("fortimanager", {})
    raw_hosts = cfg.get("hosts", [])
    if not raw_hosts:
        raise ValueError("fortimanager.hosts is empty in credentials.yaml.")
    hosts = [(h.get("host", "").strip(), h.get("api_key", "").strip()) for h in raw_hosts]
    hosts = [(h, k) for h, k in hosts if h and k]
    if not hosts:
        raise ValueError("Each fortimanager.hosts entry needs a non-empty host and api_key.")
    primary_host, primary_key = hosts[0]
    secondary_host, secondary_key = hosts[1] if len(hosts) > 1 else ("", "")
    c = FortiManagerClient(
        primary_host=primary_host, primary_key=primary_key,
        secondary_host=secondary_host, secondary_key=secondary_key,
        port=int(cfg.get("port", 443)),
        verify_ssl=bool(cfg.get("verify_ssl", True)),
        version=str(cfg.get("version", "7.4")),
    )
    c.login()
    return c


def _require_adom(adom: str) -> dict | None:
    """Return error dict if the caller's token does not allow this ADOM, else
    None. Mirrors fortimanager_mcp/server.py::_require_adom exactly — that
    function is module-private there, so this is a deliberate re-
    implementation, not a duplication bug."""
    allowed = allowed_adoms_var.get({"*"})
    if "*" in allowed or adom in allowed:
        return None
    return {
        "error": f"ADOM '{adom}' is not in your allowed list.",
        "error_code": "forbidden",
    }


def _finding_kwargs(d: dict) -> dict:
    return {
        "policy_id": str(d["policy_id"]),
        "policy_name": str(d.get("policy_name", "")),
        "seq": int(d.get("seq", 0) or 0),
        "check": str(d["check"]),
        "detail": str(d.get("detail", "")),
        "severity": str(d.get("severity", "")),
        "shadow_rule": d.get("shadow_rule"),
        "shadowing_rule": d.get("shadowing_rule"),
        "duplicate_of": d.get("duplicate_of"),
    }


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def assess_hygiene_fixes(
    adom: str, device: str, pkg: str, findings: list[dict]
) -> dict[str, Any]:
    """
    Compute deterministic remediation for a Rule Hygiene run's findings.

    Re-fetches the live policy package for `pkg` in `adom` (scoped to that
    one package — never a whole-ADOM fetch), cross-references each finding
    by policy ID, and returns per-finding fix options plus a rendered HTML
    report. Never applies anything to FortiManager.

    Parameters
    ----------
    adom     : str        — ADOM name
    device   : str        — device name (display only; not used to scope
               the fetch, since policies belong to packages, not devices)
    pkg      : str        — policy package name the hygiene run was against
    findings : list[dict] — findings from parse_hygiene_findings

    Returns the assessment dict plus html_content/html_error, or
    {"error": ..., "error_code": ...}.
    """
    try:
        adom = validate_adom(adom)
        device = validate_device_name(device)
    except ValidationError as e:
        message, code = safe_error(e)
        return {"error": message, "error_code": code}
    if err := _require_adom(adom):
        return err
    if not pkg or not pkg.strip():
        return {"error": "pkg is required", "error_code": "invalid_input"}

    try:
        parsed_findings = [Finding(**_finding_kwargs(f)) for f in findings]
    except (TypeError, KeyError) as e:
        return {"error": f"malformed findings: {e}", "error_code": "invalid_input"}

    try:
        with _fortimanager_client() as client:
            live_by_pkg = _query.get_device_policies(client, adom, [pkg])
    except Exception as e:
        message, code = safe_error(e)
        return {"error": message, "error_code": code}

    try:
        result = _assess(parsed_findings, live_by_pkg, device, adom, pkg)
    except HygieneDataError as e:
        return {"error": str(e), "error_code": "upstream_error"}

    payload = result.to_dict()
    try:
        payload["html_content"] = render_html(result)
        payload["html_error"] = None
    except Exception as e:
        payload["html_content"] = None
        payload["html_error"] = str(e)
    return payload


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def render_hygiene_report(assessment: dict[str, Any]) -> dict[str, Any]:
    """
    Re-render the HTML report from a previously computed assessment dict
    (the structure assess_hygiene_fixes returns, minus html_content/
    html_error). Retry path for when the inline render in
    assess_hygiene_fixes failed.
    """
    try:
        fixes = [
            PolicyFix(
                policy_id=f["policy_id"], policy_name=f["policy_name"], check=f["check"],
                options=[FixOption(**o) for o in f.get("options", [])],
            )
            for f in assessment["fixes"]
        ]
        result = HygieneResult(
            device=assessment["device"], adom=assessment["adom"], pkg=assessment["pkg"],
            generated_at=assessment["generated_at"], fixes=fixes,
            stale_findings=assessment.get("stale_findings", []),
        )
        return {"html_content": render_html(result)}
    except Exception as e:
        message, code = safe_error(e)
        return {"error": message, "error_code": code}


if __name__ == "__main__":
    mcp.run()
