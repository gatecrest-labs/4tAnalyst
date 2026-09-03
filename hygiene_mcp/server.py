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
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from hygiene.models import HygieneParseError
from hygiene.parse import parse_csv, parse_json

logger = logging.getLogger(__name__)

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


if __name__ == "__main__":
    mcp.run()
