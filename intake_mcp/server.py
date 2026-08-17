"""
Intake MCP Server

Replaces the ServiceNow MCP for request intake. Engineers either drop a
spreadsheet path or enter request details manually — both paths produce the
same normalised FirewallRequest that the analysis workflow consumes.

Exposes three tools to Claude:
  - parse_spreadsheet   : Parse a .xlsx firewall request form
  - parse_manual_entry  : Accept manually entered request details as JSON
  - describe_template   : Return the expected spreadsheet structure so Claude
                          can guide an engineer who is filling it out

The normalised output includes all four request types:
  - FW Rules (most common)
  - Group membership changes
  - IP block/allow requests
  - VPN tunnel configuration

Missing required fields are flagged in the response so Claude can prompt
the engineer for them before proceeding to analysis.

Run locally (stdio):
  python -m intake_mcp.server

Run as SSE server (production):
  mcp run intake_mcp/server.py --transport sse --port 8004
"""

import json
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from intake_mcp.fqdn_parser import parse_fqdn_rows, parse_fqdn_xlsx
from intake_mcp.parser import parse_manual_entry, parse_spreadsheet

logger = logging.getLogger(__name__)

mcp = FastMCP(
    name="intake",
    instructions=(
        "Firewall request intake server. "
        "Use parse_spreadsheet when the engineer provides a path to an .xlsx file. "
        "Use parse_manual_entry when the engineer describes the request in conversation "
        "or pastes details as text — collect the fields and pass them as a JSON object. "
        "Both tools return the same normalised FirewallRequest structure. "
        "Always check the missing_fields and warnings arrays in the response before "
        "proceeding to analysis — prompt the engineer to fill gaps before continuing."
    ),
)


# ---------------------------------------------------------------------------
# Tool: parse_spreadsheet
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def parse_spreadsheet_file(file_path: str) -> dict[str, Any]:
    """
    Parse a firewall request spreadsheet (.xlsx).

    Handles the standard multi-tab template with FW Rules, Group Request,
    IP Block/Allow, and VPN tabs. Tab names are matched flexibly so minor
    naming differences between template versions are handled automatically.

    Parameters
    ----------
    file_path : str
        Absolute or relative path to the .xlsx file.
        Engineers can drag-and-drop the file into the terminal to get the path,
        or use the full path (e.g. /Users/engineer/Downloads/FW_Request_RITM123.xlsx).

    Returns a FirewallRequest dict with:
      reference_id         : str   — ticket/reference number if provided in the file
      rule_owner           : str   — engineer responsible for the request
      business_contact     : str
      business_area        : str
      nuclear_environment  : bool  — true if request is for Nuclear environment
      designation          : str   — OT / CIP / IT / Gas / etc.
      estimated_completion : str
      source_file          : str   — original filename
      fw_rules             : list  — parsed firewall rules (source, dest, port, protocol, justification)
      group_changes        : list  — address group membership changes
      ip_block_allow       : list  — IP block or allow entries
      vpn_config           : dict  — VPN tunnel parameters (Local + Remote sides), or null
      missing_fields       : list  — required fields that are empty (prompt engineer for these)
      warnings             : list  — non-blocking issues found during parsing
    """
    try:
        req = parse_spreadsheet(file_path)
        result = req.to_dict()
        result["parsed_ok"] = True

        # Summary for Claude to use in its response
        summary_parts = []
        if req.fw_rules:
            summary_parts.append(f"{len(req.fw_rules)} FW rule(s)")
        if req.group_changes:
            summary_parts.append(f"{len(req.group_changes)} group change(s)")
        if req.ip_block_allow:
            summary_parts.append(f"{len(req.ip_block_allow)} IP block/allow entry(ies)")
        if req.has_vpn():
            summary_parts.append("1 VPN tunnel configuration")

        result["summary"] = (
            f"Parsed {req.source_file}: " + (", ".join(summary_parts) or "no content found")
        )
        return result

    except FileNotFoundError as e:
        return {"parsed_ok": False, "error": str(e)}
    except ImportError as e:
        return {"parsed_ok": False, "error": str(e)}
    except Exception as e:
        logger.exception("Unexpected error parsing %s", file_path)
        return {"parsed_ok": False, "error": f"Unexpected error: {e}"}


# ---------------------------------------------------------------------------
# Tool: parse_manual_entry
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def parse_manual_entry_tool(fields_json: str) -> dict[str, Any]:
    """
    Accept a firewall request entered manually (not from a spreadsheet).

    Use this when the engineer describes their request in conversation or
    provides details via a catalog form screenshot. Collect the details,
    structure them as a JSON object, and pass it here.

    Parameters
    ----------
    fields_json : str
        JSON string representing the request. Accepted keys:

        Top-level metadata (all optional, missing ones flagged):
          reference_id         : "RITM0012345" or any identifier
          rule_owner           : "Alan Wodarski"
          business_contact     : "Jane Smith"
          business_area        : "OT Engineering"
          nuclear_environment  : false
          designation          : "OT"   (OT | CIP | IT | Gas | Internet)
          estimated_completion : "2026-07-15"

        fw_rules: list of rule objects:
          [{ "rule_number": "Rule #1", "operation": "Add",
             "source": "10.1.2.3", "destination": "10.4.5.6",
             "port": "443", "protocol": "TCP",
             "application": "SCADA HMI", "justification": "..." }]

        group_changes: list of group change objects:
          [{ "group_name": "GRP_OT_SCADA", "new_membership": "10.1.2.3",
             "action": "Add" }]

        ip_block_allow: list of IP block/allow entries:
          [{ "ip_address": "8.8.8.8", "operation": "Block",
             "justification": "Known malicious IP" }]

        vpn_config: VPN tunnel parameters (see describe_template for full schema)

    Returns the same FirewallRequest structure as parse_spreadsheet.
    """
    try:
        fields = json.loads(fields_json)
    except json.JSONDecodeError as e:
        return {
            "parsed_ok": False,
            "error": f"Invalid JSON: {e}. Use describe_template to see the expected format.",
        }

    try:
        req = parse_manual_entry(fields)
        result = req.to_dict()
        result["parsed_ok"] = True

        summary_parts = []
        if req.fw_rules:
            summary_parts.append(f"{len(req.fw_rules)} FW rule(s)")
        if req.group_changes:
            summary_parts.append(f"{len(req.group_changes)} group change(s)")
        if req.ip_block_allow:
            summary_parts.append(f"{len(req.ip_block_allow)} IP block/allow entry(ies)")
        if req.has_vpn():
            summary_parts.append("1 VPN tunnel configuration")

        result["summary"] = "Manual entry: " + (", ".join(summary_parts) or "no content")
        return result

    except Exception as e:
        logger.exception("Error in parse_manual_entry")
        return {"parsed_ok": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Tool: describe_template
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def describe_template() -> dict[str, Any]:
    """
    Return the expected structure of the firewall request spreadsheet
    and the manual entry JSON format.

    Use this to:
    - Guide an engineer who is unsure what to include in their request
    - Show the expected JSON format for parse_manual_entry
    - List which fields are required vs optional

    Returns a description of each tab and field, plus an example JSON for
    parse_manual_entry.
    """
    return {
        "spreadsheet_tabs": {
            "FW Rules": {
                "purpose": "Standard firewall rule additions or removals",
                "columns": [
                    {"name": "Rule #", "required": False, "example": "Rule #1"},
                    {"name": "Add / Remove", "required": True, "example": "Add"},
                    {"name": "Source IP/Host Name", "required": True, "example": "10.1.2.3 or server01.corp"},
                    {"name": "Destination IP/Host Name", "required": True, "example": "10.4.5.6"},
                    {"name": "Port #", "required": True, "example": "443 or 8443-8445"},
                    {"name": "Protocol", "required": False, "example": "TCP (defaults to N/A if blank)"},
                    {"name": "Application Using These Ports", "required": False, "example": "SCADA HMI web interface"},
                    {"name": "Business Justification", "required": True, "example": "OT historian needs to push data to IT data lake"},
                ],
            },
            "Group Request": {
                "purpose": "Add or remove IPs/hosts from existing firewall address groups",
                "columns": [
                    {"name": "Group", "required": True, "example": "GRP_OT_SCADA_Servers"},
                    {"name": "New Group Membership Should Be", "required": True, "example": "10.1.2.3"},
                    {"name": "Action Required", "required": True, "example": "Add or Remove"},
                ],
            },
            "IP Block/Allow": {
                "purpose": "Block or allow specific IPs at the perimeter",
                "columns": [
                    {"name": "IP address", "required": True, "example": "8.8.8.8 or 203.0.113.0/24"},
                    {"name": "Business Justification", "required": True, "example": "Vendor IP for remote support"},
                ],
                "note": "The tab title (row 1) indicates whether these are Block or Allow requests",
            },
            "VPN": {
                "purpose": "Site-to-site VPN tunnel configuration",
                "sections": ["Local Section (left)", "Remote Section (right)"],
                "fields_per_side": [
                    "VPN Device", "VPN Tunnel Endpoint address",
                    "IKE Encryption", "Authentication Method", "Diffie-Helman Group",
                    "Security Association Lifetime (Phase 1)",
                    "IPSEC Encryption", "Hash (Phase 2)", "Security Association Lifetime (Phase 2)",
                    "Perfect Forward Secrecy (PFS)", "Networks/Host Routes (multiple rows)",
                ],
            },
        },
        "catalog_form_fields": {
            "required": [
                "Request is for the Nuclear environment (Yes/No)",
                "Select designation (OT / CIP / IT / Gas / Internet)",
                "Rule Owner responsible for the overall request",
                "Business Contact responsible for the implemented request",
                "Business Area responsible for the implemented Request",
                "Estimated date of completion",
            ],
            "note": (
                "The catalog form has the same FW Rules table as the spreadsheet tab. "
                "For large requests (many rules), use the spreadsheet attachment instead."
            ),
        },
        "manual_entry_example": {
            "reference_id": "RITM0012345",
            "rule_owner": "Alan Wodarski",
            "business_contact": "Jane Smith",
            "business_area": "OT Engineering",
            "nuclear_environment": False,
            "designation": "OT",
            "estimated_completion": "2026-07-15",
            "fw_rules": [
                {
                    "rule_number": "Rule #1",
                    "operation": "Add",
                    "source": "10.1.2.3",
                    "destination": "10.4.5.6",
                    "port": "443",
                    "protocol": "TCP",
                    "application": "SCADA HMI",
                    "justification": "OT historian to IT data lake",
                }
            ],
            "group_changes": [],
            "ip_block_allow": [],
            "vpn_config": None,
        },
    }


# ---------------------------------------------------------------------------
# Tool: parse_fqdn_allowlist
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def parse_fqdn_allowlist(
    src_ip: str,
    ticket_id: str,
    firewalls: list[str],
    rows: list[dict] | None = None,
    file_path: str = "",
) -> dict:
    """
    Parse a vendor URL allowlist into a normalised FQDNAllowlistRequest.

    Accepts either a list of row dicts (for conversational entry) or a path
    to an .xlsx file. The table must have columns: Hostname/Domain, Port(s),
    Protocol, Direction, Vendor, Category, Required?, Purpose/Notes.

    Parameters
    ----------
    src_ip      : Source IP or CIDR (the internal host/network that needs access)
    ticket_id   : Change ticket ID (e.g. CHG0012345)
    firewalls   : Target firewalls as "DEVICE:ADOM" strings
    rows        : List of row dicts (use when engineer pastes table in conversation)
    file_path   : Path to .xlsx file (use when engineer provides a file)

    Returns FQDNAllowlistRequest with entries, warnings, and missing_fields.
    Always check missing_fields and warnings before calling plan_fqdn_change.
    """
    import dataclasses
    try:
        if file_path:
            req = parse_fqdn_xlsx(file_path, src_ip=src_ip, ticket_id=ticket_id,
                                  firewalls=firewalls)
        else:
            req = parse_fqdn_rows(rows or [], src_ip=src_ip, ticket_id=ticket_id,
                                  firewalls=firewalls)
        return dataclasses.asdict(req)
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
