"""
Combines policy CSVs and zones.csv into a single JSON policy database.

Output structure:
  {
    "zones": {
      "<zone_name>": {
        "domain": str,
        "is_shared": bool,
        "description": str,
        "subnets": [{"subnet": str, "description": str}, ...],
        "children": [str, ...],
        "parents": [str, ...]
      }
    },
    "policies": [
      {
        "policy_set": str,       # source filename (without .csv)
        "from_domain": str,
        "from_zone": str,
        "to_domain": str,
        "to_zone": str,
        "severity": str,
        "access_type": str,      # "allow all" | "block all" | "block only"
        "services": [str, ...],  # parsed from "services/applications" column
        "rule_properties": str,
        "flows": str,
        "description": str
      }
    ]
  }
"""

import csv
import json
import re
from pathlib import Path

DATA_DIR = Path(__file__).parent / "policy-data"
OUTPUT_FILE = Path(__file__).parent / "policy_db.json"

# Policy CSV files to ingest (all non-zones CSVs)
POLICY_FILES = [
    "NETZONE CIP-H OT only domain.csv",
    "NETZONE CIP-H.csv",
    "NETZONE Gas To or From IT and Internet.csv",
    "NETZONE Inbound.csv",
    "NETZONE OT and CIP-H To and From Internet and IT.csv",
    "NETZONE OT and CIPH to_from Internet and IT OT domain only.csv",
]


def parse_zones(path: Path) -> dict:
    """Parse zones.csv (multi-section format) into a zones dict."""
    zones: dict[str, dict] = {}

    section = None
    headers: list[str] = []

    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or all(cell.strip() == "" for cell in row):
                continue

            first = row[0].strip()

            # Section header rows start with #
            if first.startswith("#"):
                section = first.lstrip("#").strip()
                headers = []
                continue

            # First non-empty row after a section header is the column header row
            if not headers:
                headers = [h.strip() for h in row]
                continue

            if section == "Zone Properties":
                record = dict(zip(headers, [c.strip() for c in row]))
                name = record.get("zone name", "")
                if not name:
                    continue
                zones.setdefault(name, {
                    "domain": record.get("domain", ""),
                    "is_shared": record.get("is shared", "false").lower() == "true",
                    "description": record.get("description", ""),
                    "subnets": [],
                    "children": [],
                    "parents": [],
                })

            elif section == "Zone Hierarchy":
                record = dict(zip(headers, [c.strip() for c in row]))
                parent = record.get("parent", "")
                child = record.get("child", "")
                if parent and child:
                    zones.setdefault(parent, _empty_zone())["children"].append(child)
                    zones.setdefault(child, _empty_zone())["parents"].append(parent)

            elif section == "Zone Subnets":
                record = dict(zip(headers, [c.strip() for c in row]))
                name = record.get("zone name", "")
                subnet = record.get("subnet", "")
                if name and subnet:
                    zones.setdefault(name, _empty_zone())["subnets"].append({
                        "subnet": subnet,
                        "description": record.get("description", ""),
                    })

            # Zone Security Groups section is currently empty — skip

    return zones


def _empty_zone() -> dict:
    return {
        "domain": "",
        "is_shared": False,
        "description": "",
        "subnets": [],
        "children": [],
        "parents": [],
    }


def parse_services(raw: str) -> list[str]:
    """Split comma/semicolon-separated services string into a list."""
    if not raw or not raw.strip():
        return []
    return [s.strip() for s in re.split(r"[,;]", raw) if s.strip()]


def parse_policies(path: Path, policy_set_name: str) -> list[dict]:
    """Parse a single policy CSV into a list of rule dicts."""
    rules = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rules.append({
                "policy_set": policy_set_name,
                "from_domain": row.get("from domain", "").strip(),
                "from_zone": row.get("from zone", "").strip(),
                "to_domain": row.get("to domain", "").strip(),
                "to_zone": row.get("to zone", "").strip(),
                "severity": row.get("severity", "").strip(),
                "access_type": row.get("access type", "").strip(),
                "services": parse_services(row.get("services/applications", "")),
                "rule_properties": row.get("rule properties", "").strip(),
                "flows": row.get("flows", "").strip(),
                "description": row.get("description", "").strip(),
            })
    return rules


def main():
    print(f"Reading zones from: {DATA_DIR / 'zones.csv'}")
    zones = parse_zones(DATA_DIR / "zones.csv")
    print(f"  {len(zones)} zones loaded")

    all_policies = []
    for filename in POLICY_FILES:
        path = DATA_DIR / filename
        if not path.exists():
            print(f"  WARNING: {filename} not found, skipping")
            continue
        policy_set_name = Path(filename).stem
        rules = parse_policies(path, policy_set_name)
        print(f"  {len(rules):3d} rules from: {filename}")
        all_policies.extend(rules)

    db = {
        "_readme": {
            "about": (
                "Network segmentation policy database — generated by build_policy_db.py. "
                "Do not edit this file by hand; use edit_db.py instead, or re-run "
                "build_policy_db.py after updating the CSV exports in policy-data/."
            ),
            "scripts": {
                "build_policy_db.py": "Re-parse all policy-data/ CSVs and rebuild this file.",
                "query_flow.py": (
                    "Query this database to evaluate whether a src→dst traffic flow "
                    "is allowed or blocked. Accepts bare IPs, CIDR subnets, or "
                    "dotted-decimal masks. Supports multiple --src and --dst values."
                ),
                "edit_db.py": (
                    "Add, remove, or modify zones and policy rules in this file. "
                    "Also validates the file with 'python3 edit_db.py validate'."
                ),
            },
            "structure": {
                "zones": {
                    "_description": (
                        "Dict keyed by zone name. Each zone represents a named "
                        "network segment. Zone names are referenced by policy rules."
                    ),
                    "_fields": {
                        "domain": "Administrative domain this zone belongs to (usually 'Default').",
                        "is_shared": "Whether this zone is shared across multiple domains.",
                        "description": "Human-readable description of the zone.",
                        "subnets": (
                            "List of {subnet, description} objects. Each 'subnet' is a "
                            "CIDR range (e.g. '10.1.2.0/24'). query_flow.py uses these "
                            "to map an IP address to a zone."
                        ),
                        "children": (
                            "Zone names that are sub-zones of this one. A policy rule "
                            "referencing a parent zone applies to all child zones."
                        ),
                        "parents": "Zone names that this zone is a sub-zone of.",
                    },
                },
                "policies": {
                    "_description": (
                        "List of policy rules. Each rule defines whether traffic "
                        "from one zone to another should be allowed or blocked. "
                        "Rules are evaluated in precedence order: 'block all' > "
                        "'block only' (service match) > 'allow all'. If no rule "
                        "covers a zone pair the flow is implicitly denied."
                    ),
                    "_fields": {
                        "policy_set": "Name of the policy set (rule group) this rule belongs to.",
                        "from_domain": "Source domain filter ('All Domains' matches any).",
                        "from_zone": "Name of the source zone (must match a key in 'zones').",
                        "to_domain": "Destination domain filter.",
                        "to_zone": "Name of the destination zone.",
                        "severity": "Severity level assigned to this rule: 'high' or 'critical'.",
                        "access_type": (
                            "One of: 'allow all' (permit traffic), "
                            "'block all' (deny all traffic), "
                            "'block only' (deny only the services listed in 'services')."
                        ),
                        "services": (
                            "List of protocol/service names blocked when access_type is "
                            "'block only' (e.g. ['ssh', 'RDP', 'telnet', 'ftp']). "
                            "Empty for 'allow all' and 'block all' rules."
                        ),
                        "rule_properties": "Optional rule property flags.",
                        "flows": "Optional flow count or reference.",
                        "description": "Optional human-readable note about this rule.",
                    },
                },
            },
        },
        "zones": zones,
        "policies": all_policies,
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)

    print(f"\nWrote {OUTPUT_FILE}")
    print(f"  {len(zones)} zones, {len(all_policies)} policy rules")


if __name__ == "__main__":
    main()
