"""
import_zone_map.py

Bootstrap / update device_zone_map.yaml from FortiManager or a CSV file.

Usage:
  python scripts/import_zone_map.py --from-fortimanager [--map-file PATH] [--dry-run] [--verbose]
  python scripts/import_zone_map.py --from-csv FILE     [--map-file PATH] [--dry-run] [--verbose]
  python scripts/import_zone_map.py --export-csv FILE   [--map-file PATH]
"""

import argparse
import csv
import os
import sys
from pathlib import Path

import yaml

# Repo root is one level up from scripts/
_REPO_ROOT = Path(__file__).parent.parent
_DEFAULT_MAP_FILE = _REPO_ROOT / "device_zone_map.yaml"
_DEFAULT_CREDS = _REPO_ROOT / "credentials.yaml"


# ---------------------------------------------------------------------------
# Credentials / client helpers (mirrors fortimanager_mcp/server.py pattern
# without importing the MCP server, which has side-effects at module load)
# ---------------------------------------------------------------------------

def _load_creds(creds_path: Path) -> dict:
    if not creds_path.exists():
        print(
            f"ERROR: credentials.yaml not found at {creds_path}.\n"
            "Copy credentials.yaml.example to credentials.yaml and fill in values.",
            file=sys.stderr,
        )
        sys.exit(1)
    with open(creds_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _build_client(creds_path: Path):
    # Import here so missing optional deps don't break CSV / export modes
    try:
        from fortimanager_mcp.client import FortiManagerAPIError, FortiManagerClient
    except ImportError as exc:
        print(
            f"ERROR: Could not import fortimanager_mcp.client: {exc}\n"
            "Run: uv pip install -e mcp_common/ -e fortimanager_mcp/",
            file=sys.stderr,
        )
        sys.exit(1)

    creds = _load_creds(creds_path)
    cfg = creds.get("fortimanager", {})

    raw_hosts = cfg.get("hosts", [])
    if not raw_hosts:
        print(
            "ERROR: fortimanager.hosts is empty in credentials.yaml.\n"
            "Add at least one entry with host and api_key.",
            file=sys.stderr,
        )
        sys.exit(1)

    hosts = []
    for entry in raw_hosts:
        h = entry.get("host", "").strip()
        k = entry.get("api_key", "").strip()
        if not h or not k:
            print(
                f"ERROR: Each fortimanager.hosts entry needs a non-empty host and api_key.\n"
                f"Bad entry: {entry}",
                file=sys.stderr,
            )
            sys.exit(1)
        hosts.append((h, k))

    primary_host, primary_key = hosts[0]
    secondary_host, secondary_key = hosts[1] if len(hosts) > 1 else ("", "")

    client = FortiManagerClient(
        primary_host=primary_host,
        primary_key=primary_key,
        secondary_host=secondary_host,
        secondary_key=secondary_key,
        port=int(cfg.get("port", 443)),
        verify_ssl=bool(cfg.get("verify_ssl", True)),
        version=str(cfg.get("version", "7.4")),
        session_timeout=int(cfg.get("session_timeout", 300)),
    )

    try:
        client.login()
    except Exception as exc:
        print(f"ERROR: FortiManager connection failed: {exc}", file=sys.stderr)
        sys.exit(1)

    return client, FortiManagerAPIError


# ---------------------------------------------------------------------------
# YAML map load / save
# ---------------------------------------------------------------------------

def _load_map(map_file: Path) -> dict:
    """Load existing device_zone_map.yaml, or return empty skeleton."""
    if not map_file.exists():
        return {"devices": {}}
    with open(map_file, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if "devices" not in data:
        data["devices"] = {}
    return data


def _save_map(map_file: Path, data: dict) -> None:
    with open(map_file, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)


# ---------------------------------------------------------------------------
# Merge helper
# ---------------------------------------------------------------------------

def _merge_interface(existing_iface: dict | None, new_alias: str, new_policy_zone, new_notes: str) -> tuple[dict, bool]:
    """
    Merge a new interface entry with an existing one (if present).

    Rules:
    - If the interface already exists and policy_zone is filled in, keep it.
    - If the interface is new, use new_policy_zone (may be None).
    - alias and notes from the new source overwrite only if existing value is empty.
    Returns (merged_dict, is_new_entry).
    """
    if existing_iface is None:
        return {
            "alias": new_alias or "",
            "policy_zone": new_policy_zone,
            "notes": new_notes or "",
        }, True

    merged = dict(existing_iface)
    # Preserve policy_zone if already set; otherwise accept incoming value
    if merged.get("policy_zone") is None and new_policy_zone is not None:
        merged["policy_zone"] = new_policy_zone
    # Update alias if it was blank
    if not merged.get("alias") and new_alias:
        merged["alias"] = new_alias
    # Update notes if it was blank
    if not merged.get("notes") and new_notes:
        merged["notes"] = new_notes
    return merged, False


# ---------------------------------------------------------------------------
# Stats tracker
# ---------------------------------------------------------------------------

class Stats:
    def __init__(self):
        self.devices_new = 0
        self.devices_existing = 0
        self.ifaces_new = 0
        self.ifaces_existing = 0

    def devices_total(self):
        return self.devices_new + self.devices_existing

    def ifaces_total(self):
        return self.ifaces_new + self.ifaces_existing


# ---------------------------------------------------------------------------
# Mode 1: --from-fortimanager
# ---------------------------------------------------------------------------

def mode_from_fortimanager(map_file: Path, creds_path: Path, dry_run: bool, verbose: bool) -> None:
    client, FortiManagerAPIError = _build_client(creds_path)
    data = _load_map(map_file)
    stats = Stats()

    try:
        try:
            adoms = client.get_adoms()
        except Exception as exc:
            print(f"ERROR: Failed to fetch ADOMs: {exc}", file=sys.stderr)
            sys.exit(1)

        adom_names = [a["name"] for a in adoms if isinstance(a, dict) and a.get("name")]

        for adom_name in adom_names:
            if verbose:
                print(f"  ADOM: {adom_name}")

            try:
                devices = client.get_devices(adom_name)
            except Exception as exc:
                print(f"  WARNING: Could not fetch devices for ADOM {adom_name!r}: {exc}")
                continue

            for dev in devices:
                dev_name = dev.get("name") if isinstance(dev, dict) else None
                if not dev_name:
                    continue

                if verbose:
                    print(f"    Device: {dev_name}")

                dev_is_new = dev_name not in data["devices"]
                if dev_is_new:
                    data["devices"][dev_name] = {}
                    stats.devices_new += 1
                else:
                    stats.devices_existing += 1

                try:
                    interfaces = client.get_device_interfaces(adom_name, dev_name)
                except Exception as exc:
                    print(f"    WARNING: Could not fetch interfaces for {dev_name!r}: {exc}")
                    continue

                for iface in interfaces:
                    if not isinstance(iface, dict):
                        continue
                    iface_name = iface.get("name")
                    if not iface_name:
                        continue

                    alias = iface.get("alias", "") or ""
                    existing = data["devices"][dev_name].get(iface_name)
                    merged, is_new = _merge_interface(existing, alias, None, "")

                    if verbose:
                        status = "NEW" if is_new else "existing"
                        print(f"      [{status}] {iface_name}  alias={alias!r}")

                    data["devices"][dev_name][iface_name] = merged

                    if is_new:
                        stats.ifaces_new += 1
                    else:
                        stats.ifaces_existing += 1
    finally:
        client.logout()
        client._http.close()

    _write_and_report(map_file, data, stats, dry_run)


# ---------------------------------------------------------------------------
# Mode 2: --from-csv
# ---------------------------------------------------------------------------

def mode_from_csv(csv_path: Path, map_file: Path, dry_run: bool, verbose: bool) -> None:
    if not csv_path.exists():
        print(f"ERROR: CSV file not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    data = _load_map(map_file)
    stats = Stats()
    # Track devices already counted to avoid double-counting across multiple interface rows
    seen_devices: set = set()

    required_columns = {"device", "interface", "alias", "policy_zone", "notes"}

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not required_columns.issubset(set(reader.fieldnames or [])):
            missing = required_columns - set(reader.fieldnames or [])
            print(
                f"ERROR: CSV is missing required columns: {', '.join(sorted(missing))}\n"
                "Expected header: device,interface,alias,policy_zone,notes",
                file=sys.stderr,
            )
            sys.exit(1)

        for row in reader:
            dev_name = row["device"].strip()
            iface_name = row["interface"].strip()
            if not dev_name or not iface_name:
                continue

            alias = row["alias"].strip()
            policy_zone_raw = row["policy_zone"].strip()
            policy_zone = policy_zone_raw if policy_zone_raw else None
            notes = row["notes"].strip()

            # Count each device once even if it appears on multiple rows
            if dev_name not in seen_devices:
                if dev_name not in data["devices"]:
                    stats.devices_new += 1
                else:
                    stats.devices_existing += 1
                seen_devices.add(dev_name)

            if dev_name not in data["devices"]:
                data["devices"][dev_name] = {}

            existing = data["devices"][dev_name].get(iface_name)
            merged, is_new = _merge_interface(existing, alias, policy_zone, notes)
            data["devices"][dev_name][iface_name] = merged

            if verbose:
                status = "NEW" if is_new else "existing"
                print(f"  [{status}] {dev_name} / {iface_name}  alias={alias!r}  zone={policy_zone!r}")

            if is_new:
                stats.ifaces_new += 1
            else:
                stats.ifaces_existing += 1

    _write_and_report(map_file, data, stats, dry_run)


# ---------------------------------------------------------------------------
# Mode 3: --export-csv
# ---------------------------------------------------------------------------

def mode_export_csv(csv_path: Path, map_file: Path) -> None:
    data = _load_map(map_file)

    if not data["devices"]:
        print(f"WARNING: {map_file} has no devices to export.")

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["device", "interface", "alias", "policy_zone", "notes"])
        for dev_name, interfaces in data["devices"].items():
            if not isinstance(interfaces, dict):
                continue
            for iface_name, iface_data in interfaces.items():
                if not isinstance(iface_data, dict):
                    continue
                writer.writerow([
                    dev_name,
                    iface_name,
                    iface_data.get("alias", "") or "",
                    iface_data.get("policy_zone", "") or "",
                    iface_data.get("notes", "") or "",
                ])

    print(f"Exported to {csv_path}")


# ---------------------------------------------------------------------------
# Shared write + summary
# ---------------------------------------------------------------------------

def _count_unmapped(data: dict) -> int:
    count = 0
    for interfaces in data["devices"].values():
        if not isinstance(interfaces, dict):
            continue
        for iface_data in interfaces.values():
            if isinstance(iface_data, dict) and iface_data.get("policy_zone") is None:
                count += 1
    return count


def _write_and_report(map_file: Path, data: dict, stats: Stats, dry_run: bool) -> None:
    unmapped = _count_unmapped(data)

    if dry_run:
        print("[dry-run] No files written.")
    else:
        _save_map(map_file, data)
        print(f"{map_file.name} updated.")

    print(f"  Devices: {stats.devices_total()}  ({stats.devices_new} new, {stats.devices_existing} existing)")
    print(f"  Interfaces: {stats.ifaces_total()}  ({stats.ifaces_new} new, {stats.ifaces_existing} existing)")
    print(f"  Unmapped policy_zones: {unmapped}  (need engineer input)")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bootstrap or update device_zone_map.yaml from FortiManager or CSV.",
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--from-fortimanager",
        action="store_true",
        help="Fetch devices and interfaces from FortiManager.",
    )
    mode_group.add_argument(
        "--from-csv",
        metavar="FILE",
        help="Merge entries from a CSV file (columns: device,interface,alias,policy_zone,notes).",
    )
    mode_group.add_argument(
        "--export-csv",
        metavar="FILE",
        help="Export the current map to a CSV file.",
    )
    parser.add_argument(
        "--map-file",
        metavar="PATH",
        default=str(_DEFAULT_MAP_FILE),
        help=f"Path to device_zone_map.yaml (default: {_DEFAULT_MAP_FILE}).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would change without writing any files.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print each device/interface as it is processed.",
    )

    args = parser.parse_args()

    map_file = Path(args.map_file)
    creds_path = Path(os.getenv("CREDENTIALS_FILE", str(_DEFAULT_CREDS)))

    if args.from_fortimanager:
        mode_from_fortimanager(map_file, creds_path, args.dry_run, args.verbose)
    elif args.from_csv:
        mode_from_csv(Path(args.from_csv), map_file, args.dry_run, args.verbose)
    elif args.export_csv:
        if args.dry_run:
            print("NOTE: --dry-run has no effect on --export-csv (reads only).")
        mode_export_csv(Path(args.export_csv), map_file)


if __name__ == "__main__":
    main()
