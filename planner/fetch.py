"""
Data acquisition for the change planner.

The planner does its own fetching — it never accepts pre-digested
FortiManager/4THealth data from a caller, so there is no lossy hop between
the source systems and the deterministic analysis. Failures are typed:
PlannerDataError means "a source failed", never "no results".
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from fortimanager_mcp.client import FortiManagerAPIError, FortiManagerClient
from fortimanager_mcp.matching import AddressCatalog, ServiceCatalog
from fortimanager_mcp.query import (
    _package_targets_device,
    build_catalogs,
    get_device_policies,
    get_routing_table,
)
from fortimanager_mcp.zone_map import load_zone_map, lookup_policy_zone
from planner.models import PlannerDataError
from zone_mcp.client import ZonePolicyClient, ZonePolicyError


@dataclass
class DeviceSnapshot:
    device: str
    adom: str
    packages: list[str]
    policies_by_package: dict[str, list[dict]]   # raw dicts, package order preserved
    addr_catalog: AddressCatalog
    svc_catalog: ServiceCatalog
    interfaces: list[dict]
    routing_table: list[dict] = field(default_factory=list)
    zone_map_warnings: list[str] = field(default_factory=list)
    degraded: bool = False
    failures: list[str] = field(default_factory=list)


def fetch_device_snapshot(
    client: FortiManagerClient, adom: str, device: str
) -> DeviceSnapshot:
    """Fetch everything the planner needs about one device.

    Raises PlannerDataError if the device is unknown or the object catalogs
    cannot be fetched at all. Per-package policy failures degrade the
    snapshot instead (callers must then refuse to claim "already covered").
    """
    try:
        devices = client.get_devices(adom)
    except FortiManagerAPIError as exc:
        raise PlannerDataError("fortimanager", f"cannot list devices in ADOM {adom!r}: {exc}") from exc

    names = {d.get("name", "") for d in devices if isinstance(d, dict)}
    if device not in names:
        raise PlannerDataError(
            "fortimanager",
            f"device {device!r} not found in ADOM {adom!r} (known: {sorted(names)})",
        )

    try:
        packages = client.get_policy_packages(adom)
        addr_catalog, svc_catalog = build_catalogs(client, adom)
    except FortiManagerAPIError as exc:
        raise PlannerDataError("fortimanager", f"cannot fetch object catalogs: {exc}") from exc

    device_pkgs = [
        p.get("name", "") for p in packages
        if isinstance(p, dict) and _package_targets_device(p, device)
    ]

    # Fetch only the packages assigned to this device. Uses the full ADOM policy
    # cache if warm (background warm-up), otherwise fetches just these packages
    # directly — avoiding a full-ADOM scan on cold start.
    pkg_results = get_device_policies(client, adom, device_pkgs)

    policies_by_package: dict[str, list[dict]] = {}
    failures: list[str] = []
    for pkg in device_pkgs:
        cached = pkg_results.get(pkg)
        if cached is None:
            failures.append(f"package {pkg!r}: fetch failed")
        else:
            policies_by_package[pkg] = cached

    interfaces: list[dict] = []
    zone_map_warnings: list[str] = []
    try:
        raw_ifaces = client.get_device_interfaces(adom, device)
        zone_map = load_zone_map()
        for iface in raw_ifaces:
            if not isinstance(iface, dict):
                continue
            iface = dict(iface)
            iface["policy_zone"] = lookup_policy_zone(zone_map, device, iface.get("name", ""))
            interfaces.append(iface)
    except FortiManagerAPIError as exc:
        failures.append(f"interfaces: {exc}")

    routing_table: list[dict] = []
    try:
        routing_table = get_routing_table(client, adom, device)
    except Exception:
        # Routing table is used only for interface-name resolution — failure
        # here does not affect coverage analysis, so do not set degraded.
        pass

    return DeviceSnapshot(
        device=device,
        adom=adom,
        packages=device_pkgs,
        policies_by_package=policies_by_package,
        addr_catalog=addr_catalog,
        svc_catalog=svc_catalog,
        interfaces=interfaces,
        routing_table=routing_table,
        zone_map_warnings=zone_map_warnings,
        degraded=bool(failures),
        failures=failures,
    )


# Zone assigned to any IP 4THealth cannot resolve. The catalogue's Internet
# zone is the deliberate catch-all ("all routable addresses not matched by
# any other zone") — enumerating the whole internet as subnets is not viable.
DEFAULT_UNMATCHED_ZONE = "Internet"


def _apply_internet_default(
    zc: ZonePolicyClient, service: str, verdict: str,
    src_zones: list, dst_zones: list, governing: list,
) -> tuple[str, list, list, list, list[str]]:
    """Substitute the catch-all Internet zone for unresolved endpoints and
    re-derive the verdict from the live 4THealth policy table."""
    from standards_mcp.policy_engine import evaluate, find_matching_policies

    notes: list[str] = []
    try:
        catalogue = zc.zones()
    except ZonePolicyError as exc:
        raise PlannerDataError("4thealth", str(exc)) from exc

    zones_by_name = {
        z.get("name", ""): z
        for z in catalogue.get("zones", []) if isinstance(z, dict)
    }
    if DEFAULT_UNMATCHED_ZONE not in zones_by_name:
        notes.append(
            "One or more IPs did not resolve to a zone and the 4THealth "
            f"catalogue has no {DEFAULT_UNMATCHED_ZONE!r} zone to default to — "
            "verdict left UNKNOWN."
        )
        return verdict, src_zones, dst_zones, governing, notes

    for label, zones in (("Source", src_zones), ("Destination", dst_zones)):
        if not zones:
            zones.append(DEFAULT_UNMATCHED_ZONE)
            notes.append(
                f"{label} did not match any zone subnet — treated as the "
                f"catch-all {DEFAULT_UNMATCHED_ZONE!r} zone."
            )

    if verdict == "UNKNOWN":
        try:
            policies = zc.policies()
        except ZonePolicyError as exc:
            raise PlannerDataError("4thealth", str(exc)) from exc
        matching = find_matching_policies(src_zones, dst_zones, zones_by_name, policies)
        verdict, governing = evaluate(matching, [service] if service else [])

    return verdict, src_zones, dst_zones, governing, notes


def fetch_zone_verdict(zc: ZonePolicyClient, src: str, dst: str, service: str) -> dict:
    """One src×dst verdict from 4THealth, check_ip_traffic-shaped.

    Endpoints 4THealth cannot resolve are treated as the catch-all Internet
    zone (with an explanatory note) and the verdict is re-derived from the
    live policy table.
    """
    try:
        results = zc.query(src=src, dst=dst, service=service, verbose=True)
    except ZonePolicyError as exc:
        raise PlannerDataError("4thealth", str(exc)) from exc

    if not results:
        raise PlannerDataError(
            "4thealth", f"zone query for {src} -> {dst} returned no result objects"
        )
    r = results[0]
    verdict = r.get("verdict", "UNKNOWN")
    src_zones = list(r.get("src_zones", []))
    dst_zones = list(r.get("dst_zones", []))
    governing = r.get("governing", [])
    notes: list[str] = []
    if not src_zones or not dst_zones:
        verdict, src_zones, dst_zones, governing, notes = _apply_internet_default(
            zc, service, verdict, src_zones, dst_zones, governing
        )
    return {
        "src_ip": src,
        "dst_ip": dst,
        "service": service,
        "verdict": verdict,
        "src_zones": src_zones,
        "dst_zones": dst_zones,
        "governing": governing,
        "all_policies": r.get("all_policies", []),
        "notes": notes,
    }


def fetch_zone_domains(zc: ZonePolicyClient) -> dict[str, str]:
    """Zone name → security domain, from the live zone catalogue."""
    try:
        catalogue = zc.zones()
    except ZonePolicyError as exc:
        raise PlannerDataError("4thealth", str(exc)) from exc
    return {
        z.get("name", ""): z.get("domain", "")
        for z in catalogue.get("zones", [])
        if isinstance(z, dict)
    }


def _route_network(route: dict):
    """Parse the dst field of a static route into an ip_network.

    Unlike _iface_network, 0.0.0.0/0 (the default route) is valid here.
    """
    raw = route.get("dst", "")
    if isinstance(raw, list) and len(raw) == 2:
        raw = f"{raw[0]}/{raw[1]}"
    elif isinstance(raw, str) and " " in raw:
        addr, mask = raw.split(None, 1)
        raw = f"{addr}/{mask.strip()}"
    if not raw:
        return None
    try:
        return ipaddress.ip_network(str(raw), strict=False)
    except ValueError:
        return None


def _iface_network(iface: dict):
    raw = iface.get("ip", "")
    if isinstance(raw, list) and len(raw) == 2:
        raw = f"{raw[0]}/{raw[1]}"
    elif isinstance(raw, str) and " " in raw:
        addr, mask = raw.split(None, 1)
        raw = f"{addr}/{mask.strip()}"
    if not raw or str(raw).startswith("0.0.0.0"):
        return None
    try:
        return ipaddress.ip_network(str(raw), strict=False)
    except ValueError:
        return None


def resolve_interface(
    snapshot: DeviceSnapshot,
    ip: str,
    zones: list[str],
    label: str,
) -> tuple[str, list[str]]:
    """Resolve one IP to a device interface. Returns (name, warnings);
    unresolvable → ("", warnings) — never a silent guess."""
    warnings: list[str] = []
    name = _resolve_one(snapshot, ip, list(zones), label, warnings)
    return name, warnings


def resolve_interfaces(
    snapshot: DeviceSnapshot,
    src: str,
    dst: str,
    src_zones: list[str] = (),
    dst_zones: list[str] = (),
) -> tuple[str, str, list[str]]:
    """Resolve src/dst IPs to device interfaces by connected-subnet match,
    falling back to the device_zone_map policy_zone ↔ 4THealth zone names.
    Unresolvable → "" plus a warning; never a silent guess.
    """
    warnings: list[str] = []
    srcintf = _resolve_one(snapshot, src, list(src_zones), "Source", warnings)
    dstintf = _resolve_one(snapshot, dst, list(dst_zones), "Destination", warnings)
    return srcintf, dstintf, warnings


def _resolve_one(
    snapshot: DeviceSnapshot,
    ip: str,
    zones: list[str],
    label: str,
    warnings: list[str],
) -> str:
    try:
        target = ipaddress.ip_network(ip, strict=False)
    except ValueError:
        warnings.append(f"{label} {ip!r} is not a valid IP/CIDR")
        return ""
    # most-specific connected subnet wins
    best = ("", -1)
    for iface in snapshot.interfaces:
        net = _iface_network(iface)
        if net is not None and net.overlaps(target) and net.prefixlen > best[1]:
            best = (iface.get("name", ""), net.prefixlen)
    if best[0]:
        return best[0]
    for iface in snapshot.interfaces:
        if iface.get("policy_zone") and iface["policy_zone"] in zones:
            warnings.append(
                f"{label} {ip} matched interface {iface.get('name', '')} via "
                "device_zone_map policy zone, not a connected subnet — verify"
            )
            return iface.get("name", "")
    # Third fallback: longest-prefix match on the static routing table.
    # Catches internet-bound destinations (default route) and routed internal
    # subnets that are not directly connected on this firewall.
    best_route = ("", -1)
    for route in snapshot.routing_table:
        if route.get("status", "enable") != "enable":
            continue
        net = _route_network(route)
        raw_dev = route.get("device", "")
        # FMG CMDB occasionally returns device as a list — always coerce to str.
        iface_name = (
            raw_dev[0] if isinstance(raw_dev, list) and raw_dev
            else raw_dev if isinstance(raw_dev, str)
            else str(raw_dev)
        )
        if net is not None and iface_name and net.overlaps(target) and net.prefixlen > best_route[1]:
            best_route = (iface_name, net.prefixlen)
    if best_route[0]:
        warnings.append(
            f"{label} {ip} resolved interface {best_route[0]!r} via routing table "
            "longest-prefix match — verify before implementation"
        )
        return best_route[0]
    warnings.append(
        f"Could not resolve {label.lower()} {ip} to an interface on "
        f"{snapshot.device} — engineer must set the interface manually"
    )
    return ""
