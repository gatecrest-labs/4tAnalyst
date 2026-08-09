"""
Set-semantics matching for FortiManager policy analysis.

Replaces the substring-based service/address matching previously in query.py:
service references are resolved to numeric (protocol, port-range) sets and
address references to ipaddress networks, so "80" can never match TCP_8080.

Resolution rules:
  - Unknown object names resolve to None — callers must treat that as
    "cannot prove a match", never as a silent non-match or match.
  - Group references recurse with a cycle guard.
  - "all"/"any" (case-insensitive) are wildcards.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

_WILDCARD_PROTOCOLS = ("ip",)


@dataclass(frozen=True)
class PortRange:
    """A contiguous destination-port range on one protocol.

    protocol "ip" (with 0-65535) is the wildcard: it contains/overlaps
    everything. "icmp" has no ports; it is stored as a full range and only
    matches other icmp/ip entries.
    """

    protocol: str  # "tcp" | "udp" | "sctp" | "icmp" | "ip"
    start: int
    end: int

    def _proto_compatible(self, other: "PortRange") -> bool:
        return (
            self.protocol in _WILDCARD_PROTOCOLS
            or other.protocol in _WILDCARD_PROTOCOLS
            or self.protocol == other.protocol
        )

    def contains(self, other: "PortRange") -> bool:
        if not self._proto_compatible(other):
            return False
        if self.protocol in _WILDCARD_PROTOCOLS:
            return True
        if other.protocol in _WILDCARD_PROTOCOLS:
            return False
        return self.start <= other.start and other.end <= self.end

    def overlaps(self, other: "PortRange") -> bool:
        if not self._proto_compatible(other):
            return False
        if self.protocol in _WILDCARD_PROTOCOLS or other.protocol in _WILDCARD_PROTOCOLS:
            return True
        return self.start <= other.end and other.start <= self.end


WILDCARD_RANGE = PortRange("ip", 0, 65535)

# Fallback for conversationally-entered service names. FortiGate's predefined
# services live in the same custom-service table and take precedence when a
# ServiceCatalog is consulted; this table only backs parse_service_request.
_WELL_KNOWN: dict[str, list[PortRange]] = {
    "ssh": [PortRange("tcp", 22, 22)],
    "https": [PortRange("tcp", 443, 443)],
    "http": [PortRange("tcp", 80, 80)],
    "rdp": [PortRange("tcp", 3389, 3389)],
    "dns": [PortRange("tcp", 53, 53), PortRange("udp", 53, 53)],
    "ntp": [PortRange("udp", 123, 123)],
    "snmp": [PortRange("udp", 161, 161)],
    "syslog": [PortRange("udp", 514, 514)],
    "smtp": [PortRange("tcp", 25, 25)],
    "ftp": [PortRange("tcp", 21, 21)],
    "telnet": [PortRange("tcp", 23, 23)],
    "smb": [PortRange("tcp", 445, 445)],
    "ldap": [PortRange("tcp", 389, 389)],
    "ldaps": [PortRange("tcp", 636, 636)],
    "mssql": [PortRange("tcp", 1433, 1433)],
    "mysql": [PortRange("tcp", 3306, 3306)],
    "postgres": [PortRange("tcp", 5432, 5432)],
    "icmp": [PortRange("icmp", 0, 65535)],
    "ping": [PortRange("icmp", 0, 65535)],
}


def _parse_port_expr(expr: str, protocol: str) -> PortRange:
    """Parse "8443" or "8000-8100" into a PortRange (raises ValueError)."""
    expr = expr.strip()
    if "-" in expr:
        lo, hi = expr.split("-", 1)
        return PortRange(protocol, int(lo), int(hi))
    port = int(expr)
    return PortRange(protocol, port, port)


def parse_service_request(service: str, protocol_hint: str = "") -> list[PortRange]:
    """
    Parse an engineer-entered service string into port ranges.

    Accepts: "443", "tcp/8443", "udp/514", "tcp/8000-8100", well-known names
    ("ssh", "dns", ...), and "any"/"all"/"" (wildcard).

    Raises ValueError for anything unrecognisable — callers must surface
    that to the engineer rather than guessing.
    """
    raw = service.strip().lower()
    if raw in ("", "any", "all"):
        return [WILDCARD_RANGE]

    if "/" in raw:
        proto, _, port_part = raw.partition("/")
        proto = proto.strip()
        if proto not in ("tcp", "udp", "sctp", "icmp", "ip"):
            raise ValueError(f"Unknown protocol in service {service!r}")
        if proto in ("icmp", "ip"):
            return [PortRange(proto, 0, 65535)]
        return [_parse_port_expr(port_part, proto)]

    if raw in _WELL_KNOWN:
        return list(_WELL_KNOWN[raw])

    try:
        proto = protocol_hint.strip().lower() or "tcp"
        if proto in ("any", "n/a", "tcp/udp", ""):
            proto = "tcp"
        return [_parse_port_expr(raw, proto)]
    except ValueError:
        raise ValueError(
            f"Cannot interpret service {service!r} — use a port number, "
            "proto/port (e.g. tcp/8443), or a well-known name"
        ) from None


def _is_wildcard_name(name: str) -> bool:
    return name.strip().lower() in ("all", "any")


class ServiceCatalog:
    """Resolves FortiManager service object/group references to PortRanges."""

    def __init__(self, custom_objects: list[dict], groups: list[dict]) -> None:
        self._objects = {
            o["name"]: o for o in custom_objects if isinstance(o, dict) and "name" in o
        }
        self._groups = {
            g["name"]: g for g in groups if isinstance(g, dict) and "name" in g
        }

    def ranges_for_ref(self, name: str) -> list[PortRange] | None:
        """Resolve a reference by name. None means unresolvable (unknown)."""
        return self._resolve(name, seen=set())

    def exact_match_name(self, ranges: list[PortRange]) -> str | None:
        """Name of an existing service object whose ranges equal `ranges`."""
        want = set(ranges)
        for name, obj in self._objects.items():
            resolved = self._ranges_for_object(obj)
            if resolved is not None and set(resolved) == want:
                return name
        return None

    def _resolve(self, name: str, seen: set[str]) -> list[PortRange] | None:
        if _is_wildcard_name(name):
            return [WILDCARD_RANGE]
        if name in seen:
            return []  # cycle — contributes nothing further
        seen.add(name)

        obj = self._objects.get(name)
        if obj is not None:
            return self._ranges_for_object(obj)

        group = self._groups.get(name)
        if group is not None:
            members = group.get("member", [])
            resolved: list[PortRange] = []
            any_known = False
            for m in members:
                member_name = m if isinstance(m, str) else m.get("name", "")
                sub = self._resolve(member_name, seen)
                if sub is not None:
                    any_known = True
                    resolved.extend(sub)
            return resolved if any_known else None

        return None

    @staticmethod
    def _ranges_for_object(obj: dict) -> list[PortRange]:
        protocol = str(obj.get("protocol", "TCP/UDP/SCTP")).upper()
        if "ICMP" in protocol:
            return [PortRange("icmp", 0, 65535)]
        if protocol == "IP":
            # Objects with protocol=IP and a protocol-number are IP-protocol
            # typed (e.g. icmp-proto has protocol-number=1). Map known protocol
            # numbers to their PortRange types so they can be correctly compared
            # against the requested service. Unknown protocol numbers return None
            # (unresolvable) so callers treat coverage as uncertain.
            proto_num = obj.get("protocol-number")
            if proto_num is not None:
                _PROTO_NUM_MAP = {1: PortRange("icmp", 0, 65535)}
                pr = _PROTO_NUM_MAP.get(int(proto_num))
                return [pr] if pr is not None else None
            return [WILDCARD_RANGE]

        ranges: list[PortRange] = []
        for proto, key in (("tcp", "tcp-portrange"), ("udp", "udp-portrange"),
                           ("sctp", "sctp-portrange")):
            raw = obj.get(key, "")
            if isinstance(raw, list):
                raw = " ".join(str(r) for r in raw)
            for token in str(raw).split():
                # "443:1024-65535" — part after ':' is the source-port range
                dst_part = token.split(":", 1)[0]
                try:
                    ranges.append(_parse_port_expr(dst_part, proto))
                except ValueError:
                    continue
        return ranges


class AddressCatalog:
    """
    Resolves FortiManager address object/group references to ip networks.

    Per-ADOM names shadow global-ADOM names (same precedence query.py always
    used). None means the reference is unresolvable — fqdn/geo/dynamic types
    or an unknown name — and callers must not treat it as a non-match.
    """

    def __init__(
        self,
        objects: list[dict],
        groups: list[dict],
        global_objects: list[dict] = (),
        global_groups: list[dict] = (),
    ) -> None:
        self._objects: dict[str, dict] = {}
        self._groups: dict[str, dict] = {}
        for o in global_objects or ():
            if isinstance(o, dict) and "name" in o:
                self._objects[o["name"]] = o
        for g in global_groups or ():
            if isinstance(g, dict) and "name" in g:
                self._groups[g["name"]] = g
        for o in objects:
            if isinstance(o, dict) and "name" in o:
                self._objects[o["name"]] = o
        for g in groups:
            if isinstance(g, dict) and "name" in g:
                self._groups[g["name"]] = g

    def networks_for_ref(self, name: str):
        return self._resolve(name, seen=set())

    def is_group(self, name: str) -> bool:
        return name in self._groups

    def groups_containing(self, name: str) -> set[str]:
        """All groups that (transitively) include `name` as a member.
        Used for blast-radius analysis before appending to a group."""
        parents: dict[str, set[str]] = {}
        for gname, g in self._groups.items():
            for m in _names(g.get("member", [])):
                parents.setdefault(m, set()).add(gname)
        result: set[str] = set()
        queue = [name]
        while queue:
            for p in parents.get(queue.pop(), ()):
                if p not in result:
                    result.add(p)
                    queue.append(p)
        return result

    def exact_match_name(self, cidr: str) -> str | None:
        """Name of an existing address object exactly equal to `cidr`."""
        try:
            target = [ipaddress.ip_network(cidr, strict=False)]
        except ValueError:
            return None
        for name, obj in self._objects.items():
            nets = self._networks_for_object(obj)
            if nets is not None and list(nets) == target:
                return name
        return None

    def _resolve(self, name: str, seen: set[str]):
        if _is_wildcard_name(name):
            return [ipaddress.ip_network("0.0.0.0/0")]
        if name in seen:
            return []
        seen.add(name)

        obj = self._objects.get(name)
        if obj is not None:
            return self._networks_for_object(obj)

        group = self._groups.get(name)
        if group is not None:
            nets = []
            any_known = False
            for m in group.get("member", []):
                member_name = m if isinstance(m, str) else m.get("name", "")
                sub = self._resolve(member_name, seen)
                if sub is not None:
                    any_known = True
                    nets.extend(sub)
            return nets if any_known else None

        return None

    @staticmethod
    def _networks_for_object(obj: dict):
        obj_type = str(obj.get("type", "ipmask")).lower()

        if obj_type in ("ipmask", "0", "subnet"):
            subnet = obj.get("subnet", obj.get("ip", ""))
            if isinstance(subnet, list) and len(subnet) == 2:
                subnet = f"{subnet[0]}/{subnet[1]}"
            elif isinstance(subnet, str) and " " in subnet:
                addr, mask = subnet.split(None, 1)
                subnet = f"{addr}/{mask.strip()}"
            try:
                return [ipaddress.ip_network(str(subnet), strict=False)]
            except ValueError:
                return None

        if obj_type in ("iprange", "1", "range"):
            try:
                start = ipaddress.ip_address(obj.get("start-ip", ""))
                end = ipaddress.ip_address(obj.get("end-ip", ""))
                return list(ipaddress.summarize_address_range(start, end))
            except ValueError:
                return None

        # fqdn, geography, dynamic, mac — not resolvable to static networks
        return None


@dataclass
class MatchResult:
    """Outcome of evaluating one policy against a requested flow.

    matched=True with full_cover=False means partial overlap — the policy
    would catch some of the requested traffic but does not prove coverage.
    Unknown refs make a dimension conservatively matched but never full.
    """

    matched: bool
    full_cover: bool
    action: str
    disabled: bool
    conditional_schedule: bool
    unknown_refs: list[str]
    notes: list[str]


_ACTION_MAP = {0: "deny", 1: "accept", 2: "ipsec", 3: "ssl-vpn"}


def _names(field) -> list[str]:
    if isinstance(field, list):
        return [x if isinstance(x, str) else x.get("name", str(x)) for x in field]
    if isinstance(field, str):
        return [field]
    return []


class PolicyMatcher:
    """Evaluates raw FortiManager policy dicts against a requested flow
    using resolved set semantics (no substring matching)."""

    def __init__(self, addr_catalog: AddressCatalog, svc_catalog: ServiceCatalog) -> None:
        self._addr = addr_catalog
        self._svc = svc_catalog

    def evaluate(
        self,
        pol: dict,
        src: str,
        dst: str,
        service_ranges: list[PortRange],
    ) -> MatchResult:
        """src/dst are IP or CIDR strings; "" means unconstrained (wildcard).

        Containment is per-item: a requested range/network must fit inside a
        single resolved ref entry to count as covered (unions of fragmented
        refs are approximated via collapse for addresses; port ranges are not
        merged — a request spanning two adjacent objects reports partial).
        """
        unknown: list[str] = []
        notes: list[str] = []

        src_m, src_f = self._addr_dim(pol, "srcaddr", src, unknown)
        dst_m, dst_f = self._addr_dim(pol, "dstaddr", dst, unknown)
        svc_m, svc_f = self._svc_dim(pol, service_ranges, unknown)

        matched = src_m and dst_m and svc_m
        full_cover = matched and src_f and dst_f and svc_f

        raw_status = pol.get("status", "enable")
        disabled = raw_status in ("disable", 0)

        schedule = _names(pol.get("schedule", ["always"]))
        conditional_schedule = bool(schedule) and schedule != ["always"]
        if conditional_schedule:
            notes.append(f"schedule is {'/'.join(schedule)!r}, not 'always'")

        raw_action = pol.get("action", 0)
        action = _ACTION_MAP.get(raw_action, str(raw_action))

        return MatchResult(
            matched=matched,
            full_cover=full_cover,
            action=action,
            disabled=disabled,
            conditional_schedule=conditional_schedule,
            unknown_refs=unknown,
            notes=notes,
        )

    def addr_side(self, pol: dict, key: str, target: str) -> tuple[bool, bool]:
        """Public (matched, full_cover) for one address side of a policy
        (key is "srcaddr" or "dstaddr")."""
        return self._addr_dim(pol, key, target, [])

    def svc_side(self, pol: dict, requested: list[PortRange]) -> tuple[bool, bool]:
        """Public (matched, full_cover) for the service dimension."""
        return self._svc_dim(pol, requested, [])

    # ------------------------------------------------------------------

    def _addr_dim(self, pol: dict, key: str, target: str, unknown: list[str]):
        """Return (matched, full) for one address dimension."""
        if not target:
            target_net = ipaddress.ip_network("0.0.0.0/0")
        else:
            try:
                target_net = ipaddress.ip_network(target, strict=False)
            except ValueError:
                unknown.append(f"{key}:{target}")
                return True, False

        refs = _names(pol.get(key, []))
        negate = pol.get(f"{key}-negate", "disable") in ("enable", 1, True)

        nets = []
        has_unknown = False
        for name in refs:
            resolved = self._addr.networks_for_ref(name)
            if resolved is None:
                has_unknown = True
                unknown.append(name)
            else:
                nets.extend(resolved)

        overlap = any(target_net.overlaps(n) for n in nets)
        collapsed = list(ipaddress.collapse_addresses(nets)) if nets else []
        contained = any(
            target_net.subnet_of(n) for n in collapsed
            if n.version == target_net.version
        )

        if negate:
            # Policy matches traffic NOT in refs. Unknown refs make the
            # complement uncertain in both directions.
            if has_unknown:
                return True, False
            matched = not contained if target_net.num_addresses > 1 else not overlap
            full = not overlap  # fully covered only if target entirely outside refs
            return matched, full

        if contained:
            return True, True
        if overlap:
            return True, False
        if has_unknown:
            return True, False  # cannot prove non-match
        return False, False

    def _svc_dim(self, pol: dict, requested: list[PortRange], unknown: list[str]):
        refs = _names(pol.get("service", []))
        ranges: list[PortRange] = []
        has_unknown = False
        for name in refs:
            resolved = self._svc.ranges_for_ref(name)
            if resolved is None:
                has_unknown = True
                unknown.append(name)
            else:
                ranges.extend(resolved)

        overlap = any(r.overlaps(req) for r in ranges for req in requested)
        contained = bool(requested) and all(
            any(r.contains(req) for r in ranges) for req in requested
        )

        if contained:
            return True, True
        if overlap:
            return True, False
        if has_unknown:
            return True, False
        return False, False

