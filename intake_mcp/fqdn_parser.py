"""FQDN allowlist intake models and parsing."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

import openpyxl


@dataclass
class FQDNEntry:
    fqdn: str
    is_wildcard: bool
    ports: list[int]
    protocol: str   # "TCP" | "UDP"
    required: bool
    comment: str


@dataclass
class FQDNAllowlistRequest:
    vendor: str
    category: str
    src_ip: str
    ticket_id: str
    firewalls: list[str]
    entries: list[FQDNEntry]
    warnings: list[str] = field(default_factory=list)
    missing_fields: list[str] = field(default_factory=list)


# Column name aliases: normalised → canonical
_COL_ALIASES: dict[str, str] = {
    "hostname / domain": "fqdn",
    "hostname/domain": "fqdn",
    "domain": "fqdn",
    "fqdn": "fqdn",
    "port(s)": "ports",
    "ports": "ports",
    "port": "ports",
    "protocol": "protocol",
    "direction": "direction",
    "vendor": "vendor",
    "category": "category",
    "required?": "required",
    "required": "required",
    "purpose / notes": "comment",
    "purpose/notes": "comment",
    "notes": "comment",
    "purpose": "comment",
}


def _normalise_col(name: str) -> str:
    return _COL_ALIASES.get(name.strip().lower(), "")


def _parse_ports(raw: str) -> tuple[list[int], list[str]]:
    """Parse "80, 443, 5223" → ([80, 443, 5223], warnings)."""
    ports = []
    warnings = []
    for tok in raw.replace(";", ",").split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            ports.append(int(tok))
        except ValueError:
            warnings.append(f"Non-numeric port {tok!r} skipped")
    return ports, warnings


def _parse_bool(raw: str) -> bool:
    return str(raw).strip().lower() in ("yes", "true", "required", "1")


def parse_fqdn_rows(
    rows: list[dict],
    src_ip: str = "",
    ticket_id: str = "",
    firewalls: list[str] | None = None,
) -> FQDNAllowlistRequest:
    """Normalise a list of row dicts into a FQDNAllowlistRequest."""
    firewalls = firewalls or []
    warnings: list[str] = []
    missing: list[str] = []
    entries: list[FQDNEntry] = []
    vendor = ""
    category = ""

    for i, row in enumerate(rows):
        # Normalise key names
        norm = {_normalise_col(k): v for k, v in row.items() if _normalise_col(k)}

        if not vendor and norm.get("vendor"):
            vendor = str(norm["vendor"]).strip()
        if not category and norm.get("category"):
            category = str(norm["category"]).strip()

        fqdn_val = str(norm.get("fqdn", "")).strip()
        if not fqdn_val:
            warnings.append(f"Row {i + 1}: empty Hostname/Domain — skipped")
            continue
        if any(c in fqdn_val for c in ('"', '\n', '\r')):
            warnings.append(
                f"Row {i + 1}: FQDN {fqdn_val!r} contains illegal characters "
                '(", newline, or carriage-return) — skipped'
            )
            continue

        direction = str(norm.get("direction", "Outbound")).strip()
        if direction.lower() not in ("outbound", ""):
            warnings.append(
                f"Row {i + 1}: Direction={direction!r} — FQDNs are destination-only on FortiGate;"
                " only Outbound is supported. Review this entry before proceeding."
            )

        ports, port_warnings = _parse_ports(str(norm.get("ports", "443")))
        warnings.extend(f"Row {i + 1}: {w}" for w in port_warnings)
        if not ports:
            warnings.append(f"Row {i + 1}: no valid ports — skipped")
            continue

        protocol = str(norm.get("protocol", "TCP")).strip().upper()
        if protocol not in ("TCP", "UDP"):
            warnings.append(f"Row {i + 1}: unknown protocol {protocol!r}, defaulting to TCP")
            protocol = "TCP"

        entries.append(FQDNEntry(
            fqdn=fqdn_val,
            is_wildcard=fqdn_val.startswith("*."),
            ports=ports,
            protocol=protocol,
            required=_parse_bool(str(norm.get("required", "yes"))),
            comment=str(norm.get("comment", "")).strip(),
        ))

    if not src_ip:
        missing.append("src_ip")
    elif src_ip.strip().lower() in ("any", "all"):
        warnings.append(
            f"src_ip {src_ip!r} will be treated as FortiGate built-in 'all' address object — "
            "policy will allow traffic from any source zone. Consider restricting to a specific subnet."
        )
    else:
        try:
            ipaddress.ip_network(src_ip.strip(), strict=False)
        except ValueError:
            # Treat as a named FortiGate address object or group — not an error
            warnings.append(
                f"src_ip {src_ip!r} is not a valid IP/CIDR — treating as a FortiGate address "
                "object/group name. Zone verdict will be skipped; verify the object exists in FortiManager."
            )

    return FQDNAllowlistRequest(
        vendor=vendor,
        category=category,
        src_ip=src_ip,
        ticket_id=ticket_id,
        firewalls=firewalls,
        entries=entries,
        warnings=warnings,
        missing_fields=missing,
    )


def parse_fqdn_xlsx(
    file_path: str,
    src_ip: str = "",
    ticket_id: str = "",
    firewalls: list[str] | None = None,
) -> FQDNAllowlistRequest:
    """Parse a vendor URL allowlist from an .xlsx file."""
    wb = openpyxl.load_workbook(file_path, read_only=True, data_only=True)
    ws = wb.active
    rows_iter = ws.iter_rows(values_only=True)
    header = [str(c or "").strip() for c in next(rows_iter, [])]
    rows = [
        {header[i]: str(v or "").strip() for i, v in enumerate(row) if i < len(header)}
        for row in rows_iter
        if any(v is not None for v in row)
    ]
    wb.close()
    return parse_fqdn_rows(rows, src_ip=src_ip, ticket_id=ticket_id, firewalls=firewalls)
