"""
FortiGate CLI generation for the change planner.

Emits exact `config firewall ...` blocks. <TICKET_ID> placeholders are left
in place — scripts/render_report.py substitutes the real ticket number when
one is known (same contract the /analyze-request skill has always used).
"""

from __future__ import annotations

import ipaddress


def _quote_list(names: list[str]) -> str:
    return " ".join(f'"{n}"' for n in names)


def _safe_cli_str(s: str) -> str:
    """Escape a string for embedding in a double-quoted FortiGate CLI field.

    Replaces `"` with `''` (the FortiGate-CLI escape for a literal quote
    inside a quoted string) and strips newlines/carriage-returns so an
    attacker-controlled value cannot inject additional CLI commands.
    """
    return s.replace('"', "''").replace("\n", "").replace("\r", "")


def address_object_cli(name: str, cidr: str) -> str:
    net = ipaddress.ip_network(cidr, strict=False)
    return (
        'config firewall address\n'
        f'    edit "{name}"\n'
        '        set type ipmask\n'
        f'        set subnet {net.network_address} {net.netmask}\n'
        '        set comment "<TICKET_ID>"\n'
        '    next\n'
        'end'
    )


def service_object_cli(name: str, proto: str, port_expr: str) -> str:
    proto = proto.lower()
    if proto not in ("tcp", "udp", "sctp"):
        raise ValueError(f"Cannot generate a service object for protocol {proto!r}")
    return (
        'config firewall service custom\n'
        f'    edit "{name}"\n'
        f'        set {proto}-portrange {port_expr}\n'
        '        set comment "<TICKET_ID>"\n'
        '    next\n'
        'end'
    )


def policy_cli(
    *,
    name: str,
    srcintf: str,
    dstintf: str,
    srcaddr: list[str],
    dstaddr: list[str],
    service: list[str],
    logtraffic: str,
    logtraffic_start: bool,
    comments: str,
    insert_before: int | None,
) -> str:
    lines = [
        "config firewall policy",
        "    edit 0",
        f'        set name "{name}"',
        f'        set srcintf "{srcintf}"',
        f'        set dstintf "{dstintf}"',
        f"        set srcaddr {_quote_list(srcaddr)}",
        f"        set dstaddr {_quote_list(dstaddr)}",
        f"        set service {_quote_list(service)}",
        "        set action accept",
        '        set schedule "always"',
        f"        set logtraffic {logtraffic}",
    ]
    if logtraffic_start:
        lines.append("        set logtraffic-start enable")
    if comments:
        lines.append(f'        set comments "{comments}"')
    lines += ["    next", "end"]

    if insert_before is not None:
        lines += [
            "",
            f"# Position: this policy must sit before policy ID {insert_before}",
            "# (first-match order). After the edit above, note the new policy ID",
            f"# shown by the CLI and run:  move <new-id> before {insert_before}",
        ]
    return "\n".join(lines)


def exception_comment(ticket: str) -> str:
    ticket = ticket or "<TICKET_ID>"
    return (
        f"EXCEPTION to active block policy — ticket {ticket}. "
        "Requires SecOps approval before implementation: <SecOps approver>"
    )


def addrgrp_append_cli(group: str, member: str | list[str]) -> str:
    """CLI to append member(s) to an existing address group. `append`
    preserves the group's current members (unlike `set member`)."""
    members = [member] if isinstance(member, str) else list(member)
    appends = "\n".join(f'        append member "{m}"' for m in members)
    return (
        'config firewall addrgrp\n'
        f'    edit "{group}"\n'
        f'{appends}\n'
        '    next\n'
        'end'
    )


def policy_addr_append_cli(policy_id: int, key: str, members: list[str]) -> str:
    """CLI to append address object(s) directly to a policy's srcaddr or
    dstaddr list.  `append` preserves the existing entries (unlike `set`).
    `key` must be "srcaddr" or "dstaddr"."""
    appends = "\n".join(f'        append {key} "{m}"' for m in members)
    return (
        'config firewall policy\n'
        f'    edit {policy_id}\n'
        f'{appends}\n'
        '    next\n'
        'end'
    )


def addrgrp_create_cli(name: str, members: list[str], warn_replace: bool = False) -> str:
    """CLI to create a new address group with the given members.

    When ``warn_replace`` is True a comment is prepended reminding the engineer
    that ``set member`` replaces all existing group members — use this whenever
    a group may already exist in FortiManager.
    """
    quoted = " ".join(f'"{m}"' for m in members)
    body = (
        'config firewall addrgrp\n'
        f'    edit "{name}"\n'
        f'        set member {quoted}\n'
        '        set comment "<TICKET_ID>"\n'
        '    next\n'
        'end'
    )
    if warn_replace:
        warning = (
            "# WARNING: 'set member' replaces all existing members. "
            "Verify existing members first.\n"
        )
        return warning + body
    return body


def fqdn_address_object_cli(name: str, fqdn_str: str, comment: str = "") -> str:
    """CLI block to create an address object of type fqdn."""
    safe_fqdn = _safe_cli_str(fqdn_str)
    lines = [
        "config firewall address",
        f'    edit "{name}"',
        "        set type fqdn",
        f'        set fqdn "{safe_fqdn}"',
    ]
    if comment:
        lines.append(f'        set comment "{_safe_cli_str(comment)}"')
    lines += ["    next", "end"]
    return "\n".join(lines)


def wildcard_fqdn_address_object_cli(name: str, wildcard_str: str,
                                      comment: str = "") -> str:
    """CLI block to create an address object of type wildcard-fqdn."""
    safe_wildcard = _safe_cli_str(wildcard_str)
    lines = [
        "config firewall address",
        f'    edit "{name}"',
        "        set type wildcard-fqdn",
        f'        set wildcard-fqdn "{safe_wildcard}"',
    ]
    if comment:
        lines.append(f'        set comment "{_safe_cli_str(comment)}"')
    lines += ["    next", "end"]
    return "\n".join(lines)
