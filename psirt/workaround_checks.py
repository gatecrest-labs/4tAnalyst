"""
Registry of recognized PSIRT workaround patterns and the deterministic
FortiManager config checks that verify whether each is already applied.

Advisory workaround text is free-form English written by Fortinet. Rather
than have the LLM guess whether a workaround is in place, `parse_advisory`
only extracts the raw text; this module matches that text against a small,
explicitly-registered set of patterns and runs a real config check for
each match. Unrecognized text never gets a guessed status — it comes back
as "manual_verification_required", and the registry is expected to grow
one advisory at a time as new patterns are seen (see the design spec's
Open Questions).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fortimanager_mcp import query as _query

_ADMIN_ACCESS_SERVICES = {"http", "https"}


def _check_disable_http_https_admin_access(client: Any, adom: str, device: str) -> str:
    result = _query.get_device_interface_config(client, device)
    raw_interfaces = result.get("interfaces", [])
    raw_list = raw_interfaces if isinstance(raw_interfaces, list) else [raw_interfaces]
    found_any_interface = False
    for iface in raw_list:
        if not isinstance(iface, dict):
            continue
        found_any_interface = True
        allowaccess = iface.get("allowaccess", []) or []
        if isinstance(allowaccess, str):
            allowaccess = allowaccess.split()
        if _ADMIN_ACCESS_SERVICES & {str(a).lower() for a in allowaccess}:
            return "not_in_place"
    if not found_any_interface:
        return "manual_verification_required"
    return "in_place"


# pattern key -> (substrings that identify this workaround in advisory text, check function)
WORKAROUND_REGISTRY: dict[str, tuple[tuple[str, ...], Callable[[Any, str, str], str]]] = {
    "disable_http_https_admin_access": (
        ("http/https admin", "https admin access", "http admin access",
         "disable http", "disable https"),
        _check_disable_http_https_admin_access,
    ),
}


def match_workaround_pattern(workaround_text: str) -> str | None:
    text = (workaround_text or "").lower()
    for key, (substrings, _fn) in WORKAROUND_REGISTRY.items():
        if any(s in text for s in substrings):
            return key
    return None


def check_workaround(pattern_key: str, client: Any, adom: str, device: str) -> str:
    entry = WORKAROUND_REGISTRY.get(pattern_key)
    if entry is None:
        return "manual_verification_required"
    _substrings, check_fn = entry
    return check_fn(client, adom, device)
