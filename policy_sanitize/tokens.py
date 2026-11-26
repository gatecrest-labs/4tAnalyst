"""IPv4 tokenizer for names, comments and other free text in policy exports."""

from __future__ import annotations

import re
from dataclasses import dataclass

# One IPv4 address spelled with a consistent separator ('.', '-' or '_'),
# bounded by non-digits, with an optional /nn or _nn prefix suffix.
_IP_RE = re.compile(
    r"(?<![0-9])"
    r"(?P<a>[0-9]{1,3})(?P<sep>[._-])"
    r"(?P<b>[0-9]{1,3})(?P=sep)"
    r"(?P<c>[0-9]{1,3})(?P=sep)"
    r"(?P<d>[0-9]{1,3})"
    r"(?![0-9])"
    r"(?:(?P<psep>[/_])(?P<pfx>[0-9]{1,2})(?![0-9]))?"
)


@dataclass(frozen=True)
class IpToken:
    start: int
    end: int
    text: str
    octets: tuple[int, int, int, int]
    prefix: int | None
    sep: str


def is_mask(octets: tuple[int, int, int, int]) -> bool:
    """True for netmasks, wildcard masks and the all-zero address."""
    for form in (octets, tuple(255 - o for o in octets)):
        bits = "".join(f"{o:08b}" for o in form)
        if re.fullmatch(r"1*0*", bits):
            return True
    return False


def find_ip_tokens(text: str) -> list[IpToken]:
    """Find non-overlapping IPv4 tokens, left to right."""
    out: list[IpToken] = []
    pos = 0
    while pos <= len(text):
        m = _IP_RE.search(text, pos)
        if not m:
            break
        octets = tuple(int(m.group(g)) for g in "abcd")
        if any(o > 255 for o in octets):
            pos = m.start() + 1
            continue
        sep = m.group("sep")
        prefix = None
        end = m.end("d")
        psep, pfx = m.group("psep"), m.group("pfx")
        if pfx is not None and int(pfx) <= 32 and (psep == "/" or sep == "."):
            prefix = int(pfx)
            end = m.end()
        out.append(IpToken(m.start(), end, text[m.start():end], octets, prefix, sep))  # type: ignore[arg-type]
        pos = end
    return out


# --- IPv6 ---------------------------------------------------------------------
# A candidate is a run of hex groups and colons (>= 2 colons) bounded by
# non-alphanumeric, non-colon characters, with an optional /nn prefix. A run
# followed by '.digit' is the head of an IPv4-mapped form (::ffff:a.b.c.d) and
# is left for the IPv4 tokenizer.
_V6_RE = re.compile(
    r"(?<![A-Za-z0-9:])"
    r"(?P<addr>[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})"
    r"(?:/(?P<pfx>[0-9]{1,3}))?"
    r"(?![A-Za-z0-9:]|\.[0-9])"
)


@dataclass(frozen=True)
class Ip6Token:
    start: int
    end: int
    text: str  # as written, including any /nn
    addr: str  # normalized (compressed, lowercase) address, no prefix
    prefix: int | None


def _v6_shape_ok(addr: str) -> bool:
    if "::" in addr or addr.count(":") == 7:
        return True
    groups = addr.split(":")
    return len(groups) >= 3 and any(3 <= len(g) <= 4 for g in groups)


def normalize_ipv6(addr: str) -> str | None:
    """Compressed lowercase form, or None if ``addr`` is not an IPv6 literal."""
    import ipaddress

    if addr.count(":") < 2 or not any(c in "0123456789abcdefABCDEF" for c in addr):
        return None
    if not _v6_shape_ok(addr):
        return None
    try:
        return ipaddress.IPv6Address(addr).compressed
    except ValueError:
        return None


def find_ipv6_tokens(text: str) -> list[Ip6Token]:
    out: list[Ip6Token] = []
    if text.count(":") < 2:
        return out
    for m in _V6_RE.finditer(text):
        norm = normalize_ipv6(m.group("addr"))
        if norm is None:
            continue
        pfx = m.group("pfx")
        prefix = int(pfx) if pfx is not None and int(pfx) <= 128 else None
        end = m.end() if prefix is not None else m.end("addr")
        out.append(Ip6Token(m.start(), end, text[m.start():end], norm, prefix))
    return out
