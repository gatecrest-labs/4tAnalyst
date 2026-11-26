"""Fail-closed leak verifier: scan sanitized output for any original value.

Violations carry only a JSON path and a kind, never any matched text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from policy_sanitize.tokens import find_ip_tokens, find_ipv6_tokens, normalize_ipv6

SUBSTRING_MIN = 4  # term originals at least this long are flagged as substrings

_SAFE_KEY = re.compile(r"^[A-Za-z0-9_]{1,32}$")


@dataclass(frozen=True)
class Violation:
    path: str
    kind: str  # "ip" | "fqdn" | "term"


def _parse_ip(token: str) -> tuple[int, int, int, int] | None:
    toks = find_ip_tokens(token)
    if len(toks) == 1 and toks[0].start == 0 and toks[0].end == len(token):
        return toks[0].octets
    return None


def _extra_variants(octets: tuple[int, int, int, int]) -> set[str]:
    a, b, c, d = octets
    n = (a << 24) | (b << 16) | (c << 8) | d
    return {f"0x{n:08x}", str(n), f"{d}.{c}.{b}.{a}.in-addr.arpa"}


def variants(token: str) -> set[str]:
    """Spellings of ``token``: itself, lowercase and, for IPs, other forms."""
    out = {token, token.lower()}
    octets = _parse_ip(token)
    if octets is None:
        return out
    for sep in ".-_":
        out.add(sep.join(str(o) for o in octets))
        out.add(sep.join(f"{o:03d}" for o in octets))
    if _parse_ip(token) is not None and "." in token:
        out |= _extra_variants(octets)
    return out


_ALNUM_RUN = re.compile(r"[A-Za-z0-9]+")
_RDNS = re.compile(
    r"(?<![A-Za-z0-9])[0-9]{1,3}(?:\.[0-9]{1,3}){3}\.in-addr\.arpa(?![A-Za-z0-9])",
    re.IGNORECASE,
)


_PLACEHOLDER_SPAN = re.compile(
    r"(?<![A-Za-z0-9])(?:host-[0-9]{3,}\.example\.test|SITE-[0-9]+|ORG|PKG-[0-9]+"
    r"|ADOM-[0-9]+|2001:db8::[0-9a-f]+)(?![A-Za-z0-9])"
)


def _bounded(text: str) -> "re.Pattern[str]":
    return re.compile(
        r"(?<![A-Za-z0-9])" + re.escape(text) + r"(?![A-Za-z0-9])", re.IGNORECASE
    )


def _fold_char(c: str) -> str:
    """Length-preserving single-char fold (superset of re.IGNORECASE matching)."""
    if c == "\u0131":  # dotless i
        return "i"
    x = c.lower()
    if len(x) != 1:
        x = x[0]
    y = x.casefold()
    return y if len(y) == 1 else x


def _fold(s: str) -> str:
    """Lowercase/casefold without ever changing the string length."""
    if s.isascii():
        return s.lower()
    return "".join(_fold_char(c) for c in s)


def _is_alnum(ch: str) -> bool:
    return ch.isascii() and ch.isalnum()


class _Matcher:
    """Set/dict based matching: cost per string is independent of #originals."""

    def __init__(self, originals: set[str]) -> None:
        self.ips: set[tuple[int, int, int, int]] = set()
        self.alnum_ip: set[str] = set()  # hex / decimal spellings (single alnum run)
        self.rdns: set[str] = set()
        # word originals keyed by lowercase first alnum run -> [(kind, lower, len)]
        self.words: dict[str, list[tuple[str, str]]] = {}
        # originals not starting with an alnum char fall back to a regex each
        self.odd: list[tuple[str, "re.Pattern[str]"]] = []
        self.v6: set[str] = set()  # normalized IPv6 addresses
        # long term originals indexed by their first SUBSTRING_MIN folded chars
        self.subs: dict[str, list[str]] = {}
        for orig in originals:
            octets = _parse_ip(orig)
            if octets is not None:
                if octets not in self.ips:
                    self.ips.add(octets)
                    for v in _extra_variants(octets):
                        if v.endswith(".in-addr.arpa"):
                            self.rdns.add(v)
                        else:
                            self.alnum_ip.add(v)
                continue
            v6 = normalize_ipv6(re.sub(r"/[0-9]+$", "", orig))
            if v6 is not None:
                self.v6.add(v6)
                continue
            if len(orig) < 2:
                continue
            kind = "fqdn" if ("." in orig and re.search(r"[A-Za-z]", orig)) else "term"
            forig = _fold(orig)
            if kind == "term" and len(forig) >= SUBSTRING_MIN:
                self.subs.setdefault(forig[:SUBSTRING_MIN], []).append(forig)
            elif _is_alnum(forig[0]):
                first = _ALNUM_RUN.match(forig).group(0)  # type: ignore[union-attr]
                self.words.setdefault(first, []).append((kind, forig))
            else:
                self.odd.append((kind, _bounded(orig)))

    def kinds(self, text: str) -> set[str]:
        found: set[str] = set()
        lowered = _fold(text)  # same length as text; offsets stay aligned
        runs = list(_ALNUM_RUN.finditer(lowered))
        if self.ips:
            if any(t.octets in self.ips for t in find_ip_tokens(text)):
                found.add("ip")
            elif any(m.group(0) in self.alnum_ip for m in runs):
                found.add("ip")
            elif self.rdns and "arpa" in lowered and any(
                m.group(0) in self.rdns for m in _RDNS.finditer(lowered)
            ):
                found.add("ip")
        if self.v6 and text.count(":") >= 2:
            if any(t.addr in self.v6 for t in find_ipv6_tokens(text)):
                found.add("ip")
        # Term/FQDN checks ignore the sanitizer's own fixed placeholders (a term
        # like 'host' or 'site' would otherwise match inside them). Spans are
        # blanked with equal-length spaces so offsets and boundaries hold.
        if _PLACEHOLDER_SPAN.search(text):
            masked = _PLACEHOLDER_SPAN.sub(lambda m: " " * len(m.group(0)), text)
            text, lowered = masked, _fold(masked)
            runs = list(_ALNUM_RUN.finditer(lowered))
        if self.subs and "term" not in found:
            subs, n = self.subs, SUBSTRING_MIN
            for i in range(len(lowered) - n + 1):
                cands = subs.get(lowered[i:i + n])
                if cands and any(lowered.startswith(c, i) for c in cands):
                    found.add("term")
                    break
        if self.words:
            for m in runs:
                cands = self.words.get(m.group(0))
                if not cands:
                    continue
                for kind, low in cands:
                    if kind in found:
                        continue
                    end = m.start() + len(low)
                    if lowered.startswith(low, m.start()) and (
                        end >= len(lowered) or not _is_alnum(lowered[end])
                    ):
                        found.add(kind)
        for kind, pat in self.odd:
            if pat.search(text):
                found.add(kind)
        return found


def verify(sanitized: object, originals: set[str]) -> list[Violation]:
    """Return violations (empty list = clean), sorted by path."""
    matcher = _Matcher(originals)
    found: set[Violation] = set()

    def walk(node: object, path: str) -> None:
        if isinstance(node, str):
            for kind in matcher.kinds(node):
                found.add(Violation(path, kind))
        elif isinstance(node, dict):
            for i, (key, val) in enumerate(node.items()):
                key_kinds = matcher.kinds(key) if isinstance(key, str) else set()
                if isinstance(key, str) and _SAFE_KEY.match(key) and not key_kinds:
                    child = f"{path}.{key}"
                else:
                    child = f"{path}.key#{i}"
                for kind in key_kinds:
                    found.add(Violation(f"{child}@key", kind))
                walk(val, child)
        elif isinstance(node, (list, tuple)):
            for i, item in enumerate(node):
                walk(item, f"{path}[{i}]")

    walk(sanitized, "$")
    return sorted(found, key=lambda v: (v.path, v.kind))
