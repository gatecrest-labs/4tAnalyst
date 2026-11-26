"""Free-text scrubber: FQDNs, IPv6, terms, then IPv4 addresses.

FQDN = two or more dot-separated labels (letters, digits, hyphens; no
leading/trailing hyphen) whose final label is 2-24 letters and not one of
FILE_EXTENSIONS (so ``report.json`` / ``server.py`` are left alone).

Terms of length >= 4 match case-insensitively as substrings, even inside
alphanumeric runs (``acmecorp`` -> ``ORGcorp``); shorter terms match only as
whole tokens (non-alphanumeric boundary on both sides).
"""

from __future__ import annotations

import re

from .ipmap import IpMapper
from .tokens import find_ip_tokens, find_ipv6_tokens

FILE_EXTENSIONS = frozenset({
    "json", "py", "txt", "csv", "xml", "html", "log", "conf", "cfg", "yaml",
    "yml", "pdf", "xlsx", "md", "tmp",
})
SUBSTRING_MIN = 4  # terms at least this long match as substrings

# Labels may contain underscores anywhere (``_scada_01.plant.ca``,
# ``scada.db_hmi.plant.ca``) so the whole name is replaced and recorded, never
# leaving a stem behind; hyphens still may not lead or trail a label.
_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?"
_FQDN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"(?:" + _LABEL + r"\.)+"
    r"(?P<tld>[A-Za-z]{2,24})"
    r"(?![A-Za-z0-9-]|\.[A-Za-z0-9])",
)
_PLACEHOLDER_FQDN = re.compile(r"host-\d{3}\.example\.test", re.IGNORECASE)
_IDENT_RE = re.compile(r"[A-Za-z0-9]+")
# Meaning words / units that mix letters and digits but identify nothing.
_IDENT_EXEMPT = frozenset({
    "ipv4", "ipv6", "icmp6", "icmpv6", "http2", "http3", "sha1", "sha256",
    "sha384", "sha512", "md5", "aes128", "aes256", "3des", "x509", "tls12",
    "tls13", "ssl3", "dns64", "nat64", "nat46", "l2tp", "l2vpn", "l3vpn",
    "ospf3", "ospfv3", "snmpv2", "snmpv3", "snmpv2c", "ikev1", "ikev2", "p2p",
    "b2b", "s3", "ec2", "dhcp6", "dhcpv6", "win10", "win11",
})
# Generic FortiGate interface-name shapes (matched on one alphanumeric run).
_INTF_RE = re.compile(
    r"(?:port|wan|lan|internal|dmz|mgmt|ha|vlan|npu|vlink|x|a|ssl|"
    r"tunnel|loopback|lo)\d*",
    re.IGNORECASE,
)
_UNIT_RE = re.compile(
    r"\d+(?:st|nd|rd|th|s|m|h|d|w|y|ms|k|g|t|kb|mb|gb|tb|kbps|mbps|gbps|x)",
    re.IGNORECASE,
)
# Placeholders are wrapped in private-use sentinels so later passes never
# re-match inside or across them; sentinels are stripped at the end.
_OPEN, _CLOSE = "\ue000", "\ue001"
_PROTECTED = re.compile(f"{_OPEN}.*?{_CLOSE}", re.DOTALL)


class SanitizeError(Exception):
    """Carries only a code and JSON paths; never any original/sanitized text."""

    def __init__(self, code: str, paths: list[str]):
        self.code = code
        self.paths = list(paths)
        super().__init__(f"{code}: {', '.join(self.paths)}" if self.paths else code)


def _host_bits(octets: tuple[int, int, int, int], prefix: int) -> int:
    n = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    return n & ((1 << (32 - prefix)) - 1) if prefix < 32 else 0


def _outside_protected(s: str, fn) -> str:
    """Apply fn to every stretch of s that is not a protected placeholder."""
    out, pos = [], 0
    for pm in _PROTECTED.finditer(s):
        out.append(fn(s[pos:pm.start()]))
        out.append(pm.group(0))
        pos = pm.end()
    out.append(fn(s[pos:]))
    return "".join(out)


class Scrubber:
    def __init__(self, mapper: IpMapper, terms: list[tuple[str, str | None]]):
        self.mapper = mapper
        self.ips: dict[str, str] = {}
        self._ip_fakes: dict[str, object] = {}  # rendered fake -> original identity
        self._v6: dict[str, str] = {}  # normalized original -> fake address
        self.fqdns: dict[str, str] = {}  # original spelling -> placeholder
        self._fqdn_ci: dict[str, str] = {}
        self.term_map: dict[str, str] = {}
        self.ip_count = self.fqdn_count = self.term_count = 0
        self._unmatched = 0

        explicit_org = any(ph == "ORG" for _, ph in terms)
        self._term_ph: dict[str, str] = {}
        org_free, n = not explicit_org, 0
        for term, ph in terms:
            if ph is None:
                if org_free:
                    ph, org_free = "ORG", False
                else:
                    n += 1
                    ph = f"SITE-{n}"
            self._term_ph[term.casefold()] = ph
        self._term_re = None
        if self._term_ph:
            alts = sorted(self._term_ph, key=len, reverse=True)
            long_ = [a for a in alts if len(a) >= SUBSTRING_MIN]
            short = [a for a in alts if len(a) < SUBSTRING_MIN]
            branches = [f"{_OPEN}.*?{_CLOSE}"]
            if long_:
                branches.append("(?:" + "|".join(re.escape(a) for a in long_) + ")")
            if short:
                branches.append(
                    "(?<![A-Za-z0-9])(?:" + "|".join(re.escape(a) for a in short)
                    + ")(?![A-Za-z0-9])"
                )
            self._term_re = re.compile("|".join(branches), re.IGNORECASE | re.DOTALL)

    def unmatched_identifier_count(self) -> int:
        return self._unmatched

    def _ph_for(self, matched: str) -> str:
        ph = self._term_ph.get(matched.casefold()) or self._term_ph.get(matched.lower())
        if ph is None:  # exotic case folding: find the term that matches
            for term, p in self._term_ph.items():
                if re.fullmatch(re.escape(term), matched, re.IGNORECASE):
                    return p
            raise SanitizeError("term", [])
        return ph

    def _term(self, m: re.Match) -> str:
        if m.group(0).startswith(_OPEN):
            return m.group(0)
        ph = self._ph_for(m.group(0))
        self.term_map[m.group(0)] = ph
        self.term_count += 1
        return _OPEN + ph + _CLOSE

    def _fqdn(self, m: re.Match) -> str:
        orig = m.group(0)
        if _PLACEHOLDER_FQDN.fullmatch(orig):
            return _OPEN + orig + _CLOSE
        if m.group("tld").lower() in FILE_EXTENSIONS:
            return orig
        key = orig.lower()
        if key not in self._fqdn_ci:
            self._fqdn_ci[key] = f"host-{len(self._fqdn_ci) + 1:03d}.example.test"
        self.fqdns[orig] = self._fqdn_ci[key]
        self.fqdn_count += 1
        return _OPEN + self._fqdn_ci[key] + _CLOSE

    def _record_ip(self, orig: str, fake: str, ident: object = None) -> None:
        """Record orig -> fake; two different originals sharing a fake fail closed.

        ``ident`` identifies the original value (defaults to its spelling); IPv6
        case/compression variants of one address share an identity.
        """
        ident = orig if ident is None else ident
        prev = self._ip_fakes.get(fake)
        if prev is not None and prev != ident:
            raise SanitizeError("collision", [])
        self._ip_fakes[fake] = ident
        self.ips[orig] = fake
        self.ip_count += 1

    def _ip_text(self, tok) -> str:
        sep = tok.sep
        ip_part_len = len(tok.text)
        if tok.prefix is not None:
            # a zero-padded prefix (e.g. /08) keeps its own width
            ip_part_len -= len(re.search(r"[/_]\d+$", tok.text).group(0))
        ip_part, suffix = tok.text[:ip_part_len], tok.text[ip_part_len:]
        orig = ip_part.split(sep)
        if tok.prefix is None:
            fake = self.mapper.map_ip(tok.octets)
        elif _host_bits(tok.octets, tok.prefix):
            # host-with-prefix (10.1.1.7/24, H_10.1.1.7_22): inside the fake
            # network, never equal to the network's own fake
            fake = self.mapper.map_host_in_net(tok.octets, tok.prefix)
        else:
            fake = self.mapper.map_cidr(tok.octets, tok.prefix)
        if fake == tok.octets:
            return tok.text  # exempt (mask etc.)
        parts = []
        for o, f in zip(orig, fake):
            s = str(f)
            if len(o) > 1 and o.startswith("0"):
                s = s.zfill(len(o))
            parts.append(s)
        out = sep.join(parts) + suffix
        self._record_ip(tok.text, out)
        return _OPEN + out + _CLOSE

    def _ips_in(self, seg: str) -> str:
        pieces, pos = [], 0
        for t in find_ip_tokens(seg):
            pieces.append(seg[pos:t.start])
            pieces.append(self._ip_text(t))
            pos = t.end
        pieces.append(seg[pos:])
        return "".join(pieces)

    def _ipv6_in(self, seg: str) -> str:
        pieces, pos = [], 0
        for t in find_ipv6_tokens(seg):
            if t.addr not in self._v6:
                self._v6[t.addr] = f"2001:db8::{len(self._v6) + 1:x}"
            out = self._v6[t.addr] + ("" if t.prefix is None else f"/{t.prefix}")
            self._record_ip(t.text, out, ("v6", t.addr, t.prefix))
            pieces.append(seg[pos:t.start])
            pieces.append(_OPEN + out + _CLOSE)
            pos = t.end
        pieces.append(seg[pos:])
        return "".join(pieces)

    def _count_unmatched(self, s: str) -> None:
        bare = _PROTECTED.sub(" ", s)  # placeholders and fakes never count
        for m in _IDENT_RE.finditer(bare):
            w = m.group(0)
            if (len(w) >= 3 and any(c.isdigit() for c in w) and any(c.isalpha() for c in w)
                    and w.lower() not in _IDENT_EXEMPT and not _UNIT_RE.fullmatch(w)
                    and not _INTF_RE.fullmatch(w)):
                self._unmatched += 1

    def text(self, s: str, count_unmatched: bool = True) -> str:
        """Scrub s. ``count_unmatched=False`` (interface fields) skips the
        unmatched-identifier count; every replacement still applies."""
        s = s.replace(_OPEN, "").replace(_CLOSE, "")
        s = _FQDN_RE.sub(self._fqdn, s)
        s = _outside_protected(s, self._ipv6_in)
        if self._term_re is not None:
            s = self._term_re.sub(self._term, s)
        s = _outside_protected(s, self._ips_in)
        if count_unmatched:
            self._count_unmatched(s)
        return s.replace(_OPEN, "").replace(_CLOSE, "")
