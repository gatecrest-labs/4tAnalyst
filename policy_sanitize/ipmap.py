"""Keyed, prefix-preserving IPv4 mapper.

Private addresses map into reserved class-E space (one disjoint block per
RFC1918 range) via a Crypto-PAn style keyed bit-flip, so subnet structure
survives. Everything else is allocated sequentially from 100.64.0.0/10 and
keeps only equality (no structure).
"""

from __future__ import annotations

import hashlib
import hmac

from .tokens import is_mask

Octets = tuple[int, int, int, int]

# (name, real base, offset bits, fake base)
_BLOCKS = (
    ("10", (10 << 24), 24, (240 << 24)),
    ("172.16", (172 << 24) | (16 << 16), 20, (241 << 24)),
    ("192.168", (192 << 24) | (168 << 16), 16, (241 << 24) | (16 << 16)),
)
_POOL_SIZE = 1 << 22  # 100.64.0.0/10


def _to_int(o: Octets) -> int:
    return (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]


def _to_octets(n: int) -> Octets:
    return ((n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255)


def _dotted(o: Octets) -> str:
    return ".".join(map(str, o))


class IpMapper:
    def __init__(self, key: bytes):
        self._key = key
        self.mapping: dict[str, str] = {}
        self._public: dict[object, int] = {}
        self._next_public = 0

    def _flip(self, tag: str, bits: int, nbits: int, i: int) -> int:
        prefix = format(bits >> (nbits - i), f"0{i}b") if i else ""
        msg = f"{tag}|{i}|{prefix}".encode()
        return hmac.new(self._key, msg, hashlib.sha256).digest()[0] >> 7

    def _map_offset(self, tag: str, off: int, nbits: int) -> int:
        out = 0
        for i in range(nbits):
            bit = (off >> (nbits - 1 - i)) & 1
            out = (out << 1) | (bit ^ self._flip(tag, off, nbits, i))
        return out

    def _alloc_public(self, key: object) -> int:
        if key not in self._public:
            if self._next_public >= _POOL_SIZE:
                raise ValueError("public address pool 100.64.0.0/10 exhausted")
            self._public[key] = (100 << 24) | (64 << 16) | self._next_public
            self._next_public += 1
        return self._public[key]

    def _map_int(self, n: int) -> int:
        for tag, base, nbits, fake in _BLOCKS:
            if base <= n < base + (1 << nbits):
                return fake + self._map_offset(tag, n - base, nbits)
        return self._alloc_public(n)

    def map_ip(self, octets: Octets) -> Octets:
        if is_mask(octets) or octets == (255, 255, 255, 255):
            return octets
        fake = _to_octets(self._map_int(_to_int(octets)))
        self.mapping[_dotted(octets)] = _dotted(fake)
        return fake

    def map_cidr(self, octets: Octets, prefix: int) -> Octets:
        """Network address of the mapped block (host bits zeroed).

        For private ranges this is consistent with map_ip of any address in
        the block. For public addresses only equality and the prefix length
        carry over: the allocated fake of the base address is returned.
        """
        if is_mask(octets) or octets == (255, 255, 255, 255):
            return octets
        n = _to_int(octets)
        for _tag, base, nbits, _fake in _BLOCKS:
            if base <= n < base + (1 << nbits) and prefix < 32 - nbits:
                # wider than the real private block: no structure, public pool
                return _to_octets(self._alloc_public(("wide", n, prefix)))
        fake = _to_int(self.map_ip(octets))
        if _to_int(octets) in self._public:
            return _to_octets(fake)
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        return _to_octets(fake & mask)

    def map_host_in_net(self, octets: Octets, prefix: int) -> Octets:
        """Fake for an address written with a prefix whose host bits are non-zero
        (``10.1.1.7/24``, ``H_10.1.1.7_22``).

        Private, block-sized or narrower: the prefix bits are those of
        ``map_cidr`` of the network (containment holds; the network token's own
        fake is unchanged) and the host bits go through a keyed bijection that
        fixes zero, so a non-zero host can never land on the network's fake.
        Wide private prefixes and public addresses keep equality only (public
        pool / ``map_ip``), which is distinct per original by construction.
        """
        n = _to_int(octets)
        k = 32 - prefix
        host_mask = (1 << k) - 1 if k > 0 else 0
        if not n & host_mask:
            return self.map_cidr(octets, prefix)
        net = n & ~host_mask & 0xFFFFFFFF
        for tag, base, nbits, _fake in _BLOCKS:
            if base <= n < base + (1 << nbits):
                if prefix < 32 - nbits:
                    return _to_octets(self._alloc_public(("wide", n, prefix)))
                net_fake = _to_int(self.map_cidr(_to_octets(net), prefix))
                htag = f"{tag}|host|{prefix}|{net}"
                g0 = self._map_offset(htag, 0, k)
                h = self._map_offset(htag, n & host_mask, k) ^ g0
                return _to_octets(net_fake | h)
        return self.map_ip(octets)
