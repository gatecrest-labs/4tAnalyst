import pytest

from policy_sanitize.ipmap import IpMapper


def _bits(o):
    return "".join(f"{x:08b}" for x in o)


def _common(a, b):
    n = 0
    for x, y in zip(_bits(a), _bits(b)):
        if x != y:
            break
        n += 1
    return n


def test_deterministic_for_same_key_differs_across_keys():
    a, b, c = IpMapper(b"k1"), IpMapper(b"k1"), IpMapper(b"k2")
    ip = (10, 1, 1, 5)
    assert a.map_ip(ip) == b.map_ip(ip)
    assert a.map_ip(ip) != c.map_ip(ip)


def test_private_prefix_preserved():
    m = IpMapper(b"k")
    a, b, c = (10, 1, 1, 5), (10, 1, 1, 200), (10, 1, 2, 5)
    fa, fb, fc = m.map_ip(a), m.map_ip(b), m.map_ip(c)
    assert _common(fa, fb) == _common(a, b)
    assert _common(fa, fc) == _common(a, c)


def test_cidr_network_aligned():
    m = IpMapper(b"k")
    net = m.map_cidr((10, 1, 1, 0), 24)
    host = m.map_ip((10, 1, 1, 77))
    assert net[3] == 0
    assert net[:3] == host[:3]


def test_cidr_wider_than_range_does_not_crash():
    # final-wave ruling: wider than the real block -> public pool, not 240/241
    m = IpMapper(b"k")
    assert m.map_cidr((10, 0, 0, 0), 7)[0] == 100


def test_range_blocks_disjoint():
    m = IpMapper(b"k")
    assert m.map_ip((10, 1, 1, 5))[0] == 240
    f = m.map_ip((172, 16, 5, 9))
    assert f[0] == 241 and f[1] < 16
    f = m.map_ip((192, 168, 7, 9))
    assert f[:2] == (241, 16)


def test_public_sequential_stable_injective():
    m = IpMapper(b"k")
    a = m.map_ip((203, 0, 113, 5))
    b = m.map_ip((198, 51, 100, 7))
    assert a != b
    assert a[0] == 100 and 64 <= a[1] < 128
    assert b[0] == 100 and 64 <= b[1] < 128
    assert m.map_ip((203, 0, 113, 5)) == a
    assert m.mapping["203.0.113.5"] == ".".join(map(str, a))


def test_public_pool_exhaustion():
    m = IpMapper(b"k")
    m._next_public = 1 << 22
    with pytest.raises(ValueError):
        m.map_ip((203, 0, 113, 5))


def test_private_injective():
    m = IpMapper(b"k")
    fakes = {m.map_ip((10, i // 250, i % 250, 1)) for i in range(500)}
    assert len(fakes) == 500


def test_masks_unchanged():
    m = IpMapper(b"k")
    for ip in [(255, 255, 255, 0), (0, 0, 0, 0), (255, 255, 255, 255)]:
        assert m.map_ip(ip) == ip
    assert m.mapping == {}


@pytest.mark.parametrize("octets,prefix", [
    ((10, 0, 0, 0), 7), ((172, 0, 0, 0), 8), ((172, 16, 0, 0), 11),
    ((192, 168, 0, 0), 15), ((192, 168, 0, 0), 8),
])
def test_wide_cidr_uses_public_pool(octets, prefix):
    m = IpMapper(b"k" * 32)
    fake = m.map_cidr(octets, prefix)
    assert fake[0] == 100 and 64 <= fake[1] < 128
    assert m.map_cidr(octets, prefix) == fake  # stable


def test_block_sized_cidr_stays_private():
    m = IpMapper(b"k" * 32)
    assert m.map_cidr((10, 0, 0, 0), 8)[0] == 240
    assert m.map_cidr((172, 16, 0, 0), 12)[0] == 241
    assert m.map_cidr((192, 168, 0, 0), 16)[:2] == (241, 16)
