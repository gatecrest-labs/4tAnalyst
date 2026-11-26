import pytest

from policy_sanitize.ipmap import IpMapper
from policy_sanitize.scrub import Scrubber
from policy_sanitize.terms import TermsError, load_terms


def mk(terms=None):
    return Scrubber(IpMapper(b"k" * 32), terms or [])


def test_ip_in_name_replaced_keeps_surroundings():
    out = mk().text("ns-10.1.1.11")
    assert out.startswith("ns-")
    assert "10.1.1.11" not in out


def test_same_ip_all_spellings_same_fake():
    s = mk()
    a = s.text("a-10.1.1.11")
    b = s.text("a-10-1-1-11")
    c = s.text("a_10_1_1_11")
    fake = a[2:]
    assert b == "a-" + fake.replace(".", "-")
    assert c == "a_" + fake.replace(".", "_")
    assert s.ips["10.1.1.11"] == fake
    assert s.ips["10-1-1-11"] == fake.replace(".", "-")


def test_cidr_underscore_prefix_kept():
    s = mk()
    out = s.text("LAB-10.2.3.0_24_global")
    assert out.endswith("_24_global")
    assert "10.2.3.0" not in out
    assert "10.2.3.0_24" in s.ips


def test_cidr_slash_prefix_and_zero_padding():
    s = mk()
    out = s.text("172.16.5.0/24")
    assert out.endswith("/24") and "172.16" not in out
    padded = s.text("010.001.001.001")
    parts = padded.split(".")
    assert [len(p) for p in parts] == [3, 3, 3, 3]


def test_masks_untouched():
    assert mk().text("mask 255.255.255.0 and 0.0.0.0") == "mask 255.255.255.0 and 0.0.0.0"


def test_fqdn_replaced_consistently():
    s = mk()
    out = s.text("portal.acme.example.com x portal.acme.example.com y vpn.acme.example.com")
    assert out == "host-001.example.test x host-001.example.test y host-002.example.test"
    assert s.text("host-001.example.test") == "host-001.example.test"
    assert s.fqdn_count == 3


def test_terms_long_substring_short_whole_token():
    s = mk([("acme", None)])
    assert s.text("acme-ot-oob") == "ORG-ot-oob"
    # ruling (final wave): terms of length >= 4 match as substrings
    assert s.text("acmeprod-ot") == "ORGprod-ot"
    assert mk([("OT", None)]).text("BOT") == "BOT"
    assert s.term_map == {"acme": "ORG"}


def test_term_placeholder_override():
    s = mk([("acme", "ORG"), ("beta", None), ("gamma", None)])
    assert s.text("acme/beta_gamma") == "ORG/SITE-1_SITE-2"


def test_term_placeholder_order():
    s = mk([("acme", None), ("beta", None)])
    assert s.text("Acme beta") == "ORG SITE-1"


def test_load_terms(tmp_path):
    p = tmp_path / "t.txt"
    p.write_text("# c\n\nacme=ORG\nbeta\n")
    assert load_terms(p) == [("acme", "ORG"), ("beta", None)]


def test_load_terms_missing_or_empty_raises(tmp_path):
    with pytest.raises(TermsError):
        load_terms(None)
    with pytest.raises(TermsError) as e:
        load_terms(tmp_path / "nope.txt")
    assert "nope.txt" in str(e.value)
    p = tmp_path / "e.txt"
    p.write_text("# only\n\n")
    with pytest.raises(TermsError):
        load_terms(p)


def test_unmatched_identifier_count():
    s = mk()
    s.text("abc123xyz accept ALL")
    assert s.unmatched_identifier_count() == 1


def test_fqdn_with_term_keyed_by_original():
    s = mk([("acme", None)])
    out = s.text("portal.acme.example.com")
    assert out == "host-001.example.test"
    assert "portal.acme.example.com" in s.fqdns
    assert "acme" not in out


def test_shared_placeholder_fqdns_distinct():
    s = mk([("acme", "ORG"), ("beta", "ORG")])
    a = s.text("portal.acme.example.com")
    b = s.text("portal.beta.example.com")
    assert a != b
    assert set(s.fqdns) == {"portal.acme.example.com", "portal.beta.example.com"}


def test_fqdn_case_variants_share_placeholder_both_recorded():
    s = mk()
    assert s.text("Portal.Example.com") == s.text("portal.example.com")
    assert set(s.fqdns) == {"Portal.Example.com", "portal.example.com"}


def test_placeholder_not_rematched_by_ip_pass():
    s = mk([("gamma", None), ("delta", None)])
    assert s.text("delta-2-3-4") == "SITE-1-2-3-4"
    assert "2-2-3-4" not in s.ips and not s.ips
    out = s.text("portal.example.com 5-6-7")
    assert out == "host-001.example.test 5-6-7"
    assert not s.ips


def test_ip_next_to_fqdn_name():
    s = mk([("acme", None)])
    out = s.text("host-10.1.1.9.acme.example.com")
    assert "10.1.1.9" not in out and "acme" not in out
    assert s.text("x 10.1.1.9 y").count("10.1.1.9") == 0


def test_term_in_dn_and_punctuation_boundaries():
    s = mk([("acme", None)])
    assert "acme" not in s.text("cn=acme-admins,dc=acme,dc=example,dc=com").lower()
    assert s.text("(acme)") == "(ORG)"
    assert s.text("acme,x") == "ORG,x"
    assert s.text("x:acme;y") == "x:ORG;y"


def test_term_alnum_neighbours_long_substring_short_block():
    assert mk([("acme", None)]).text("acmeprod 1acme") == "ORGprod 1ORG"
    assert mk([("OT", None)]).text("BOT") == "BOT"
    assert mk([("ot", None)]).text("pivot ot-x OT") == "pivot ORG-x ORG"


def test_fqdn_inside_dn():
    s = mk([("acme", None)])
    out = s.text("dc=portal.acme.example.com")
    assert out == "dc=host-001.example.test"


def test_input_sentinels_stripped():
    assert mk().text("a\ue000b\ue001c") == "abc"


# --- final wave: A2 FQDNs -------------------------------------------------

@pytest.mark.parametrize("host", ["scada01.plant.ca", "portal.acme.energy", "x.cloud"])
def test_fqdn_any_alpha_tld_replaced(host):
    s = mk()
    out = s.text(f"to {host} now")
    assert out == "to host-001.example.test now"
    assert host in s.fqdns


def test_fqdn_email_host_part_replaced():
    out = mk().text("john.smith@corp-mail.ca")
    assert "corp-mail" not in out and ".ca" not in out
    assert "@host-" in out


@pytest.mark.parametrize("text", ["report.json", "server.py", "10.1.1.5", "v1.2",
                                  "notes.TXT", "a.b"])
def test_fqdn_exempt_and_non_hosts_untouched(text):
    s = mk()
    out = s.text(text)
    assert "host-" not in out
    assert not s.fqdns


def test_fqdn_in_url():
    out = mk([("acme", None)]).text("https://portal.acme.energy/x")
    assert "acme" not in out.lower() and ".energy" not in out
    assert out == "https://host-001.example.test/x"


def test_fqdn_placeholder_unchanged():
    assert mk().text("host-007.example.test") == "host-007.example.test"


# --- final wave: A3 IPv6 --------------------------------------------------

@pytest.mark.parametrize("lit", [
    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    "fe80::1",
    "FE80::ABCD:1",
    "::1",
    "3fff:1f18:abcd::",
])
def test_ipv6_replaced(lit):
    s = mk()
    out = s.text(f"x {lit} y")
    assert out == "x 2001:db8::1 y"
    assert s.ips[lit] == "2001:db8::1"


def test_ipv6_prefix_kept_and_distinct_sequential():
    s = mk()
    out = s.text("fd00:1::/48 fd00:2::5 fd00:1::/48 FD00:2::5")
    assert out == "2001:db8::1/48 2001:db8::2 2001:db8::1/48 2001:db8::2"
    assert s.ips["fd00:1::/48"] == "2001:db8::1/48"
    assert s.ips["FD00:2::5"] == "2001:db8::2"


@pytest.mark.parametrize("text", ["12:30:45", "00:1a:2b:3c:4d:5e", "aa:bb:cc",
                                  "std::vector", "a::b::c", "10:20"])
def test_ipv6_not_time_mac_or_code(text):
    s = mk()
    assert s.text(text) == text
    assert not s.ips


def test_ipv4_mapped_ipv6_keeps_ipv4_handling():
    s = mk()
    out = s.text("::ffff:10.1.1.5")
    assert out.startswith("::ffff:") and "10.1.1.5" not in out
    assert "10.1.1.5" in s.ips


def test_ipv6_in_name_with_separators():
    s = mk()
    out = s.text("h_fe80::1_x")
    assert out == "h_2001:db8::1_x"


# --- final wave: A4 unmatched identifiers -----------------------------------

@pytest.mark.parametrize("text,n", [
    ("fw01", 1), ("LABX-DC01", 1), ("abc123xyz accept ALL", 1),
    ("accept ALL 443 tcp", 0), ("host-001.example.test SITE-1 PKG-1 ADOM-1 ORG", 0),
    ("ipv6 HTTP2 sha256 24h 10G", 0),
])
def test_unmatched_identifiers(text, n):
    s = mk()
    s.text(text)
    assert s.unmatched_identifier_count() == n


def test_unmatched_ignores_fake_ip_runs_and_placeholders():
    s = mk([("acme", None)])
    s.text("srv10.1.1.5 acme01 h_fe80::1 x")
    assert s.unmatched_identifier_count() == 0  # 'srv', '01', placeholders only


def test_unmatched_counts_residue_next_to_term():
    s = mk([("acme", None)])
    s.text("acmefw01")
    assert s.unmatched_identifier_count() == 1


@pytest.mark.parametrize("text", ["acmecorp-fw", "AcmeEnergy_Servers",
                                  "cn=acme-admins,dc=acme"])
def test_long_term_substrings_scrubbed(text):
    out = mk([("acme", None)]).text(text)
    assert "acme" not in out.lower()
    assert "ORG" in out


# --- final wave: B3 collision -----------------------------------------------

def test_two_originals_one_fake_raises_collision():
    # second-pass ruling: host-with-prefix no longer collides; the check stays
    # as an internal fail-closed assertion
    from policy_sanitize.engine import SanitizeError
    s = mk()
    s.text("10.1.1.0/24")
    s.text("10.1.1.7/24")  # no collision any more
    with pytest.raises(SanitizeError) as e:
        s._record_ip("10.9.9.9", s.ips["10.1.1.0/24"])
    assert e.value.code == "collision" and e.value.paths == []
    assert str(e.value) == "collision"


# --- second fix pass ----------------------------------------------------------

@pytest.mark.parametrize("name", ["port1", "wan1", "lan", "internal1", "dmz", "mgmt", "ha1",
                                  "VLAN100", "npu0_vlink0", "x1", "a1", "ssl", "tunnel2",
                                  "loopback0", "lo1"])
def test_interface_shapes_not_counted(name):
    s = mk()
    s.text(name)
    assert s.unmatched_identifier_count() == 0


def test_count_unmatched_flag():
    s = mk([("acme", None)])
    assert s.text("zz9plural acme", count_unmatched=False) == "zz9plural ORG"
    assert s.unmatched_identifier_count() == 0
    s.text("zz9plural")
    assert s.unmatched_identifier_count() == 1


def test_host_with_prefix_uses_host_fake_inside_network():
    m = IpMapper(b"k" * 32)
    s = Scrubber(m, [])
    net = s.text("10.1.1.0/24")
    host = s.text("10.1.1.7/24")
    assert host.endswith("/24") and net != host
    assert host[:-3].rsplit(".", 1)[0] == net[:-3].rsplit(".", 1)[0]  # first 24 bits
    assert host[:-3] == ".".join(map(str, m.map_host_in_net((10, 1, 1, 7), 24)))
    a, b = s.text("H_10.1.1.7_22"), s.text("H_10.1.1.9_22")
    assert a != b and a.endswith("_22") and b.endswith("_22")


@pytest.mark.parametrize("text,stem", [("scada_01.plant.ca", "scada"),
                                       ("srv-app_db.corp.ca", "srv-app")])
def test_fqdn_stem_before_underscore_included(text, stem):
    s = mk()
    out = s.text(f"x {text} y")
    assert stem not in out and out == "x host-001.example.test y"
    assert text in s.fqdns
    from policy_sanitize.store import map_back
    assert map_back(out, {"fqdns": s.fqdns}) == f"x {text} y"


def test_terms_like_placeholders_not_rescrubbed():
    s = mk([("host", None), ("beta", None), ("site", None)])
    assert s.text("a.b.example.com") == "host-001.example.test"
    assert s.text("beta x") == "SITE-1 x"  # emitted placeholder not re-scrubbed by 'site'
    assert s.text("a.b.example.com beta") == "host-001.example.test SITE-1"


# --- third fix pass -----------------------------------------------------------
import secrets  # noqa: E402

from policy_sanitize.store import map_back as _map_back  # noqa: E402

_KEYS = [b"k" * 32] + [secrets.token_bytes(32) for _ in range(300)]


def _bits32(dotted):
    a, b, c, d = (int(x) for x in dotted.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _ip_of(rendered):
    import re as _re
    return _re.search(r"\d+\.\d+\.\d+\.\d+", rendered).group(0)


def _check_group(key, net_tok, prefix, host_toks):
    s = Scrubber(IpMapper(key), [])
    net = s.text(net_tok)
    hosts = [s.text(h) for h in host_toks]
    fakes = [net] + hosts
    assert len(set(fakes)) == len(fakes)
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    nb = _bits32(_ip_of(net))
    for h in hosts:
        assert _bits32(_ip_of(h)) & mask == nb & mask
        assert _bits32(_ip_of(h)) & ~mask & 0xFFFFFFFF != 0
    joined = " | ".join(fakes)
    assert _map_back(joined, {"ips": s.ips}) == " | ".join([net_tok] + host_toks)


@pytest.mark.parametrize("net,prefix,hosts", [
    ("10.1.1.0/31", 31, ["10.1.1.1/31"]),
    ("10.1.1.4/30", 30, ["10.1.1.5/30", "10.1.1.6/30", "10.1.1.7/30"]),
    ("172.16.5.0/31", 31, ["172.16.5.1/31"]),
    ("192.168.7.8/29", 29, [f"192.168.7.{i}/29" for i in range(9, 16)]),
])
def test_host_with_prefix_never_collides_any_key(net, prefix, hosts):
    for key in _KEYS:
        _check_group(key, net, prefix, hosts)


def test_full_slash24_hosts_any_key():
    hosts = [f"10.1.1.{i}/24" for i in range(1, 255)]
    for key in _KEYS:
        _check_group(key, "10.1.1.0/24", 24, hosts)


def test_underscore_prefix_names_any_key():
    for key in _KEYS:
        _check_group(key, "H_10.1.1.0_22", 22, ["H_10.1.1.7_22", "H_10.1.1.9_22"])


def test_bare_ip_unchanged_by_host_in_net():
    m = IpMapper(b"k" * 32)
    assert Scrubber(m, []).text("10.1.1.7") == ".".join(map(str, m.map_ip((10, 1, 1, 7))))


def test_wide_and_public_host_with_prefix_distinct():
    for key in _KEYS[:50]:
        s = Scrubber(IpMapper(key), [])
        outs = [s.text(x) for x in ("10.0.0.0/7", "10.0.0.5/7", "203.0.113.0/24",
                                     "203.0.113.9/24")]
        assert len(set(outs)) == 4


@pytest.mark.parametrize("text", ["_scada_01.plant.ca", "scada.db_hmi.plant.ca"])
def test_fqdn_underscore_labels_whole(text):
    s = mk()
    out = s.text(f"x {text} y")
    assert out == "x host-001.example.test y"
    assert set(s.fqdns) == {text}
    assert _map_back(out, {"fqdns": s.fqdns}) == f"x {text} y"
