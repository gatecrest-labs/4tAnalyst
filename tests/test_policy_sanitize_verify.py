from policy_sanitize.verify import Violation, variants, verify

ORIG = {"10.1.1.11"}


def test_clean_output_has_no_violations():
    doc = {"name": "host-240.9.9.9", "items": ["a", "b"]}
    assert verify(doc, ORIG | {"acme", "portal.acme.example.com"}) == []


def test_leak_in_value_and_key_detected():
    doc = {"policies": [{"comment": "see 10.1.1.11 now"}], "10.1.1.11": "x"}
    vs = verify(doc, ORIG)
    assert len(vs) == 2
    assert all(isinstance(v, Violation) and v.kind == "ip" for v in vs)
    paths = [v.path for v in vs]
    assert paths == sorted(paths)
    assert "$.policies[0].comment" in paths
    assert any("key#" in p or "10.1.1.11" not in p for p in paths)
    assert not any("10.1.1.11" in p for p in paths)


def test_variants_detected():
    for text in [
        "10-1-1-11", "10_1_1_11", "010.001.001.011", "0x0a01010b", "0X0A01010B",
        "167837963", "11.1.1.10.in-addr.arpa", "x 10.1.1.11/32",
    ]:
        vs = verify({"v": text}, ORIG)
        assert [v.kind for v in vs] == ["ip"], text


def test_variants_function():
    v = variants("10.1.1.11")
    assert {"10-1-1-11", "10_1_1_11", "010.001.001.011", "0x0a01010b",
            "167837963", "11.1.1.10.in-addr.arpa", "10.1.1.11"} <= v


def test_no_false_positive_on_embedded_or_longer_number():
    assert verify({"v": "240.10.1.1.11.5"}, ORIG) == []
    assert verify({"v": "1167837963"}, ORIG) == []
    assert verify({"v": "10.1.1.110"}, ORIG) == []


def test_fqdn_and_term_boundaries():
    o = {"acme", "portal.acme.example.com", "ot"}
    assert verify({"v": "other"}, o) == []
    assert [v.kind for v in verify({"v": "my-ACME-rule"}, o)] == ["term"]
    assert [v.kind for v in verify({"v": "PORTAL.acme.example.com."}, {"portal.acme.example.com"})] == ["fqdn"]
    assert verify({"v": "a"}, {"a"}) == []


def test_prefix_original_classified_ip():
    assert [v.kind for v in verify({"v": "10_20_30_41"}, {"10_20_30_41"})] == ["ip"]
    assert [v.kind for v in verify({"v": "10.1.1.0/24"}, {"10.1.1.0/24"})] == ["ip"]


def test_violation_never_contains_value():
    doc = {"weird key acme 10.1.1.11": "acme 10.1.1.11", "n": ["10.1.1.11"]}
    vs = verify(doc, ORIG | {"acme"})
    r = repr(vs)
    assert "10.1.1.11" not in r and "acme" not in r
    assert len(vs) >= 3


def test_performance_many_originals():
    import time

    ips = {f"10.{i // 250}.{i % 250}.{j}" for i in range(12) for j in range(1, 251)}
    ips = set(sorted(ips)[:3000])
    words = {f"host{i}.corp{i}.example.com" for i in range(750)} | {f"term{i}x" for i in range(750)}
    records = [
        {"name": f"rule-{n}", "comment": f"allow 172.16.{n % 250}.{n % 200 + 1} for svc{n}"}
        for n in range(20000)
    ]
    assert len(ips) == 3000 and len(words) == 1500
    start = time.perf_counter()
    assert verify(records, ips | words) == []
    elapsed = time.perf_counter() - start
    assert elapsed < 5.0, elapsed
    records[12345]["comment"] = "see HOST7.corp7.example.com now"
    records[777]["name"] = "x-0x0a000102-y"
    vs = verify(records, ips | words)
    assert sorted((v.path, v.kind) for v in vs) == sorted(
        [("$[12345].comment", "fqdn"), ("$[777].name", "ip")]
    )


def test_length_changing_lowercase_does_not_shift_offsets():
    assert [v.kind for v in verify({"k": "İ acme"}, {"Acme"})] == ["term"]
    kinds = sorted(v.kind for v in verify({"k": "İİ portal.acme.example.com"},
                                          {"portal.acme.example.com", "acme"}))
    assert kinds == ["fqdn", "term"]


def test_unicode_casefold_variants_flagged():
    assert [v.kind for v in verify({"v": "acK-rule"}, {"ack"})] == ["term"]
    assert [v.kind for v in verify({"v": "hoſt1"}, {"host1"})] == ["term"]
    assert [v.kind for v in verify({"v": "x Key.example.com"}, {"key.example.com"})] == ["fqdn"]


def test_differential_superset_of_ignorecase_reference():
    import re

    originals = [
        "acme", "ot", "key", "host1", "ack", "portal.acme.example.com", "web-01",
        "db.corp.example.com", "ab", "Site9", "kiosk", "fw_core", "x1y2", "sk",
        "mail.example.org", "scada", "plant7", "ids", "isp", "it",
    ]
    strings = [
        "acme", "ACME", "an acme rule", "acme-rule", "acme_rule", "acmeX", "Xacme", "other",
        "ot", "OT", "pivot", "ot2", "İ acme", "İİ portal.acme.example.com",
        "acK", "Key", "hoſt1", "KEY", "key.", "web-01-a", "web-011",
        "DB.Corp.Example.com", "db.corp.example.com.", "éacme", "acmeé", "K",
        "kioskK", "ſK", "aıs", "ıt IT it", "Plant7/x", "mail.example.org:25",
    ]

    def kind_of(o):
        return "fqdn" if ("." in o and re.search(r"[A-Za-z]", o)) else "term"

    for s in strings:
        expected = {
            kind_of(o)
            for o in originals
            if len(o) >= 2
            and re.search(r"(?<![A-Za-z0-9])" + re.escape(o) + r"(?![A-Za-z0-9])", s, re.IGNORECASE)
        }
        got = {v.kind for v in verify({"v": s}, set(originals))}
        assert expected <= got, (s, expected, got)


# --- final wave ---------------------------------------------------------------

def test_long_term_substring_flagged():
    for text in ("acmecorp-fw", "AcmeEnergy_Servers", "xACMEx", "cn=acme-admins"):
        assert [v.kind for v in verify({"v": text}, {"acme"})] == ["term"], text


def test_short_term_whole_token_only():
    assert verify({"v": "pivot BOT"}, {"ot"}) == []
    assert [v.kind for v in verify({"v": "x OT y"}, {"ot"})] == ["term"]


def test_ipv6_original_detected_case_insensitive_whole_token():
    o = {"fe80::1", "3fff:1f18:abcd::/48"}
    assert [v.kind for v in verify({"v": "see FE80::1 now"}, o)] == ["ip"]
    assert [v.kind for v in verify({"v": "net 3FFF:1F18:ABCD::"}, o)] == ["ip"]
    assert [v.kind for v in verify({"v": "h_fe80::1_x"}, o)] == ["ip"]
    assert verify({"v": "fe80::10 fe80::1:2 2001:db8::1"}, o) == []


def test_new_fqdn_original_flagged():
    assert [v.kind for v in verify({"v": "to SCADA01.plant.ca"}, {"scada01.plant.ca"})] == ["fqdn"]


# --- second fix pass ----------------------------------------------------------

def test_placeholder_spans_ignored_for_terms():
    o = {"host", "site", "test", "example"}
    doc = {"a": "host-001.example.test", "b": "SITE-1 and SITE-12", "c": "ORG PKG-1 ADOM-2",
           "d": "to 2001:db8::1f now"}
    assert verify(doc, o) == []
    assert [v.kind for v in verify({"v": "myhost-001.example.test"}, o)] == ["term"]
    assert [v.kind for v in verify({"v": "web host here"}, o)] == ["term"]
    assert [v.kind for v in verify({"v": "SITE-1 site"}, o)] == ["term"]


def test_placeholder_strip_keeps_ip_detection():
    assert [v.kind for v in verify({"v": "SITE-1 10.1.1.11"}, {"10.1.1.11"})] == ["ip"]
