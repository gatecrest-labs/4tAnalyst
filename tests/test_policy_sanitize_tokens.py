from policy_sanitize.tokens import find_ip_tokens, is_mask


def test_finds_dotted_ip_inside_name():
    toks = find_ip_tokens("ns-10.20.30.41")
    assert len(toks) == 1
    assert toks[0].octets == (10, 20, 30, 41)
    assert toks[0].text == "10.20.30.41"


def test_whole_token_only():
    toks = find_ip_tokens("10.1.1.12")
    assert [t.octets for t in toks] == [(10, 1, 1, 12)]
    assert find_ip_tokens("110.1.1.1")[0].octets == (110, 1, 1, 1)


def test_cidr_and_underscore_prefix():
    assert find_ip_tokens("x-10.99.7.0_24_global")[0].prefix == 24
    assert find_ip_tokens("10.0.0.0/8")[0].prefix == 8


def test_hyphen_and_underscore_spellings():
    a = find_ip_tokens("h-10-20-30-41")
    b = find_ip_tokens("h_10_20_30_41")
    assert len(a) == 1 and a[0].sep == "-" and a[0].octets == (10, 20, 30, 41)
    assert len(b) == 1 and b[0].sep == "_" and b[0].octets == (10, 20, 30, 41)


def test_masks_and_zero_are_exempt():
    for m in [(255, 255, 255, 0), (0, 0, 0, 255), (0, 0, 0, 0), (255, 255, 255, 255)]:
        assert is_mask(m)
    assert not is_mask((10, 1, 1, 1))
    assert len(find_ip_tokens("mask 255.255.255.0")) == 1


def test_invalid_octets_ignored():
    assert find_ip_tokens("999.1.1.1") == []
