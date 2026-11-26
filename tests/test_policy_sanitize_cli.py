import json
import re
import stat
from pathlib import Path

import pytest

from policy_sanitize.__main__ import main

FIXTURE = Path(__file__).parent / "fixtures" / "policy_export_synthetic.json"


@pytest.fixture
def env(tmp_path, monkeypatch):
    mapdir = tmp_path / "maps"
    monkeypatch.setenv("FW_ANALYST_SANITIZE_DIR", str(mapdir))
    terms = tmp_path / "terms.txt"
    terms.write_text("acme\n", encoding="utf-8")
    return tmp_path, mapdir, terms


def _run_id(out):
    return re.search(r"run-id: ([0-9a-f]{16})", out).group(1)


def test_end_to_end_fixture(env, capsys):
    tmp, mapdir, terms = env
    out_dir = tmp / "out"
    rc = main(["sanitize", "--input", str(FIXTURE), "--out-dir", str(out_dir),
               "--terms", str(terms)])
    cap = capsys.readouterr()
    assert rc == 0
    rid = _run_id(cap.out)
    outf = out_dir / f"sanitized-{rid}-1.json"
    assert outf.is_file()
    text = outf.read_text(encoding="utf-8")
    for orig in ("10.1.1.11", "10.2.3.0", "203.0.113.7", "portal.acme.example.com",
                 "acme", "Acme", "acme_pkg_synthetic"):
        assert orig not in text
    assert "verifier: clean" in cap.out
    assert "map: stored (not shown)" in cap.out
    assert str(mapdir) not in cap.out and "10.1.1.11" not in cap.out
    mp = mapdir / f"{rid}.map.json"
    assert stat.S_IMODE(mp.stat().st_mode) == 0o600


def test_missing_terms_fails_closed_and_no_terms_warns(env, capsys, monkeypatch):
    tmp, mapdir, terms = env
    monkeypatch.setenv("HOME", str(tmp / "nohome"))
    out_dir = tmp / "out"
    rc = main(["sanitize", "--input", str(FIXTURE), "--out-dir", str(out_dir),
               "--terms", str(tmp / "missing.txt")])
    assert rc == 2
    assert not out_dir.exists() or not list(out_dir.iterdir())
    capsys.readouterr()
    rc = main(["sanitize", "--input", str(FIXTURE), "--out-dir", str(out_dir),
               "--no-terms"])
    cap = capsys.readouterr()
    assert rc == 0
    assert "WARNING" in cap.err


def test_bad_json_message_has_no_contents(env, capsys):
    tmp, _, terms = env
    bad = tmp / "bad.json"
    bad.write_text('{"secret-10.9.9.9": ', encoding="utf-8")
    rc = main(["sanitize", "--input", str(bad), "--out-dir", str(tmp / "out"),
               "--terms", str(terms)])
    cap = capsys.readouterr()
    assert rc == 2
    blob = cap.out + cap.err
    assert "secret" not in blob and "10.9.9.9" not in blob and "bad.json" not in blob


def test_strict_blocks_on_unmatched(env, capsys):
    tmp, mapdir, terms = env
    doc = json.loads(FIXTURE.read_text())
    doc["rules"][0]["name"] = "abc123xyz"
    inp = tmp / "in.json"
    inp.write_text(json.dumps(doc))
    out_dir = tmp / "out"
    rc = main(["sanitize", "--input", str(inp), "--out-dir", str(out_dir),
               "--terms", str(terms), "--strict"])
    assert rc == 4
    assert not out_dir.exists() or not list(out_dir.iterdir())
    assert not mapdir.exists() or not list(mapdir.iterdir())


def test_map_back_roundtrip(env, capsys):
    tmp, _, terms = env
    out_dir = tmp / "out"
    assert main(["sanitize", "--input", str(FIXTURE), "--out-dir", str(out_dir),
                 "--terms", str(terms)]) == 0
    rid = _run_id(capsys.readouterr().out)
    sanitized = json.loads((out_dir / f"sanitized-{rid}-1.json").read_text())
    fake = sanitized["rules"][0]["srcaddr"][0]
    ipfake = re.search(r"\d+\.\d+\.\d+\.\d+", fake).group(0)
    src = tmp / "note.txt"
    src.write_text(f"see host {ipfake} now", encoding="utf-8")
    dst = tmp / "sub" / "restored.txt"
    rc = main(["map-back", "--run-id", rid, "--input", str(src), "--output", str(dst)])
    assert rc == 0
    assert "10.1.1.11" in dst.read_text()
    assert "written:" in capsys.readouterr().out


def test_two_inputs_share_map(env, capsys):
    tmp, _, terms = env
    a, b = tmp / "a.json", tmp / "b.json"
    for p, name in ((a, "r1"), (b, "r2")):
        p.write_text(json.dumps({"rules": [{"name": name, "srcaddr": ["172.16.5.9"]}]}))
    out_dir = tmp / "out"
    rc = main(["sanitize", "--input", str(a), "--input", str(b),
               "--out-dir", str(out_dir), "--terms", str(terms)])
    assert rc == 0
    rid = _run_id(capsys.readouterr().out)
    o1 = json.loads((out_dir / f"sanitized-{rid}-1.json").read_text())
    o2 = json.loads((out_dir / f"sanitized-{rid}-2.json").read_text())
    assert o1["rules"][0]["srcaddr"] == o2["rules"][0]["srcaddr"]
    assert o1["rules"][0]["srcaddr"] != ["172.16.5.9"]


def test_purge(env, capsys):
    rc = main(["purge"])
    assert rc == 0
    assert "purged: 0" in capsys.readouterr().out


def _empty(d):
    return not d.exists() or not list(d.iterdir())


@pytest.mark.parametrize("exc", [ValueError("secret-10.9.9.9"), RecursionError()])
def test_top_level_guard(env, capsys, monkeypatch, exc):
    tmp, mapdir, terms = env
    import policy_sanitize.__main__ as m

    def boom(*a, **k):
        raise exc
    monkeypatch.setattr(m, "sanitize_documents", boom)
    out_dir = tmp / "out"
    rc = main(["sanitize", "--input", str(FIXTURE), "--out-dir", str(out_dir),
               "--terms", str(terms)])
    cap = capsys.readouterr()
    blob = cap.out + cap.err
    assert rc == 2
    assert "secret" not in blob and "10.9.9.9" not in blob and "Traceback" not in blob
    assert _empty(out_dir) and _empty(mapdir)


def test_atomic_outputs_cleaned_on_failure(env, capsys, monkeypatch):
    tmp, mapdir, terms = env
    a, b = tmp / "a.json", tmp / "b.json"
    for p in (a, b):
        p.write_text(json.dumps({"rules": [{"name": "r", "srcaddr": ["172.16.5.9"]}]}))
    import os
    real = os.replace
    calls = []

    def flaky(src, dst):
        calls.append(1)
        if len(calls) == 2:
            raise OSError("nope")
        return real(src, dst)
    monkeypatch.setattr(os, "replace", flaky)
    out_dir = tmp / "out"
    rc = main(["sanitize", "--input", str(a), "--input", str(b),
               "--out-dir", str(out_dir), "--terms", str(terms)])
    assert rc == 2
    assert list(out_dir.iterdir()) == []


@pytest.mark.parametrize("argv", [
    ["sanitize", "--input", "secret-10.9.9.9.json", "--bogus", "x"],
    ["nonsense", "10.9.9.9"],
])
def test_argparse_errors_do_not_echo(env, capsys, argv):
    rc = main(argv)
    cap = capsys.readouterr()
    assert rc == 2
    blob = cap.out + cap.err
    assert "secret" not in blob and "10.9.9.9" not in blob and "bogus" not in blob


def test_map_back_output_location(env, capsys):
    tmp, _, terms = env
    out_dir = tmp / "out"
    assert main(["sanitize", "--input", str(FIXTURE), "--out-dir", str(out_dir),
                 "--terms", str(terms)]) == 0
    rid = _run_id(capsys.readouterr().out)
    src = tmp / "n.txt"
    src.write_text("x")
    bad = tmp / "OneDrive-x" / "CloudStorage" / "a" / "o.txt"
    assert main(["map-back", "--run-id", rid, "--input", str(src),
                 "--output", str(bad)]) == 2
    assert "output location not allowed (MapError)" in capsys.readouterr().err
    assert not bad.parent.exists()
    good = tmp / "fine" / "o.txt"
    assert main(["map-back", "--run-id", rid, "--input", str(src),
                 "--output", str(good)]) == 0
    assert stat.S_IMODE(good.stat().st_mode) == 0o600


def test_exit3_mocked_verifier(env, capsys, monkeypatch):
    tmp, mapdir, terms = env
    import policy_sanitize.__main__ as m
    from policy_sanitize.verify import Violation
    monkeypatch.setattr(m, "verify", lambda d, o: [Violation("$.rules[0].name", "ip")])
    out_dir = tmp / "out"
    rc = main(["sanitize", "--input", str(FIXTURE), "--out-dir", str(out_dir),
               "--terms", str(terms)])
    cap = capsys.readouterr()
    assert rc == 3
    assert _empty(out_dir) and _empty(mapdir)
    assert "doc1.rules[0].name:ip" in cap.err
    assert "10.1.1.11" not in cap.out + cap.err


def test_exit3_real_leak(env, capsys, monkeypatch):
    tmp, mapdir, terms = env
    import policy_sanitize.__main__ as m
    real = m.sanitize_documents

    def leaky(docs, sc):
        r = real(docs, sc)
        r.documents["doc1"]["leak"] = "see acme and 10.1.1.11"
        return r
    monkeypatch.setattr(m, "sanitize_documents", leaky)
    out_dir = tmp / "out"
    rc = main(["sanitize", "--input", str(FIXTURE), "--out-dir", str(out_dir),
               "--terms", str(terms)])
    cap = capsys.readouterr()
    assert rc == 3
    assert _empty(out_dir) and _empty(mapdir)
    assert "doc1.leak:ip" in cap.err and "doc1.leak:term" in cap.err
    assert "10.1.1.11" not in cap.out + cap.err


def test_map_write_failure(env, capsys, monkeypatch):
    tmp, mapdir, terms = env
    import policy_sanitize.__main__ as m
    from policy_sanitize.store import MapError

    def bad(*a, **k):
        raise MapError("x")
    monkeypatch.setattr(m, "write_map", bad)
    out_dir = tmp / "out"
    rc = main(["sanitize", "--input", str(FIXTURE), "--out-dir", str(out_dir),
               "--terms", str(terms)])
    assert rc == 2
    assert _empty(out_dir)


@pytest.mark.parametrize("name", ["fw01", "LABX-DC01"])
def test_strict_blocks_short_device_names(env, capsys, name):
    tmp, mapdir, terms = env
    doc = json.loads(FIXTURE.read_text())
    doc["rules"][0]["name"] = name
    inp = tmp / "in.json"
    inp.write_text(json.dumps(doc))
    out_dir = tmp / "out"
    rc = main(["sanitize", "--input", str(inp), "--out-dir", str(out_dir),
               "--terms", str(terms), "--strict"])
    assert rc == 4
    assert _empty(out_dir) and _empty(mapdir)


def test_lone_surrogate_in_second_doc_cleans_everything(env, capsys):
    tmp, mapdir, terms = env
    a, b = tmp / "a.json", tmp / "b.json"
    a.write_text(json.dumps({"rules": [{"name": "r1", "srcaddr": ["172.16.5.9"]}]}))
    b.write_text('{"rules": [{"name": "r2\\ud800", "srcaddr": ["172.16.5.10"]}]}')
    out_dir = tmp / "out"
    rc = main(["sanitize", "--input", str(a), "--input", str(b),
               "--out-dir", str(out_dir), "--terms", str(terms)])
    cap = capsys.readouterr()
    assert rc == 2
    assert "Traceback" not in cap.err
    assert _empty(out_dir) and _empty(mapdir)


def test_write_loop_non_oserror_unlinks_outputs_and_map(env, capsys, monkeypatch):
    tmp, mapdir, terms = env
    import policy_sanitize.__main__ as m
    a, b = tmp / "a.json", tmp / "b.json"
    for p in (a, b):
        p.write_text(json.dumps({"rules": [{"name": "r", "srcaddr": ["172.16.5.9"]}]}))
    real = m._atomic_write
    calls = []

    def flaky(path, data):
        calls.append(1)
        if len(calls) == 2:
            raise ValueError("secret-10.9.9.9")
        return real(path, data)
    monkeypatch.setattr(m, "_atomic_write", flaky)
    out_dir = tmp / "out"
    rc = main(["sanitize", "--input", str(a), "--input", str(b),
               "--out-dir", str(out_dir), "--terms", str(terms)])
    cap = capsys.readouterr()
    assert rc == 2
    assert "secret" not in cap.err
    assert _empty(out_dir) and _empty(mapdir)


# --- second fix pass ----------------------------------------------------------
REALISTIC = Path(__file__).parent / "fixtures" / "policy_export_realistic_synthetic.json"


def test_realistic_fixture_strict_passes(env, capsys):
    tmp, mapdir, terms = env
    out_dir = tmp / "out"
    rc = main(["sanitize", "--input", str(REALISTIC), "--out-dir", str(out_dir),
               "--terms", str(terms), "--strict"])
    cap = capsys.readouterr()
    assert rc == 0, cap.err
    assert "unmatched-identifiers: 0" in cap.out
    rid = _run_id(cap.out)
    text = (out_dir / f"sanitized-{rid}-1.json").read_text()
    for orig in ("10.1.1.7", "10.1.1.1", "10.1.1.0", "acme", "172.16.5"):
        assert orig not in text
    out = json.loads(text)
    assert out["rules"][0]["srcintf"] == ["port1"]


def test_realistic_fixture_name_device_still_strict_fails(env, capsys):
    tmp, mapdir, terms = env
    doc = json.loads(REALISTIC.read_text())
    doc["rules"][0]["name"] = "fw01-allow"
    inp = tmp / "in.json"
    inp.write_text(json.dumps(doc))
    rc = main(["sanitize", "--input", str(inp), "--out-dir", str(tmp / "out"),
               "--terms", str(terms), "--strict"])
    assert rc == 4


def test_intf_values_not_counted_but_scrubbed(env, capsys):
    tmp, mapdir, terms = env
    doc = json.loads(REALISTIC.read_text())
    doc["rules"][0]["srcintf"] = ["zz9plural", "acme-ipsec-10.1.1.5"]
    inp = tmp / "in.json"
    inp.write_text(json.dumps(doc))
    out_dir = tmp / "out"
    rc = main(["sanitize", "--input", str(inp), "--out-dir", str(out_dir),
               "--terms", str(terms), "--strict"])
    cap = capsys.readouterr()
    assert rc == 0, cap.err
    text = (out_dir / f"sanitized-{_run_id(cap.out)}-1.json").read_text()
    assert "acme" not in text and "10.1.1.5" not in text


def test_host_with_prefix_and_network_round_trip(env, capsys):
    tmp, mapdir, terms = env
    doc = {"rules": [{"name": "r", "srcaddr": ["10.1.1.0/24", "10.1.1.7/24",
                                               "H_10.1.1.7_22", "H_10.1.1.9_22"]}]}
    inp = tmp / "in.json"
    inp.write_text(json.dumps(doc))
    out_dir = tmp / "out"
    rc = main(["sanitize", "--input", str(inp), "--out-dir", str(out_dir),
               "--terms", str(terms)])
    cap = capsys.readouterr()
    assert rc == 0, cap.err
    rid = _run_id(cap.out)
    fakes = json.loads((out_dir / f"sanitized-{rid}-1.json").read_text())["rules"][0]["srcaddr"]
    assert len(set(fakes)) == 4
    src = tmp / "n.txt"
    src.write_text(" | ".join(fakes), encoding="utf-8")
    dst = tmp / "back" / "n.txt"
    assert main(["map-back", "--run-id", rid, "--input", str(src), "--output", str(dst)]) == 0
    assert dst.read_text() == " | ".join(doc["rules"][0]["srcaddr"])


def test_terms_matching_placeholders_do_not_trip_verifier(env, capsys):
    tmp, mapdir, _ = env
    terms = tmp / "t2.txt"
    terms.write_text("acme\nhost\nsite\nbeta\n", encoding="utf-8")
    doc = json.loads(REALISTIC.read_text())
    doc["rules"][1]["name"] = "beta-web"
    inp = tmp / "in.json"
    inp.write_text(json.dumps(doc))
    out_dir = tmp / "out"
    rc = main(["sanitize", "--input", str(inp), "--out-dir", str(out_dir),
               "--terms", str(terms)])
    cap = capsys.readouterr()
    assert rc == 0, cap.err
    text = (out_dir / f"sanitized-{_run_id(cap.out)}-1.json").read_text()
    assert "host-001.example.test" in text and "SITE-" in text



def test_realistic_fixture_many_keys(env, capsys, monkeypatch):
    import secrets as real_secrets

    import policy_sanitize.__main__ as m
    from policy_sanitize.ipmap import IpMapper
    tmp, mapdir, terms = env
    keys = [real_secrets.token_bytes(32) for _ in range(50)]
    for i, key in enumerate(keys):
        # fix the mapper key only (run ids still come from the real secrets)
        monkeypatch.setattr(m, "IpMapper", lambda _ignored, _k=key: IpMapper(_k))
        out_dir = tmp / f"out{i}"
        rc = main(["sanitize", "--input", str(REALISTIC), "--out-dir", str(out_dir),
                   "--terms", str(terms), "--strict"])
        cap = capsys.readouterr()
        assert rc == 0, (i, cap.err)


def test_internal_collision_assertion(env, capsys, monkeypatch):
    import policy_sanitize.__main__ as m
    from policy_sanitize.ipmap import IpMapper
    tmp, mapdir, terms = env

    class Same(IpMapper):
        def map_ip(self, octets):
            return (240, 9, 9, 9)
    monkeypatch.setattr(m, "IpMapper", Same)
    inp = tmp / "in.json"
    inp.write_text(json.dumps({"rules": [{"name": "r", "srcaddr": ["10.1.1.5", "10.1.1.6"]}]}))
    out_dir = tmp / "out"
    rc = main(["sanitize", "--input", str(inp), "--out-dir", str(out_dir),
               "--terms", str(terms)])
    cap = capsys.readouterr()
    assert rc == 2
    assert "error: collision (SanitizeError) code=collision" in cap.err
    blob = cap.out + cap.err
    assert "10.1.1.5" not in blob and "10.1.1.6" not in blob and "240.9.9.9" not in blob
    assert _empty(out_dir) and _empty(mapdir)
