import json
import os
import stat
import time

import pytest

from policy_sanitize import store
from policy_sanitize.store import MapError, map_back, purge_expired, read_map, write_map

RID = "0123456789abcdef"
M = {"ips": {"10.1.1.1": "240.0.0.9"}, "fqdns": {}, "terms": {}, "labels": {}}


def _age(path, days):
    t = time.time() - days * 86400
    os.utime(path, (t, t))


def _backdate(path, days):
    doc = json.loads(path.read_text())
    doc["created"] = time.time() - days * 86400
    path.write_text(json.dumps(doc))
    _age(path, days)


def test_map_file_mode_0600(tmp_path):
    p = write_map(RID, M, map_dir=tmp_path / "m")
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert stat.S_IMODE(p.parent.stat().st_mode) == 0o700
    doc = read_map(RID, map_dir=tmp_path / "m")
    assert doc["version"] == 1 and doc["ips"] == M["ips"]


def test_refuses_synced_and_repo_paths(tmp_path):
    with pytest.raises(MapError):
        write_map(RID, M, map_dir=tmp_path / "OneDrive-x" / "CloudStorage" / "a")
    with pytest.raises(MapError):
        write_map(RID, M, map_dir=store._repo_root() / "out")


def test_bad_run_id(tmp_path):
    with pytest.raises(MapError):
        write_map("../evil", M, map_dir=tmp_path)
    with pytest.raises(MapError):
        read_map("../evil", map_dir=tmp_path)


def test_read_missing_and_expired(tmp_path):
    with pytest.raises(MapError):
        read_map(RID, map_dir=tmp_path)
    p = write_map(RID, M, map_dir=tmp_path)
    _backdate(p, 31)
    with pytest.raises(MapError) as e:
        read_map(RID, map_dir=tmp_path)
    assert RID in str(e.value) and "240.0.0.9" not in str(e.value)


def test_map_back_longest_first():
    m = {"ips": {"10.1.1.1": "240.0.0.9", "10.1.1.12": "240.0.0.90"}}
    assert map_back("see 240.0.0.90 and 240.0.0.9", m) == "see 10.1.1.12 and 10.1.1.1"


def test_map_back_boundary():
    m = {"ips": {"10.1.1.1": "240.0.0.9"}}
    assert map_back("240.0.0.95 x1.240.0.0.9 240.0.0.9.4", m) == "240.0.0.95 x1.240.0.0.9 240.0.0.9.4"
    assert map_back("(240.0.0.9)", m) == "(10.1.1.1)"


def test_map_back_fqdn_terms_labels_single_pass():
    m = {
        "ips": {},
        "fqdns": {"portal.acme.example.com": "host-001.example.test"},
        "terms": {"acme": "ORG", "Acme": "ORG", "corp": "T1"},
        "labels": {"PKG-1": "acme_pkg"},
    }
    out = map_back("host-001.example.test ORG T1 PKG-1", m)
    assert out == "portal.acme.example.com ORG corp acme_pkg"


def test_purge_expired_counts(tmp_path):
    old = write_map("aaaaaaaaaaaaaaaa", M, map_dir=tmp_path)
    write_map("bbbbbbbbbbbbbbbb", M, map_dir=tmp_path)
    other = tmp_path / "keep.txt"
    other.write_text("x")
    _backdate(old, 40)
    _age(other, 40)
    assert purge_expired(tmp_path) == 1
    assert other.exists() and not old.exists()


def test_utime_only_backdate_expires(tmp_path):
    p = write_map(RID, M, map_dir=tmp_path)
    _age(p, 31)  # created untouched
    with pytest.raises(MapError):
        read_map(RID, map_dir=tmp_path)
    assert purge_expired(tmp_path) == 1 and not p.exists()


def test_created_only_backdate_expires(tmp_path):
    p = write_map(RID, M, map_dir=tmp_path)
    doc = json.loads(p.read_text())
    doc["created"] = time.time() - 31 * 86400
    p.write_text(json.dumps(doc))  # mtime fresh
    with pytest.raises(MapError):
        read_map(RID, map_dir=tmp_path)
    assert purge_expired(tmp_path) == 1


def test_map_back_dotted_placeholders_and_ip_regression():
    m = {"ips": {"10.1.1.1": "240.0.0.9"}, "labels": {"PKG-1": "acme_pkg"},
         "terms": {"acme": "SITE-1"}}
    assert map_back("see PKG-1.2 and SITE-1.5", m) == "see acme_pkg.2 and acme.5"
    assert map_back("240.0.0.95 1.240.0.0.9", m) == "240.0.0.95 1.240.0.0.9"


def test_map_back_ipv6_fakes():
    m = {"ips": {"fe80::1": "2001:db8::1", "fd00::/48": "2001:db8::2/48",
                 "fd00::7": "2001:db8::10"}}
    out = map_back("a 2001:db8::1 b 2001:db8::2/48 c 2001:db8::10 d 2001:db8::1:5", m)
    assert out == "a fe80::1 b fd00::/48 c fd00::7 d 2001:db8::1:5"


def test_ipv6_round_trip():
    from policy_sanitize.ipmap import IpMapper
    from policy_sanitize.scrub import Scrubber
    s = Scrubber(IpMapper(b"k" * 32), [])
    src = "allow fe80::1 to 3fff:1f18::/32 and FE80::1"
    out = s.text(src)
    assert "fe80" not in out.lower() and "3fff" not in out
    # case variants share one fake, so case is not restored (accepted)
    assert map_back(out, {"ips": s.ips}).lower() == src.lower()


def test_no_chmod_on_preexisting_dir(tmp_path):
    d = tmp_path / "pre"
    d.mkdir(mode=0o755)
    os.chmod(d, 0o755)
    write_map(RID, M, map_dir=d)
    assert stat.S_IMODE(d.stat().st_mode) == 0o755


def test_created_dirs_are_0700(tmp_path):
    d = tmp_path / "a" / "b"
    write_map(RID, M, map_dir=d)
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    assert stat.S_IMODE(d.parent.stat().st_mode) == 0o700


@pytest.mark.parametrize("part", ["Mobile Documents", "Dropbox", "Google Drive",
                                  "GoogleDrive", "iCloud", "iCloudDrive", "OneDrive - x",
                                  "CloudStorage", "my-dropbox-sync"])
def test_more_synced_locations_refused(tmp_path, part):
    with pytest.raises(MapError):
        write_map(RID, M, map_dir=tmp_path / part / "m")


@pytest.mark.parametrize("doc", [
    [], "x", {"ips": {}}, {"version": 1, "ips": []}, {"version": 1, "terms": "x"},
    {"version": 1, "labels": {"PKG-1": "a"}, "fqdns": None},
])
def test_read_map_validates_shape(tmp_path, doc):
    p = tmp_path / f"{RID}.map.json"
    p.write_text(json.dumps(doc))
    with pytest.raises(MapError):
        read_map(RID, map_dir=tmp_path)


def test_read_map_defaults_missing_sections(tmp_path):
    p = tmp_path / f"{RID}.map.json"
    p.write_text(json.dumps({"version": 1, "created": time.time(), "ips": {"a": "b"}}))
    doc = read_map(RID, map_dir=tmp_path)
    assert doc["fqdns"] == {} and doc["terms"] == {} and doc["labels"] == {}
    assert doc["ips"] == {"a": "b"}


def test_delete_map(tmp_path):
    p = write_map(RID, M, map_dir=tmp_path)
    store.delete_map(RID, map_dir=tmp_path)
    assert not p.exists()
    store.delete_map(RID, map_dir=tmp_path)  # missing is fine
