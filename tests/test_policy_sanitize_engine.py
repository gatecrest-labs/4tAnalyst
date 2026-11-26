import copy
import json
import pathlib

import pytest

from policy_sanitize.engine import SanitizeError, SanitizeResult, sanitize_documents
from policy_sanitize.ipmap import IpMapper
from policy_sanitize.scrub import Scrubber

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "policy_export_synthetic.json"


def _scrubber():
    return Scrubber(IpMapper(b"k" * 32), [("acme", None)])


def test_fixture_sanitizes_schema_intact():
    doc = json.load(open(FIXTURE))
    orig = copy.deepcopy(doc)
    res = sanitize_documents({"policy": doc}, _scrubber())
    assert isinstance(res, SanitizeResult)
    assert doc == orig  # input not mutated
    out = res.documents["policy"]
    assert out["package"] == "PKG-1"
    assert out["adom"] == "ADOM-1"
    assert out["generated"] == "1970-01-01T00:00:00Z"
    assert res.labels == {"PKG-1": orig["package"], "ADOM-1": orig["adom"]}
    assert len(out["rules"]) == len(orig["rules"])
    for o, s in zip(orig["rules"], out["rules"]):
        assert list(o.keys()) == list(s.keys())
        assert s["seq"] == o["seq"] and s["id"] == o["id"]
        assert s["comment"] == ""
    dumped = json.dumps(out)
    for ip in ("10.1.1.11", "10.2.3.0", "203.0.113.7"):
        assert ip not in dumped
    assert "acme-allow" not in dumped
    assert "acme" not in dumped.lower()
    assert res.name_map


def test_nonstring_values_pass_through():
    doc = {"rules": [{"seq": 1, "comment": None, "srcaddr": [], "x": True, "y": 0}]}
    res = sanitize_documents({"d": doc}, _scrubber())
    r = res.documents["d"]["rules"][0]
    assert r["seq"] == 1 and r["srcaddr"] == [] and r["x"] is True and r["y"] == 0
    assert r["comment"] == ""


def test_empty_and_missing():
    sanitize_documents({"a": {"rules": []}, "b": {}}, _scrubber())


def test_bare_list_and_string_documents():
    res = sanitize_documents({"a": ["10.1.1.5", 3], "b": "10.1.1.5"}, _scrubber())
    assert "10.1.1.5" not in json.dumps(res.documents)


def test_keys_are_scrubbed():
    res = sanitize_documents({"d": {"host 10.1.1.5": 1}}, _scrubber())
    (k,) = res.documents["d"].keys()
    assert "10.1.1.5" not in k


def test_labels_across_documents():
    docs = {
        "a": {"package": "p1", "adom": "x"},
        "b": {"package": "p2", "adom": "x"},
        "c": {"package": "p1"},
    }
    res = sanitize_documents(docs, _scrubber())
    assert res.documents["a"]["package"] == "PKG-1"
    assert res.documents["b"]["package"] == "PKG-2"
    assert res.documents["c"]["package"] == "PKG-1"
    assert res.documents["b"]["adom"] == "ADOM-1"
    assert res.labels == {"PKG-1": "p1", "PKG-2": "p2", "ADOM-1": "x"}


def test_name_collision_raises():
    doc = {"rules": [
        {"srcaddr": ["acme-web"], "dstaddr": []},
        {"srcaddr": ["ACME-web"], "dstaddr": []},
    ]}
    with pytest.raises(SanitizeError) as ei:
        sanitize_documents({"doc1": doc}, _scrubber())
    e = ei.value
    assert e.code == "collision"
    assert "documents.doc1.rules[0].srcaddr[0]" in e.paths
    assert "documents.doc1.rules[1].srcaddr[0]" in e.paths
    msg = str(e)
    assert "collision" in msg and "documents.doc1.rules[1].srcaddr[0]" in msg
    assert "web" not in msg.lower() and "acme" not in msg.lower()


def test_same_original_not_a_collision():
    doc = {"rules": [{"srcaddr": ["acme-web"]}, {"srcaddr": ["acme-web"]}]}
    sanitize_documents({"d": doc}, _scrubber())


def test_key_collision_raises_with_dict_path_only():
    doc = {"filters": {"acme-a": 1, "ACME-a": 2}}
    with pytest.raises(SanitizeError) as ei:
        sanitize_documents({"d": doc}, _scrubber())
    e = ei.value
    assert e.code == "collision"
    assert e.paths == ["documents.d.filters"]
    msg = str(e).lower()
    assert "acme" not in msg and "-a" not in msg


def test_key_collision_top_level_and_rule_dict():
    with pytest.raises(SanitizeError) as ei:
        sanitize_documents({"d": {"acme-x": 1, "ACME-x": 2}}, _scrubber())
    assert ei.value.paths == ["documents.d"]
    with pytest.raises(SanitizeError) as ei:
        sanitize_documents({"d": {"rules": [{"acme-x": 1, "ACME-x": 2}]}}, _scrubber())
    assert ei.value.paths == ["documents.d.rules[0]"]
