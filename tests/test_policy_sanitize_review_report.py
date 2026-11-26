import json
import re
import stat

import pytest

from policy_sanitize.__main__ import main
from policy_sanitize.review_report import (
    DEFAULT_SCOPE_LIMITS,
    ReportError,
    render_review_html,
    validate_findings,
)
from policy_sanitize.store import map_back

RID = "0123456789abcdef"


def _f(**kw):
    base = {"severity": "High", "rule_seq": 1, "rule_id": 7, "rule_name": "ORG-web-out",
            "title": "Any service to the internet", "why": "Too broad.",
            "fix": "Restrict the service to HTTPS.", "unverified": False}
    base.update(kw)
    return base


def _doc(findings=None, **kw):
    d = {"run_id": RID, "summary": "Two issues.", "findings": findings or [_f()],
         "scope_limits": []}
    d.update(kw)
    return d


def test_escapes_every_dynamic_value_and_no_script():
    evil = '<script>alert(1)</script>" onmouseover="x'
    doc = _doc([_f(title=evil, why=evil, fix="Remove it " + evil, rule_name=evil,
                   rule_seq=evil, rule_id=evil)],
               summary=evil, generated_note=evil, scope_limits=[evil])
    out = render_review_html(doc)
    assert "<script" not in out.lower()
    assert '" onmouseover=' not in out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;&quot; onmouseover=&quot;x" in out
    assert "javascript" not in out.lower()


def test_csp_and_self_contained():
    out = render_review_html(_doc())
    assert ('<meta http-equiv="Content-Security-Policy" '
            "content=\"default-src 'none'; style-src 'unsafe-inline'\">") in out
    assert "<style>" in out
    assert not re.search(r"(src|href)\s*=", out, re.I)
    assert "http://" not in out and "https://" not in out


def test_severity_ordering_and_counts():
    fs = [_f(severity="Low", title="L1"), _f(severity="Critical", title="C1"),
          _f(severity="Medium", title="M1"), _f(severity="High", title="H1"),
          _f(severity="Critical", title="C2")]
    out = render_review_html(_doc(fs))
    pos = [out.index(t) for t in ("C1", "C2", "H1", "M1", "L1")]
    assert pos == sorted(pos)
    heads = [out.index(f'id="sev-{s.lower()}"') for s in ("Critical", "High", "Medium", "Low")]
    assert heads == sorted(heads)
    assert re.search(r"Critical</td><td>2<", out)
    assert re.search(r"Low</td><td>1<", out)


def test_unverified_label_banner_and_default_scope_limits():
    out = render_review_html(_doc([_f(unverified=True)], scope_limits=["custom limit"]))
    assert "unverified — confirm with the hygiene checks" in out
    assert ("Values in this report are sanitized stand-ins — use the local map-back "
            "step to restore real names. Do not paste the mapped report into Claude.") in out
    for s in DEFAULT_SCOPE_LIMITS:
        assert s in out
    assert "no group membership in the export; findings on group references are limited" in out
    assert "sanitized values are fake" in out
    assert "custom limit" in out
    out2 = render_review_html(_doc(scope_limits=[]))
    assert all(s in out2 for s in DEFAULT_SCOPE_LIMITS)
    del_doc = _doc()
    del del_doc["scope_limits"]
    assert all(s in render_review_html(del_doc) for s in DEFAULT_SCOPE_LIMITS)


@pytest.mark.parametrize("doc,code", [
    ([], "not_object"),
    (_doc(run_id="xyz"), "run_id"),
    (_doc(run_id="0123456789ABCDEF"), "run_id"),
    (_doc(summary=5), "summary"),
    (_doc([_f(severity="Severe")]), "severity"),
    (_doc([_f(title="x" * 201)]), "too_long"),
    (_doc([_f(why="x" * 2001)]), "too_long"),
    (_doc([_f(fix="x" * 2001)]), "too_long"),
    (_doc([_f(title=3)]), "field_type"),
    (_doc([_f(unverified="yes")]), "field_type"),
    (_doc([_f(rule_seq=True)]), "field_type"),
    (_doc([_f()] * 501), "too_many"),
    (_doc(findings="x"), "findings"),
    (_doc(scope_limits=[1]), "scope_limits"),
    (_doc([_f(fix="Do this:\nconfig firewall policy\n    edit 7\n        set action deny\n    next\nend")]),
     "cli_not_allowed"),
    (_doc([_f(fix="set action deny")]), "cli_not_allowed"),
    (_doc([_f(fix="Then:\nend")]), "cli_not_allowed"),
])
def test_validate_rejects(doc, code):
    with pytest.raises(ReportError) as e:
        validate_findings(doc)
    assert e.value.code == code
    assert "x" * 50 not in str(e.value) and "action deny" not in str(e.value)


def test_validate_accepts_prose_fix():
    validate_findings(_doc([_f(fix="Set the action to deny and enable logging. The end.")]))


def _write(tmp_path, doc):
    p = tmp_path / "in.findings.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def test_cli_render_review_end_to_end(tmp_path, capsys):
    inp = _write(tmp_path, _doc([_f(severity="Critical", unverified=True)]))
    out_dir = tmp_path / "pr" / "nested"
    rc = main(["render-review", "--input", str(inp), "--out-dir", str(out_dir)])
    cap = capsys.readouterr()
    assert rc == 0
    out = out_dir / f"policy-review-{RID}.html"
    assert cap.out == f"report: {out}\n"
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert [p.name for p in out_dir.iterdir()] == [out.name]  # no temp files left
    assert "unverified — confirm with the hygiene checks" in out.read_text(encoding="utf-8")


def test_cli_render_review_errors_do_not_echo(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('{"run_id": "secret-10.9.9.9", ', encoding="utf-8")
    assert main(["render-review", "--input", str(bad), "--out-dir", str(tmp_path / "o")]) == 2
    inp = _write(tmp_path, _doc([_f(fix="set action deny secret-10.9.9.9")]))
    assert main(["render-review", "--input", str(inp), "--out-dir", str(tmp_path / "o")]) == 2
    cap = capsys.readouterr()
    blob = cap.out + cap.err
    assert "secret" not in blob and "10.9.9.9" not in blob and "Traceback" not in blob
    assert "cli_not_allowed" in cap.err and "ReportError" in cap.err
    assert not (tmp_path / "o").exists() or not list((tmp_path / "o").iterdir())
    assert main(["render-review", "--input", str(tmp_path / "missing.json"),
                 "--out-dir", str(tmp_path / "o")]) == 2


def test_cli_render_review_atomic_on_replace_failure(tmp_path, capsys, monkeypatch):
    import os
    inp = _write(tmp_path, _doc())
    out_dir = tmp_path / "o"

    def boom(src, dst):
        raise OSError("nope")
    monkeypatch.setattr(os, "replace", boom)
    assert main(["render-review", "--input", str(inp), "--out-dir", str(out_dir)]) == 2
    assert list(out_dir.iterdir()) == []


def test_map_back_on_html_report():
    fake_ip, label = "240.9.8.7", "PKG-1"
    html_doc = render_review_html(_doc([_f(title=f"Rule in {label} allows {fake_ip}",
                                           why=f"Source {fake_ip}/32 is broad.")]))
    mapping = {"ips": {"10.1.1.5": fake_ip}, "labels": {"PKG-1": "acme_pkg"}}
    out = map_back(html_doc, mapping)
    assert "Rule in acme_pkg allows 10.1.1.5" in out
    assert "Source 10.1.1.5/32 is broad." in out
    assert fake_ip not in out and "PKG-1" not in out
    assert out.count("<table") == html_doc.count("<table")
    assert out.startswith("<!DOCTYPE html>") and out.rstrip().endswith("</html>")
