import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hygiene.models import FixOption, HygieneResult, PolicyFix
from hygiene.report import render_html


def test_render_html_includes_device_pkg_date_banner():
    result = HygieneResult(device="FW1", adom="OT-ADOM", pkg="pkg1",
                            generated_at="2026-09-03T12:00:00+00:00", fixes=[], stale_findings=[])
    html = render_html(result)
    assert "FW1" in html
    assert "pkg1" in html
    assert "2026-09-03" in html


def test_render_html_renders_finding_cards_with_cli():
    fix = PolicyFix(policy_id="1", policy_name="P1", check="unhit", options=[
        FixOption("A", "Disable", "disable it", ["config firewall policy\n    edit 1\nend"], None),
    ])
    result = HygieneResult(device="FW1", adom="OT-ADOM", pkg="pkg1",
                            generated_at="2026-09-03T12:00:00+00:00", fixes=[fix], stale_findings=[])
    html = render_html(result)
    assert "P1" in html
    assert "config firewall policy" in html


def test_render_html_flags_irreversible_option():
    fix = PolicyFix(policy_id="1", policy_name="P1", check="disabled", options=[
        FixOption("A", "Delete", "delete it", ["config firewall policy\n    delete 1\nend"], None, irreversible=True),
    ])
    result = HygieneResult(device="FW1", adom="OT-ADOM", pkg="pkg1",
                            generated_at="2026-09-03T12:00:00+00:00", fixes=[fix], stale_findings=[])
    html = render_html(result)
    assert "Irreversible" in html


def test_render_html_lists_stale_findings_separately():
    result = HygieneResult(device="FW1", adom="OT-ADOM", pkg="pkg1",
                            generated_at="2026-09-03T12:00:00+00:00", fixes=[],
                            stale_findings=[{"policy_id": "99", "policy_name": "Gone",
                                              "reason": "policy_id not found in live package"}])
    html = render_html(result)
    assert "Stale findings" in html
    assert "Gone" in html


def test_render_html_escapes_untrusted_text():
    fix = PolicyFix(policy_id="1", policy_name="<script>alert(1)</script>", check="unhit", options=[
        FixOption("A", "Disable", "disable it", [], None),
    ])
    result = HygieneResult(device="FW1", adom="OT-ADOM", pkg="pkg1",
                            generated_at="2026-09-03T12:00:00+00:00", fixes=[fix], stale_findings=[])
    html = render_html(result)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
