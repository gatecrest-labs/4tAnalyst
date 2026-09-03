import sys
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from hygiene.engine import assess
from hygiene.models import Finding, HygieneDataError

LIVE = [
    {"policyid": 1, "name": "P1", "comments": "", "srcaddr": ["S1"], "dstaddr": ["D1"], "action": "accept"},
    {"policyid": 2, "name": "P2", "comments": ""},
]


def _finding(policy_id, check, **kw):
    base = dict(policy_id=policy_id, policy_name="P", seq=1, check=check, detail="d")
    base.update(kw)
    return Finding(**base)


def test_assess_matches_findings_to_live_policies_by_id():
    result = assess(
        [_finding("1", "unhit")], {"pkg1": LIVE}, "FW1", "OT-ADOM", "pkg1",
        now=date(2026, 9, 3),
    )
    assert len(result.fixes) == 1
    assert result.fixes[0].policy_id == "1"
    assert result.stale_findings == []


def test_assess_marks_missing_policy_id_as_stale():
    result = assess(
        [_finding("99", "unhit")], {"pkg1": LIVE}, "FW1", "OT-ADOM", "pkg1",
        now=date(2026, 9, 3),
    )
    assert result.fixes == []
    assert len(result.stale_findings) == 1
    assert result.stale_findings[0]["policy_id"] == "99"
    assert "not found in live package" in result.stale_findings[0]["reason"]


def test_assess_skips_unrecognized_check_without_error():
    result = assess(
        [_finding("1", "some_future_check")], {"pkg1": LIVE}, "FW1", "OT-ADOM", "pkg1",
        now=date(2026, 9, 3),
    )
    assert result.fixes == []
    assert result.stale_findings == []


def test_assess_raises_when_package_missing_from_fetch():
    with pytest.raises(HygieneDataError):
        assess([_finding("1", "unhit")], {}, "FW1", "OT-ADOM", "pkg1", now=date(2026, 9, 3))


def test_assess_raises_when_fetch_failed_for_package():
    with pytest.raises(HygieneDataError):
        assess([_finding("1", "unhit")], {"pkg1": None}, "FW1", "OT-ADOM", "pkg1", now=date(2026, 9, 3))


def test_assess_result_carries_scope_metadata():
    result = assess([], {"pkg1": LIVE}, "FW1", "OT-ADOM", "pkg1", now=date(2026, 9, 3))
    assert result.device == "FW1"
    assert result.adom == "OT-ADOM"
    assert result.pkg == "pkg1"


def test_assess_suppresses_shadow_narrow_option_for_redundant_policy():
    # Shadowing rule covers a superset of policy 1's src (S1 vs S1+S2), so
    # _shadow_narrow_option would normally offer Option C -- unless
    # policy_id "1" is also flagged "redundant" elsewhere in the same
    # findings list, in which case ctx.redundant_policy_ids (built by
    # assess() from the whole findings list) must suppress it.
    shadowing_rule = {
        "policy_id": "5",
        "srcaddr": ["S1", "S2"],
        "dstaddr": ["D1"],
        "action": "accept",
    }
    findings = [
        _finding("1", "shadow", shadowing_rule=shadowing_rule),
        _finding("1", "redundant", duplicate_of={"name": "P5", "policy_id": "5"}),
    ]
    result = assess(findings, {"pkg1": LIVE}, "FW1", "OT-ADOM", "pkg1", now=date(2026, 9, 3))

    shadow_fixes = [f for f in result.fixes if f.check == "shadow"]
    assert len(shadow_fixes) == 1
    option_ids = {o.option_id for o in shadow_fixes[0].options}
    assert "C" not in option_ids
