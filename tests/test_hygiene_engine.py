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
