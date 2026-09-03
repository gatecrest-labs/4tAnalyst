import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hygiene.fix_logic import (
    FixContext, _fix_unhit, _fix_expired, _fix_unlogged,
    _fix_missing_security_profile, _fix_redundant, _fix_unnamed, _fix_over_permissive,
)
from hygiene.models import Finding

CTX = FixContext(now=date(2026, 9, 3))


def _finding(check, **kw):
    base = dict(policy_id="1", policy_name="P1", seq=1, check=check, detail="d")
    base.update(kw)
    return Finding(**base)


def test_fix_unhit_disables_and_tags():
    live = {"comments": "Allow web"}
    opts = _fix_unhit(_finding("unhit"), live, CTX)
    assert len(opts) == 1
    assert "set status disable" in opts[0].cli[0]
    assert "[HygieneFix 2026-09-03]" in opts[0].new_comment


def test_fix_expired_disables_and_tags():
    live = {"comments": ""}
    opts = _fix_expired(_finding("expired"), live, CTX)
    assert len(opts) == 1
    assert "set status disable" in opts[0].cli[0]


def test_fix_unlogged_sets_logtraffic_all_no_comment_change():
    live = {"comments": "Allow web"}
    opts = _fix_unlogged(_finding("unlogged"), live, CTX)
    assert len(opts) == 1
    assert "set logtraffic all" in opts[0].cli[0]
    assert opts[0].new_comment is None


def test_fix_missing_security_profile_is_informational_only():
    live = {"comments": ""}
    opts = _fix_missing_security_profile(_finding("missing_security_profile", detail="accept rule, no UTM"), live, CTX)
    assert len(opts) == 1
    assert opts[0].cli == []
    assert "accept rule, no UTM" in opts[0].description


def test_fix_redundant_cites_duplicate_of():
    live = {"comments": ""}
    finding = _finding("redundant", duplicate_of={"name": "Older-Rule", "policy_id": "3"})
    opts = _fix_redundant(finding, live, CTX)
    assert len(opts) == 1
    assert "Older-Rule" in opts[0].description
    assert "3" in opts[0].description
    assert "set status disable" in opts[0].cli[0]


def test_fix_unnamed_with_resolvable_src_and_dst():
    live = {"comments": "", "srcaddr": ["WEB-SRV"], "dstaddr": ["DB-SRV"]}
    opts = _fix_unnamed(_finding("unnamed"), live, CTX)
    assert len(opts) == 1
    assert 'set name "Allow WEB-SRV to DB-SRV"' in opts[0].cli[0]


def test_fix_unnamed_falls_back_when_src_is_any():
    live = {"comments": "", "srcaddr": ["all"], "dstaddr": ["DB-SRV"]}
    opts = _fix_unnamed(_finding("unnamed"), live, CTX)
    # extract the quoted name value
    line = [l for l in opts[0].cli[0].splitlines() if "set name" in l][0]
    name = line.split('"')[1]
    # fallback is truncated to 35 chars: "Unknown -- Requires additional..."
    assert len(name) <= 35
    assert name.startswith("Unknown -- Requires additio")


def test_fix_unnamed_falls_back_when_dst_is_any():
    live = {"comments": "", "srcaddr": ["WEB-SRV"], "dstaddr": ["all"]}
    opts = _fix_unnamed(_finding("unnamed"), live, CTX)
    # extract the quoted name value
    line = [l for l in opts[0].cli[0].splitlines() if "set name" in l][0]
    name = line.split('"')[1]
    assert len(name) <= 35
    assert name.startswith("Unknown -- Requires additio")


def test_fix_unnamed_falls_back_when_src_and_dst_missing():
    live = {"comments": ""}
    opts = _fix_unnamed(_finding("unnamed"), live, CTX)
    # extract the quoted name value
    line = [l for l in opts[0].cli[0].splitlines() if "set name" in l][0]
    name = line.split('"')[1]
    assert len(name) <= 35
    assert name.startswith("Unknown -- Requires additio")


def test_fix_unnamed_truncates_name_to_35_chars():
    live = {"comments": "", "srcaddr": ["A-VERY-LONG-SOURCE-ADDRESS-NAME-INDEED"], "dstaddr": ["DST"]}
    opts = _fix_unnamed(_finding("unnamed"), live, CTX)
    # extract the quoted name value
    line = [l for l in opts[0].cli[0].splitlines() if "set name" in l][0]
    name = line.split('"')[1]
    assert len(name) <= 35


def test_fix_over_permissive_returns_disable_and_exempt_options():
    live = {"comments": "Allow any to any"}
    opts = _fix_over_permissive(_finding("over_permissive"), live, CTX)
    assert len(opts) == 2
    assert opts[0].option_id == "A"
    assert "set status disable" in opts[0].cli[0]
    assert opts[1].option_id == "B"
    assert "EXEMPT" in opts[1].new_comment
    assert "set status disable" not in opts[1].cli[0]


from hygiene.fix_logic import _fix_disabled


def test_fix_disabled_no_tag_proposes_tagging():
    live = {"comments": "Was in use"}
    opts = _fix_disabled(_finding("disabled"), live, CTX)
    assert len(opts) == 1
    assert opts[0].label == "Tag for tracking"
    assert opts[0].cli[0].count("set status disable") == 0  # comment-only, rule already disabled
    assert "[HygieneFix 2026-09-03]" in opts[0].new_comment


def test_fix_disabled_recent_tag_no_action():
    live = {"comments": "Was in use [HygieneFix 2026-08-01]"}  # 33 days before CTX.now
    opts = _fix_disabled(_finding("disabled"), live, CTX)
    assert len(opts) == 1
    assert opts[0].cli == []
    assert "33 days" in opts[0].description
    assert opts[0].irreversible is False


def test_fix_disabled_old_tag_proposes_delete():
    live = {"comments": "Was in use [HygieneFix 2026-01-01]"}  # 245 days before CTX.now
    opts = _fix_disabled(_finding("disabled"), live, CTX)
    assert len(opts) == 1
    assert "delete" in opts[0].cli[0]
    assert opts[0].irreversible is True
