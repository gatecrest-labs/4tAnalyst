import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from hygiene.models import HygieneParseError
from hygiene.parse import parse_csv, parse_json


def test_parse_json_bare_list():
    text = '[{"policy_id": "1", "policy_name": "P1", "seq": 1, "check": "unhit", "detail": "no hits"}]'
    findings = parse_json(text)
    assert len(findings) == 1
    assert findings[0].policy_id == "1"
    assert findings[0].check == "unhit"


def test_parse_json_envelope():
    text = '{"findings": [{"policy_id": "2", "policy_name": "P2", "seq": 2, "check": "unlogged", "detail": "no log"}], "package": "pkg1"}'
    findings = parse_json(text)
    assert len(findings) == 1
    assert findings[0].policy_id == "2"


def test_parse_json_shadow_embeds_rule_summaries():
    text = (
        '[{"policy_id": "5", "policy_name": "P5", "seq": 5, "check": "shadow", '
        '"detail": "shadowed", "shadow_rule": {"policy_id": "5"}, '
        '"shadowing_rule": {"policy_id": "2", "action": "deny"}}]'
    )
    findings = parse_json(text)
    assert findings[0].shadowing_rule == {"policy_id": "2", "action": "deny"}


def test_parse_json_invalid_syntax_raises():
    with pytest.raises(HygieneParseError):
        parse_json("not json")


def test_parse_json_object_without_findings_key_raises():
    with pytest.raises(HygieneParseError):
        parse_json('{"package": "pkg1"}')


def test_parse_json_missing_required_field_raises():
    with pytest.raises(HygieneParseError):
        parse_json('[{"policy_id": "1", "check": "unhit"}]')


def test_parse_json_invalid_seq_raises():
    with pytest.raises(HygieneParseError):
        parse_json('[{"policy_id": "1", "policy_name": "P1", "seq": "not-a-number", "check": "unhit"}]')


_CLEAN_CSV = (
    "Policy ID,Policy Name,Seq,Check,Detail\r\n"
    "1,P1,1,unhit,no hits in 90 days\r\n"
    "2,P2,2,unnamed,no comment set\r\n"
)

_SCHEDULER_CSV = (
    "# 4THealth Rule Hygiene\r\n"
    "# Package: pkg1\r\n"
    "# Device(s): FW1\r\n"
    "# Generated: 2026-09-03T20:06:03+00:00\r\n"
    "\r\n"
    "Policy ID,Policy Name,Seq,Check,Detail\r\n"
    "1,P1,1,unhit,no hits in 90 days\r\n"
    "\r\n"
    "# Unused Addresses\r\n"
    "Name,Type\r\n"
    "OLD-HOST,ipmask\r\n"
    "# Unused Services\r\n"
    "Name,Type\r\n"
)


def test_parse_csv_clean_header_shape():
    findings = parse_csv(_CLEAN_CSV)
    assert len(findings) == 2
    assert findings[0].policy_id == "1"
    assert findings[0].check == "unhit"
    assert findings[1].check == "unnamed"


def test_parse_csv_scheduler_attachment_shape():
    """Real scheduler attachment: # comment header rows, blank line, then
    the findings header, then a trailing '# Unused Addresses' section that
    must be ignored."""
    findings = parse_csv(_SCHEDULER_CSV)
    assert len(findings) == 1
    assert findings[0].policy_id == "1"
    assert findings[0].policy_name == "P1"


def test_parse_csv_scheduler_attachment_with_error_row():
    text = (
        "# 4THealth Rule Hygiene\r\n"
        "# Package: pkg1\r\n"
        "ERROR,connection timed out\r\n"
        "\r\n"
        "Policy ID,Policy Name,Seq,Check,Detail\r\n"
        "3,P3,3,expired,schedule ended\r\n"
    )
    findings = parse_csv(text)
    assert len(findings) == 1
    assert findings[0].check == "expired"


def test_parse_csv_no_header_found_raises():
    with pytest.raises(HygieneParseError):
        parse_csv("just,some,random,csv\r\n1,2,3,4\r\n")


def test_parse_csv_empty_input_raises():
    with pytest.raises(HygieneParseError):
        parse_csv("")
