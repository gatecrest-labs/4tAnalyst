import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from hygiene.models import HygieneParseError
from hygiene.parse import parse_json


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
