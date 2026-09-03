import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hygiene_mcp.server import parse_hygiene_findings


def test_parse_hygiene_findings_from_pasted_json():
    text = '[{"policy_id": "1", "policy_name": "P1", "seq": 1, "check": "unhit", "detail": "d"}]'
    result = parse_hygiene_findings(text=text, file_type="json")
    assert "error" not in result
    assert result["findings"][0]["policy_id"] == "1"


def test_parse_hygiene_findings_file_content_wins_over_text():
    text_findings = '[{"policy_id": "1", "policy_name": "P1", "seq": 1, "check": "unhit", "detail": "d"}]'
    file_findings = '[{"policy_id": "2", "policy_name": "P2", "seq": 2, "check": "unlogged", "detail": "d"}]'
    result = parse_hygiene_findings(text=text_findings, file_content=file_findings, file_type="json")
    assert result["findings"][0]["policy_id"] == "2"


def test_parse_hygiene_findings_malformed_returns_error_not_exception():
    result = parse_hygiene_findings(text="not json", file_type="json")
    assert result["error_code"] == "parse_error"


def test_parse_hygiene_findings_no_input_returns_error():
    result = parse_hygiene_findings(text="", file_content="", file_type="json")
    assert result["error_code"] == "invalid_input"


def test_parse_hygiene_findings_invalid_file_type_returns_error():
    result = parse_hygiene_findings(text="[]", file_type="xml")
    assert result["error_code"] == "invalid_input"


def test_parse_hygiene_findings_csv():
    text = "Policy ID,Policy Name,Seq,Check,Detail\r\n1,P1,1,unhit,no hits\r\n"
    result = parse_hygiene_findings(text=text, file_type="csv")
    assert result["findings"][0]["check"] == "unhit"
