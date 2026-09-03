import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hygiene.tag import append_tag, find_tag, MAX_COMMENT_LEN


def test_append_tag_to_empty_comment():
    result = append_tag("", date(2026, 9, 3))
    assert result == "[HygieneFix 2026-09-03]"


def test_append_tag_to_existing_comment():
    result = append_tag("Allow web to db", date(2026, 9, 3))
    assert result == "Allow web to db [HygieneFix 2026-09-03]"


def test_append_tag_exempt_variant():
    result = append_tag("Reviewed manually", date(2026, 9, 3), exempt=True)
    assert result == "Reviewed manually [HygieneFix EXEMPT 2026-09-03]"


def test_append_tag_truncates_original_content_not_tag():
    long_comment = "x" * 300
    result = append_tag(long_comment, date(2026, 9, 3))
    assert len(result) == MAX_COMMENT_LEN
    assert result.endswith("[HygieneFix 2026-09-03]")


def test_find_tag_returns_date():
    assert find_tag("Allow web to db [HygieneFix 2026-09-03]") == date(2026, 9, 3)


def test_find_tag_returns_date_for_exempt_variant():
    assert find_tag("Reviewed [HygieneFix EXEMPT 2026-06-01]") == date(2026, 6, 1)


def test_find_tag_returns_none_when_absent():
    assert find_tag("Allow web to db") is None


def test_find_tag_returns_none_for_empty_comment():
    assert find_tag("") is None
