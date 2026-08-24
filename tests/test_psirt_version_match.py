"""Tests for psirt.version_match: FortiOS/FortiManager version comparison."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from psirt.models import AffectedRange
from psirt.version_match import (
    VersionMatchError,
    compare_versions,
    parse_version,
    version_in_range,
)


def test_parse_version_three_component():
    assert parse_version("7.4.4") == (7, 4, 4)


def test_parse_version_two_component_pads_zero():
    assert parse_version("7.4") == (7, 4, 0)


def test_parse_version_rejects_garbage():
    with pytest.raises(VersionMatchError):
        parse_version("not-a-version")


def test_parse_version_rejects_empty():
    with pytest.raises(VersionMatchError):
        parse_version("")


def test_compare_versions():
    assert compare_versions("7.4.4", "7.4.5") == -1
    assert compare_versions("7.4.5", "7.4.4") == 1
    assert compare_versions("7.4.4", "7.4.4") == 0


def test_version_in_range_inclusive_bounds():
    rng = AffectedRange(product="FortiOS", min_version="7.4.0", max_version="7.4.4")
    assert version_in_range("7.4.0", rng) is True
    assert version_in_range("7.4.4", rng) is True
    assert version_in_range("7.4.2", rng) is True
    assert version_in_range("7.4.5", rng) is False
    assert version_in_range("7.3.9", rng) is False


def test_version_in_range_open_ended_below():
    # "7.4.0 and below" -> min_version empty, max_version="7.4.0"
    rng = AffectedRange(product="FortiOS", min_version="", max_version="7.4.0")
    assert version_in_range("7.0.0", rng) is True
    assert version_in_range("7.4.0", rng) is True
    assert version_in_range("7.4.1", rng) is False


def test_version_in_range_open_ended_above():
    rng = AffectedRange(product="FortiOS", min_version="7.4.0", max_version="")
    assert version_in_range("7.4.0", rng) is True
    assert version_in_range("9.9.9", rng) is True
    assert version_in_range("7.3.9", rng) is False


def test_version_in_range_unparseable_current_version_raises():
    rng = AffectedRange(product="FortiOS", min_version="7.4.0", max_version="7.4.4")
    with pytest.raises(VersionMatchError):
        version_in_range("unknown", rng)
