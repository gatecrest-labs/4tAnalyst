"""
FortiOS/FortiManager version comparison.

Versions are MAJOR.MINOR.PATCH (e.g. "7.4.4"); a two-component version
("7.4") is padded with a zero patch level. Advisory ranges arrive already
structured (min/max version strings extracted by the LLM step, not raw
"X through Y" prose) — this module only compares dotted version strings,
it does not parse English range text.

Unparseable version syntax raises VersionMatchError rather than defaulting
to "not affected" — callers must surface this to the engineer, never
silently skip the device.
"""

from __future__ import annotations

import re

from psirt.models import AffectedRange

_VERSION_RE = re.compile(r"^\d+(\.\d+){1,2}$")


class VersionMatchError(Exception):
    """A version string could not be parsed."""


def parse_version(text: str) -> tuple[int, ...]:
    text = (text or "").strip()
    if not _VERSION_RE.match(text):
        raise VersionMatchError(f"cannot parse version string: {text!r}")
    parts = [int(p) for p in text.split(".")]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def compare_versions(a: str, b: str) -> int:
    va, vb = parse_version(a), parse_version(b)
    if va < vb:
        return -1
    if va > vb:
        return 1
    return 0


def version_in_range(version: str, rng: AffectedRange) -> bool:
    v = parse_version(version)
    if rng.min_version and v < parse_version(rng.min_version):
        return False
    if rng.max_version and v > parse_version(rng.max_version):
        return False
    return True
