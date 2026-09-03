"""
Parses a Rule Hygiene run's findings from pasted/uploaded JSON or CSV text.

Verified against the actual 4thealth-plus exporters (not just its own
design doc): the interactive UI export writes a clean single-header CSV,
but the scheduled-job attachment prepends `#`-comment metadata rows and a
blank line before the real header, and can append trailing `# Unused
Addresses`/`# Unused Services` sections after the findings. Both are real,
expected inputs. See parse_csv.
"""

from __future__ import annotations

import csv
import json

from hygiene.models import Finding, HygieneParseError

_REQUIRED_FIELDS = ("policy_id", "policy_name", "check")


def parse_json(text: str) -> list[Finding]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise HygieneParseError(f"invalid JSON: {e}") from e

    if isinstance(data, dict):
        raw = data.get("findings")
        if raw is None:
            raise HygieneParseError("JSON object must contain a 'findings' list")
    elif isinstance(data, list):
        raw = data
    else:
        raise HygieneParseError(
            "JSON must be a list of findings or {'findings': [...]}"
        )

    if not isinstance(raw, list):
        raise HygieneParseError("'findings' must be a list")

    findings = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise HygieneParseError(f"finding[{i}] is not an object")
        findings.append(_finding_from_dict(item))
    return findings


def _finding_from_dict(item: dict) -> Finding:
    for key in _REQUIRED_FIELDS:
        if not item.get(key):
            raise HygieneParseError(f"finding missing required field: {key}")

    try:
        seq = int(item.get("seq", 0) or 0)
    except (ValueError, TypeError):
        raise HygieneParseError(f"finding has invalid seq: {item.get('seq')!r}") from None

    return Finding(
        policy_id=str(item["policy_id"]),
        policy_name=str(item["policy_name"]),
        seq=seq,
        check=str(item["check"]),
        detail=str(item.get("detail", "")),
        severity=str(item.get("severity", "")),
        shadow_rule=item.get("shadow_rule"),
        shadowing_rule=item.get("shadowing_rule"),
        duplicate_of=item.get("duplicate_of"),
    )


_REQUIRED_CSV_COLS = {"Policy ID", "Policy Name", "Seq", "Check", "Detail"}


def parse_csv(text: str) -> list[Finding]:
    lines = text.splitlines()
    header_idx = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.upper().startswith("ERROR,"):
            continue
        cols = {c.strip() for c in next(csv.reader([line]))}
        if _REQUIRED_CSV_COLS.issubset(cols):
            header_idx = i
        break

    if header_idx is None:
        raise HygieneParseError(
            "no findings header row found in CSV input "
            "(expected columns: Policy ID, Policy Name, Seq, Check, Detail)"
        )

    data_lines = []
    for line in lines[header_idx + 1:]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            break
        data_lines.append(line)

    reader = csv.DictReader([lines[header_idx]] + data_lines)
    findings = []
    for row in reader:
        findings.append(_finding_from_dict({
            "policy_id": row.get("Policy ID", ""),
            "policy_name": row.get("Policy Name", ""),
            "seq": row.get("Seq", "0"),
            "check": row.get("Check", ""),
            "detail": row.get("Detail", ""),
        }))
    return findings
