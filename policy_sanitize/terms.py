"""Sensitive-term list loading."""

from __future__ import annotations

import pathlib


class TermsError(Exception):
    """Terms file missing or empty. Message names the path only."""


def load_terms(path: pathlib.Path | None) -> list[tuple[str, str | None]]:
    if path is None:
        raise TermsError("terms file path not provided")
    p = pathlib.Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError:
        raise TermsError(f"terms file missing or unreadable: {p}") from None
    out: list[tuple[str, str | None]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        term, sep, ph = line.partition("=")
        term, ph = term.strip(), ph.strip()
        if term:
            out.append((term, ph if sep and ph else None))
    if not out:
        raise TermsError(f"terms file has no terms: {p}")
    return out
