"""
The [HygieneFix YYYY-MM-DD] / [HygieneFix EXEMPT YYYY-MM-DD] traceability
tag ported from the 4thealth-plus hygiene-fix-ai-assist design. Any fix that
disables a rule or otherwise annotates it appends this tag to the end of the
rule's existing comment; find_tag() is what makes the `disabled` check's
90-day-age branch possible without guessing at human-written dates.
"""

from __future__ import annotations

import re
from datetime import date

MAX_COMMENT_LEN = 255

_TAG_RE = re.compile(r"\[HygieneFix(?: EXEMPT)? (\d{4}-\d{2}-\d{2})\]")


def append_tag(comment: str, today: date, exempt: bool = False) -> str:
    """Append the traceability tag, truncating the *original* comment (never
    the tag) if the combined length would exceed FortiOS's 255-char limit."""
    marker = "EXEMPT " if exempt else ""
    tag = f"[HygieneFix {marker}{today.isoformat()}]"
    comment = (comment or "").strip()
    combined = f"{comment} {tag}" if comment else tag
    if len(combined) <= MAX_COMMENT_LEN:
        return combined
    budget = MAX_COMMENT_LEN - len(tag) - 1  # -1 for the separating space
    if budget <= 0:
        return tag[:MAX_COMMENT_LEN]
    truncated = comment[:budget].rstrip()
    return f"{truncated} {tag}" if truncated else tag


def find_tag(comment: str) -> date | None:
    """Return the date embedded in the most recent HygieneFix tag, if any."""
    if not comment:
        return None
    m = _TAG_RE.search(comment)
    if not m:
        return None
    return date.fromisoformat(m.group(1))
