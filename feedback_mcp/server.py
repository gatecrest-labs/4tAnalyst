"""
Feedback MCP Server

Exposes four tools to Claude:
  - record_feedback    : Save an engineer's decision on a recommendation
  - get_similar_cases  : Find past requests with similar traffic patterns
  - get_feedback_summary : Aggregate acceptance/modification/rejection stats
  - flag_for_review    : Mark a recommendation for team standards review

Also exposes one audit tool:
  - get_audit_log      : Read recent audit entries (filtered by ticket or engineer)

Data is stored in a local SQLite file (feedback.db by default).
Set FEEDBACK_DB env var to override the path.
Set FEEDBACK_DB=postgresql://... in Phase 4 to switch to Postgres
(requires replacing store._connect() — all other code is DB-agnostic).

Engineer identity note: engineer_id is currently a free-form string passed
explicitly by the caller. In Phase 5, wire this to your AD/Entra token via
the MCP session headers and remove it as a parameter.

Run locally (stdio):
  python -m feedback_mcp.server

Run as SSE server (production):
  MCP_TRANSPORT=sse FASTMCP_PORT=8003 python -m feedback_mcp
"""

import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from feedback_mcp.store import FeedbackStore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Store initialisation
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parent.parent
_DEFAULT_DB = _REPO_ROOT / "feedback.db"


@lru_cache(maxsize=1)
def _get_store() -> FeedbackStore:
    db_path = Path(os.getenv("FEEDBACK_DB", str(_DEFAULT_DB)))
    return FeedbackStore(db_path)


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

mcp = MCPServer(
    name="feedback",
    instructions=(
        "Engineer feedback and learning store. "
        "Use record_feedback after every ticket decision to capture what the engineer accepted, "
        "modified, or rejected and why. "
        "Use get_similar_cases before generating a recommendation to see how analogous "
        "traffic patterns were handled in the past — this improves recommendation quality. "
        "Use flag_for_review when a decision exposes a gap in the standards that the team "
        "should discuss. "
        "Use get_feedback_summary to report on team patterns over time."
    ),
)


# ---------------------------------------------------------------------------
# Tool: record_feedback
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False))
def record_feedback(
    request_id: str,
    recommendation_id: str,
    engineer_id: str,
    decision: str,
    recommendation_json: str,
    reason: str = "",
    modification: str = "",
    platform: str = "",
    src_zone: str = "",
    dst_zone: str = "",
    service: str = "",
) -> dict[str, Any]:
    """
    Save an engineer's decision on a firewall change recommendation.

    Call this after the engineer reviews a recommendation, regardless of outcome.
    The accumulated decisions train the similarity engine over time.

    Parameters
    ----------
    request_id         : str  — ServiceNow ticket ID (e.g. "RITM1234567")
    recommendation_id  : str  — Identifier for the specific recommendation within
                                the ticket (use a short descriptor if no formal ID,
                                e.g. "rule-1" or the ticket ID itself)
    engineer_id        : str  — Engineer who made the decision. Use Windows username
                                or email. This will be replaced by session auth in Phase 5.
    decision           : str  — One of: ACCEPTED, MODIFIED, REJECTED
    recommendation_json: str  — Full recommendation as a JSON string. Include at minimum:
                                src_zone, dst_zone, service, and the proposed rule details.
    reason             : str  — Why the engineer made this decision (optional but valuable)
    modification       : str  — What the engineer changed, if decision is MODIFIED (optional)
    platform           : str  — FORTIGATE or BOTH (optional)
    src_zone           : str  — Source zone from the recommendation (optional — extracted
                                from recommendation_json if omitted)
    dst_zone           : str  — Destination zone (optional — extracted from JSON if omitted)
    service            : str  — Service/port (optional — extracted from JSON if omitted)

    Returns the new feedback record ID and a confirmation summary.
    """
    store = _get_store()
    record_id = store.record_feedback(
        request_id=request_id,
        engineer_id=engineer_id,
        recommendation_json=recommendation_json,
        decision=decision,
        reason=reason or None,
        modification=modification or None,
        platform=platform or None,
        src_zone=src_zone or None,
        dst_zone=dst_zone or None,
        service=service or None,
    )
    return {
        "feedback_id": record_id,
        "request_id": request_id,
        "engineer_id": engineer_id,
        "decision": decision.upper(),
        "recorded": True,
    }


# ---------------------------------------------------------------------------
# Tool: get_similar_cases
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
def get_similar_cases(
    src_zone: str,
    dst_zone: str,
    service: str = "",
    limit: int = 5,
) -> list[dict[str, Any]]:
    """
    Find past requests with similar traffic patterns and how engineers handled them.

    Call this before generating a recommendation to surface precedents.
    Returns the most recent matching cases first.

    Parameters
    ----------
    src_zone : str  — Source zone name (must match zone names used in record_feedback)
    dst_zone : str  — Destination zone name
    service  : str  — Port or service name (optional). If provided, tries exact
                      service match first, then falls back to zone-pair only.
    limit    : int  — Maximum number of cases to return (default 5, max 20)

    Returns a list of past decisions, each with: request_id, engineer_id, decision,
    reason, modification (if any), platform, and the original recommendation snapshot.
    """
    limit = min(limit, 20)
    store = _get_store()
    return store.get_similar_cases(src_zone, dst_zone, service, limit)


# ---------------------------------------------------------------------------
# Tool: get_feedback_summary
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
def get_feedback_summary(days: int = 30) -> dict[str, Any]:
    """
    Return aggregate statistics on team decision patterns over the last N days.

    Use this to report on recommendation quality, track acceptance trends,
    and identify zone pairs that frequently require modifications.

    Parameters
    ----------
    days : int  — Lookback window in days (default 30)

    Returns:
      total_decisions      : int    — total records in period
      accepted             : int
      modified             : int
      rejected             : int
      acceptance_rate_pct  : float  — % accepted out of total
      modification_rate_pct: float
      rejection_rate_pct   : float
      flagged_for_review   : int    — records flagged for standards discussion
      by_platform          : dict   — breakdown by FORTIGATE / BOTH
      top_zone_pairs       : list   — top 5 zone pairs by decision volume
    """
    store = _get_store()
    return store.get_feedback_summary(days)


# ---------------------------------------------------------------------------
# Tool: flag_for_review
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False))
def flag_for_review(
    recommendation_id: str,
    engineer_id: str,
    note: str = "",
) -> dict[str, Any]:
    """
    Mark a feedback record for team standards review.

    Use when an engineer's decision reveals a gap in the zone matrix, naming
    conventions, or approval policy that the team should discuss.  Flagged
    records are surfaced in get_feedback_summary and can be exported for
    standards meetings.

    Parameters
    ----------
    recommendation_id : str  — The feedback record ID returned by record_feedback
    engineer_id       : str  — Engineer raising the flag
    note              : str  — Description of what standards issue this reveals (optional)

    Returns a confirmation with the flagged record's request ID and decision.
    """
    store = _get_store()
    return store.flag_for_review(recommendation_id, engineer_id, note)


# ---------------------------------------------------------------------------
# Tool: get_audit_log
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
def get_audit_log(
    ticket_id: str = "",
    engineer_id: str = "",
    limit: int = 50,
) -> list[dict[str, Any]]:
    """
    Return recent audit log entries.

    The audit log records every record_feedback and flag_for_review action
    with a full context snapshot. It is append-only and cannot be modified.

    Parameters
    ----------
    ticket_id   : str  — Filter to a specific ServiceNow ticket (optional)
    engineer_id : str  — Filter to a specific engineer (optional)
    limit       : int  — Maximum entries to return (default 50, max 200)

    Returns entries in reverse chronological order, each with: timestamp,
    engineer_id, action, ticket_id, and a detail snapshot.
    """
    limit = min(limit, 200)
    store = _get_store()
    return store.get_audit_log(
        ticket_id=ticket_id or None,
        engineer_id=engineer_id or None,
        limit=limit,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
