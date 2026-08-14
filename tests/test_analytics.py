import sqlite3
import time

import pytest

from fwanalyst_server.analytics import AnalyticsDB


@pytest.fixture
def db(tmp_path):
    return AnalyticsDB(str(tmp_path / "test.db"))


def drain(db):
    """Wait for the writer queue to drain."""
    db._queue.join()


def test_log_and_query_tool_call(db):
    db.log_tool_call("alice", "search_policies", "OT-ADOM")
    drain(db)
    rows = db.query_tool_calls(range_seconds=3600)
    assert len(rows) == 1
    assert rows[0]["token_label"] == "alice"
    assert rows[0]["tool_name"] == "search_policies"
    assert rows[0]["adom"] == "OT-ADOM"


def test_log_usage_event(db):
    db.log_usage_event("bob", "sess-1", 1000, 500, "claude-sonnet-5", 0.0105)
    drain(db)
    rows = db.query_usage_events(range_seconds=3600)
    assert len(rows) == 1
    assert rows[0]["input_tokens"] == 1000
    assert rows[0]["estimated_cost"] == pytest.approx(0.0105)


def test_log_system_metric(db):
    db.log_system_metric(42.0, 61.0, 38.0)
    drain(db)
    rows = db.query_metrics(range_seconds=3600)
    assert len(rows) == 1
    assert rows[0]["cpu_pct"] == pytest.approx(42.0)


def test_get_current_metrics_returns_latest(db):
    db.log_system_metric(10.0, 20.0, 30.0)
    db.log_system_metric(50.0, 60.0, 70.0)
    drain(db)
    m = db.get_current_metrics()
    assert m is not None
    assert m["cpu_pct"] == pytest.approx(50.0)


def test_purge_old_records(db):
    with sqlite3.connect(db._db_path) as conn:
        conn.execute(
            "INSERT INTO tool_calls (ts, token_label, tool_name, adom) VALUES (?,?,?,?)",
            (int(time.time()) - 100 * 86400, "alice", "old_tool", None),
        )
    db.purge_old_records(retention_days=90)
    assert db.query_tool_calls(range_seconds=200 * 86400) == []


def test_query_metrics_downsampled(db):
    now = int(time.time())
    with sqlite3.connect(db._db_path) as conn:
        conn.executemany(
            "INSERT INTO system_metrics (ts, cpu_pct, mem_pct, disk_pct) VALUES (?,?,?,?)",
            [(now - i * 12, 50.0, 60.0, 40.0) for i in range(300)],
        )
    rows = db.query_metrics(range_seconds=3600, max_points=200)
    assert len(rows) <= 200


def test_bucket_usage_totals(db):
    db.log_tool_call("alice", "search_policies", None)
    db.log_usage_event("alice", None, 1000, 500, "claude-sonnet-5", 0.0105)
    drain(db)
    result = db.bucket_usage(range_seconds=3600)
    assert result["totals"]["tool_calls"] >= 1
    assert result["totals"]["input_tokens"] >= 1000
    assert any(u["token_label"] == "alice" for u in result["by_user"])
