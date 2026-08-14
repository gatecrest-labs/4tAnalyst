from __future__ import annotations

import queue
import sqlite3
import threading
import time
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tool_calls (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    token_label TEXT NOT NULL,
    tool_name   TEXT NOT NULL,
    adom        TEXT
);
CREATE TABLE IF NOT EXISTS usage_events (
    id             INTEGER PRIMARY KEY,
    ts             INTEGER NOT NULL,
    token_label    TEXT NOT NULL,
    session_id     TEXT,
    input_tokens   INTEGER NOT NULL,
    output_tokens  INTEGER NOT NULL,
    model          TEXT,
    estimated_cost REAL
);
CREATE TABLE IF NOT EXISTS system_metrics (
    id       INTEGER PRIMARY KEY,
    ts       INTEGER NOT NULL,
    cpu_pct  REAL NOT NULL,
    mem_pct  REAL NOT NULL,
    disk_pct REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tc_ts    ON tool_calls(ts);
CREATE INDEX IF NOT EXISTS idx_tc_label ON tool_calls(token_label, ts);
CREATE INDEX IF NOT EXISTS idx_ue_ts    ON usage_events(ts);
CREATE INDEX IF NOT EXISTS idx_sm_ts    ON system_metrics(ts);
"""


class AnalyticsDB:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._queue: queue.Queue[tuple[str, tuple[Any, ...]] | None] = queue.Queue()
        self._init_schema()
        t = threading.Thread(target=self._writer_loop, daemon=True)
        t.start()

    def _init_schema(self) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)

    def _writer_loop(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                self._queue.task_done()
                return
            sql, params = item
            try:
                with sqlite3.connect(self._db_path) as conn:
                    conn.execute(sql, params)
            except Exception:
                pass
            finally:
                self._queue.task_done()

    def _enqueue(self, sql: str, params: tuple[Any, ...]) -> None:
        self._queue.put((sql, params))

    def log_tool_call(self, token_label: str, tool_name: str, adom: str | None) -> None:
        self._enqueue(
            "INSERT INTO tool_calls (ts, token_label, tool_name, adom) VALUES (?,?,?,?)",
            (int(time.time()), token_label, tool_name, adom),
        )

    def log_usage_event(
        self,
        token_label: str,
        session_id: str | None,
        input_tokens: int,
        output_tokens: int,
        model: str | None,
        estimated_cost: float,
    ) -> None:
        self._enqueue(
            "INSERT INTO usage_events "
            "(ts, token_label, session_id, input_tokens, output_tokens, model, estimated_cost) "
            "VALUES (?,?,?,?,?,?,?)",
            (int(time.time()), token_label, session_id, input_tokens, output_tokens, model, estimated_cost),
        )

    def log_system_metric(self, cpu_pct: float, mem_pct: float, disk_pct: float) -> None:
        self._enqueue(
            "INSERT INTO system_metrics (ts, cpu_pct, mem_pct, disk_pct) VALUES (?,?,?,?)",
            (int(time.time()), cpu_pct, mem_pct, disk_pct),
        )

    def query_tool_calls(self, range_seconds: int) -> list[dict]:
        since = int(time.time()) - range_seconds
        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT ts, token_label, tool_name, adom FROM tool_calls WHERE ts >= ? ORDER BY ts",
                (since,),
            ).fetchall()
        return [dict(r) for r in rows]

    def query_usage_events(self, range_seconds: int) -> list[dict]:
        since = int(time.time()) - range_seconds
        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT ts, token_label, session_id, input_tokens, output_tokens, model, estimated_cost "
                "FROM usage_events WHERE ts >= ? ORDER BY ts",
                (since,),
            ).fetchall()
        return [dict(r) for r in rows]

    def query_metrics(self, range_seconds: int, max_points: int = 200) -> list[dict]:
        since = int(time.time()) - range_seconds
        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT ts, cpu_pct, mem_pct, disk_pct FROM system_metrics WHERE ts >= ? ORDER BY ts",
                (since,),
            ).fetchall()
        data = [dict(r) for r in rows]
        if len(data) <= max_points:
            return data
        step = len(data) // max_points
        return data[::step][:max_points]

    def get_current_metrics(self) -> dict | None:
        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT ts, cpu_pct, mem_pct, disk_pct FROM system_metrics ORDER BY ts DESC LIMIT 1"
            ).fetchone()
        return dict(row) if row else None

    def purge_old_records(self, retention_days: int) -> None:
        cutoff = int(time.time()) - retention_days * 86400
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("DELETE FROM tool_calls WHERE ts < ?", (cutoff,))
            conn.execute("DELETE FROM usage_events WHERE ts < ?", (cutoff,))
            conn.execute("DELETE FROM system_metrics WHERE ts < ?", (cutoff,))

    def bucket_usage(self, range_seconds: int) -> dict:
        since = int(time.time()) - range_seconds
        if range_seconds <= 4 * 3600:
            interval = 300
        elif range_seconds <= 86400:
            interval = 3600
        else:
            interval = 86400

        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            tc_rows = conn.execute(
                "SELECT ts, token_label FROM tool_calls WHERE ts >= ? ORDER BY ts", (since,)
            ).fetchall()
            ue_rows = conn.execute(
                "SELECT ts, token_label, input_tokens, output_tokens, estimated_cost "
                "FROM usage_events WHERE ts >= ? ORDER BY ts",
                (since,),
            ).fetchall()

        buckets: dict[int, dict] = {}
        users: set[str] = set()

        def get_bucket(ts: int) -> dict:
            bts = (ts // interval) * interval
            if bts not in buckets:
                buckets[bts] = {
                    "ts": bts,
                    "tool_calls": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cost": 0.0,
                    "by_user": {},
                }
            return buckets[bts]

        for row in tc_rows:
            b = get_bucket(row["ts"])
            b["tool_calls"] += 1
            ub = b["by_user"].setdefault(
                row["token_label"],
                {"tool_calls": 0, "input_tokens": 0, "output_tokens": 0, "cost": 0.0},
            )
            ub["tool_calls"] += 1
            users.add(row["token_label"])

        for row in ue_rows:
            b = get_bucket(row["ts"])
            b["input_tokens"] += row["input_tokens"]
            b["output_tokens"] += row["output_tokens"]
            b["cost"] += row["estimated_cost"] or 0.0
            ub = b["by_user"].setdefault(
                row["token_label"],
                {"tool_calls": 0, "input_tokens": 0, "output_tokens": 0, "cost": 0.0},
            )
            ub["input_tokens"] += row["input_tokens"]
            ub["output_tokens"] += row["output_tokens"]
            ub["cost"] += row["estimated_cost"] or 0.0
            users.add(row["token_label"])

        sorted_buckets = sorted(buckets.values(), key=lambda x: x["ts"])

        by_user: list[dict] = []
        for label in sorted(users):
            totals: dict = {
                "token_label": label,
                "tool_calls": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "estimated_cost": 0.0,
            }
            for b in sorted_buckets:
                u = b["by_user"].get(label, {})
                totals["tool_calls"] += u.get("tool_calls", 0)
                totals["input_tokens"] += u.get("input_tokens", 0)
                totals["output_tokens"] += u.get("output_tokens", 0)
                totals["estimated_cost"] += u.get("cost", 0.0)
            by_user.append(totals)

        return {
            "buckets": sorted_buckets,
            "by_user": by_user,
            "totals": {
                "tool_calls": sum(b["tool_calls"] for b in sorted_buckets),
                "input_tokens": sum(b["input_tokens"] for b in sorted_buckets),
                "output_tokens": sum(b["output_tokens"] for b in sorted_buckets),
                "cost": sum(b["cost"] for b in sorted_buckets),
            },
        }


# Module-level singleton used by UsageMiddleware and __main__.py
_db: AnalyticsDB | None = None


def init(db_path: str) -> AnalyticsDB:
    global _db
    _db = AnalyticsDB(db_path)
    return _db


def log_tool_call(token_label: str, tool_name: str, adom: str | None) -> None:
    if _db:
        _db.log_tool_call(token_label, tool_name, adom)


def log_usage_event(
    token_label: str,
    session_id: str | None,
    input_tokens: int,
    output_tokens: int,
    model: str | None,
    estimated_cost: float,
) -> None:
    if _db:
        _db.log_usage_event(token_label, session_id, input_tokens, output_tokens, model, estimated_cost)


def log_system_metric(cpu_pct: float, mem_pct: float, disk_pct: float) -> None:
    if _db:
        _db.log_system_metric(cpu_pct, mem_pct, disk_pct)
