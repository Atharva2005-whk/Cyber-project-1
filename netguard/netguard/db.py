"""
db.py — thin SQLite wrapper for storing NetGuard alerts.

Schema is intentionally simple: one table of alert events. If this
project grows, this is the first thing to swap for a real ORM
(SQLAlchemy) — noting that here as a TODO rather than over-engineering
a portfolio project on day one.
"""

import sqlite3
import os
from datetime import datetime, timezone
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    detector TEXT NOT NULL,
    source_ip TEXT,
    severity TEXT NOT NULL,
    message TEXT NOT NULL
);
"""


class AlertStore:
    def __init__(self, db_path: str):
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self.db_path = db_path
        self._init_schema()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()

    def _init_schema(self):
        with self._connect() as conn:
            conn.execute(SCHEMA)
            conn.commit()

    def add_alert(self, detector: str, source_ip: str, severity: str, message: str):
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO alerts (timestamp, detector, source_ip, severity, message) "
                "VALUES (?, ?, ?, ?, ?)",
                (ts, detector, source_ip, severity, message),
            )
            conn.commit()

    def recent_alerts(self, limit: int = 50):
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
            )
            return [dict(row) for row in cur.fetchall()]

    def alert_counts_by_detector(self):
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT detector, COUNT(*) as count FROM alerts GROUP BY detector"
            )
            return {row[0]: row[1] for row in cur.fetchall()}
