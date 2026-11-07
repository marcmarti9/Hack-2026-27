"""Persistencia mínima en SQLite: resultados de triaje y registro de auditoría."""
from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from backend.models.triage_result import TriageResult


class Storage:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with closing(self._conn()) as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS results (alert_id TEXT PRIMARY KEY, body TEXT NOT NULL, updated_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT NOT NULL,
                                                  at TEXT NOT NULL, event TEXT NOT NULL, detail TEXT);
            """)
            c.commit()

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def save_result(self, r: TriageResult, event: str, detail: str) -> None:
        with closing(self._conn()) as c:
            now = datetime.now(timezone.utc).isoformat()
            c.execute("INSERT INTO results (alert_id, body, updated_at) VALUES (?,?,?) "
                      "ON CONFLICT(alert_id) DO UPDATE SET body=excluded.body, updated_at=excluded.updated_at",
                      (r.alert_id, r.model_dump_json(), now))
            c.execute("INSERT INTO audit (alert_id, at, event, detail) VALUES (?,?,?,?)",
                      (r.alert_id, now, event, detail))
            c.commit()

    def get_result(self, alert_id: str) -> Optional[TriageResult]:
        with closing(self._conn()) as c:
            row = c.execute("SELECT body FROM results WHERE alert_id=?", (alert_id,)).fetchone()
        return TriageResult.model_validate_json(row[0]) if row else None

    def list_results(self) -> list[TriageResult]:
        with closing(self._conn()) as c:
            rows = c.execute("SELECT body FROM results ORDER BY alert_id").fetchall()
        return [TriageResult.model_validate_json(r[0]) for r in rows]

    def audit(self, alert_id: str) -> list[dict]:
        with closing(self._conn()) as c:
            rows = c.execute("SELECT at, event, detail FROM audit WHERE alert_id=? ORDER BY id", (alert_id,)).fetchall()
        return [{"at": a, "event": e, "detail": d} for a, e, d in rows]
