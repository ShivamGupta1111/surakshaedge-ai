"""SQLite persistence for alerts. Raw SMS, full URLs, and payloads are not stored by default."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

from src.config import Settings, get_settings
from src.exceptions import NotFoundError
from src.schemas import AlertRecord, RiskAssessment
from src.security import redact_text


SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    detector_type TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    risk_score REAL NOT NULL,
    evidence_redacted TEXT NOT NULL,
    content_hash TEXT,
    advisor_backend TEXT NOT NULL,
    model_versions TEXT NOT NULL,
    feedback TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_risk_level ON alerts(risk_level);
CREATE INDEX IF NOT EXISTS idx_alerts_detector ON alerts(detector_type);
"""


class Storage:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.path = self.settings.database_path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    def purge_expired(self) -> int:
        days = self.settings.retention_days
        if days <= 0:
            return 0
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM alerts WHERE created_at < ?", (cutoff,))
            return cur.rowcount

    def save_assessment(
        self,
        assessment: RiskAssessment,
        *,
        detector_type: str,
        content_hash: str | None,
    ) -> str:
        alert_id = assessment.alert_id or str(uuid.uuid4())
        versions = {d.detector: d.model_version for d in assessment.detectors}
        evidence = redact_text("; ".join(assessment.evidence), max_len=800)
        created = assessment.created_at.astimezone(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO alerts (
                    alert_id, created_at, detector_type, risk_level, risk_score,
                    evidence_redacted, content_hash, advisor_backend, model_versions, feedback
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    alert_id,
                    created,
                    detector_type,
                    assessment.risk_level,
                    assessment.risk_score,
                    evidence,
                    content_hash,
                    assessment.advisor_backend or "local_template",
                    json.dumps(versions),
                ),
            )
        return alert_id

    def get(self, alert_id: str) -> AlertRecord:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        if row is None:
            raise NotFoundError("Alert not found")
        return AlertRecord(**dict(row))

    def list_alerts(self, *, limit: int = 50, offset: int = 0) -> list[AlertRecord]:
        limit = min(max(limit, 1), 200)
        offset = max(offset, 0)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [AlertRecord(**dict(row)) for row in rows]

    def delete(self, alert_id: str) -> None:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM alerts WHERE alert_id = ?", (alert_id,))
            if cur.rowcount == 0:
                raise NotFoundError("Alert not found")

    def set_feedback(self, alert_id: str, useful: bool, comment: str | None) -> None:
        self.get(alert_id)
        payload = json.dumps({"useful": useful, "comment": redact_text(comment or "", max_len=200)})
        with self._connect() as conn:
            conn.execute("UPDATE alerts SET feedback = ? WHERE alert_id = ?", (payload, alert_id))

    def contains_raw(self, needle: str) -> bool:
        if not needle:
            return False
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM alerts WHERE evidence_redacted LIKE ?",
                (f"%{needle}%",),
            ).fetchone()
        return bool(row["c"])


@lru_cache(maxsize=1)
def get_storage() -> Storage:
    return Storage()


def reset_storage_cache() -> None:
    get_storage.cache_clear()
