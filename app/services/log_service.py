import json
from datetime import datetime, timezone
from typing import List, Optional

from app.core.database import get_db_connection
from app.models.schemas import ScanLogRecord, ScanResult, ThreatEventUpsertRequest


class LogService:
    def save_scan(
        self,
        result: ScanResult,
        content_preview: str | None = None,
    ) -> None:
        preview = (content_preview or "")[:200] or None
        with get_db_connection() as connection:
            connection.execute(
                """
                INSERT INTO scan_logs (
                    status,
                    source_type,
                    source_app,
                    content_preview,
                    label,
                    risk_score,
                    should_block,
                    reasons,
                    provider_used,
                    created_at,
                    external_id,
                    raw_text,
                    raw_url,
                    metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "pending",
                    result.source_type,
                    None,
                    preview,
                    result.label,
                    result.risk_score,
                    1 if result.should_block else 0,
                    json.dumps(result.reasons),
                    result.provider_used,
                    datetime.now(timezone.utc).isoformat(),
                    None,
                    content_preview,
                    None,
                    json.dumps(
                        {
                            "detection_mode": result.detection_mode,
                            "partial_scan": result.partial_scan,
                            "ai_summary": result.ai_summary,
                        }
                    ),
                ),
            )
            connection.commit()

    def save_event(self, payload: ThreatEventUpsertRequest) -> Optional[int]:
        with get_db_connection() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO scan_logs (
                    status,
                    source_type,
                    source_app,
                    content_preview,
                    label,
                    risk_score,
                    should_block,
                    reasons,
                    provider_used,
                    created_at,
                    external_id,
                    raw_text,
                    raw_url,
                    metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.status,
                    payload.source_type,
                    payload.source_app,
                    payload.content_preview[:200],
                    payload.label,
                    payload.risk_score,
                    1 if payload.should_block else 0,
                    json.dumps(payload.reasons),
                    None,
                    datetime.now(timezone.utc).isoformat(),
                    payload.external_id,
                    payload.raw_text,
                    payload.raw_url,
                    json.dumps(payload.metadata),
                ),
            )
            connection.commit()
            inserted_id = cursor.lastrowid

            if inserted_id:
                return inserted_id

            if payload.external_id:
                row = connection.execute(
                    "SELECT id FROM scan_logs WHERE external_id = ?",
                    (payload.external_id,),
                ).fetchone()
                if row:
                    return int(row[0])
        return None

    def list_recent(self, limit: int = 20) -> List[ScanLogRecord]:
        with get_db_connection() as connection:
            rows = connection.execute(
                """
                SELECT id, status, source_type, source_app, content_preview, raw_text, raw_url,
                       label, risk_score, should_block, reasons, provider_used, created_at, external_id
                FROM scan_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [
            ScanLogRecord(
                id=row[0],
                status=row[1],
                source_type=row[2],
                source_app=row[3],
                content_preview=row[4],
                raw_text=row[5],
                raw_url=row[6],
                label=row[7],
                risk_score=row[8],
                should_block=bool(row[9]),
                reasons=json.loads(row[10]),
                provider_used=row[11],
                created_at=datetime.fromisoformat(row[12]),
                external_id=row[13],
            )
            for row in rows
        ]
