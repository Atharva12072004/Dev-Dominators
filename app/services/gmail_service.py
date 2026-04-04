import base64
import json
import re
import logging
from datetime import datetime, timezone
from html import unescape
from typing import Optional

import httpx

from app.core.config import get_settings
from app.core.database import get_db_connection
from app.models.schemas import (
    GmailConnectRequest,
    GmailConnectResponse,
    GmailSyncRequest,
    GmailSyncResponse,
    GmailWatchNotificationResponse,
    GmailWatchSetupRequest,
    GmailWatchSetupResponse,
    ScanLogRecord,
    ThreatEventUpsertRequest,
)
from app.services.ai_enhancement_service import AIEnhancementService
from app.services.detection_service import DetectionService
from app.services.log_service import LogService
from app.services.threat_intel_service import ThreatIntelService
from app.utils.text import URL_REGEX

logger = logging.getLogger(__name__)


class GmailService:
    def __init__(
        self,
        detection_service: DetectionService,
        log_service: LogService,
        ai_service: AIEnhancementService,
        threat_intel_service: ThreatIntelService,
    ) -> None:
        self.detection_service = detection_service
        self.log_service = log_service
        self.ai_service = ai_service
        self.threat_intel_service = threat_intel_service

    async def connect_account(self, payload: GmailConnectRequest) -> GmailConnectResponse:
        profile = await self._fetch_profile(payload.access_token)
        email = payload.email or profile["emailAddress"]
        history_id = str(profile.get("historyId")) if profile.get("historyId") else None
        now = datetime.now(timezone.utc).isoformat()

        with get_db_connection() as connection:
            connection.execute(
                """
                INSERT INTO gmail_connections (
                    email, access_token, refresh_token, expires_at, watch_configured, last_history_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(email) DO UPDATE SET
                    access_token = excluded.access_token,
                    refresh_token = excluded.refresh_token,
                    expires_at = excluded.expires_at,
                    last_history_id = COALESCE(gmail_connections.last_history_id, excluded.last_history_id),
                    updated_at = excluded.updated_at
                """,
                (
                    email,
                    payload.access_token,
                    payload.refresh_token,
                    payload.expires_at,
                    0,
                    history_id,
                    now,
                    now,
                ),
            )
            connection.commit()

        return GmailConnectResponse(
            connected=True,
            email=email,
            watch_configured=False,
            last_history_id=history_id,
        )

    async def setup_watch(self, payload: GmailWatchSetupRequest) -> GmailWatchSetupResponse:
        connection = self._get_connection(payload.email)
        if not connection:
            return GmailWatchSetupResponse(
                success=False,
                email=payload.email,
                watch_configured=False,
                message="Gmail account is not connected.",
            )

        # This endpoint supports Gmail watch/push architecture when a Pub/Sub topic is configured.
        # Without it, the app can still use near-real-time sync polling.
        topic_name = get_settings().gmail_pubsub_topic.strip()
        public_backend_url = get_settings().public_backend_url.strip()
        if topic_name:
            try:
                await self._call_gmail_api(
                    connection["access_token"],
                    "POST",
                    "https://gmail.googleapis.com/gmail/v1/users/me/watch",
                    json={"topicName": topic_name, "labelIds": ["INBOX"]},
                )
                with get_db_connection() as db:
                    db.execute(
                        "UPDATE gmail_connections SET watch_configured = 1, updated_at = ? WHERE email = ?",
                        (datetime.now(timezone.utc).isoformat(), payload.email),
                    )
                    db.commit()
                return GmailWatchSetupResponse(
                    success=True,
                    email=payload.email,
                    watch_configured=True,
                    message=(
                        "Gmail watch configured successfully. "
                        if public_backend_url
                        else "Gmail watch configured on Gmail, but true push delivery still needs a public backend URL and Pub/Sub push subscription."
                    ),
                    realtime_ready=bool(public_backend_url),
                )
            except Exception as exc:
                logger.warning("Failed to configure Gmail watch for %s: %s", payload.email, exc)

        return GmailWatchSetupResponse(
            success=True,
            email=payload.email,
            watch_configured=False,
            message="Watch endpoint is ready, but Pub/Sub topic is not configured. Falling back to sync polling.",
            realtime_ready=False,
        )

    async def handle_watch_notification(
        self,
        *,
        envelope: dict,
        verification_token: Optional[str] = None,
    ) -> GmailWatchNotificationResponse:
        expected_token = get_settings().gmail_watch_verification_token.strip()
        if expected_token and verification_token != expected_token:
            return GmailWatchNotificationResponse(
                success=False,
                message="Invalid Gmail watch verification token.",
            )

        message = (envelope or {}).get("message") or {}
        data = message.get("data")
        if not data:
            return GmailWatchNotificationResponse(
                success=False,
                message="Pub/Sub payload did not include Gmail watch data.",
            )

        try:
            decoded = self._decode_base64(data)
            payload = json.loads(decoded)
        except Exception:
            logger.exception("Failed to decode Gmail watch Pub/Sub payload")
            return GmailWatchNotificationResponse(
                success=False,
                message="Failed to decode Gmail watch payload.",
            )

        email = payload.get("emailAddress")
        history_id = str(payload.get("historyId")) if payload.get("historyId") else None
        if not email:
            return GmailWatchNotificationResponse(
                success=False,
                message="Gmail watch payload did not include emailAddress.",
            )

        sync_response = await self.sync_messages(GmailSyncRequest(email=email, max_results=10))

        if history_id:
            connection = self._get_connection(email)
            self._update_connection_state(
                email,
                watch_configured=connection["watch_configured"] if connection else False,
                last_history_id=history_id,
            )

        return GmailWatchNotificationResponse(
            success=sync_response.success,
            email=email,
            history_id=history_id,
            synced_count=sync_response.synced_count,
            suspicious_count=sync_response.suspicious_count,
            message=sync_response.message or "Gmail watch notification processed.",
        )

    async def sync_messages(self, payload: GmailSyncRequest) -> GmailSyncResponse:
        connection = self._get_connection(payload.email)
        if not connection:
            return GmailSyncResponse(
                success=False,
                email=payload.email,
                synced_count=0,
                suspicious_count=0,
                watch_configured=False,
                last_history_id=None,
                message="Gmail account is not connected.",
                events=[],
            )
        try:
            current_profile = await self._fetch_profile(connection["access_token"])
            current_history_id = str(current_profile.get("historyId")) if current_profile.get("historyId") else None
            message_refs = await self._fetch_message_refs(
                access_token=connection["access_token"],
                email=payload.email,
                previous_history_id=connection.get("last_history_id"),
                current_history_id=current_history_id,
                max_results=payload.max_results,
            )

            suspicious_count = 0
            synced_count = 0
            events: list[ScanLogRecord] = []

            for message in message_refs:
                message_id = message["id"]
                try:
                    details = await self._call_gmail_api(
                        connection["access_token"],
                        "GET",
                        f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}",
                        params={"format": "full"},
                    )
                except httpx.HTTPStatusError as exc:
                    status_code = exc.response.status_code if exc.response else None
                    if status_code == 404:
                        logger.warning(
                            "Skipping Gmail message %s during sync because it is no longer available.",
                            message_id,
                        )
                        continue
                    raise
                content = self._extract_message_text(details)
                if not content:
                    continue

                embedded_urls = URL_REGEX.findall(content)
                embedded_url = embedded_urls[0] if embedded_urls else None
                result = self.detection_service.scan_text(content, "email")
                text_support = self.threat_intel_service.analyze_text_support(content, result)
                url_rule_result = self.detection_service.scan_url(embedded_url, "email") if embedded_url else None
                url_intel = await self.threat_intel_service.analyze_url(embedded_url) if embedded_url else None
                ai_assessment = await self.ai_service.assess_scan(
                    text=content,
                    url=embedded_url,
                    source_type="email",
                    rule_result=self.detection_service.scan_unified(content, embedded_url, "email")
                    if embedded_url
                    else result,
                    partial_scan=False,
                )
                result = (
                    self.threat_intel_service.compose_unified_result(
                        base_rule_result=self.detection_service.scan_unified(content, embedded_url, "email"),
                        text_rule_result=result,
                        url_rule_result=url_rule_result,
                        text_support=text_support,
                        url_intel=url_intel,
                        ai_assessment=ai_assessment,
                        source_type="email",
                        partial_scan=False,
                    )
                    if embedded_url and url_rule_result and url_intel
                    else self.threat_intel_service.compose_text_result(
                        rule_result=result,
                        text_support=text_support,
                        ai_assessment=ai_assessment,
                        source_type="email",
                        partial_scan=False,
                    )
                )
                status = "suspicious" if result.risk_score >= 35 else "safe"
                event_id = self.log_service.save_event(
                    ThreatEventUpsertRequest(
                        external_id=f"gmail:{message_id}",
                        source_type="email",
                        source_app="gmail",
                        content_preview=content[:200],
                        raw_text=content,
                        risk_score=result.risk_score,
                        reasons=result.reasons,
                        label=result.label,
                        status=status,
                        should_block=result.should_block,
                        metadata={
                            "gmail_message_id": message_id,
                            "detection_mode": result.detection_mode,
                            "partial_scan": result.partial_scan,
                            "ai_summary": result.ai_summary,
                        },
                    )
                )
                synced_count += 1
                if result.risk_score >= 35:
                    suspicious_count += 1

                if event_id:
                    record = self.log_service.list_recent(limit=200)
                    match = next((item for item in record if item.id == event_id), None)
                    if match:
                        events.append(match)

            self._update_connection_state(
                payload.email,
                watch_configured=connection["watch_configured"],
                last_history_id=current_history_id,
            )

            return GmailSyncResponse(
                success=True,
                email=payload.email,
                synced_count=synced_count,
                suspicious_count=suspicious_count,
                watch_configured=connection["watch_configured"],
                last_history_id=current_history_id,
                message=None,
                events=events,
            )
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code if exc.response else None
            message = "Gmail sync failed."
            if status_code in {401, 403}:
                message = "Gmail session expired or access was denied. Reconnect Gmail and try again."
            logger.warning("Gmail sync failed for %s with HTTP %s: %s", payload.email, status_code, exc)
            return GmailSyncResponse(
                success=False,
                email=payload.email,
                synced_count=0,
                suspicious_count=0,
                watch_configured=connection["watch_configured"],
                last_history_id=connection.get("last_history_id"),
                message=message,
                events=[],
            )
        except Exception as exc:
            logger.exception("Unexpected Gmail sync failure for %s", payload.email)
            return GmailSyncResponse(
                success=False,
                email=payload.email,
                synced_count=0,
                suspicious_count=0,
                watch_configured=connection["watch_configured"],
                last_history_id=connection.get("last_history_id"),
                message=f"Gmail sync failed: {exc}",
                events=[],
            )

    async def _fetch_profile(self, access_token: str) -> dict:
        return await self._call_gmail_api(
            access_token,
            "GET",
            "https://gmail.googleapis.com/gmail/v1/users/me/profile",
        )

    def _get_connection(self, email: str):
        with get_db_connection() as connection:
            row = connection.execute(
                """
                SELECT email, access_token, refresh_token, expires_at, watch_configured, last_history_id
                FROM gmail_connections
                WHERE email = ?
                """,
                (email,),
            ).fetchone()
        if not row:
            return None
        return {
            "email": row[0],
            "access_token": row[1],
            "refresh_token": row[2],
            "expires_at": row[3],
            "watch_configured": bool(row[4]),
            "last_history_id": row[5],
        }

    async def _fetch_message_refs(
        self,
        *,
        access_token: str,
        email: str,
        previous_history_id: Optional[str],
        current_history_id: Optional[str],
        max_results: int,
    ) -> list[dict]:
        if not previous_history_id and current_history_id:
            logger.info("Gmail sync baseline established at historyId=%s; skipping old inbox backlog.", current_history_id)
            return []

        if previous_history_id and current_history_id and previous_history_id == current_history_id:
            return []

        if previous_history_id and current_history_id and previous_history_id != current_history_id:
            try:
                history_data = await self._call_gmail_api(
                    access_token,
                    "GET",
                    "https://gmail.googleapis.com/gmail/v1/users/me/history",
                    params={
                        "startHistoryId": previous_history_id,
                        "historyTypes": "messageAdded",
                        "maxResults": max_results,
                    },
                )
                message_map: dict[str, dict] = {}
                for record in history_data.get("history", []):
                    for item in record.get("messagesAdded", []):
                        message = item.get("message") or {}
                        message_id = message.get("id")
                        if message_id:
                            message_map[message_id] = {"id": message_id}
                if message_map:
                    return list(message_map.values())[:max_results]
            except httpx.HTTPStatusError as exc:
                logger.warning("Gmail history sync unavailable, falling back to message list: %s", exc)

        return await self._fetch_recent_unlogged_message_refs(
            access_token=access_token,
            email=email,
            max_results=max_results,
        )

    async def _fetch_recent_unlogged_message_refs(
        self,
        *,
        access_token: str,
        email: str,
        max_results: int,
    ) -> list[dict]:
        list_data = await self._call_gmail_api(
            access_token,
            "GET",
            "https://gmail.googleapis.com/gmail/v1/users/me/messages",
            params={"labelIds": "INBOX", "maxResults": max_results * 3, "q": "newer_than:2d"},
        )
        candidates = list_data.get("messages", [])
        if not candidates:
            return []

        existing_ids = self._get_logged_gmail_message_ids(email=email)
        unseen = [message for message in candidates if f"gmail:{message.get('id')}" not in existing_ids]
        return unseen[:max_results]

    @staticmethod
    def _get_logged_gmail_message_ids(*, email: str) -> set[str]:
        with get_db_connection() as connection:
            rows = connection.execute(
                """
                SELECT external_id
                FROM scan_logs
                WHERE source_app = 'gmail'
                  AND external_id IS NOT NULL
                """
            ).fetchall()
        return {row[0] for row in rows if row and row[0]}

    def _update_connection_state(
        self,
        email: str,
        *,
        watch_configured: bool,
        last_history_id: Optional[str],
    ) -> None:
        with get_db_connection() as connection:
            connection.execute(
                """
                UPDATE gmail_connections
                SET watch_configured = ?, last_history_id = ?, updated_at = ?
                WHERE email = ?
                """,
                (
                    1 if watch_configured else 0,
                    last_history_id,
                    datetime.now(timezone.utc).isoformat(),
                    email,
                ),
            )
            connection.commit()

    async def _call_gmail_api(self, access_token: str, method: str, url: str, **kwargs):
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {access_token}"
        async with httpx.AsyncClient(timeout=20.0, trust_env=False) as client:
            response = await client.request(method, url, headers=headers, **kwargs)
            response.raise_for_status()
            return response.json()

    def _extract_message_text(self, details: dict) -> str:
        snippet = details.get("snippet", "")
        payload = details.get("payload", {})
        parts = payload.get("parts", []) or []
        plain_texts = [snippet] if snippet else []
        html_texts: list[str] = []

        def walk(part: dict):
            body = part.get("body", {})
            data = body.get("data")
            mime = part.get("mimeType", "")
            if data and mime.startswith("text/"):
                decoded = self._decode_base64(data)
                cleaned = self._clean_message_text(decoded, is_html=mime == "text/html")
                if not cleaned:
                    return
                if mime == "text/plain":
                    plain_texts.append(cleaned)
                elif mime == "text/html":
                    html_texts.append(cleaned)
            for child in part.get("parts", []) or []:
                walk(child)

        for part in parts:
            walk(part)

        if payload.get("body", {}).get("data"):
            cleaned = self._clean_message_text(self._decode_base64(payload["body"]["data"]), is_html=True)
            if cleaned:
                html_texts.append(cleaned)

        candidate_texts = plain_texts if plain_texts else html_texts
        deduped = list(dict.fromkeys(item.strip() for item in candidate_texts if item.strip()))
        return "\n\n".join(deduped).strip()

    @staticmethod
    def _decode_base64(value: str) -> str:
        padded = value + "=" * (-len(value) % 4)
        try:
            return base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8", errors="ignore")
        except Exception:
            return ""

    @staticmethod
    def _clean_message_text(value: str, *, is_html: bool) -> str:
        text = value or ""
        if is_html:
            text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", text)
            text = re.sub(r"(?i)<br\s*/?>", "\n", text)
            text = re.sub(r"(?i)</p>|</div>|</li>|</tr>|</h[1-6]>", "\n", text)
            text = re.sub(r"(?s)<[^>]+>", " ", text)
            text = unescape(text)
        text = text.replace("\r", "\n")
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        text = re.sub(r"(?i)^<!doctype html>.*?$", "", text, flags=re.MULTILINE)
        text = text.strip()
        return text[:4000]
