from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from ..config import get_client_ip_from_request
    from ..models.database import get_db
    from ..models.schemas import (
        AttachmentScanRequest,
        AttachmentScanResponse,
        BatchScanRequest,
        ChatScanRequest,
        ChatScanResponse,
        EmailScanRequest,
        EmailScanResponse,
        URLScanRequest,
        URLScanResponse,
    )
    from ..services.aggregator import (
        scan_attachment_content,
        scan_batch_urls,
        scan_chat_content,
        scan_email_content,
        scan_single_url,
    )
except ImportError:  # pragma: no cover - supports running from package root
    from config import get_client_ip_from_request
    from models.database import get_db
    from models.schemas import (
        AttachmentScanRequest,
        AttachmentScanResponse,
        BatchScanRequest,
        ChatScanRequest,
        ChatScanResponse,
        EmailScanRequest,
        EmailScanResponse,
        URLScanRequest,
        URLScanResponse,
    )
    from services.aggregator import (
        scan_attachment_content,
        scan_batch_urls,
        scan_chat_content,
        scan_email_content,
        scan_single_url,
    )


router = APIRouter(tags=["scan"])


@router.post("/scan/url", response_model=URLScanResponse)
async def scan_url(
    payload: URLScanRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    return await scan_single_url(
        db,
        url=payload.url,
        source=payload.source.value,
        analysis_mode=payload.analysis_mode.value,
        ip_address=get_client_ip_from_request(request),
    )


@router.post("/scan/email", response_model=EmailScanResponse)
async def scan_email(
    payload: EmailScanRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    return await scan_email_content(
        db,
        content=payload.content,
        subject=payload.subject,
        links=payload.links,
        attachments=[item.model_dump() for item in payload.attachments],
        source=payload.source.value,
        ip_address=get_client_ip_from_request(request),
    )


@router.post("/scan/chat", response_model=ChatScanResponse)
async def scan_chat(
    payload: ChatScanRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    return await scan_chat_content(
        db,
        content=payload.content,
        sender=payload.sender,
        links=payload.links,
        attachments=[item.model_dump() for item in payload.attachments],
        source=payload.source.value,
        ip_address=get_client_ip_from_request(request),
    )


@router.post("/scan/attachment", response_model=AttachmentScanResponse)
async def scan_attachment(
    payload: AttachmentScanRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    return await scan_attachment_content(
        db,
        attachment=payload.attachment.model_dump(),
        source=payload.source.value,
        ip_address=get_client_ip_from_request(request),
        context_label=payload.context_label,
    )


@router.post("/scan/batch", response_model=list[URLScanResponse])
async def scan_batch(
    payload: BatchScanRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    return await scan_batch_urls(
        db,
        urls=payload.urls,
        source=payload.source.value,
        ip_address=get_client_ip_from_request(request),
    )
