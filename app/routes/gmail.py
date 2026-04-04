from fastapi import APIRouter, Depends, Query, Request

from app.api.deps import get_gmail_service
from app.models.schemas import (
    GmailConnectRequest,
    GmailConnectResponse,
    GmailSyncRequest,
    GmailSyncResponse,
    GmailWatchNotificationResponse,
    GmailWatchSetupRequest,
    GmailWatchSetupResponse,
)
from app.services.gmail_service import GmailService

router = APIRouter(prefix="/gmail", tags=["gmail"])


@router.post("/connect", response_model=GmailConnectResponse)
async def gmail_connect(
    payload: GmailConnectRequest,
    gmail_service: GmailService = Depends(get_gmail_service),
) -> GmailConnectResponse:
    return await gmail_service.connect_account(payload)


@router.post("/watch/setup", response_model=GmailWatchSetupResponse)
async def gmail_watch_setup(
    payload: GmailWatchSetupRequest,
    gmail_service: GmailService = Depends(get_gmail_service),
) -> GmailWatchSetupResponse:
    return await gmail_service.setup_watch(payload)


@router.post("/sync", response_model=GmailSyncResponse)
async def gmail_sync(
    payload: GmailSyncRequest,
    gmail_service: GmailService = Depends(get_gmail_service),
) -> GmailSyncResponse:
    return await gmail_service.sync_messages(payload)


@router.post("/watch/notify", response_model=GmailWatchNotificationResponse)
async def gmail_watch_notify(
    request: Request,
    token: str | None = Query(default=None),
    gmail_service: GmailService = Depends(get_gmail_service),
) -> GmailWatchNotificationResponse:
    payload = await request.json()
    return await gmail_service.handle_watch_notification(
        envelope=payload,
        verification_token=token,
    )
