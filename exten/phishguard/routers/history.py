from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import timezone

try:
    from ..models.database import AttackChain, AttackChainStep, ScanResult, WhitelistEntry, get_db
    from ..models.schemas import (
        HistoryItem,
        HistoryDetailResponse,
        MessageResponse,
        PaginatedHistoryResponse,
        ScanFeedbackRequest,
        ScanFeedbackResponse,
        WhitelistCreateRequest,
        WhitelistEntryResponse,
        normalize_domain,
    )
    from ..services import correlation
except ImportError:  # pragma: no cover - supports running from package root
    from models.database import AttackChain, AttackChainStep, ScanResult, WhitelistEntry, get_db
    from models.schemas import (
        HistoryItem,
        HistoryDetailResponse,
        MessageResponse,
        PaginatedHistoryResponse,
        ScanFeedbackRequest,
        ScanFeedbackResponse,
        WhitelistCreateRequest,
        WhitelistEntryResponse,
        normalize_domain,
    )
    from services import correlation


router = APIRouter(tags=["history"])

RISK_LEVEL_MAP = {
    "safe": (0, 30),
    "low": (0, 30),
    "suspicious": (31, 60),
    "medium": (31, 60),
    "phishing": (61, 85),
    "high": (61, 85),
    "malware": (86, 100),
    "critical": (86, 100),
}


@router.get("/history", response_model=PaginatedHistoryResponse)
async def get_history(
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=100),
    risk_level: str | None = Query(default=None),
    source: str | None = Query(default=None),
    date_from: datetime | None = Query(default=None),
    date_to: datetime | None = Query(default=None),
    search: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
) -> PaginatedHistoryResponse:
    query = select(ScanResult).order_by(ScanResult.timestamp.desc())

    if risk_level:
        bounds = RISK_LEVEL_MAP.get(risk_level.lower())
        if bounds:
            query = query.where(ScanResult.risk_score.between(bounds[0], bounds[1]))
        else:
            query = query.where(ScanResult.verdict == risk_level.lower())
    if source:
        query = query.where(ScanResult.source == source.lower())
    if date_from:
        query = query.where(ScanResult.timestamp >= date_from)
    if date_to:
        query = query.where(ScanResult.timestamp <= date_to)
    if search:
        query = query.where(func.lower(ScanResult.url_or_content).like(f"%{search.lower()}%"))

    total_query = select(func.count()).select_from(query.subquery())
    total = int((await db.execute(total_query)).scalar_one())

    paginated_query = query.offset((page - 1) * limit).limit(limit)
    records = (await db.execute(paginated_query)).scalars().all()
    return PaginatedHistoryResponse(
        page=page,
        limit=limit,
        total=total,
        items=[HistoryItem.model_validate(record) for record in records],
    )


@router.get("/history/{scan_id}", response_model=HistoryDetailResponse)
async def get_history_detail(
    scan_id: int = Path(..., ge=1),
    db: AsyncSession = Depends(get_db),
) -> HistoryDetailResponse:
    record = await db.get(ScanResult, scan_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="History entry not found")

    attack_chain = await correlation.get_attack_chain_for_scan(db, scan_id)
    campaign = await correlation.get_campaign_summary(db, record.campaign_key)
    payload = HistoryDetailResponse.model_validate(record).model_dump()
    heuristics_result = payload.get("heuristics_result") or {}
    payload["ai_fingerprint"] = heuristics_result.get("ai_fingerprint")
    payload["attack_chain"] = attack_chain
    payload["campaign"] = campaign
    return HistoryDetailResponse.model_validate(payload)


@router.delete("/history/all", response_model=MessageResponse)
async def delete_all_history(db: AsyncSession = Depends(get_db)) -> MessageResponse:
    await db.execute(delete(AttackChainStep))
    await db.execute(delete(AttackChain))
    result = await db.execute(delete(ScanResult))
    await db.commit()
    deleted_count = result.rowcount or 0
    return MessageResponse(message=f"Deleted {deleted_count} history records")


@router.delete("/history/{scan_id}", response_model=MessageResponse)
async def delete_history_item(
    scan_id: int = Path(..., ge=1),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    record = await db.get(ScanResult, scan_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="History entry not found")
    chain_ids = list((await db.execute(select(AttackChain.id).where(AttackChain.root_scan_id == scan_id))).scalars().all())
    if chain_ids:
        await db.execute(delete(AttackChainStep).where(AttackChainStep.chain_id.in_(chain_ids)))
        await db.execute(delete(AttackChain).where(AttackChain.id.in_(chain_ids)))
    await db.delete(record)
    await db.commit()
    return MessageResponse(message="History entry deleted")


@router.post("/history/{scan_id}/feedback", response_model=ScanFeedbackResponse)
async def submit_scan_feedback(
    scan_id: int,
    payload: ScanFeedbackRequest,
    db: AsyncSession = Depends(get_db),
) -> ScanFeedbackResponse:
    record = await db.get(ScanResult, scan_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="History entry not found")

    record.actual_verdict = payload.actual_verdict.value
    record.feedback_notes = payload.notes
    record.feedback_timestamp = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(record)
    return ScanFeedbackResponse(
        id=record.id,
        predicted_verdict=record.verdict,
        actual_verdict=payload.actual_verdict,
        message="Feedback recorded",
    )


@router.post("/whitelist", response_model=WhitelistEntryResponse, status_code=status.HTTP_201_CREATED)
async def add_whitelist_entry(
    payload: WhitelistCreateRequest,
    db: AsyncSession = Depends(get_db),
) -> WhitelistEntryResponse:
    existing = await db.execute(select(WhitelistEntry).where(WhitelistEntry.domain == payload.domain))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Domain already whitelisted")

    entry = WhitelistEntry(domain=payload.domain)
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return WhitelistEntryResponse.model_validate(entry)


@router.get("/whitelist", response_model=list[WhitelistEntryResponse])
async def list_whitelist(db: AsyncSession = Depends(get_db)) -> list[WhitelistEntryResponse]:
    records = (await db.execute(select(WhitelistEntry).order_by(WhitelistEntry.added_at.desc()))).scalars().all()
    return [WhitelistEntryResponse.model_validate(record) for record in records]


@router.delete("/whitelist/{domain}", response_model=MessageResponse)
async def delete_whitelist_entry(
    domain: str,
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    normalized = normalize_domain(domain)
    result = await db.execute(select(WhitelistEntry).where(WhitelistEntry.domain == normalized))
    record = result.scalar_one_or_none()
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Whitelist entry not found")
    await db.delete(record)
    await db.commit()
    return MessageResponse(message="Whitelist entry deleted")
