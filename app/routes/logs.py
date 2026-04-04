from fastapi import APIRouter, Depends, Query

from app.api.deps import get_log_service
from app.models.schemas import ScanLogRecord
from app.services.log_service import LogService

router = APIRouter(tags=["logs"])


@router.get("/logs", response_model=list[ScanLogRecord])
def get_logs(
    limit: int = Query(default=50, ge=1, le=200),
    log_service: LogService = Depends(get_log_service),
) -> list[ScanLogRecord]:
    return log_service.list_recent(limit=limit)
