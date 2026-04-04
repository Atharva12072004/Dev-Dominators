from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from ..models.database import ScanResult, get_db
    from ..models.schemas import StatsResponse
except ImportError:  # pragma: no cover - supports running from package root
    from models.database import ScanResult, get_db
    from models.schemas import StatsResponse


router = APIRouter(tags=["stats"])
DAILY_ACTIVITY_WINDOW_DAYS = 14


def _percentile(values: list[int], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round((percentile / 100) * (len(ordered) - 1)))))
    return float(ordered[index])


@router.get("/stats", response_model=StatsResponse)
async def get_stats(db: AsyncSession = Depends(get_db)) -> StatsResponse:
    total_scanned = int((await db.execute(select(func.count()).select_from(ScanResult))).scalar_one() or 0)
    threats_blocked = int(
        (
            await db.execute(
                select(func.count()).select_from(ScanResult).where(ScanResult.verdict.in_(["phishing", "malware"]))
            )
        ).scalar_one()
        or 0
    )
    safe_count = int(
        (await db.execute(select(func.count()).select_from(ScanResult).where(ScanResult.verdict == "safe"))).scalar_one() or 0
    )
    detection_speed_rows = (
        await db.execute(select(ScanResult.detection_time_ms).where(ScanResult.detection_time_ms.is_not(None)))
    ).scalars().all()
    explainability_rows = (
        await db.execute(select(ScanResult.explainability_score).where(ScanResult.explainability_score.is_not(None)))
    ).scalars().all()
    labeled_rows = (
        await db.execute(
            select(ScanResult.verdict, ScanResult.actual_verdict).where(ScanResult.actual_verdict.is_not(None))
        )
    ).all()

    category_rows = await db.execute(select(ScanResult.verdict, func.count()).group_by(ScanResult.verdict))
    by_category = {verdict: count for verdict, count in category_rows.all()}

    since = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(
        days=DAILY_ACTIVITY_WINDOW_DAYS - 1
    )
    daily_rows = (
        await db.execute(
            select(ScanResult.timestamp, ScanResult.verdict).where(ScanResult.timestamp >= since).order_by(ScanResult.timestamp.asc())
        )
    ).all()
    daily_bucket: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "blocked": 0})
    for timestamp, verdict in daily_rows:
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        day_key = timestamp.astimezone(timezone.utc).date().isoformat()
        daily_bucket[day_key]["total"] += 1
        if verdict in {"phishing", "malware"}:
            daily_bucket[day_key]["blocked"] += 1

    by_day: list[dict[str, int | str]] = []
    for offset in range(DAILY_ACTIVITY_WINDOW_DAYS):
        day = (since + timedelta(days=offset)).date().isoformat()
        bucket = daily_bucket.get(day, {"total": 0, "blocked": 0})
        by_day.append({"date": day, "total": bucket["total"], "blocked": bucket["blocked"]})

    threat_labels = {"suspicious", "phishing", "malware"}
    labeled_samples = len(labeled_rows)
    detection_accuracy = 0.0
    false_positive_rate = 0.0
    if labeled_rows:
        correct = 0
        false_positives = 0
        actual_safe_count = 0
        for predicted_verdict, actual_verdict in labeled_rows:
            predicted_threat = predicted_verdict in threat_labels
            actual_threat = actual_verdict in threat_labels
            if predicted_threat == actual_threat:
                correct += 1
            if not actual_threat:
                actual_safe_count += 1
                if predicted_threat:
                    false_positives += 1
        detection_accuracy = round(correct / labeled_samples, 4)
        false_positive_rate = round(false_positives / actual_safe_count, 4) if actual_safe_count else 0.0

    avg_detection_speed_ms = round(sum(detection_speed_rows) / len(detection_speed_rows), 2) if detection_speed_rows else 0.0
    p95_detection_speed_ms = round(_percentile(list(detection_speed_rows), 95), 2) if detection_speed_rows else 0.0
    avg_explainability_score = round(sum(explainability_rows) / len(explainability_rows), 2) if explainability_rows else 0.0

    latency_component = 0.0
    if avg_detection_speed_ms > 0:
        latency_component = max(0.0, min(1.0, 1 - (avg_detection_speed_ms / 5000)))
    explainability_component = avg_explainability_score / 100 if avg_explainability_score else 0.0
    if labeled_samples > 0:
        false_positive_component = max(0.0, min(1.0, 1 - false_positive_rate))
        user_experience_score = round(
            ((latency_component * 0.35) + (explainability_component * 0.3) + (false_positive_component * 0.35)) * 100,
            2,
        )
    else:
        user_experience_score = round(((latency_component * 0.55) + (explainability_component * 0.45)) * 100, 2)

    return StatsResponse(
        total_scanned=total_scanned,
        threats_blocked=threats_blocked,
        safe_count=safe_count,
        accuracy=detection_accuracy,
        detection_accuracy=detection_accuracy,
        false_positive_rate=false_positive_rate,
        avg_detection_speed_ms=avg_detection_speed_ms,
        p95_detection_speed_ms=p95_detection_speed_ms,
        avg_explainability_score=avg_explainability_score,
        user_experience_score=user_experience_score,
        labeled_samples=labeled_samples,
        by_category=by_category,
        by_day=by_day,
    )
