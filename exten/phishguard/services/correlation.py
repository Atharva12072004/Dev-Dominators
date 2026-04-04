from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from ..models.database import AttackChain, AttackChainStep, ScanResult
except ImportError:  # pragma: no cover - supports running from package root
    from models.database import AttackChain, AttackChainStep, ScanResult


STOP_WORDS = {
    "the",
    "and",
    "for",
    "your",
    "with",
    "this",
    "that",
    "from",
    "have",
    "please",
    "account",
    "message",
    "chat",
    "email",
}


def _tokenize(value: str | None) -> list[str]:
    return [token for token in re.findall(r"[a-z0-9]{4,}", (value or "").lower()) if token not in STOP_WORDS]


def _normalize_domains(urls: list[str] | None) -> list[str]:
    domains: set[str] = set()
    for url in urls or []:
        hostname = (urlsplit(url).hostname or "").lower()
        if hostname:
            domains.add(hostname)
    return sorted(domains)


def build_campaign_key(
    *,
    content_type: str,
    source: str,
    primary_text: str | None = None,
    subject: str | None = None,
    sender: str | None = None,
    urls: list[str] | None = None,
    flags: list[dict[str, object]] | None = None,
    attachment_hashes: list[str] | None = None,
) -> str | None:
    domains = _normalize_domains(urls)
    flag_rules = sorted(
        {
            str(flag.get("rule", "")).lower()
            for flag in flags or []
            if str(flag.get("severity", "")).lower() in {"medium", "high"}
        }
    )
    text_tokens = sorted(set(_tokenize(subject) + _tokenize(sender) + _tokenize(primary_text)))[:6]
    hash_tokens = sorted((attachment_hashes or [])[:3])

    signal_parts = [
        "|".join(domains[:4]),
        "|".join(flag_rules[:4]),
        "|".join(text_tokens),
        "|".join(hash_tokens),
    ]
    if not any(signal_parts):
        return None

    raw = "||".join([content_type, source, *signal_parts])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


async def get_campaign_summary(db: AsyncSession, campaign_key: str | None) -> dict[str, object] | None:
    if not campaign_key:
        return None
    count = int(
        (
            await db.execute(
                select(func.count()).select_from(ScanResult).where(ScanResult.campaign_key == campaign_key)
            )
        ).scalar_one()
        or 0
    )
    return {
        "key": campaign_key,
        "size": count,
    }


async def create_attack_chain(
    db: AsyncSession,
    *,
    root_scan_id: int,
    content_type: str,
    source: str,
    risk_score: int,
    verdict: str,
    summary: str,
    steps: list[dict[str, object]],
) -> int | None:
    if not steps:
        return None

    chain = AttackChain(
        root_scan_id=root_scan_id,
        content_type=content_type,
        source=source,
        risk_score=risk_score,
        verdict=verdict,
        summary=summary,
    )
    db.add(chain)
    await db.flush()

    for index, step in enumerate(steps):
        db.add(
            AttackChainStep(
                chain_id=chain.id,
                step_order=int(step.get("step_order", index)),
                relation=str(step.get("relation", "relates_to")),
                step_type=str(step.get("step_type", "artifact")),
                label=str(step.get("label", "")),
                risk_score=int(step.get("risk_score", 0)),
                verdict=str(step["verdict"]) if step.get("verdict") is not None else None,
                details=step.get("details") if isinstance(step.get("details"), dict) else None,
            )
        )

    await db.commit()
    await db.refresh(chain)
    return chain.id


async def get_attack_chain_for_scan(db: AsyncSession, scan_id: int) -> dict[str, object] | None:
    chain = (
        await db.execute(
            select(AttackChain).where(AttackChain.root_scan_id == scan_id).order_by(AttackChain.created_at.desc())
        )
    ).scalar_one_or_none()
    if chain is None:
        return None

    steps = (
        await db.execute(
            select(AttackChainStep)
            .where(AttackChainStep.chain_id == chain.id)
            .order_by(AttackChainStep.step_order.asc(), AttackChainStep.id.asc())
        )
    ).scalars().all()

    return {
        "id": chain.id,
        "summary": chain.summary,
        "risk_score": chain.risk_score,
        "verdict": chain.verdict,
        "content_type": chain.content_type,
        "source": chain.source,
        "created_at": chain.created_at,
        "steps": [
            {
                "step_order": step.step_order,
                "relation": step.relation,
                "step_type": step.step_type,
                "label": step.label,
                "risk_score": step.risk_score,
                "verdict": step.verdict,
                "details": step.details,
            }
            for step in steps
        ],
    }
