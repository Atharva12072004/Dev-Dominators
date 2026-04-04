from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

try:
    from ..config import get_settings
except ImportError:  # pragma: no cover - supports running from package root
    from config import get_settings


settings = get_settings()


class Base(DeclarativeBase):
    pass


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    url_or_content: Mapped[str] = mapped_column(Text, nullable=False)
    content_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    gsb_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    urlhaus_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    yara_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    heuristics_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    vt_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    pt_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    falcon_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    llm_analysis: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    flags: Mapped[list | None] = mapped_column(JSON, nullable=True, default=list)
    score_breakdown: Mapped[list | None] = mapped_column(JSON, nullable=True, default=list)
    detection_time_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    explainability_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    recommended_action: Mapped[str] = mapped_column(String(16), nullable=False, default="allow")
    block_recommended: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ai_generated_probability: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    campaign_key: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    actual_verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    feedback_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    feedback_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)


class AttackChain(Base):
    __tablename__ = "attack_chains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    root_scan_id: Mapped[int] = mapped_column(ForeignKey("scan_results.id"), nullable=False, index=True)
    content_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AttackChainStep(Base):
    __tablename__ = "attack_chain_steps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    chain_id: Mapped[int] = mapped_column(ForeignKey("attack_chains.id"), nullable=False, index=True)
    step_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    relation: Mapped[str] = mapped_column(String(64), nullable=False)
    step_type: Mapped[str] = mapped_column(String(32), nullable=False)
    label: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class WhitelistEntry(Base):
    __tablename__ = "whitelist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


engine = create_async_engine(settings.database_url, future=True, echo=False)
AsyncSessionLocal = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


async def init_db() -> None:
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        if settings.database_url.startswith("sqlite"):
            await _ensure_sqlite_columns(connection)


async def _ensure_sqlite_columns(connection) -> None:
    existing_columns = {
        row[1]
        for row in (await connection.execute(text("PRAGMA table_info(scan_results)"))).all()
    }
    column_statements = {
        "score_breakdown": "ALTER TABLE scan_results ADD COLUMN score_breakdown JSON",
        "detection_time_ms": "ALTER TABLE scan_results ADD COLUMN detection_time_ms INTEGER DEFAULT 0",
        "explainability_score": "ALTER TABLE scan_results ADD COLUMN explainability_score FLOAT DEFAULT 0.0",
        "recommended_action": "ALTER TABLE scan_results ADD COLUMN recommended_action VARCHAR(16) DEFAULT 'allow'",
        "block_recommended": "ALTER TABLE scan_results ADD COLUMN block_recommended BOOLEAN DEFAULT 0",
        "ai_generated_probability": "ALTER TABLE scan_results ADD COLUMN ai_generated_probability FLOAT DEFAULT 0.0",
        "campaign_key": "ALTER TABLE scan_results ADD COLUMN campaign_key VARCHAR(64)",
        "falcon_result": "ALTER TABLE scan_results ADD COLUMN falcon_result JSON",
        "llm_analysis": "ALTER TABLE scan_results ADD COLUMN llm_analysis JSON",
        "actual_verdict": "ALTER TABLE scan_results ADD COLUMN actual_verdict VARCHAR(32)",
        "feedback_notes": "ALTER TABLE scan_results ADD COLUMN feedback_notes TEXT",
        "feedback_timestamp": "ALTER TABLE scan_results ADD COLUMN feedback_timestamp DATETIME",
    }
    for column_name, statement in column_statements.items():
        if column_name not in existing_columns:
            await connection.execute(text(statement))
