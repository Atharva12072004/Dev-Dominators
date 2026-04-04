from __future__ import annotations

import base64
import binascii
import re
from datetime import datetime
from enum import Enum
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator


MAX_URL_LENGTH = 2048


class SourceType(str, Enum):
    browser = "browser"
    email = "email"
    whatsapp = "whatsapp"
    manual = "manual"


class AnalysisMode(str, Enum):
    standard = "standard"
    sandbox = "sandbox"


class VerdictType(str, Enum):
    safe = "safe"
    suspicious = "suspicious"
    phishing = "phishing"
    malware = "malware"


class ContentType(str, Enum):
    url = "url"
    email = "email"
    chat = "chat"
    attachment = "attachment"
    content = "content"


class ActionType(str, Enum):
    allow = "allow"
    warn = "warn"
    block = "block"


def normalize_url(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        raise ValueError("URL cannot be empty")
    if len(candidate) > MAX_URL_LENGTH:
        raise ValueError(f"URL exceeds maximum length of {MAX_URL_LENGTH}")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", candidate):
        candidate = f"https://{candidate}"

    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https URLs are supported")
    if not parsed.netloc:
        raise ValueError("URL must include a host")
    sanitized_path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), sanitized_path, parsed.query, ""))


def normalize_domain(value: str) -> str:
    candidate = value.strip().lower()
    candidate = re.sub(r"^[a-z]+://", "", candidate)
    candidate = candidate.split("/")[0]
    if not candidate or "." not in candidate:
        raise ValueError("A valid domain is required")
    return candidate


class FlagSchema(BaseModel):
    rule: str
    severity: str
    description: str


class BlockingDecision(BaseModel):
    action: ActionType
    block_recommended: bool
    show_warning: bool
    reason_summary: str
    top_flags: list[str] = Field(default_factory=list)
    override_allowed: bool = True


class ScoreBreakdownItem(BaseModel):
    signal: str
    points: float
    severity: str = "info"
    description: str


class CampaignSummary(BaseModel):
    key: str
    size: int


class AttackChainStepSchema(BaseModel):
    step_order: int
    relation: str
    step_type: str
    label: str
    risk_score: int = 0
    verdict: str | None = None
    details: dict[str, Any] | None = None


class AttackChainSchema(BaseModel):
    id: int
    summary: str
    risk_score: int
    verdict: str
    content_type: str
    source: str
    created_at: datetime
    steps: list[AttackChainStepSchema] = Field(default_factory=list)


class AttachmentInput(BaseModel):
    filename: str = Field(..., min_length=1, max_length=255)
    content_base64: str = Field(..., min_length=1, max_length=20_000_000)
    mime_type: str | None = Field(default=None, max_length=255)

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise ValueError("Attachment filename cannot be empty")
        return candidate

    @field_validator("content_base64")
    @classmethod
    def validate_content_base64(cls, value: str) -> str:
        candidate = value.strip()
        if candidate.lower().startswith("data:") and "," in candidate:
            candidate = candidate.split(",", 1)[1]
        try:
            base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("Attachment content_base64 must be valid base64") from exc
        return value


class ChatScanRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=100_000)
    links: list[str] = Field(default_factory=list, max_length=20)
    attachments: list[AttachmentInput] = Field(default_factory=list, max_length=10)
    sender: str | None = Field(default=None, max_length=255)
    source: SourceType = SourceType.whatsapp

    @field_validator("links", mode="before")
    @classmethod
    def default_chat_links(cls, value: Any) -> list[str]:
        return value or []

    @field_validator("links")
    @classmethod
    def validate_chat_links(cls, value: list[str]) -> list[str]:
        return [normalize_url(item) for item in value]


class URLScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=MAX_URL_LENGTH)
    source: SourceType = SourceType.manual
    analysis_mode: AnalysisMode = AnalysisMode.standard

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return normalize_url(value)


class EmailScanRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=100_000)
    links: list[str] = Field(default_factory=list, max_length=20)
    attachments: list[AttachmentInput] = Field(default_factory=list, max_length=10)
    subject: str | None = Field(default=None, max_length=255)
    source: SourceType = SourceType.email

    @field_validator("links", mode="before")
    @classmethod
    def default_links(cls, value: Any) -> list[str]:
        return value or []

    @field_validator("links")
    @classmethod
    def validate_links(cls, value: list[str]) -> list[str]:
        return [normalize_url(item) for item in value]


class BatchScanRequest(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=20)
    source: SourceType = SourceType.manual

    @field_validator("urls")
    @classmethod
    def validate_urls(cls, value: list[str]) -> list[str]:
        if len(value) > 20:
            raise ValueError("Batch scanning is limited to 20 URLs")
        return [normalize_url(item) for item in value]


class AttachmentScanRequest(BaseModel):
    attachment: AttachmentInput
    source: SourceType = SourceType.manual
    context_label: str | None = Field(default=None, max_length=255)


class URLScanResponse(BaseModel):
    url: str
    risk_score: int
    verdict: VerdictType
    confidence: float
    engines: dict[str, Any]
    falcon_result: dict[str, Any] | None = None
    llm_analysis: dict[str, Any] | None = None
    flags: list[FlagSchema]
    score_breakdown: list[ScoreBreakdownItem] = Field(default_factory=list)
    detection_time_ms: int
    explainability_score: float
    block_decision: BlockingDecision
    ai_generated_probability: float = 0.0
    timestamp: datetime
    whitelisted: bool = False
    campaign: CampaignSummary | None = None


class AttachmentScanResponse(BaseModel):
    filename: str
    sha256: str
    mime_type: str | None = None
    detected_type: str | None = None
    extension: str | None = None
    file_size: int
    password_protected: bool = False
    contained_filenames: list[str] = Field(default_factory=list)
    extracted_urls: list[str] = Field(default_factory=list)
    extracted_url_scans: list[URLScanResponse] = Field(default_factory=list)
    risk_score: int
    verdict: VerdictType
    confidence: float
    engines: dict[str, Any]
    falcon_result: dict[str, Any] | None = None
    llm_analysis: dict[str, Any] | None = None
    flags: list[FlagSchema]
    score_breakdown: list[ScoreBreakdownItem] = Field(default_factory=list)
    detection_time_ms: int
    explainability_score: float
    block_decision: BlockingDecision
    ai_generated_probability: float = 0.0
    timestamp: datetime
    campaign: CampaignSummary | None = None


class EmailScanResponse(BaseModel):
    subject: str | None = None
    risk_score: int
    verdict: VerdictType
    confidence: float
    phishing_probability: float
    ai_generated_probability: float
    ai_fingerprint: dict[str, Any] | None = None
    falcon_result: dict[str, Any] | None = None
    llm_analysis: dict[str, Any] | None = None
    scanned_links: list[URLScanResponse]
    scanned_attachments: list[AttachmentScanResponse] = Field(default_factory=list)
    flags: list[FlagSchema]
    score_breakdown: list[ScoreBreakdownItem] = Field(default_factory=list)
    detection_time_ms: int
    explainability_score: float
    block_decision: BlockingDecision
    timestamp: datetime
    campaign: CampaignSummary | None = None


class ChatScanResponse(BaseModel):
    sender: str | None = None
    risk_score: int
    verdict: VerdictType
    confidence: float
    phishing_probability: float
    ai_generated_probability: float
    ai_fingerprint: dict[str, Any] | None = None
    falcon_result: dict[str, Any] | None = None
    llm_analysis: dict[str, Any] | None = None
    scanned_links: list[URLScanResponse]
    scanned_attachments: list[AttachmentScanResponse] = Field(default_factory=list)
    flags: list[FlagSchema]
    score_breakdown: list[ScoreBreakdownItem] = Field(default_factory=list)
    detection_time_ms: int
    explainability_score: float
    block_decision: BlockingDecision
    timestamp: datetime
    campaign: CampaignSummary | None = None


class HistoryItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    url_or_content: str
    content_type: str
    source: str
    risk_score: int
    verdict: str
    confidence: float
    flags: list[dict[str, Any]] | None = None
    detection_time_ms: int = 0
    explainability_score: float = 0.0
    recommended_action: str = "allow"
    block_recommended: bool = False
    ai_generated_probability: float = 0.0
    campaign_key: str | None = None
    actual_verdict: str | None = None
    feedback_timestamp: datetime | None = None
    timestamp: datetime
    ip_address: str | None = None


class HistoryDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    url_or_content: str
    content_type: str
    source: str
    risk_score: int
    verdict: str
    confidence: float
    gsb_result: dict[str, Any] | None = None
    urlhaus_result: dict[str, Any] | None = None
    yara_result: dict[str, Any] | None = None
    heuristics_result: dict[str, Any] | None = None
    vt_result: dict[str, Any] | None = None
    pt_result: dict[str, Any] | None = None
    falcon_result: dict[str, Any] | None = None
    llm_analysis: dict[str, Any] | None = None
    ai_fingerprint: dict[str, Any] | None = None
    flags: list[dict[str, Any]] | None = None
    score_breakdown: list[dict[str, Any]] | None = None
    detection_time_ms: int = 0
    explainability_score: float = 0.0
    recommended_action: str = "allow"
    block_recommended: bool = False
    ai_generated_probability: float = 0.0
    campaign_key: str | None = None
    actual_verdict: str | None = None
    feedback_notes: str | None = None
    feedback_timestamp: datetime | None = None
    timestamp: datetime
    ip_address: str | None = None
    campaign: CampaignSummary | None = None
    attack_chain: AttackChainSchema | None = None


class PaginatedHistoryResponse(BaseModel):
    page: int
    limit: int
    total: int
    items: list[HistoryItem]


class StatsResponse(BaseModel):
    total_scanned: int
    threats_blocked: int
    safe_count: int
    accuracy: float | None = None
    detection_accuracy: float | None = None
    false_positive_rate: float | None = None
    avg_detection_speed_ms: float
    p95_detection_speed_ms: float
    avg_explainability_score: float
    user_experience_score: float | None = None
    labeled_samples: int
    by_category: dict[str, int]
    by_day: list[dict[str, Any]]


class WhitelistCreateRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=255)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        return normalize_domain(value)


class WhitelistEntryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    domain: str
    added_at: datetime


class MessageResponse(BaseModel):
    message: str


class ScanFeedbackRequest(BaseModel):
    actual_verdict: VerdictType
    notes: str | None = Field(default=None, max_length=1000)


class ScanFeedbackResponse(BaseModel):
    id: int
    predicted_verdict: VerdictType
    actual_verdict: VerdictType
    message: str
