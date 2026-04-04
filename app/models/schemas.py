from datetime import datetime
from typing import Any, List, Literal, Optional

from pydantic import BaseModel, Field


ClassificationLabel = Literal["safe", "suspicious", "phishing"]
DetectionMode = Literal["ai", "rule", "hybrid"]
SourceType = Literal["text", "sms", "email", "url", "notification", "browser", "unified"]
ThreatStatus = Literal["pending", "safe", "suspicious", "blocked", "ignored"]


class ScanTextRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Raw text to scan.")
    source_type: Literal["text", "sms", "email", "notification"] = "text"
    metadata: dict = Field(default_factory=dict)
    use_ai: bool = False


class ScanUrlRequest(BaseModel):
    url: str = Field(..., min_length=3, description="URL to scan.")
    source_type: Literal["url", "browser"] = "url"
    metadata: dict = Field(default_factory=dict)
    use_ai: bool = False


class UnifiedScanRequest(BaseModel):
    text: Optional[str] = None
    url: Optional[str] = None
    source_type: SourceType = "unified"
    metadata: dict = Field(default_factory=dict)
    use_ai: bool = False


class AttachmentUploadRequest(BaseModel):
    file_name: str = Field(..., min_length=1)
    mime_type: Optional[str] = None
    size: Optional[int] = Field(default=None, ge=0)
    content_base64: str = Field(..., min_length=8)


class AttachmentScanRequest(BaseModel):
    text: Optional[str] = None
    url: Optional[str] = None
    source_type: SourceType = "unified"
    metadata: dict = Field(default_factory=dict)
    use_ai: bool = False
    attachments: List[AttachmentUploadRequest] = Field(default_factory=list)


class ExplanationRequest(BaseModel):
    label: ClassificationLabel
    risk_score: int = Field(..., ge=0, le=100)
    reasons: List[str] = Field(default_factory=list)
    text: Optional[str] = None
    url: Optional[str] = None
    preferred_provider: Optional[Literal["openai", "gemini", "grok"]] = None


class ScanResult(BaseModel):
    label: ClassificationLabel
    risk_score: int = Field(..., ge=0, le=100)
    reasons: List[str]
    confidence: float = Field(..., ge=0.0, le=1.0)
    source_type: SourceType
    should_block: bool
    detection_mode: DetectionMode = "rule"
    provider_used: Optional[str] = None
    ai_summary: Optional[str] = None
    partial_scan: bool = False
    base_risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    attachment_analysis: Optional[dict[str, Any]] = None
    explainability: Optional[dict[str, Any]] = None
    threat_intel: Optional[dict[str, Any]] = None


class ExplainResponse(BaseModel):
    explanation: str
    provider_used: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    app_name: str
    environment: str
    timestamp: datetime


class ScanLogRecord(BaseModel):
    id: int
    status: ThreatStatus = "pending"
    source_type: str
    source_app: Optional[str] = None
    content_preview: Optional[str]
    raw_text: Optional[str] = None
    raw_url: Optional[str] = None
    label: str
    risk_score: int
    should_block: bool
    reasons: List[str]
    provider_used: Optional[str]
    created_at: datetime
    external_id: Optional[str] = None


class ThreatEventUpsertRequest(BaseModel):
    external_id: Optional[str] = None
    source_type: SourceType | Literal["gmail"] = "text"
    source_app: Optional[str] = None
    content_preview: str
    raw_text: Optional[str] = None
    raw_url: Optional[str] = None
    risk_score: int = Field(..., ge=0, le=100)
    reasons: List[str] = Field(default_factory=list)
    label: ClassificationLabel
    status: ThreatStatus = "pending"
    should_block: bool = False
    metadata: dict = Field(default_factory=dict)


class GmailConnectRequest(BaseModel):
    access_token: str = Field(..., min_length=10)
    refresh_token: Optional[str] = None
    email: Optional[str] = None
    expires_at: Optional[int] = None


class GmailConnectResponse(BaseModel):
    connected: bool
    email: str
    watch_configured: bool
    last_history_id: Optional[str] = None


class GmailWatchSetupRequest(BaseModel):
    email: str


class GmailWatchSetupResponse(BaseModel):
    success: bool
    email: str
    watch_configured: bool
    message: str
    realtime_ready: bool = False


class GmailSyncRequest(BaseModel):
    email: str
    max_results: int = Field(default=10, ge=1, le=50)


class GmailSyncResponse(BaseModel):
    success: bool
    email: str
    synced_count: int
    suspicious_count: int
    watch_configured: bool = False
    last_history_id: Optional[str] = None
    message: Optional[str] = None
    events: List[ScanLogRecord]


class GmailWatchNotificationResponse(BaseModel):
    success: bool
    email: Optional[str] = None
    history_id: Optional[str] = None
    synced_count: int = 0
    suspicious_count: int = 0
    message: str
