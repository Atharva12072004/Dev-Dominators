import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.deps import (
    get_ai_service,
    get_attachment_detection_service,
    get_detection_service,
    get_log_service,
    get_threat_intel_service,
)
from app.models.schemas import (
    AttachmentScanRequest,
    ScanLogRecord,
    ScanTextRequest,
    ScanResult,
    ScanUrlRequest,
    UnifiedScanRequest,
)
from app.services.ai_enhancement_service import AIEnhancementService
from app.services.attachment_detection_service import AttachmentDetectionService
from app.services.detection_service import DetectionService
from app.services.log_service import LogService
from app.services.threat_intel_service import ThreatIntelService
from app.utils.text import URL_REGEX

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scan", tags=["scan"])


@router.post("/text", response_model=ScanResult)
async def scan_text(
    payload: ScanTextRequest,
    detection_service: DetectionService = Depends(get_detection_service),
    ai_service: AIEnhancementService = Depends(get_ai_service),
    log_service: LogService = Depends(get_log_service),
    threat_intel_service: ThreatIntelService = Depends(get_threat_intel_service),
) -> ScanResult:
    partial_scan = bool(payload.metadata.get("partialContent") or payload.metadata.get("groupedNotification"))
    embedded_urls = URL_REGEX.findall(payload.text)
    embedded_url = embedded_urls[0] if embedded_urls else None
    result = detection_service.scan_text(payload.text, payload.source_type)
    text_support = threat_intel_service.analyze_text_support(payload.text, result)
    url_rule_result = detection_service.scan_url(embedded_url, payload.source_type) if embedded_url else None
    url_intel = await threat_intel_service.analyze_url(embedded_url) if embedded_url else None
    ai_assessment = None
    if payload.use_ai:
        ai_assessment = await ai_service.assess_scan(
            text=payload.text,
            url=embedded_url,
            source_type=payload.source_type,
            rule_result=detection_service.scan_unified(payload.text, embedded_url, payload.source_type)
            if embedded_url
            else result,
            partial_scan=partial_scan,
        )
    result = (
        threat_intel_service.compose_unified_result(
            base_rule_result=detection_service.scan_unified(payload.text, embedded_url, payload.source_type),
            text_rule_result=result,
            url_rule_result=url_rule_result,
            text_support=text_support,
            url_intel=url_intel,
            ai_assessment=ai_assessment,
            source_type=payload.source_type,
            partial_scan=partial_scan,
        )
        if embedded_url and url_rule_result and url_intel
        else threat_intel_service.compose_text_result(
            rule_result=result,
            text_support=text_support,
            ai_assessment=ai_assessment,
            source_type=payload.source_type,
            partial_scan=partial_scan,
        )
    )
    log_service.save_scan(result, content_preview=payload.text)
    logger.info("Text scan completed with label=%s risk_score=%s", result.label, result.risk_score)
    return result


@router.post("/url", response_model=ScanResult)
async def scan_url(
    payload: ScanUrlRequest,
    detection_service: DetectionService = Depends(get_detection_service),
    ai_service: AIEnhancementService = Depends(get_ai_service),
    log_service: LogService = Depends(get_log_service),
    threat_intel_service: ThreatIntelService = Depends(get_threat_intel_service),
) -> ScanResult:
    partial_scan = bool(payload.metadata.get("partialContent") or payload.metadata.get("groupedNotification"))
    result = detection_service.scan_url(payload.url, payload.source_type)
    url_intel = await threat_intel_service.analyze_url(payload.url)
    ai_assessment = None
    if payload.use_ai:
        ai_assessment = await ai_service.assess_scan(
            url=payload.url,
            source_type=payload.source_type,
            rule_result=result,
            partial_scan=partial_scan,
        )
    result = threat_intel_service.compose_url_result(
        rule_result=result,
        url_intel=url_intel,
        ai_assessment=ai_assessment,
        source_type=payload.source_type,
        partial_scan=partial_scan,
    )
    log_service.save_scan(result, content_preview=payload.url)
    logger.info("URL scan completed with label=%s risk_score=%s", result.label, result.risk_score)
    return result


@router.post("/unified", response_model=ScanResult)
async def scan_unified(
    payload: UnifiedScanRequest,
    detection_service: DetectionService = Depends(get_detection_service),
    ai_service: AIEnhancementService = Depends(get_ai_service),
    log_service: LogService = Depends(get_log_service),
    threat_intel_service: ThreatIntelService = Depends(get_threat_intel_service),
) -> ScanResult:
    if not payload.text and not payload.url:
        raise HTTPException(status_code=400, detail="At least one of text or url is required.")

    partial_scan = bool(payload.metadata.get("partialContent") or payload.metadata.get("groupedNotification"))
    result = detection_service.scan_unified(payload.text, payload.url, payload.source_type)
    text_rule_result = detection_service.scan_text(payload.text, payload.source_type) if payload.text else None
    url_rule_result = detection_service.scan_url(payload.url, payload.source_type) if payload.url else None
    text_support = threat_intel_service.analyze_text_support(payload.text, text_rule_result) if payload.text and text_rule_result else None
    url_intel = await threat_intel_service.analyze_url(payload.url) if payload.url else None
    ai_assessment = None
    if payload.use_ai:
        ai_assessment = await ai_service.assess_scan(
            text=payload.text,
            url=payload.url,
            source_type=payload.source_type,
            rule_result=result,
            partial_scan=partial_scan,
        )
    result = threat_intel_service.compose_unified_result(
        base_rule_result=result,
        text_rule_result=text_rule_result,
        url_rule_result=url_rule_result,
        text_support=text_support,
        url_intel=url_intel,
        ai_assessment=ai_assessment,
        source_type=payload.source_type,
        partial_scan=partial_scan,
    )
    log_service.save_scan(result, content_preview=payload.text or payload.url)
    logger.info("Unified scan completed with label=%s risk_score=%s", result.label, result.risk_score)
    return result


@router.post("/attachment", response_model=ScanResult)
async def scan_attachment(
    payload: AttachmentScanRequest,
    detection_service: DetectionService = Depends(get_detection_service),
    ai_service: AIEnhancementService = Depends(get_ai_service),
    attachment_detection_service: AttachmentDetectionService = Depends(get_attachment_detection_service),
    log_service: LogService = Depends(get_log_service),
    threat_intel_service: ThreatIntelService = Depends(get_threat_intel_service),
) -> ScanResult:
    if not payload.attachments:
        raise HTTPException(status_code=400, detail="At least one attachment is required.")

    result = attachment_detection_service.scan_attachments(
        attachments=payload.attachments,
        detection_service=detection_service,
        text=payload.text,
        url=payload.url,
        source_type=payload.source_type,
        declared_attachments=payload.metadata.get("attachments") if isinstance(payload.metadata, dict) else None,
    )
    attachment_analysis = result.attachment_analysis or {"attachments": [], "combinedReasons": []}
    attachment_intel = await threat_intel_service.analyze_attachments(
        payload.attachments,
        attachment_analysis.get("attachments", []),
    )
    ai_assessment = None
    if payload.use_ai:
        ai_assessment = await ai_service.assess_scan(
            text=payload.text,
            url=payload.url,
            attachment_context=attachment_detection_service.build_ai_attachment_context(
                attachment_intel["attachments"]
            ),
            source_type=payload.source_type,
            rule_result=result,
            partial_scan=False,
        )
    result = threat_intel_service.compose_attachment_result(
        rule_result=result,
        attachment_analysis=attachment_analysis,
        attachment_intel=attachment_intel,
        ai_assessment=ai_assessment,
        source_type=payload.source_type,
    )
    if result.attachment_analysis:
        result = result.model_copy(
            update={
                "explainability": attachment_detection_service.build_explainability_report(
                    result=result,
                    attachment_analysis=result.attachment_analysis,
                    text=payload.text,
                    url=payload.url,
                )
            }
        )
    log_service.save_scan(result, content_preview=payload.text or payload.url or payload.attachments[0].file_name)
    logger.info("Attachment scan completed with label=%s risk_score=%s", result.label, result.risk_score)
    return result


@router.get("/logs", response_model=list[ScanLogRecord])
def recent_logs(
    limit: int = Query(default=20, ge=1, le=100),
    log_service: LogService = Depends(get_log_service),
) -> list[ScanLogRecord]:
    return log_service.list_recent(limit=limit)
