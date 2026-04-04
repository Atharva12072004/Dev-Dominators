from fastapi import Depends

from app.core.config import Settings, get_settings
from app.services.ai_enhancement_service import AIEnhancementService
from app.services.attachment_detection_service import AttachmentDetectionService
from app.services.detection_service import DetectionService
from app.services.gmail_service import GmailService
from app.services.log_service import LogService
from app.services.threat_intel_service import ThreatIntelService


def get_detection_service() -> DetectionService:
    return DetectionService()


def get_attachment_detection_service() -> AttachmentDetectionService:
    return AttachmentDetectionService()


def get_ai_service(settings: Settings = Depends(get_settings)) -> AIEnhancementService:
    return AIEnhancementService(settings)


def get_threat_intel_service(settings: Settings = Depends(get_settings)) -> ThreatIntelService:
    return ThreatIntelService(settings)


def get_log_service() -> LogService:
    return LogService()


def get_gmail_service(
    detection_service: DetectionService = Depends(get_detection_service),
    log_service: LogService = Depends(get_log_service),
    ai_service: AIEnhancementService = Depends(get_ai_service),
    threat_intel_service: ThreatIntelService = Depends(get_threat_intel_service),
) -> GmailService:
    return GmailService(detection_service, log_service, ai_service, threat_intel_service)
