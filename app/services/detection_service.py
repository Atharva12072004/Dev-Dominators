from typing import Optional

from app.models.schemas import ScanResult
from app.utils.text import analyze_text_indicators
from app.utils.url import analyze_url_indicators


class DetectionService:
    def scan_text(self, text: str, source_type: str = "text") -> ScanResult:
        risk_score, reasons = analyze_text_indicators(text)
        return self._build_result(
            risk_score=risk_score,
            reasons=reasons,
            source_type=source_type,
            should_block=risk_score >= 70,
            detection_mode="rule",
        )

    def scan_url(self, url: str, source_type: str = "url") -> ScanResult:
        risk_score, reasons = analyze_url_indicators(url)
        return self._build_result(
            risk_score=risk_score,
            reasons=reasons,
            source_type=source_type,
            should_block=risk_score >= 65,
            detection_mode="rule",
        )

    def scan_unified(
        self,
        text: Optional[str] = None,
        url: Optional[str] = None,
        source_type: str = "unified",
    ) -> ScanResult:
        total_score = 0
        reasons: list[str] = []

        if text:
            text_score, text_reasons = analyze_text_indicators(text)
            total_score += text_score
            reasons.extend(text_reasons)

        if url:
            url_score, url_reasons = analyze_url_indicators(url)
            total_score += url_score
            reasons.extend(url_reasons)

        if not text and not url:
            reasons.append("No scanable text or URL provided")

        normalized_score = min(total_score, 100)
        return self._build_result(
            risk_score=normalized_score,
            reasons=reasons or ["No strong phishing indicators detected"],
            source_type=source_type,
            should_block=normalized_score >= 65,
            detection_mode="rule",
        )

    def merge_ai_with_rule(
        self,
        rule_result: ScanResult,
        ai_assessment: Optional[dict],
        source_type: str,
        partial_scan: bool = False,
    ) -> ScanResult:
        if not ai_assessment:
            fallback_confidence = min(rule_result.confidence, 0.55) if partial_scan else rule_result.confidence
            return rule_result.model_copy(
                update={
                    "source_type": source_type,
                    "partial_scan": partial_scan,
                    "confidence": round(fallback_confidence, 2),
                    "ai_summary": (
                        "Exact message content was not available. Partial scan applied."
                        if partial_scan
                        else rule_result.ai_summary
                    ),
                }
            )

        ai_score = int(ai_assessment["risk_score"])
        rule_score = rule_result.risk_score
        final_score = round((ai_score * 0.7) + (rule_score * 0.3))
        if partial_scan:
            final_score = min(final_score, 82)
        reasons = list(
            dict.fromkeys(
                (ai_assessment.get("reasons") or [])
                + rule_result.reasons
                + (["Partial notification metadata was scanned"] if partial_scan else [])
            )
        )
        confidence = float(ai_assessment.get("confidence") or 0.45)
        final_confidence = min(0.99, max(0.2 if partial_scan else 0.35, confidence * (0.72 if partial_scan else 0.96)))

        return self._build_result(
            risk_score=max(final_score, rule_score if rule_result.label == "phishing" else 0),
            reasons=reasons,
            source_type=source_type,
            should_block=final_score >= 65 or rule_result.should_block,
            detection_mode="hybrid",
            provider_used=ai_assessment.get("provider_used"),
            ai_summary=ai_assessment.get("summary"),
            confidence=final_confidence,
            partial_scan=partial_scan,
        )

    def _build_result(
        self,
        risk_score: int,
        reasons: list[str],
        source_type: str,
        should_block: bool,
        detection_mode: str = "rule",
        provider_used: Optional[str] = None,
        ai_summary: Optional[str] = None,
        confidence: Optional[float] = None,
        partial_scan: bool = False,
    ) -> ScanResult:
        label = self._classify(risk_score)
        resolved_confidence = confidence if confidence is not None else min(0.99, max(0.15, risk_score / 100))
        unique_reasons = list(dict.fromkeys(reasons or ["No strong phishing indicators detected"]))
        return ScanResult(
            label=label,
            risk_score=risk_score,
            reasons=unique_reasons,
            confidence=round(resolved_confidence, 2),
            source_type=source_type,
            should_block=should_block,
            detection_mode=detection_mode,
            provider_used=provider_used,
            ai_summary=ai_summary,
            partial_scan=partial_scan,
        )

    @staticmethod
    def _classify(risk_score: int) -> str:
        if risk_score >= 70:
            return "phishing"
        if risk_score >= 35:
            return "suspicious"
        return "safe"
