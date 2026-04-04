import asyncio
import base64
import hashlib
import json
import logging
from typing import Optional

import httpx

from app.core.config import Settings
from app.models.schemas import AttachmentUploadRequest, ScanResult
from app.utils.ai_fingerprint import analyze_ai_fingerprint
from app.utils.random_forest_support import score_url_with_random_forest_support
from app.utils.yara_support import score_rule_matches, scan_attachment_yara_support, scan_text_yara_support

logger = logging.getLogger(__name__)


def _clamp(value: int, minimum: int = 0, maximum: int = 100) -> int:
    return max(minimum, min(maximum, value))


def _classify(score: int) -> str:
    if score >= 70:
        return "phishing"
    if score >= 35:
        return "suspicious"
    return "safe"


def _risk_level(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _unique(values: list[str]) -> list[str]:
    filtered = [value for value in values if value]
    if len(filtered) > 1:
        filtered = [value for value in filtered if value != "No strong phishing indicators detected"]
    return list(dict.fromkeys(filtered))


class ThreatIntelService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def analyze_text_support(self, text: str, rule_result: ScanResult) -> dict:
        fingerprint = analyze_ai_fingerprint(text)
        yara_matches = scan_text_yara_support(text)
        yara_score = score_rule_matches(yara_matches)
        support_score = _clamp(
            round(max(rule_result.risk_score, (rule_result.risk_score * 0.6) + (fingerprint["score"] * 0.4)))
        )
        reasons = _unique(
            list(rule_result.reasons)
            + list(fingerprint["reasons"])
            + [match["reason"] for match in yara_matches]
        )
        return {
            "support_score": support_score,
            "ai_fingerprint_score": fingerprint["score"],
            "ai_fingerprint_signals": fingerprint["signals"],
            "ai_fingerprint_reasons": fingerprint["reasons"],
            "yara_score": yara_score,
            "yara_matches": yara_matches,
            "support_reasons": reasons,
        }

    async def analyze_url(self, url: str) -> dict:
        rf_score, rf_reasons, rf_features = score_url_with_random_forest_support(url)
        safe_browsing = await self._check_google_safe_browsing(url)
        virus_total = await self._check_virustotal_url(url)
        falcon = await self._check_falcon_url(url)
        return {
            "random_forest_score": rf_score,
            "random_forest_reasons": rf_reasons,
            "random_forest_features": rf_features,
            "components": [safe_browsing, falcon, virus_total],
        }

    async def analyze_attachments(
        self,
        attachments: list[AttachmentUploadRequest],
        analyzed_attachments: list[dict],
    ) -> dict:
        enriched_items = []
        combined_reasons: list[str] = []
        component_hits = 0

        for upload, analyzed in zip(attachments, analyzed_attachments):
            content = self._decode_base64(upload.content_base64)
            sha256 = hashlib.sha256(content).hexdigest() if content else None
            yara_matches = scan_attachment_yara_support(upload.file_name, content)
            yara_score = score_rule_matches(yara_matches)
            virus_total = await self._check_virustotal_file(upload, content, sha256)
            falcon = await self._check_falcon_file(upload, sha256)

            local_support_score = _clamp(
                max(
                    analyzed.get("finalRiskScore", 0),
                    round((analyzed.get("finalRiskScore", 0) * 0.7) + (yara_score * 0.3)),
                )
            )
            matched_components = [
                self._component(
                    "local_static_yara",
                    local_support_score,
                    25,
                    True,
                    _unique([*analyzed.get("evidenceSummary", []), *[match["reason"] for match in yara_matches]]),
                ),
            ]
            if falcon.get("matched"):
                matched_components.append(falcon | {"weight": 45})
            if virus_total.get("matched"):
                matched_components.append(virus_total | {"weight": 30})

            combined_score = self._weighted_score(matched_components, fallback=local_support_score)
            combined_score = max(combined_score, analyzed.get("finalRiskScore", 0))
            combined_level = _risk_level(combined_score)
            provider_reasons = _unique(
                [match["reason"] for match in yara_matches]
                + falcon.get("reasons", [])
                + virus_total.get("reasons", [])
            )
            if provider_reasons:
                component_hits += 1
            combined_reasons.extend(f'{upload.file_name}: {reason}' for reason in provider_reasons)

            updated_item = dict(analyzed)
            updated_item["sha256"] = sha256
            updated_item["externalRiskScore"] = combined_score
            updated_item["finalRiskScore"] = combined_score
            updated_item["finalRiskLevel"] = combined_level
            updated_item["vendorSignals"] = [
                {
                    "name": "Falcon Sandbox",
                    "matched": falcon.get("matched", False),
                    "score": falcon.get("score", 0),
                    "reasons": falcon.get("reasons", []),
                },
                {
                    "name": "VirusTotal",
                    "matched": virus_total.get("matched", False),
                    "score": virus_total.get("score", 0),
                    "reasons": virus_total.get("reasons", []),
                },
                {
                    "name": "YARA support rules",
                    "matched": bool(yara_matches),
                    "score": yara_score,
                    "reasons": [match["reason"] for match in yara_matches],
                },
            ]
            if provider_reasons:
                summary = updated_item.get("explanationSummary", "")
                vendor_summary = "; ".join(provider_reasons[:3])
                updated_item["explanationSummary"] = f"{summary} External intelligence: {vendor_summary}"

            enriched_items.append(updated_item)

        overall_score = round(sum(item.get("finalRiskScore", 0) for item in enriched_items) / len(enriched_items)) if enriched_items else 0
        return {
            "attachments": enriched_items,
            "overall_score": overall_score,
            "overall_level": _risk_level(overall_score),
            "combined_reasons": _unique(combined_reasons),
            "component_hits": component_hits,
        }

    def compose_text_result(
        self,
        *,
        rule_result: ScanResult,
        text_support: dict,
        ai_assessment: Optional[dict],
        source_type: str,
        partial_scan: bool = False,
    ) -> ScanResult:
        components = [
            self._component(
                "local_support",
                max(rule_result.risk_score, text_support["support_score"]),
                30 if ai_assessment else 70,
                True,
                text_support["support_reasons"],
            )
        ]
        if text_support["yara_score"] > 0:
            components.append(
                self._component(
                    "yara_text",
                    text_support["yara_score"],
                    15 if ai_assessment else 30,
                    True,
                    [match["reason"] for match in text_support["yara_matches"]],
                )
            )
        if ai_assessment:
            components.append(
                self._component(
                    "llm_reasoning",
                    ai_assessment["risk_score"],
                    55,
                    True,
                    ai_assessment.get("reasons", []),
                )
            )

        final_score = self._weighted_score(components, fallback=rule_result.risk_score)
        if partial_scan:
            final_score = min(final_score, 82)

        reasons = _unique(
            (list(ai_assessment.get("reasons", [])) if ai_assessment else [])
            + list(rule_result.reasons)
            + list(text_support["ai_fingerprint_reasons"])
            + [match["reason"] for match in text_support["yara_matches"]]
            + (["Partial notification metadata was scanned"] if partial_scan else [])
        )
        confidence = self._resolve_confidence(
            base_confidence=rule_result.confidence,
            ai_confidence=(ai_assessment or {}).get("confidence"),
            final_score=final_score,
            component_count=len(components),
            partial_scan=partial_scan,
        )
        detection_mode = "hybrid" if ai_assessment else "rule"
        summary = (
            ai_assessment.get("summary")
            if ai_assessment
            else "Groq was unavailable, so local AI-fingerprint heuristics and YARA support rules were used."
            if (text_support["ai_fingerprint_score"] > 0 or text_support["yara_score"] > 0)
            else rule_result.ai_summary
        )
        return self._build_result_from_rule(
            rule_result=rule_result,
            score=final_score,
            reasons=reasons,
            source_type=source_type,
            confidence=confidence,
            detection_mode=detection_mode,
            provider_used=(ai_assessment or {}).get("provider_used"),
            ai_summary=summary,
            partial_scan=partial_scan,
            threat_intel={
                "category": "text",
                "weighted_score": final_score,
                "components": components,
                "ai_fingerprint_signals": text_support["ai_fingerprint_signals"],
            },
        )

    def compose_url_result(
        self,
        *,
        rule_result: ScanResult,
        url_intel: dict,
        ai_assessment: Optional[dict],
        source_type: str,
        partial_scan: bool = False,
    ) -> ScanResult:
        components = [
            self._component(
                "local_url_support",
                max(rule_result.risk_score, url_intel["random_forest_score"]),
                16 if ai_assessment else 24,
                True,
                _unique(list(rule_result.reasons) + list(url_intel["random_forest_reasons"])),
            )
        ]
        for component in url_intel["components"]:
            if component.get("matched"):
                components.append(component)
        if ai_assessment:
            components.append(
                self._component(
                    "llm_page_analysis",
                    ai_assessment["risk_score"],
                    10,
                    True,
                    ai_assessment.get("reasons", []),
                )
            )

        final_score = self._weighted_score(
            components,
            fallback=max(rule_result.risk_score, url_intel["random_forest_score"]),
        )
        google_component = next((item for item in url_intel["components"] if item["name"] == "google_safe_browsing"), None)
        falcon_component = next((item for item in url_intel["components"] if item["name"] == "falcon_sandbox"), None)
        virus_component = next((item for item in url_intel["components"] if item["name"] == "virus_total"), None)
        if google_component and google_component.get("matched"):
            final_score = max(final_score, 88)
        elif falcon_component and falcon_component.get("matched"):
            final_score = max(final_score, 76)
        elif virus_component and virus_component.get("matched"):
            final_score = max(final_score, 66)
        if partial_scan:
            final_score = min(final_score, 86)

        reasons = _unique(
            list(rule_result.reasons)
            + list(url_intel["random_forest_reasons"])
            + [reason for component in url_intel["components"] for reason in component.get("reasons", [])]
            + (list(ai_assessment.get("reasons", [])) if ai_assessment else [])
            + (["Partial notification metadata was scanned"] if partial_scan else [])
        )
        confidence = self._resolve_confidence(
            base_confidence=rule_result.confidence,
            ai_confidence=(ai_assessment or {}).get("confidence"),
            final_score=final_score,
            component_count=len(components),
            partial_scan=partial_scan,
        )
        detection_mode = "hybrid" if ai_assessment or len(components) > 1 else "rule"
        summary = ai_assessment.get("summary") if ai_assessment else self._summarize_url_intel(url_intel)
        return self._build_result_from_rule(
            rule_result=rule_result,
            score=final_score,
            reasons=reasons,
            source_type=source_type,
            confidence=confidence,
            detection_mode=detection_mode,
            provider_used=(ai_assessment or {}).get("provider_used"),
            ai_summary=summary,
            partial_scan=partial_scan,
            threat_intel={
                "category": "url",
                "weighted_score": final_score,
                "components": components + [component for component in url_intel["components"] if not component.get("matched")],
                "random_forest_features": url_intel["random_forest_features"],
            },
        )

    def compose_unified_result(
        self,
        *,
        base_rule_result: ScanResult,
        text_rule_result: Optional[ScanResult],
        url_rule_result: Optional[ScanResult],
        text_support: Optional[dict],
        url_intel: Optional[dict],
        ai_assessment: Optional[dict],
        source_type: str,
        partial_scan: bool = False,
    ) -> ScanResult:
        if text_rule_result and not url_rule_result:
            return self.compose_text_result(
                rule_result=base_rule_result,
                text_support=text_support or self.analyze_text_support("", base_rule_result),
                ai_assessment=ai_assessment,
                source_type=source_type,
                partial_scan=partial_scan,
            )
        if url_rule_result and not text_rule_result:
            return self.compose_url_result(
                rule_result=base_rule_result,
                url_intel=url_intel
                or {
                    "random_forest_score": base_rule_result.risk_score,
                    "random_forest_reasons": [],
                    "random_forest_features": {},
                    "components": [],
                },
                ai_assessment=ai_assessment,
                source_type=source_type,
                partial_scan=partial_scan,
            )

        text_result = self.compose_text_result(
            rule_result=text_rule_result or base_rule_result,
            text_support=text_support or self.analyze_text_support("", text_rule_result or base_rule_result),
            ai_assessment=ai_assessment,
            source_type=source_type,
            partial_scan=partial_scan,
        )
        url_result = self.compose_url_result(
            rule_result=url_rule_result or base_rule_result,
            url_intel=url_intel
            or {
                "random_forest_score": base_rule_result.risk_score,
                "random_forest_reasons": [],
                "random_forest_features": {},
                "components": [],
            },
            ai_assessment=ai_assessment,
            source_type=source_type,
            partial_scan=partial_scan,
        )
        final_score = _clamp(round((text_result.risk_score * 0.45) + (url_result.risk_score * 0.55)))
        reasons = _unique(text_result.reasons + url_result.reasons)
        confidence = self._resolve_confidence(
            base_confidence=base_rule_result.confidence,
            ai_confidence=(ai_assessment or {}).get("confidence"),
            final_score=final_score,
            component_count=4,
            partial_scan=partial_scan,
        )
        detection_mode = (
            "hybrid"
            if ai_assessment or (url_intel and any(component.get("matched") for component in url_intel["components"]))
            else "rule"
        )
        summary = (
            ai_assessment.get("summary")
            if ai_assessment
            else "Unified phishing analysis used local heuristics, AI-fingerprint support, and URL reputation signals."
        )
        return self._build_result_from_rule(
            rule_result=base_rule_result,
            score=final_score,
            reasons=reasons,
            source_type=source_type,
            confidence=confidence,
            detection_mode=detection_mode,
            provider_used=(ai_assessment or {}).get("provider_used"),
            ai_summary=summary,
            partial_scan=partial_scan,
            threat_intel={
                "category": "unified",
                "weighted_score": final_score,
                "text_components": text_result.threat_intel,
                "url_components": url_result.threat_intel,
            },
        )

    def compose_attachment_result(
        self,
        *,
        rule_result: ScanResult,
        attachment_analysis: dict,
        attachment_intel: dict,
        ai_assessment: Optional[dict],
        source_type: str,
    ) -> ScanResult:
        local_support_score = attachment_intel["overall_score"]
        components = [
            self._component(
                "local_static_yara",
                local_support_score,
                24 if ai_assessment else 30,
                True,
                attachment_intel["combined_reasons"],
            )
        ]
        external_hit_reasons = []
        if any(
            signal.get("matched")
            for item in attachment_intel["attachments"]
            for signal in item.get("vendorSignals", [])
            if signal["name"] == "Falcon Sandbox"
        ):
            for item in attachment_intel["attachments"]:
                for signal in item.get("vendorSignals", []):
                    if signal["name"] == "Falcon Sandbox" and signal.get("matched"):
                        external_hit_reasons.extend(f'{item["fileName"]}: {reason}' for reason in signal.get("reasons", []))
            components.append(self._component("falcon_sandbox", attachment_intel["overall_score"], 46, True, external_hit_reasons))
        if any(
            signal.get("matched")
            for item in attachment_intel["attachments"]
            for signal in item.get("vendorSignals", [])
            if signal["name"] == "VirusTotal"
        ):
            for item in attachment_intel["attachments"]:
                for signal in item.get("vendorSignals", []):
                    if signal["name"] == "VirusTotal" and signal.get("matched"):
                        external_hit_reasons.extend(f'{item["fileName"]}: {reason}' for reason in signal.get("reasons", []))
            components.append(self._component("virus_total", attachment_intel["overall_score"], 32, True, external_hit_reasons))
        if ai_assessment:
            components.append(
                self._component(
                    "llm_attachment_enrichment",
                    ai_assessment["risk_score"],
                    8 if len(components) > 1 else 20,
                    True,
                    ai_assessment.get("reasons", []),
                )
            )

        attachment_score = self._weighted_score(components, fallback=local_support_score)
        attachment_score = max(attachment_score, attachment_intel["overall_score"])
        if any(
            signal.get("matched")
            for item in attachment_intel["attachments"]
            for signal in item.get("vendorSignals", [])
            if signal["name"] == "Falcon Sandbox"
        ):
            attachment_score = max(attachment_score, 78)
        elif any(
            signal.get("matched")
            for item in attachment_intel["attachments"]
            for signal in item.get("vendorSignals", [])
            if signal["name"] == "VirusTotal"
        ):
            attachment_score = max(attachment_score, 68)

        base_score = rule_result.base_risk_score or 0
        final_score = attachment_score if base_score == 0 else _clamp(round((base_score * 0.42) + (attachment_score * 0.58)))
        reasons = _unique(
            [reason for reason in rule_result.reasons if reason != "No strong phishing indicators detected"]
            + attachment_analysis.get("combinedReasons", [])
            + attachment_intel["combined_reasons"]
            + (list(ai_assessment.get("reasons", [])) if ai_assessment else [])
        )
        confidence = self._resolve_confidence(
            base_confidence=rule_result.confidence,
            ai_confidence=(ai_assessment or {}).get("confidence"),
            final_score=final_score,
            component_count=len(components),
            partial_scan=False,
        )
        detection_mode = "hybrid" if ai_assessment or attachment_intel["component_hits"] > 0 else "rule"
        summary = (
            ai_assessment.get("summary")
            if ai_assessment
            else f"Attachment intelligence used static analysis, YARA support rules, and external reputation checks to reach {attachment_score}/100 {_risk_level(attachment_score)} risk."
        )
        updated_attachment_analysis = dict(attachment_analysis)
        updated_attachment_analysis["attachments"] = attachment_intel["attachments"]
        updated_attachment_analysis["overallRiskScore"] = attachment_score
        updated_attachment_analysis["overallRiskLevel"] = _risk_level(attachment_score)
        updated_attachment_analysis["combinedReasons"] = _unique(
            list(attachment_analysis.get("combinedReasons", [])) + list(attachment_intel["combined_reasons"])
        )
        updated_attachment_analysis["externalReasonCount"] = attachment_intel["component_hits"]
        updated_attachment_analysis["simulated"] = False

        return self._build_result_from_rule(
            rule_result=rule_result,
            score=final_score,
            reasons=reasons,
            source_type=source_type,
            confidence=confidence,
            detection_mode=detection_mode,
            provider_used=(ai_assessment or {}).get("provider_used"),
            ai_summary=summary,
            partial_scan=False,
            base_risk_score=base_score,
            attachment_analysis=updated_attachment_analysis,
            threat_intel={
                "category": "attachment",
                "weighted_score": final_score,
                "components": components,
            },
        )

    async def _check_google_safe_browsing(self, url: str) -> dict:
        if not self.settings.google_safe_browsing_api_key:
            return self._component("google_safe_browsing", 0, 42, False, [], available=False)

        payload = {
            "client": {"clientId": "cybershield-ai", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            async with httpx.AsyncClient(timeout=self.settings.threat_intel_timeout_seconds, trust_env=False) as client:
                response = await client.post(
                    "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                    params={"key": self.settings.google_safe_browsing_api_key},
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
        except Exception as exc:
            logger.warning("Google Safe Browsing lookup failed: %s", exc)
            return self._component("google_safe_browsing", 0, 42, False, [], available=False, error=str(exc))

        matches = data.get("matches", [])
        if not matches:
            return self._component("google_safe_browsing", 0, 42, False, [], available=True)

        threat_types = sorted({match.get("threatType", "UNKNOWN") for match in matches})
        if "MALWARE" in threat_types:
            score = 100
        elif "SOCIAL_ENGINEERING" in threat_types:
            score = 96
        else:
            score = 88
        reasons = [f"Google Safe Browsing flagged this URL for {', '.join(threat_types).lower().replace('_', ' ')}."]
        return self._component(
            "google_safe_browsing",
            score,
            42,
            True,
            reasons,
            available=True,
            details={"threat_types": threat_types},
        )

    async def _check_virustotal_url(self, url: str) -> dict:
        if not self.settings.virus_total_api_key:
            return self._component("virus_total", 0, 20, False, [], available=False)

        headers = {"x-apikey": self.settings.virus_total_api_key}
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").strip("=")
        report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        try:
            async with httpx.AsyncClient(timeout=self.settings.threat_intel_timeout_seconds, trust_env=False) as client:
                response = await client.get(report_url, headers=headers)
                if response.status_code == 404:
                    submit = await client.post(
                        "https://www.virustotal.com/api/v3/urls",
                        headers=headers,
                        data={"url": url},
                    )
                    submit.raise_for_status()
                    await asyncio.sleep(1.0)
                    response = await client.get(report_url, headers=headers)
                response.raise_for_status()
                data = response.json()
        except Exception as exc:
            logger.warning("VirusTotal URL lookup failed: %s", exc)
            return self._component("virus_total", 0, 20, False, [], available=False, error=str(exc))

        stats = ((data.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
        return self._build_virustotal_component(stats, category="url")

    async def _check_virustotal_file(self, upload: AttachmentUploadRequest, content: bytes, sha256: Optional[str]) -> dict:
        if not self.settings.virus_total_api_key or not sha256:
            return self._component("virus_total", 0, 30, False, [], available=False)

        headers = {"x-apikey": self.settings.virus_total_api_key}
        report_url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        try:
            async with httpx.AsyncClient(timeout=self.settings.threat_intel_timeout_seconds, trust_env=False) as client:
                response = await client.get(report_url, headers=headers)
                if response.status_code == 404 and content:
                    files = {"file": (upload.file_name, content, upload.mime_type or "application/octet-stream")}
                    submit = await client.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)
                    submit.raise_for_status()
                    await asyncio.sleep(1.2)
                    response = await client.get(report_url, headers=headers)
                response.raise_for_status()
                data = response.json()
        except Exception as exc:
            logger.warning("VirusTotal file lookup failed for %s: %s", upload.file_name, exc)
            return self._component("virus_total", 0, 30, False, [], available=False, error=str(exc))

        stats = ((data.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
        return self._build_virustotal_component(stats, category="file")

    async def _check_falcon_url(self, url: str) -> dict:
        if not self.settings.falcon_sandbox_api_key:
            return self._component("falcon_sandbox", 0, 26, False, [], available=False)

        headers = {
            "api-key": self.settings.falcon_sandbox_api_key,
            "accept": "application/json",
            "user-agent": "Falcon Sandbox",
        }
        try:
            async with httpx.AsyncClient(timeout=self.settings.threat_intel_timeout_seconds, trust_env=False) as client:
                response = await client.post(
                    f"{self.settings.falcon_sandbox_base_url.rstrip('/')}/quick-scan/url",
                    headers=headers,
                    data={"url": url, "scan_type": "all"},
                )
                response.raise_for_status()
                data = response.json()
        except Exception as exc:
            logger.warning("Falcon Sandbox URL lookup failed: %s", exc)
            return self._component("falcon_sandbox", 0, 26, False, [], available=False, error=str(exc))

        return self._build_falcon_component(data)

    async def _check_falcon_file(self, upload: AttachmentUploadRequest, sha256: Optional[str]) -> dict:
        if not self.settings.falcon_sandbox_api_key or not sha256:
            return self._component("falcon_sandbox", 0, 45, False, [], available=False)

        headers = {
            "api-key": self.settings.falcon_sandbox_api_key,
            "accept": "application/json",
            "user-agent": "Falcon Sandbox",
        }
        try:
            async with httpx.AsyncClient(timeout=self.settings.threat_intel_timeout_seconds, trust_env=False) as client:
                response = await client.get(
                    f"{self.settings.falcon_sandbox_base_url.rstrip('/')}/search/hash",
                    headers=headers,
                    params={"hash": sha256},
                )
                response.raise_for_status()
                data = response.json()
        except Exception as exc:
            logger.warning("Falcon Sandbox file hash lookup failed for %s: %s", upload.file_name, exc)
            return self._component("falcon_sandbox", 0, 45, False, [], available=False, error=str(exc))

        return self._build_falcon_component(data)

    def _build_virustotal_component(self, stats: dict, *, category: str) -> dict:
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        total = sum(int(value or 0) for value in stats.values()) or 0
        if malicious == 0 and suspicious == 0:
            return self._component(
                "virus_total",
                0,
                20 if category == "url" else 30,
                False,
                [],
                available=True,
                details={"stats": stats},
            )

        ratio = ((malicious * 1.0) + (suspicious * 0.65)) / max(1, total)
        score = _clamp(round(62 + (ratio * 28) + min((malicious * 3) + (suspicious * 2), 16)))
        reasons = [
            f"VirusTotal flagged the {category} with {malicious} malicious and {suspicious} suspicious engine verdicts."
        ]
        return self._component(
            "virus_total",
            score,
            20 if category == "url" else 30,
            True,
            reasons,
            available=True,
            details={"stats": stats},
        )

    def _build_falcon_component(self, data: dict) -> dict:
        raw = data.get("scanners_v2") or data.get("scanners") or data.get("verdict") or data
        blob = json.dumps(raw, ensure_ascii=True).lower()
        if any(token in blob for token in ["malicious", "\"threat_level\":2", "\"threat_score\":100", "\"classification\":\"malicious\""]):
            return self._component(
                "falcon_sandbox",
                94,
                45,
                True,
                ["Falcon Sandbox marked this item as malicious in its sandbox verdict."],
                available=True,
                details={"raw": raw},
            )
        if any(token in blob for token in ["suspicious", "\"threat_level\":1", "\"classification\":\"suspicious\""]):
            return self._component(
                "falcon_sandbox",
                76,
                45,
                True,
                ["Falcon Sandbox reported suspicious behavior or indicators for this item."],
                available=True,
                details={"raw": raw},
            )
        return self._component("falcon_sandbox", 0, 45, False, [], available=True, details={"raw": raw})

    def _component(
        self,
        name: str,
        score: int,
        weight: int,
        matched: bool,
        reasons: list[str],
        *,
        available: bool = True,
        details: Optional[dict] = None,
        error: Optional[str] = None,
    ) -> dict:
        payload = {
            "name": name,
            "score": _clamp(score),
            "weight": weight,
            "matched": matched,
            "available": available,
            "reasons": _unique(reasons),
        }
        if details:
            payload["details"] = details
        if error:
            payload["error"] = error
        return payload

    def _weighted_score(self, components: list[dict], fallback: int) -> int:
        active = [component for component in components if component.get("matched")]
        if not active:
            return _clamp(fallback)
        total_weight = sum(max(1, int(component.get("weight", 0))) for component in active)
        weighted = sum(int(component.get("score", 0)) * max(1, int(component.get("weight", 0))) for component in active)
        return _clamp(round(weighted / max(1, total_weight)))

    def _resolve_confidence(
        self,
        *,
        base_confidence: float,
        ai_confidence: Optional[float],
        final_score: int,
        component_count: int,
        partial_scan: bool,
    ) -> float:
        resolved = max(base_confidence, min(0.95, final_score / 100))
        if ai_confidence is not None:
            resolved = max(resolved, float(ai_confidence))
        resolved = min(0.99, resolved + min(component_count * 0.03, 0.12))
        if partial_scan:
            resolved *= 0.8
        return round(max(0.2, resolved), 2)

    def _summarize_url_intel(self, url_intel: dict) -> str:
        matched = [component for component in url_intel["components"] if component.get("matched")]
        if matched:
            providers = ", ".join(component["name"].replace("_", " ") for component in matched)
            return f"URL intelligence used {providers} along with local heuristics and the support model."
        return "URL intelligence relied on local heuristics and the local support model because external engines did not flag the URL."

    def _build_result_from_rule(
        self,
        *,
        rule_result: ScanResult,
        score: int,
        reasons: list[str],
        source_type: str,
        confidence: float,
        detection_mode: str,
        provider_used: Optional[str],
        ai_summary: Optional[str],
        partial_scan: bool,
        threat_intel: Optional[dict] = None,
        base_risk_score: Optional[int] = None,
        attachment_analysis: Optional[dict] = None,
    ) -> ScanResult:
        final_score = _clamp(score)
        return rule_result.model_copy(
            update={
                "label": _classify(final_score),
                "risk_score": final_score,
                "reasons": _unique(reasons),
                "confidence": confidence,
                "source_type": source_type,
                "should_block": final_score >= 70 or rule_result.should_block,
                "detection_mode": detection_mode,
                "provider_used": provider_used,
                "ai_summary": ai_summary,
                "partial_scan": partial_scan,
                "base_risk_score": base_risk_score if base_risk_score is not None else rule_result.base_risk_score,
                "attachment_analysis": attachment_analysis if attachment_analysis is not None else rule_result.attachment_analysis,
                "threat_intel": threat_intel,
            }
        )

    @staticmethod
    def _decode_base64(content_base64: str) -> bytes:
        try:
            return base64.b64decode(content_base64, validate=True)
        except Exception:
            return b""
