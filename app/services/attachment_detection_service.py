import base64
import io
import re
import zipfile
from typing import Optional

from app.models.schemas import AttachmentUploadRequest, ScanResult
from app.services.detection_service import DetectionService

MAX_ATTACHMENT_BYTES = 4 * 1024 * 1024

FILE_TYPE_RISK = {
    "exe": (40, "critical", "Windows executable"),
    "dll": (36, "critical", "Dynamic library"),
    "scr": (36, "critical", "Screen saver executable"),
    "ps1": (34, "high", "PowerShell script"),
    "bat": (34, "high", "Batch script"),
    "cmd": (34, "high", "Command script"),
    "js": (32, "high", "JavaScript file"),
    "html": (28, "high", "HTML file"),
    "htm": (28, "high", "HTML file"),
    "zip": (24, "high", "ZIP archive"),
    "rar": (24, "high", "RAR archive"),
    "7z": (24, "high", "7-Zip archive"),
    "docm": (26, "high", "Macro-enabled Word document"),
    "xlsm": (26, "high", "Macro-enabled Excel workbook"),
    "pdf": (14, "medium", "PDF document"),
    "docx": (14, "medium", "Word document"),
    "xlsx": (14, "medium", "Excel workbook"),
}


def _clamp(value: int, minimum: int = 0, maximum: int = 100) -> int:
    return max(minimum, min(maximum, value))


def _risk_level(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _make_indicator(indicator_id: str, title: str, detail: str, severity: str, **extra) -> dict:
    return {
        "id": indicator_id,
        "title": title,
        "detail": detail,
        "severity": severity,
        **extra,
    }


def _extension(file_name: str) -> str:
    match = re.search(r"\.([a-z0-9]{1,8})$", file_name.lower())
    return match.group(1) if match else "unknown"


def _decode_text(content: bytes) -> str:
    preview = content[:300000]
    try:
        return preview.decode("utf-8", errors="ignore")
    except Exception:
        return preview.decode("latin-1", errors="ignore")


def _extract_urls_from_text(text: str) -> list[str]:
    return _unique(re.findall(r"https?://[^\s\"'<>]+", text, flags=re.IGNORECASE))


def _analyze_pdf(content: bytes) -> dict:
    text = _decode_text(content)
    lower = text.lower()
    urls = _extract_urls_from_text(text)
    lure_terms = {
        term
        for term in ["login", "verify", "password", "account", "bank", "otp", "signin", "sign in"]
        if term in lower
    }
    has_action_marker = any(marker in lower for marker in ["/uri", "/launch", "/openaction", "/submitform"])
    return {
        "urls": urls,
        "has_embedded_link": bool(urls) or has_action_marker,
        "has_javascript": "/javascript" in lower or "/js" in lower,
        "credential_lure": (
            len(lure_terms) >= 2 and (bool(urls) or has_action_marker or any(term in lure_terms for term in ["login", "verify", "password", "signin", "sign in"]))
        ),
    }


def _analyze_zip_like(content: bytes) -> dict:
    findings = {
        "nested_names": [],
        "encrypted": False,
        "external_links": [],
        "has_macro": False,
    }
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names = archive.namelist()
            findings["nested_names"] = names
            findings["encrypted"] = any(info.flag_bits & 0x1 for info in archive.infolist())
            findings["has_macro"] = any(name.lower().endswith("vbaproject.bin") for name in names)
            for name in names:
                lower_name = name.lower()
                if lower_name.endswith(".rels") or lower_name.endswith(".xml") or lower_name.endswith(".html"):
                    try:
                        member = archive.read(name)
                    except Exception:
                        continue
                    findings["external_links"].extend(_extract_urls_from_text(_decode_text(member)))
    except Exception:
        return findings

    findings["external_links"] = _unique(findings["external_links"])
    return findings


def _analyze_script_text(content: bytes) -> dict:
    text = _decode_text(content)
    lower = text.lower()
    return {
        "urls": _extract_urls_from_text(text),
        "redirect": bool(re.search(r"window\.location|document\.location|location\.href|redirect", lower)),
        "network": bool(re.search(r"fetch\(|axios|xmlhttprequest|websocket|sendbeacon", lower)),
        "credential_lure": bool(re.search(r"login|verify|password|credential|account|bank", lower)),
        "execution": bool(re.search(r"powershell|cmd\.exe|wscript|cscript|exec\(|spawn\(", lower)),
        "payload": bool(re.search(r"download|payload|dropper|install", lower)),
        "system_modification": bool(re.search(r"registry|startup|scheduled task|autorun|modify system", lower)),
    }


def _analyze_executable(content: bytes) -> dict:
    text = _decode_text(content)
    lower = text.lower()
    return {
        "mz_header": content[:2] == b"MZ",
        "urls": _extract_urls_from_text(text),
        "network": bool(re.search(r"http|https|winsock|wininet|urlmon", lower)),
        "payload": bool(re.search(r"download|payload|install|temp\\|appdata\\", lower)),
        "system_modification": bool(re.search(r"registry|runonce|startup|schtasks", lower)),
    }


class AttachmentDetectionService:
    def build_explainability_report(
        self,
        *,
        result: ScanResult,
        attachment_analysis: dict,
        text: Optional[str] = None,
        url: Optional[str] = None,
    ) -> dict:
        base_reasons = [
            reason
            for reason in result.reasons
            if reason not in set(attachment_analysis.get("combinedReasons", []))
            and not reason.startswith("Real attachment analysis added ")
        ]
        return self._build_explainability(
            risk_score=result.risk_score,
            base_risk_score=result.base_risk_score or 0,
            confidence=result.confidence,
            final_label=result.label,
            base_reasons=base_reasons,
            attachment_analysis=attachment_analysis,
            text=text,
            url=url,
        )

    def scan_attachments(
        self,
        attachments: list[AttachmentUploadRequest],
        detection_service: DetectionService,
        text: Optional[str] = None,
        url: Optional[str] = None,
        source_type: str = "unified",
        declared_attachments: Optional[list[dict]] = None,
    ) -> ScanResult:
        note_map = {
            str(item.get("fileName", "")).lower(): str(item.get("notes") or "")
            for item in (declared_attachments or [])
            if item.get("fileName")
        }

        analyzed = [
            self._analyze_attachment(upload, note_map.get(upload.file_name.lower()))
            for upload in attachments
        ]

        if text or url:
            base_result = detection_service.scan_unified(text, url, source_type)
            base_reasons = list(base_result.reasons)
            base_score = base_result.risk_score
        else:
            base_result = detection_service._build_result(
                risk_score=0,
                reasons=["No strong phishing indicators detected"],
                source_type=source_type,
                should_block=False,
                detection_mode="rule",
            )
            base_reasons = list(base_result.reasons)
            base_score = 0

        overall_attachment_score = (
            round(sum(item["finalRiskScore"] for item in analyzed) / len(analyzed)) if analyzed else 0
        )
        uplift = round(max(12, overall_attachment_score * 0.55)) if analyzed else 0
        final_score = (
            max(overall_attachment_score, _clamp(base_score + uplift))
            if not text and not url
            else _clamp(base_score + uplift)
        )
        final_label = "phishing" if final_score >= 80 else "suspicious" if final_score >= 45 else "safe"
        should_block = final_score >= 80 or any(item["finalRiskScore"] >= 85 for item in analyzed)
        combined_attachment_reasons = [
            *[
                f'{item["fileName"]}: {indicator["title"]}'
                for item in analyzed
                for indicator in item["staticIndicators"]
            ],
            *[
                f'{item["fileName"]}: {indicator["title"]} (simulated)'
                for item in analyzed
                for indicator in item["dynamicIndicators"]
            ],
        ]
        reasons = _unique(
            [
                *base_reasons,
                *combined_attachment_reasons,
                *(
                    [f"Real attachment analysis added {uplift} risk points based on file content and structure."]
                    if analyzed
                    else []
                ),
            ]
        )
        confidence = round(min(0.99, max(base_result.confidence, overall_attachment_score / 100, 0.35)), 2)
        attachment_analysis = {
            "attachments": analyzed,
            "overallRiskScore": overall_attachment_score,
            "overallRiskLevel": _risk_level(overall_attachment_score),
            "staticReasonCount": sum(len(item["staticIndicators"]) for item in analyzed),
            "dynamicReasonCount": sum(len(item["dynamicIndicators"]) for item in analyzed),
            "combinedReasons": combined_attachment_reasons,
            "simulated": False,
        }
        explainability = self._build_explainability(
            risk_score=final_score,
            base_risk_score=base_score,
            confidence=confidence,
            final_label=final_label,
            base_reasons=base_reasons,
            attachment_analysis=attachment_analysis,
            text=text,
            url=url,
        )

        return base_result.model_copy(
            update={
                "label": final_label,
                "risk_score": final_score,
                "reasons": reasons,
                "confidence": confidence,
                "source_type": source_type,
                "should_block": should_block,
                "detection_mode": "rule",
                "ai_summary": (
                    f"Real attachment analysis found {attachment_analysis['overallRiskScore']}/100 "
                    f"{attachment_analysis['overallRiskLevel']} risk across uploaded files."
                ),
                "base_risk_score": base_score,
                "attachment_analysis": attachment_analysis,
                "explainability": explainability,
            }
        )

    def build_ai_attachment_context(self, analyzed: list[dict]) -> dict:
        attachments_context = []
        for item in analyzed:
            attachments_context.append(
                {
                    "file_name": item["fileName"],
                    "file_type": item["fileTypeLabel"],
                    "risk_score": item["finalRiskScore"],
                    "risk_level": item["finalRiskLevel"],
                    "static_indicators": [indicator["title"] for indicator in item["staticIndicators"]],
                    "dynamic_indicators": [indicator["title"] for indicator in item["dynamicIndicators"]],
                    "evidence_urls": item.get("evidenceUrls", []),
                    "content_excerpt": item.get("contentExcerpt"),
                    "evidence_summary": item.get("evidenceSummary"),
                }
            )
        return {
            "attachments": attachments_context,
            "overall_risk_score": round(sum(item["finalRiskScore"] for item in analyzed) / len(analyzed)) if analyzed else 0,
        }

    def _analyze_attachment(self, upload: AttachmentUploadRequest, declared_notes: Optional[str]) -> dict:
        extension = _extension(upload.file_name)
        type_score, type_level, type_label = FILE_TYPE_RISK.get(
            extension, (8, "medium", f"{extension.upper()} file" if extension != "unknown" else "UNKNOWN file")
        )
        attachment_id = re.sub(r"[^a-z0-9]+", "-", upload.file_name.lower()).strip("-") or "attachment"
        static_indicators = [
            _make_indicator(
                f"{attachment_id}-type",
                "File type risk",
                f"{type_label} attachments can be used to deliver phishing lures or payloads.",
                type_level,
                category="file-type",
            )
        ]
        dynamic_indicators: list[dict] = []
        timeline = [
            {
                "id": f"{attachment_id}-open",
                "label": "File opened",
                "detail": f"{upload.file_name} is opened inside the safe analysis pipeline.",
                "severity": "low",
                "simulated": True,
            }
        ]

        try:
            content = base64.b64decode(upload.content_base64, validate=True)
        except Exception:
            content = b""
            static_indicators.append(
                _make_indicator(
                    f"{attachment_id}-decode-error",
                    "Attachment decoding issue",
                    "The uploaded attachment could not be decoded cleanly, so only metadata-based checks were applied.",
                    "medium",
                    category="file-type",
                )
            )

        if len(content) > MAX_ATTACHMENT_BYTES:
            content = content[:MAX_ATTACHMENT_BYTES]
            static_indicators.append(
                _make_indicator(
                    f"{attachment_id}-truncated",
                    "Large attachment sampled",
                    "Only the first part of this attachment was analyzed to keep the demo scan safe and fast.",
                    "medium",
                    category="file-type",
                )
            )

        lower_name = upload.file_name.lower()
        lower_notes = (declared_notes or "").lower()
        if re.search(r"\.(pdf|docx|xlsx|txt|jpg|png)\.(exe|js|html|scr|bat|cmd|ps1)$", lower_name):
            static_indicators.append(
                _make_indicator(
                    f"{attachment_id}-double-extension",
                    "Double extension detected",
                    f'The filename "{upload.file_name}" disguises an active file behind a document-like extension.',
                    "critical",
                    category="obfuscation",
                )
            )
        if re.search(r"invoice|statement|update|urgent|payment|account|secure|verify|login", lower_name):
            static_indicators.append(
                _make_indicator(
                    f"{attachment_id}-name",
                    "Suspicious filename pattern",
                    f'The filename "{upload.file_name}" uses wording often seen in phishing lures.',
                    "medium",
                    category="filename",
                )
            )

        features = {
            "urls": [],
            "has_embedded_link": False,
            "credential_lure": False,
            "redirect": False,
            "network": False,
            "execution": False,
            "payload": False,
            "system_modification": False,
            "has_macro": False,
            "encrypted": False,
            "nested_suspicious": False,
        }

        content_excerpt = None
        evidence_summary: list[str] = []

        if extension == "pdf":
            pdf = _analyze_pdf(content)
            features["urls"] = pdf["urls"]
            features["has_embedded_link"] = pdf["has_embedded_link"]
            features["execution"] = pdf["has_javascript"]
            features["credential_lure"] = pdf["credential_lure"]
            if pdf["urls"]:
                evidence_summary.append(f"Extracted {len(pdf['urls'])} URL(s) from PDF content.")
            if pdf["has_javascript"]:
                evidence_summary.append("PDF JavaScript marker detected.")
        elif extension in {"docx", "xlsx", "docm", "xlsm", "zip"}:
            archive = _analyze_zip_like(content)
            features["urls"] = archive["external_links"]
            features["has_embedded_link"] = bool(archive["external_links"])
            features["has_macro"] = archive["has_macro"] or extension in {"docm", "xlsm"}
            features["encrypted"] = archive["encrypted"]
            features["nested_suspicious"] = any(
                re.search(r"\.(exe|js|html|scr|ps1|bat|cmd)$", name.lower())
                or re.search(r"\.(pdf|docx|xlsx)\.(exe|js|html|scr|ps1|bat|cmd)$", name.lower())
                for name in archive["nested_names"]
            )
            if archive["nested_names"]:
                evidence_summary.append(
                    "Archive entries: " + ", ".join(archive["nested_names"][:6])
                )
            if archive["external_links"]:
                evidence_summary.append(
                    f"Found {len(archive['external_links'])} external link(s) in package relationships."
                )
        elif extension in {"html", "htm", "js", "txt", "json", "xml", "csv"}:
            script = _analyze_script_text(content)
            features["urls"] = script["urls"]
            features["has_embedded_link"] = bool(script["urls"])
            features["redirect"] = script["redirect"]
            features["network"] = script["network"]
            features["credential_lure"] = script["credential_lure"]
            features["execution"] = script["execution"] or extension == "js"
            features["payload"] = script["payload"]
            features["system_modification"] = script["system_modification"]
            decoded = _decode_text(content)
            content_excerpt = " ".join(decoded.split())[:260] or None
            if content_excerpt:
                evidence_summary.append("Readable attachment excerpt captured for AI review.")
        elif extension in {"exe", "dll", "scr"}:
            executable = _analyze_executable(content)
            features["urls"] = executable["urls"]
            features["network"] = executable["network"] or bool(executable["urls"])
            features["payload"] = executable["payload"]
            features["system_modification"] = executable["system_modification"]
            features["execution"] = executable["mz_header"]
            if executable["mz_header"]:
                evidence_summary.append("Executable MZ header detected.")
            if executable["urls"]:
                evidence_summary.append(f"Embedded URL strings found: {len(executable['urls'])}")

        if re.search(r"embedded link|browser|redirect|login|credential|network|payload|macro|script", lower_notes):
            features["has_embedded_link"] = features["has_embedded_link"] or "embedded link" in lower_notes
            features["redirect"] = features["redirect"] or bool(re.search(r"browser|redirect", lower_notes))
            features["credential_lure"] = features["credential_lure"] or bool(re.search(r"login|credential|verify|bank", lower_notes))
            features["network"] = features["network"] or "network" in lower_notes
            features["payload"] = features["payload"] or "payload" in lower_notes
            features["execution"] = features["execution"] or bool(re.search(r"macro|script|execution", lower_notes))

        if features["has_embedded_link"]:
            static_indicators.append(
                _make_indicator(
                    f"{attachment_id}-embedded-link",
                    "Embedded external link",
                    "The file contains real external URLs or document actions that point outside the attachment.",
                    "high",
                    category="embedded-link",
                )
            )
        if features["has_macro"]:
            static_indicators.append(
                _make_indicator(
                    f"{attachment_id}-macro",
                    "Macro-enabled behavior",
                    "The file structure contains real macro-enabled indicators.",
                    "high",
                    category="macro",
                )
            )
        if features["encrypted"] or extension in {"rar", "7z"}:
            static_indicators.append(
                _make_indicator(
                    f"{attachment_id}-archive",
                    "Archive evasion signal",
                    "This archive is encrypted or uses a container format that can hide nested payloads from shallow inspection.",
                    "high",
                    category="archive",
                )
            )
        elif extension == "zip":
            static_indicators.append(
                _make_indicator(
                    f"{attachment_id}-archive-container",
                    "Archive container attachment",
                    "Archive files can hide multiple nested files and delivery stages inside a single attachment.",
                    "medium",
                    category="archive",
                )
            )
        if features["nested_suspicious"]:
            static_indicators.append(
                _make_indicator(
                    f"{attachment_id}-hidden-exec",
                    "Hidden executable pattern",
                    "The uploaded archive contains nested filenames that resemble disguised executables or scripts.",
                    "critical",
                    category="obfuscation",
                )
            )

        def push_dynamic(suffix: str, title: str, detail: str, severity: str, behavior: str, step_label: str, step_detail: str):
            dynamic_indicators.append(
                _make_indicator(
                    f"{attachment_id}-{suffix}",
                    title,
                    detail,
                    severity,
                    behavior=behavior,
                    simulated=True,
                )
            )
            timeline.append(
                {
                    "id": f"{attachment_id}-{suffix}-step",
                    "label": step_label,
                    "detail": step_detail,
                    "severity": severity,
                    "simulated": True,
                }
            )

        if features["has_embedded_link"] or features["redirect"]:
            push_dynamic(
                "browser",
                "Browser launch attempt",
                "Real file content suggests the attachment opens or redirects the victim to an external destination.",
                "high" if features["has_embedded_link"] else "medium",
                "browser-open",
                "External link handling detected",
                "The analysis found a real URL or redirect marker tied to external browsing.",
            )
        if features["network"] or features["urls"]:
            push_dynamic(
                "network",
                "Suspicious network call",
                "The file contains real URLs or code patterns associated with outbound communication.",
                "high",
                "network-call",
                "Outbound communication predicted",
                "A follow-on network request is likely if the file is opened.",
            )
        if features["execution"] or features["has_macro"] or extension in {"exe", "dll", "scr", "js", "ps1", "bat", "cmd"}:
            push_dynamic(
                "execution",
                "Execution-like behavior",
                "Real content markers suggest script, macro, or executable behavior when opened.",
                "high",
                "execution",
                "Execution path detected",
                "The file structure indicates code or script execution capability.",
            )
        if features["credential_lure"]:
            push_dynamic(
                "credentials",
                "Credential capture flow",
                "The file content includes real login or account-verification wording often used to harvest credentials.",
                "critical",
                "credential-capture",
                "Credential lure identified",
                "The analysis found phishing-style login or verification language inside the attachment.",
            )
        if features["payload"] or features["nested_suspicious"]:
            push_dynamic(
                "payload",
                "Payload staging attempt",
                "The file structure suggests a follow-on payload, nested script, or download stage.",
                "critical" if features["nested_suspicious"] else "high",
                "payload-download",
                "Payload delivery chain predicted",
                "The file appears capable of unpacking or delivering an additional payload.",
            )
        if features["system_modification"]:
            push_dynamic(
                "system",
                "System modification attempt",
                "Real strings or code patterns suggest persistence or system configuration changes.",
                "high",
                "system-modification",
                "Persistence behavior predicted",
                "The file references actions consistent with startup or registry modification.",
            )

        if len(timeline) == 1:
            timeline.append(
                {
                    "id": f"{attachment_id}-benign-step",
                    "label": "No dangerous runtime behavior simulated",
                    "detail": "The real attachment content did not provide enough evidence for follow-on runtime abuse.",
                    "severity": "low",
                    "simulated": True,
                }
            )

        static_score = min(
            100,
            type_score
            + sum(22 if item["severity"] == "critical" else 16 if item["severity"] == "high" else 9 for item in static_indicators[1:]),
        )
        dynamic_score = min(
            100,
            sum(22 if item["severity"] == "critical" else 16 if item["severity"] == "high" else 10 for item in dynamic_indicators)
            + (8 if dynamic_indicators else 0),
        )
        final_score = _clamp(round(static_score * 0.55 + dynamic_score * 0.45))
        final_level = _risk_level(final_score)
        summary = (
            f"{upload.file_name} contains real structural indicators that strongly resemble phishing delivery."
            if final_score >= 70
            else f"{upload.file_name} shows several real suspicious attachment signals and should be handled carefully."
            if final_score >= 40
            else f"{upload.file_name} shows only limited suspicious indicators in the current real-file scan."
        )

        return {
            "id": attachment_id,
            "fileName": upload.file_name,
            "fileType": extension,
            "fileTypeLabel": type_label,
            "staticRiskScore": static_score,
            "dynamicRiskScore": dynamic_score,
            "finalRiskScore": final_score,
            "finalRiskLevel": final_level,
            "staticIndicators": static_indicators,
            "dynamicIndicators": dynamic_indicators,
            "timeline": timeline,
            "explanationSummary": summary,
            "evidenceUrls": features["urls"][:6],
            "contentExcerpt": content_excerpt,
            "evidenceSummary": evidence_summary[:6],
            "simulated": False,
        }

    def _build_explainability(
        self,
        risk_score: int,
        base_risk_score: int,
        confidence: float,
        final_label: str,
        base_reasons: list[str],
        attachment_analysis: dict,
        text: Optional[str],
        url: Optional[str],
    ) -> dict:
        attachment_reason_items = attachment_analysis.get("combinedReasons", [])
        final_reasons = [
            *([reason for reason in base_reasons if reason != "No strong phishing indicators detected"]),
            *attachment_reason_items,
        ] or ["No strong phishing indicators detected"]
        return {
            "riskScore": risk_score,
            "baseRiskScore": base_risk_score,
            "confidence": confidence,
            "finalLabel": final_label,
            "summary": (
                f"Real attachment analysis contributed {attachment_analysis['overallRiskScore']}/100 "
                f"{attachment_analysis['overallRiskLevel']} risk from actual file contents and structure."
                + (" Message text was also analyzed." if text else "")
                + (" A URL was also analyzed." if url else "")
            ),
            "overallReasons": final_reasons
            + [
                f"Overall attachment score: {attachment_analysis['overallRiskScore']}/100 {attachment_analysis['overallRiskLevel']} risk"
            ],
            "sections": [
                {
                    "key": "email",
                    "title": "Email / Message reasons",
                    "items": [reason for reason in base_reasons if "sender" in reason.lower() or "urgent" in reason.lower()],
                },
                {
                    "key": "url",
                    "title": "URL reasons",
                    "items": [*([f"Submitted URL: {url}"] if url else []), *[reason for reason in base_reasons if "url" in reason.lower() or "link" in reason.lower()]],
                },
                {
                    "key": "attachment",
                    "title": "Attachment reasons",
                    "items": attachment_reason_items,
                },
                {
                    "key": "final",
                    "title": "Final decision reasons",
                    "items": final_reasons,
                },
            ],
        }
