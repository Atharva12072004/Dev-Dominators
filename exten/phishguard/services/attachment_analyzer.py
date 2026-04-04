from __future__ import annotations

import base64
import binascii
import hashlib
import io
import mimetypes
import re
import zipfile
from pathlib import Path
from typing import Any

try:
    from ..config import get_settings
    from . import heuristics
except ImportError:  # pragma: no cover - supports running from package root
    from config import get_settings
    from services import heuristics


settings = get_settings()

DANGEROUS_EXTENSION_POINTS: dict[str, int] = {
    ".exe": 65,
    ".dll": 60,
    ".scr": 60,
    ".js": 42,
    ".jse": 42,
    ".vbs": 42,
    ".vbe": 42,
    ".ps1": 45,
    ".bat": 40,
    ".cmd": 40,
    ".hta": 45,
    ".lnk": 45,
    ".jar": 38,
    ".iso": 36,
    ".img": 32,
    ".zip": 20,
    ".rar": 20,
    ".7z": 20,
    ".html": 24,
    ".htm": 24,
}
OFFICE_EXTENSIONS = {".doc", ".docm", ".docx", ".xls", ".xlsm", ".xlsx", ".ppt", ".pptm", ".pptx"}
TEXTUAL_SUFFIXES = {
    ".txt",
    ".csv",
    ".json",
    ".xml",
    ".html",
    ".htm",
    ".js",
    ".vbs",
    ".ps1",
    ".bat",
    ".cmd",
    ".url",
}
SCRIPT_MARKERS = {
    r"\binvoke-webrequest\b": ("high", 18),
    r"\bfrombase64string\b": ("high", 16),
    r"\bpowershell(?:\.exe)?\b": ("high", 18),
    r"\bwscript\.shell\b": ("high", 16),
    r"\bcreateobject\(": ("high", 16),
    r"\bcmd\.exe\b": ("medium", 12),
    r"\bwindow\.location\b": ("medium", 12),
    r"\bdocument\.write\b": ("medium", 10),
    r"\bmshta\b": ("high", 18),
}


def _flag(rule: str, severity: str, description: str) -> dict[str, str]:
    return {
        "rule": rule,
        "severity": severity,
        "description": description,
    }


def _score_item(signal: str, points: float, description: str, severity: str = "info") -> dict[str, Any]:
    return {
        "signal": signal,
        "points": round(float(points), 2),
        "severity": severity,
        "description": description,
    }


def decode_attachment_payload(content_base64: str) -> bytes:
    candidate = (content_base64 or "").strip()
    if candidate.lower().startswith("data:") and "," in candidate:
        candidate = candidate.split(",", 1)[1]
    try:
        return base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Attachment content_base64 is invalid") from exc


def _detect_type(content: bytes) -> str:
    prefix = content[:32]
    if prefix.startswith(b"MZ"):
        return "portable_executable"
    if prefix.startswith(b"%PDF"):
        return "pdf"
    if prefix.startswith(b"PK\x03\x04"):
        return "zip_archive"
    if prefix.startswith(b"Rar!\x1A\x07"):
        return "rar_archive"
    if prefix.startswith(b"7z\xBC\xAF\x27\x1C"):
        return "seven_zip_archive"
    if prefix.startswith(b"\xD0\xCF\x11\xE0"):
        return "ole_document"
    lowered = prefix.lower()
    if lowered.lstrip().startswith(b"<!doctype html") or lowered.lstrip().startswith(b"<html"):
        return "html"
    if lowered.startswith(b"#!/") or b"powershell" in lowered:
        return "script_text"
    return "unknown"


def _guess_mime_type(filename: str, mime_type: str | None) -> str | None:
    if mime_type:
        return mime_type
    guessed, _ = mimetypes.guess_type(filename)
    return guessed


def _extract_ascii_urls(content: bytes) -> list[str]:
    matches = re.findall(rb"https?://[^\s\"'<>]+", content, flags=re.IGNORECASE)
    urls = []
    for match in matches:
        try:
            urls.append(match.decode("utf-8", errors="ignore"))
        except Exception:
            continue
    return list(dict.fromkeys(urls))


def _safe_decode_text(content: bytes) -> str:
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return content.decode(encoding)
        except UnicodeDecodeError:
            continue
    return content.decode("utf-8", errors="ignore")


def _analyze_text_payload(text: str) -> tuple[float, list[dict[str, str]], list[dict[str, Any]]]:
    score = 0.0
    flags: list[dict[str, str]] = []
    breakdown: list[dict[str, Any]] = []
    normalized = text.lower()

    for pattern, (severity, points) in SCRIPT_MARKERS.items():
        if re.search(pattern, normalized):
            score += points
            flags.append(_flag("script_marker", severity, f"Attachment script marker detected: {pattern}"))
            breakdown.append(_score_item("script_marker", points, f"Attachment contains script marker {pattern}", severity))

    if "<form" in normalized and ("password" in normalized or "login" in normalized):
        score += 28
        flags.append(_flag("credential_harvest_attachment", "high", "Attachment contains HTML credential collection elements"))
        breakdown.append(
            _score_item(
                "credential_harvest_attachment",
                28,
                "Attachment contains HTML form elements consistent with credential harvesting",
                "high",
            )
        )

    if re.search(r"hxxps?://|\[\.\]|\(\.\)", normalized):
        score += 14
        flags.append(_flag("obfuscated_url_text", "high", "Attachment contains obfuscated URLs"))
        breakdown.append(_score_item("obfuscated_url_text", 14, "Attachment contains obfuscated URLs", "high"))

    if "/javascript" in normalized or "/launch" in normalized:
        score += 24
        flags.append(_flag("active_pdf_content", "high", "Attachment references active PDF actions"))
        breakdown.append(_score_item("active_pdf_content", 24, "PDF-like attachment contains active content markers", "high"))

    return score, flags, breakdown


def _analyze_zip_archive(
    filename: str,
    content: bytes,
) -> tuple[float, list[dict[str, str]], list[dict[str, Any]], list[str], list[str], bool]:
    score = 0.0
    flags: list[dict[str, str]] = []
    breakdown: list[dict[str, Any]] = []
    contained_filenames: list[str] = []
    extracted_urls: list[str] = []
    password_protected = False

    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            for info in archive.infolist()[:50]:
                contained_filenames.append(info.filename)
                if info.flag_bits & 0x1:
                    password_protected = True
                suffix = Path(info.filename).suffix.lower()
                if suffix in DANGEROUS_EXTENSION_POINTS:
                    points = min(24, max(DANGEROUS_EXTENSION_POINTS[suffix] * 0.4, 10))
                    score += points
                    flags.append(
                        _flag(
                            "archive_contains_risky_file",
                            "high",
                            f"Archive contains potentially dangerous file '{info.filename}'",
                        )
                    )
                    breakdown.append(
                        _score_item(
                            "archive_contains_risky_file",
                            points,
                            f"Archive contains risky nested file '{info.filename}'",
                            "high",
                        )
                    )
                if info.filename.lower().endswith("vbaproject.bin"):
                    score += 35
                    flags.append(_flag("macro_enabled_document", "high", "Archive contains VBA macro project"))
                    breakdown.append(
                        _score_item(
                            "macro_enabled_document",
                            35,
                            "Archive contains VBA macro project content",
                            "high",
                        )
                    )

                if suffix in TEXTUAL_SUFFIXES and info.file_size <= 250_000:
                    try:
                        extracted_bytes = archive.read(info.filename)
                    except RuntimeError:
                        password_protected = True
                        continue
                    extracted_urls.extend(heuristics.extract_urls_from_text(_safe_decode_text(extracted_bytes)))
                    extracted_urls.extend(_extract_ascii_urls(extracted_bytes))
    except zipfile.BadZipFile:
        return score, flags, breakdown, contained_filenames, extracted_urls, password_protected

    if password_protected:
        score += 26
        flags.append(_flag("encrypted_archive", "high", "Archive appears password protected or encrypted"))
        breakdown.append(
            _score_item(
                "encrypted_archive",
                26,
                "Password-protected archive reduces visibility and is commonly abused in phishing delivery",
                "high",
            )
        )

    return score, flags, breakdown, contained_filenames, extracted_urls, password_protected


def analyze_attachment(filename: str, content: bytes, mime_type: str | None = None) -> dict[str, Any]:
    extension = Path(filename).suffix.lower() or None
    file_size = len(content)
    sha256 = hashlib.sha256(content).hexdigest()
    detected_type = _detect_type(content)
    normalized_mime = _guess_mime_type(filename, mime_type)

    score = 0.0
    flags: list[dict[str, str]] = []
    breakdown: list[dict[str, Any]] = []
    contained_filenames: list[str] = []
    extracted_urls: list[str] = []
    password_protected = False

    if file_size > settings.max_attachment_bytes:
        score += 30
        flags.append(_flag("oversized_attachment", "high", "Attachment exceeds the configured scan size limit"))
        breakdown.append(
            _score_item(
                "oversized_attachment",
                30,
                f"Attachment size {file_size} bytes exceeds configured limit {settings.max_attachment_bytes}",
                "high",
            )
        )

    if extension in DANGEROUS_EXTENSION_POINTS:
        points = DANGEROUS_EXTENSION_POINTS[extension]
        severity = "high" if points >= 35 else "medium"
        score += points
        flags.append(_flag("dangerous_extension", severity, f"Attachment uses risky extension '{extension}'"))
        breakdown.append(_score_item("dangerous_extension", points, f"Attachment uses risky extension '{extension}'", severity))

    suffixes = [suffix.lower() for suffix in Path(filename).suffixes]
    if len(suffixes) >= 2 and suffixes[-1] in DANGEROUS_EXTENSION_POINTS:
        score += 18
        flags.append(_flag("double_extension", "high", f"Attachment filename uses multiple extensions: {''.join(suffixes)}"))
        breakdown.append(
            _score_item(
                "double_extension",
                18,
                f"Attachment filename uses multiple extensions: {''.join(suffixes)}",
                "high",
            )
        )

    if detected_type == "portable_executable":
        score += 55
        flags.append(_flag("portable_executable", "high", "Attachment contains a Windows executable header"))
        breakdown.append(
            _score_item(
                "portable_executable",
                55,
                "Attachment contains a Windows executable header",
                "high",
            )
        )
    elif detected_type == "html":
        score += 14
        flags.append(_flag("html_attachment", "medium", "Attachment is an HTML file that may host a phishing page"))
        breakdown.append(_score_item("html_attachment", 14, "Attachment is an HTML file that may host a phishing page", "medium"))

    if extension == ".pdf" and detected_type not in {"pdf", "unknown"}:
        score += 22
        flags.append(_flag("type_mismatch", "high", "Attachment extension does not match the detected file type"))
        breakdown.append(
            _score_item(
                "type_mismatch",
                22,
                "Attachment extension does not match the detected file type",
                "high",
            )
        )

    if detected_type == "zip_archive" or extension in {".zip", ".jar", ".docx", ".xlsx", ".pptx"}:
        archive_score, archive_flags, archive_breakdown, names, archive_urls, encrypted = _analyze_zip_archive(filename, content)
        score += archive_score
        flags.extend(archive_flags)
        breakdown.extend(archive_breakdown)
        contained_filenames.extend(names)
        extracted_urls.extend(archive_urls)
        password_protected = password_protected or encrypted

    decoded_text = ""
    if extension in TEXTUAL_SUFFIXES or detected_type in {"html", "script_text", "pdf"} or not extension:
        decoded_text = _safe_decode_text(content[:500_000])
        text_score, text_flags, text_breakdown = _analyze_text_payload(decoded_text)
        score += text_score
        flags.extend(text_flags)
        breakdown.extend(text_breakdown)
        extracted_urls.extend(heuristics.extract_urls_from_text(decoded_text))

    extracted_urls.extend(_extract_ascii_urls(content[:300_000]))
    extracted_urls = list(dict.fromkeys(extracted_urls))[: settings.max_attachment_urls_to_scan]
    if extracted_urls:
        points = min(18, len(extracted_urls) * 4)
        score += points
        flags.append(_flag("embedded_urls", "medium", f"Attachment contains {len(extracted_urls)} embedded URL indicators"))
        breakdown.append(
            _score_item(
                "embedded_urls",
                points,
                f"Attachment contains {len(extracted_urls)} embedded URL indicators",
                "medium",
            )
        )

    if extension in OFFICE_EXTENSIONS and ".docm" not in suffixes and any(name.lower().endswith("vbaproject.bin") for name in contained_filenames):
        score += 15
        flags.append(_flag("office_macro_mismatch", "high", "Office attachment appears to contain macros"))
        breakdown.append(
            _score_item(
                "office_macro_mismatch",
                15,
                "Office attachment appears to contain macros",
                "high",
            )
        )

    final_score = min(100.0, round(score, 2))
    return {
        "score": final_score,
        "flags": flags,
        "score_breakdown": breakdown,
        "sha256": sha256,
        "file_size": file_size,
        "mime_type": normalized_mime,
        "detected_type": detected_type,
        "extension": extension,
        "password_protected": password_protected,
        "contained_filenames": contained_filenames[:25],
        "extracted_urls": extracted_urls,
        "features": {
            "file_size": file_size,
            "extension": extension,
            "detected_type": detected_type,
            "contained_filenames_count": len(contained_filenames),
        },
    }
