from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)

try:
    import yara
except ImportError:  # pragma: no cover - environment dependent
    yara = None


RULE_DIRECTORY = Path(__file__).resolve().parent.parent / "yara_rules"
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
_compiled_rules = None
_compile_lock = asyncio.Lock()


def compile_rules_or_raise():
    if yara is None:
        raise RuntimeError("yara-python is not installed in the current environment")

    filepaths = {
        "phishing": str(RULE_DIRECTORY / "phishing.yar"),
        "malware_urls": str(RULE_DIRECTORY / "malware_urls.yar"),
        "credential_harvest": str(RULE_DIRECTORY / "credential_harvest.yar"),
    }
    return yara.compile(filepaths=filepaths)


async def initialize_yara_rules() -> None:
    global _compiled_rules
    if yara is None:
        logger.warning("yara_unavailable")
        return

    async with _compile_lock:
        if _compiled_rules is None:
            _compiled_rules = await asyncio.to_thread(compile_rules_or_raise)
            logger.info("yara_rules_compiled", extra={"path": str(RULE_DIRECTORY)})


async def scan_content(url: str, html_content: str | None = None) -> dict[str, Any]:
    global _compiled_rules

    if yara is None:
        return {
            "matched": False,
            "rules_matched": [],
            "severity": "low",
            "enabled": False,
        }

    if _compiled_rules is None:
        await initialize_yara_rules()

    if _compiled_rules is None:
        return {
            "matched": False,
            "rules_matched": [],
            "severity": "low",
            "enabled": False,
        }

    payload = f"URL: {url}\nCONTENT:\n{html_content or ''}"
    matches = await asyncio.to_thread(_compiled_rules.match, data=payload.encode("utf-8"))

    rule_names: list[str] = []
    severities: list[str] = []
    details: list[dict[str, Any]] = []
    for match in matches:
        severity = str(match.meta.get("severity", "medium")).lower()
        rule_names.append(match.rule)
        severities.append(severity)
        details.append(
            {
                "rule": match.rule,
                "namespace": match.namespace,
                "severity": severity,
                "description": match.meta.get("description"),
            }
        )

    highest_severity = "low"
    if severities:
        highest_severity = max(severities, key=lambda item: SEVERITY_ORDER.get(item, 1))

    return {
        "matched": bool(matches),
        "rules_matched": rule_names,
        "severity": highest_severity,
        "details": details,
        "enabled": True,
    }
