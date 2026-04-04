from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import httpx

try:
    from ..config import get_settings
except ImportError:  # pragma: no cover - supports running from package root
    from config import get_settings


def _settings():
    return get_settings()


def _truncate_list(items: list[Any], limit: int = 8) -> list[Any]:
    return list(items or [])[:limit]


def _truncate_text(value: str | None, limit: int) -> str:
    candidate = (value or "").strip()
    if len(candidate) <= limit:
        return candidate
    return candidate[: limit - 3] + "..."


def _base_disabled_payload(status: str, error: str | None = None) -> dict[str, Any]:
    settings = _settings()
    return {
        "enabled": False,
        "provider": "groq",
        "model": settings.groq_model,
        "status": status,
        "phishing_text_score": None,
        "confidence": None,
        "explanation_summary": None,
        "key_indicators": [],
        "social_engineering_tactics": [],
        "cluster_label": None,
        "cluster_rationale": None,
        "analyst_summary": None,
        "triage_priority": None,
        "recommended_actions": [],
        "error": error,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _clamp_score(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return max(0, min(100, int(round(float(value)))))
    except (TypeError, ValueError):
        return None


def _clamp_confidence(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return round(max(0.0, min(1.0, float(value))), 2)
    except (TypeError, ValueError):
        return None


def _normalize_priority(value: Any) -> str | None:
    candidate = str(value or "").strip().lower()
    if candidate in {"low", "medium", "high", "critical"}:
        return candidate
    return None


def _normalize_analysis(data: dict[str, Any]) -> dict[str, Any]:
    settings = _settings()
    return {
        "enabled": True,
        "provider": "groq",
        "model": settings.groq_model,
        "status": "ok",
        "phishing_text_score": _clamp_score(data.get("phishing_text_score")),
        "confidence": _clamp_confidence(data.get("confidence")),
        "explanation_summary": _truncate_text(str(data.get("explanation_summary") or "").strip(), 600) or None,
        "key_indicators": _truncate_list([str(item).strip() for item in data.get("key_indicators", []) if str(item).strip()], 8),
        "social_engineering_tactics": _truncate_list(
            [str(item).strip() for item in data.get("social_engineering_tactics", []) if str(item).strip()],
            6,
        ),
        "cluster_label": _truncate_text(str(data.get("cluster_label") or "").strip(), 120) or None,
        "cluster_rationale": _truncate_text(str(data.get("cluster_rationale") or "").strip(), 300) or None,
        "analyst_summary": _truncate_text(str(data.get("analyst_summary") or "").strip(), 600) or None,
        "triage_priority": _normalize_priority(data.get("triage_priority")),
        "recommended_actions": _truncate_list(
            [str(item).strip() for item in data.get("recommended_actions", []) if str(item).strip()],
            6,
        ),
        "error": data.get("error"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _build_messages(scan_context: dict[str, Any]) -> list[dict[str, str]]:
    system_prompt = (
        "You are a phishing-analysis copilot enriching an existing detection engine. "
        "Do not override the local engine verdict. "
        "Return only valid JSON with these keys exactly: "
        "phishing_text_score, confidence, explanation_summary, key_indicators, "
        "social_engineering_tactics, cluster_label, cluster_rationale, analyst_summary, "
        "triage_priority, recommended_actions. "
        "Keep triage_priority to one of low, medium, high, critical. "
        "Use concise analyst language and avoid markdown."
    )
    user_prompt = json.dumps(scan_context, ensure_ascii=True)
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


def _extract_message_content(payload: dict[str, Any]) -> str:
    choices = payload.get("choices") or []
    if not choices:
        raise ValueError("Groq response did not contain choices")
    message = choices[0].get("message") or {}
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        collected = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text" and item.get("text"):
                collected.append(str(item["text"]))
        if collected:
            return "".join(collected)
    raise ValueError("Groq response did not contain text content")


async def analyze_detection(
    *,
    content_type: str,
    source: str,
    primary_text: str,
    local_verdict: str,
    local_risk_score: int,
    local_confidence: float,
    flags: list[dict[str, Any]],
    score_breakdown: list[dict[str, Any]],
    urls: list[str] | None = None,
    subject: str | None = None,
    sender: str | None = None,
    context_label: str | None = None,
    extracted_artifacts: list[str] | None = None,
    campaign_key: str | None = None,
) -> dict[str, Any]:
    settings = _settings()
    if not settings.groq_api_key:
        return _base_disabled_payload("disabled", "GROQ_API_KEY is not configured")

    scan_context = {
        "content_type": content_type,
        "source": source,
        "local_verdict": local_verdict,
        "local_risk_score": local_risk_score,
        "local_confidence": local_confidence,
        "subject": subject,
        "sender": sender,
        "context_label": context_label,
        "campaign_key": campaign_key,
        "primary_text": _truncate_text(primary_text, settings.groq_max_input_chars),
        "urls": _truncate_list(urls or [], 12),
        "extracted_artifacts": _truncate_list(extracted_artifacts or [], 12),
        "flags": _truncate_list(flags, 10),
        "score_breakdown": _truncate_list(score_breakdown, 10),
    }

    request_payload = {
        "model": settings.groq_model,
        "temperature": 0.1,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "phishing_enrichment",
                "strict": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "phishing_text_score": {"type": "integer"},
                        "confidence": {"type": "number"},
                        "explanation_summary": {"type": ["string", "null"]},
                        "key_indicators": {"type": "array", "items": {"type": "string"}},
                        "social_engineering_tactics": {"type": "array", "items": {"type": "string"}},
                        "cluster_label": {"type": ["string", "null"]},
                        "cluster_rationale": {"type": ["string", "null"]},
                        "analyst_summary": {"type": ["string", "null"]},
                        "triage_priority": {
                            "type": "string",
                            "enum": ["low", "medium", "high", "critical"],
                        },
                        "recommended_actions": {"type": "array", "items": {"type": "string"}},
                        "error": {"type": ["string", "null"]},
                    },
                    "required": [
                        "phishing_text_score",
                        "confidence",
                        "explanation_summary",
                        "key_indicators",
                        "social_engineering_tactics",
                        "cluster_label",
                        "cluster_rationale",
                        "analyst_summary",
                        "triage_priority",
                        "recommended_actions",
                        "error",
                    ],
                    "additionalProperties": False,
                },
            },
        },
        "messages": _build_messages(scan_context),
    }

    timeout = httpx.Timeout(settings.groq_timeout_seconds)
    headers = {
        "Authorization": f"Bearer {settings.groq_api_key}",
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                f"{settings.groq_base_url.rstrip('/')}/chat/completions",
                headers=headers,
                json=request_payload,
            )
            response.raise_for_status()
            payload = response.json()
        content = _extract_message_content(payload)
        parsed = json.loads(content)
        if not isinstance(parsed, dict):
            raise ValueError("Groq JSON response must be an object")
        return _normalize_analysis(parsed)
    except Exception as exc:  # pragma: no cover - external network behavior
        return _base_disabled_payload("error", str(exc))
