from __future__ import annotations

import asyncio
import copy
import hashlib
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

try:
    from ..config import get_settings
except ImportError:  # pragma: no cover - supports running from package root
    from config import get_settings


PENDING_STATES = {
    "new",
    "queued",
    "in_queue",
    "in queue",
    "submitted",
    "running",
    "processing",
    "starting",
    "pending",
}

URL_CACHE_TTL_SECONDS = 60 * 60
FILE_CACHE_TTL_SECONDS = 60 * 60
_cache_lock = asyncio.Lock()
_url_result_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_file_result_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_url_inflight: dict[str, asyncio.Task[dict[str, Any]]] = {}
_file_inflight: dict[str, asyncio.Task[dict[str, Any]]] = {}


def _settings():
    return get_settings()


def _disabled_payload(status: str, error: str | None = None) -> dict[str, Any]:
    settings = _settings()
    return {
        "enabled": False,
        "provider": "falcon_sandbox",
        "status": status,
        "error": error,
        "submission_type": None,
        "submission_id": None,
        "job_id": None,
        "sha256": None,
        "environment_id": settings.falcon_sandbox_environment_id,
        "environment_description": None,
        "state": None,
        "completed": False,
        "verdict": None,
        "threat_score": None,
        "threat_level": None,
        "malicious": False,
        "redirect_urls_count": 0,
        "extracted_files_count": 0,
        "domains_count": 0,
        "hosts_count": 0,
        "redirect_urls": [],
        "domains": [],
        "hosts": [],
        "extracted_files": [],
        "tags": [],
    }


def _soft_limit_payload(
    *,
    submission_type: str,
    error: str,
    environment_id: int | None = None,
) -> dict[str, Any]:
    settings = _settings()
    return {
        "enabled": True,
        "provider": "falcon_sandbox",
        "status": "rate_limited",
        "error": error,
        "submission_type": submission_type,
        "submission_id": None,
        "job_id": None,
        "sha256": None,
        "environment_id": environment_id or settings.falcon_sandbox_environment_id,
        "environment_description": None,
        "state": "provider_duplicate_limit",
        "completed": False,
        "verdict": None,
        "threat_score": 0,
        "threat_level": None,
        "malicious": False,
        "redirect_urls_count": 0,
        "extracted_files_count": 0,
        "domains_count": 0,
        "hosts_count": 0,
        "redirect_urls": [],
        "domains": [],
        "hosts": [],
        "extracted_files": [],
        "tags": [],
        "cache_hit": False,
        "reused_recent_submission": False,
    }


def _headers() -> dict[str, str]:
    settings = _settings()
    return {
        "api-key": settings.falcon_sandbox_api_key,
        "accept": "application/json",
        "User-Agent": settings.user_agent or "Falcon",
    }


def _clean_base_url() -> str:
    return _settings().falcon_sandbox_base_url.rstrip("/")


def _extract_error_message(response: httpx.Response) -> str:
    try:
        payload = response.json()
        if isinstance(payload, dict) and payload.get("message"):
            return str(payload["message"])
    except Exception:
        pass
    return f"HTTP {response.status_code}"


def _clone_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(payload)


def _url_cache_key(url: str) -> str:
    hostname = (urlsplit(url).hostname or "").lower().strip()
    return hostname or hashlib.sha256(url.encode("utf-8")).hexdigest()


def _file_cache_key(filename: str, content: bytes) -> str:
    digest = hashlib.sha256(content).hexdigest()
    return f"{filename.lower().strip()}:{digest}"


def _is_duplicate_limit_error(message: str) -> bool:
    text = str(message or "").lower()
    return "already submitted" in text and "last hour" in text


async def _get_cached_result(cache: dict[str, tuple[float, dict[str, Any]]], key: str) -> dict[str, Any] | None:
    async with _cache_lock:
        item = cache.get(key)
        if not item:
            return None
        expires_at, payload = item
        if expires_at < time.time():
            cache.pop(key, None)
            return None
        cloned = _clone_payload(payload)
        cloned["cache_hit"] = True
        cloned["reused_recent_submission"] = True
        if cloned.get("status") in {None, "ok", "submitted"}:
            cloned["status"] = "cached"
        return cloned


async def _store_cached_result(
    cache: dict[str, tuple[float, dict[str, Any]]],
    key: str,
    payload: dict[str, Any],
    ttl_seconds: int,
) -> None:
    async with _cache_lock:
        cache[key] = (time.time() + ttl_seconds, _clone_payload(payload))


async def _await_inflight(
    inflight: dict[str, asyncio.Task[dict[str, Any]]],
    key: str,
    factory: Any,
) -> dict[str, Any]:
    async with _cache_lock:
        task = inflight.get(key)
        if task is None:
            task = asyncio.create_task(factory())
            inflight[key] = task
    try:
        return await task
    finally:
        async with _cache_lock:
            current = inflight.get(key)
            if current is task:
                inflight.pop(key, None)


def _safe_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_list(value: Any, limit: int = 8) -> list[Any]:
    if isinstance(value, list):
        return value[:limit]
    return []


def _normalize_text_candidate(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _looks_like_web_url(value: str) -> bool:
    lower = value.lower()
    return lower.startswith("http://") or lower.startswith("https://")


def _extract_named_items(
    summary: dict[str, Any],
    keys: list[str],
    candidate_fields: list[str],
    *,
    limit: int = 8,
    require_web_url: bool = False,
) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()

    def _add_candidate(candidate: Any) -> None:
        if len(values) >= limit:
            return
        text = _normalize_text_candidate(candidate)
        if not text:
            return
        if require_web_url and not _looks_like_web_url(text):
            return
        normalized = text.lower()
        if normalized in seen:
            return
        seen.add(normalized)
        values.append(text)

    for key in keys:
        raw_value = summary.get(key)
        if raw_value is None:
            continue
        iterable = raw_value if isinstance(raw_value, list) else [raw_value]
        for item in iterable:
            if len(values) >= limit:
                return values
            if isinstance(item, dict):
                for field in candidate_fields:
                    if field in item:
                        _add_candidate(item.get(field))
                        if len(values) >= limit:
                            return values
            else:
                _add_candidate(item)
    return values


def _extract_count(summary: dict[str, Any], keys: list[str]) -> int:
    for key in keys:
        value = summary.get(key)
        if isinstance(value, list):
            return len(value)
        if isinstance(value, int):
            return value
    return 0


def _normalize_verdict(summary: dict[str, Any], state_payload: dict[str, Any]) -> str | None:
    candidates = [
        summary.get("verdict_human"),
        summary.get("verdict"),
        summary.get("threat_level_human"),
        state_payload.get("verdict"),
    ]
    for candidate in candidates:
        if candidate is None:
            continue
        text = str(candidate).strip()
        if text:
            return text
    return None


def _is_malicious(verdict: str | None, threat_score: int | None) -> bool:
    verdict_text = str(verdict or "").lower()
    if any(token in verdict_text for token in ["malicious", "phishing", "malware", "suspicious"]):
        return True
    return bool(threat_score is not None and threat_score >= 70)


def _normalize_result(
    *,
    submission_type: str,
    submission_payload: dict[str, Any],
    state_payload: dict[str, Any] | None,
    summary_payload: dict[str, Any] | None,
) -> dict[str, Any]:
    settings = _settings()
    state_payload = state_payload or {}
    summary_payload = summary_payload or {}
    verdict = _normalize_verdict(summary_payload, state_payload)
    threat_score = _safe_int(summary_payload.get("threat_score"))
    redirect_urls = _extract_named_items(
        summary_payload,
        ["redirected_urls", "redirects", "interesting_urls", "contacted_urls", "network_urls", "urls"],
        ["url", "uri", "link", "target_url", "redirect_url", "location", "value", "address"],
        limit=6,
        require_web_url=True,
    )
    domains = _extract_named_items(
        summary_payload,
        ["domains"],
        ["domain", "domain_name", "hostname", "host", "name", "value", "address"],
        limit=8,
    )
    hosts = _extract_named_items(
        summary_payload,
        ["hosts", "compromised_hosts"],
        ["host", "hostname", "name", "value", "address", "ip"],
        limit=8,
    )
    extracted_files = _extract_named_items(
        summary_payload,
        ["extracted_files", "dropped_files"],
        ["filename", "file_name", "name", "path", "sha256", "md5"],
        limit=8,
    )
    tags = [
        str(item).strip()
        for item in _safe_list(summary_payload.get("classification_tags"), 10)
        if str(item).strip()
    ]
    status = "ok" if summary_payload else "submitted"
    state = str(state_payload.get("state") or "").strip().lower() or None

    return {
        "enabled": True,
        "provider": "falcon_sandbox",
        "status": status,
        "error": None,
        "submission_type": submission_type,
        "submission_id": submission_payload.get("submission_id"),
        "job_id": submission_payload.get("job_id"),
        "sha256": submission_payload.get("sha256") or summary_payload.get("sha256"),
        "environment_id": submission_payload.get("environment_id") or settings.falcon_sandbox_environment_id,
        "environment_description": summary_payload.get("environment_description"),
        "state": state or "submitted",
        "completed": bool(summary_payload),
        "verdict": verdict,
        "threat_score": threat_score,
        "threat_level": summary_payload.get("threat_level_human") or summary_payload.get("threat_level"),
        "malicious": _is_malicious(verdict, threat_score),
        "redirect_urls_count": max(
            len(redirect_urls),
            _extract_count(summary_payload, ["redirected_urls", "redirects", "interesting_urls", "contacted_urls", "network_urls"]),
        ),
        "extracted_files_count": max(len(extracted_files), _extract_count(summary_payload, ["extracted_files", "dropped_files"])),
        "domains_count": max(len(domains), _extract_count(summary_payload, ["domains"])),
        "hosts_count": max(len(hosts), _extract_count(summary_payload, ["hosts", "compromised_hosts"])),
        "redirect_urls": redirect_urls,
        "domains": domains,
        "hosts": hosts,
        "extracted_files": extracted_files,
        "tags": tags,
    }


async def _fetch_state(client: httpx.AsyncClient, report_id: str) -> dict[str, Any] | None:
    response = await client.get(f"{_clean_base_url()}/report/{report_id}/state")
    if response.status_code in {404, 410}:
        return None
    response.raise_for_status()
    payload = response.json()
    return payload if isinstance(payload, dict) else None


async def _fetch_summary(client: httpx.AsyncClient, report_id: str) -> dict[str, Any] | None:
    response = await client.get(f"{_clean_base_url()}/report/{report_id}/summary")
    if response.status_code in {404, 410}:
        return None
    response.raise_for_status()
    payload = response.json()
    return payload if isinstance(payload, dict) else None


async def _poll_report(
    client: httpx.AsyncClient,
    report_id: str | None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if not report_id:
        return None, None

    settings = _settings()
    state_payload: dict[str, Any] | None = None
    summary_payload: dict[str, Any] | None = None
    attempts = max(1, settings.falcon_sandbox_poll_attempts)
    for attempt in range(attempts):
        state_payload = await _fetch_state(client, report_id)
        summary_payload = await _fetch_summary(client, report_id)
        if summary_payload:
            break

        state = str((state_payload or {}).get("state") or "").strip().lower()
        if state and state not in PENDING_STATES:
            break
        if attempt < attempts - 1:
            await asyncio.sleep(max(0.0, float(settings.falcon_sandbox_poll_interval_seconds)))
    return state_payload, summary_payload


async def _submit_url(url: str, cache_key: str) -> dict[str, Any]:
    settings = _settings()
    data = {
        "url": url,
        "environment_id": settings.falcon_sandbox_environment_id,
        "network_settings": settings.falcon_sandbox_network_settings,
        "action_script": settings.falcon_sandbox_action_script,
    }
    timeout = httpx.Timeout(settings.falcon_sandbox_timeout_seconds)
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=_headers()) as client:
            response = await client.post(f"{_clean_base_url()}/submit/url", data=data)
            if response.status_code >= 400:
                message = _extract_error_message(response)
                if _is_duplicate_limit_error(message):
                    cached = await _get_cached_result(_url_result_cache, cache_key)
                    if cached is not None:
                        return cached
                    return _soft_limit_payload(
                        submission_type="url",
                        error=message,
                        environment_id=settings.falcon_sandbox_environment_id,
                    )
                return _disabled_payload("error", message)
            submission_payload = response.json()
            if not isinstance(submission_payload, dict):
                return _disabled_payload("error", "Unexpected Falcon Sandbox submission response")
            report_id = str(submission_payload.get("job_id") or "").strip() or None
            state_payload, summary_payload = await _poll_report(client, report_id)
        result = _normalize_result(
            submission_type="url",
            submission_payload=submission_payload,
            state_payload=state_payload,
            summary_payload=summary_payload,
        )
        if result.get("enabled"):
            await _store_cached_result(_url_result_cache, cache_key, result, URL_CACHE_TTL_SECONDS)
        return result
    except Exception as exc:  # pragma: no cover - depends on external service
        return _disabled_payload("error", str(exc))


async def analyze_url(url: str) -> dict[str, Any]:
    settings = _settings()
    if not settings.falcon_sandbox_api_key:
        return _disabled_payload("disabled", "FALCON_SANDBOX_API_KEY is not configured")

    cache_key = _url_cache_key(url)
    cached = await _get_cached_result(_url_result_cache, cache_key)
    if cached is not None:
        return cached

    return await _await_inflight(_url_inflight, cache_key, lambda: _submit_url(url, cache_key))


async def _submit_file(
    *,
    filename: str,
    content: bytes,
    mime_type: str | None = None,
    document_password: str | None = None,
    cache_key: str,
) -> dict[str, Any]:
    settings = _settings()
    data: dict[str, Any] = {
        "environment_id": settings.falcon_sandbox_environment_id,
        "network_settings": settings.falcon_sandbox_network_settings,
        "action_script": settings.falcon_sandbox_action_script,
        "submit_name": filename,
    }
    if document_password:
        data["document_password"] = document_password

    files = {
        "file": (
            filename,
            content,
            mime_type or "application/octet-stream",
        )
    }
    timeout = httpx.Timeout(settings.falcon_sandbox_timeout_seconds)
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=_headers()) as client:
            response = await client.post(f"{_clean_base_url()}/submit/file", data=data, files=files)
            if response.status_code >= 400:
                message = _extract_error_message(response)
                if _is_duplicate_limit_error(message):
                    cached = await _get_cached_result(_file_result_cache, cache_key)
                    if cached is not None:
                        return cached
                    return _soft_limit_payload(
                        submission_type="file",
                        error=message,
                        environment_id=settings.falcon_sandbox_environment_id,
                    )
                return _disabled_payload("error", message)
            submission_payload = response.json()
            if not isinstance(submission_payload, dict):
                return _disabled_payload("error", "Unexpected Falcon Sandbox submission response")
            report_id = str(submission_payload.get("job_id") or "").strip() or None
            state_payload, summary_payload = await _poll_report(client, report_id)
        result = _normalize_result(
            submission_type="file",
            submission_payload=submission_payload,
            state_payload=state_payload,
            summary_payload=summary_payload,
        )
        if result.get("enabled"):
            await _store_cached_result(_file_result_cache, cache_key, result, FILE_CACHE_TTL_SECONDS)
        return result
    except Exception as exc:  # pragma: no cover - depends on external service
        return _disabled_payload("error", str(exc))


async def analyze_file(
    *,
    filename: str,
    content: bytes,
    mime_type: str | None = None,
    document_password: str | None = None,
) -> dict[str, Any]:
    settings = _settings()
    if not settings.falcon_sandbox_api_key:
        return _disabled_payload("disabled", "FALCON_SANDBOX_API_KEY is not configured")

    cache_key = _file_cache_key(filename, content)
    cached = await _get_cached_result(_file_result_cache, cache_key)
    if cached is not None:
        return cached

    return await _await_inflight(
        _file_inflight,
        cache_key,
        lambda: _submit_file(
            filename=filename,
            content=content,
            mime_type=mime_type,
            document_password=document_password,
            cache_key=cache_key,
        ),
    )
