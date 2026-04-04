from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from typing import Any

import httpx

try:
    from ..config import get_settings
except ImportError:  # pragma: no cover - supports running from package root
    from config import get_settings


logger = logging.getLogger(__name__)
settings = get_settings()


class CacheBackend:
    def __init__(self) -> None:
        self._memory: dict[str, tuple[float, dict[str, Any]]] = {}
        self._lock = asyncio.Lock()
        self._redis = None
        self._redis_unavailable = False

    async def _get_redis(self):
        if self._redis_unavailable:
            return None
        if self._redis is not None:
            return self._redis
        try:
            import redis.asyncio as redis

            self._redis = redis.from_url(settings.redis_url, decode_responses=True)
            await self._redis.ping()
            logger.info("redis_cache_enabled", extra={"service": "google_safe_browsing"})
            return self._redis
        except Exception as exc:
            self._redis_unavailable = True
            logger.warning(
                "redis_cache_unavailable",
                extra={"service": "google_safe_browsing", "error": str(exc)},
            )
            return None

    async def get(self, key: str) -> dict[str, Any] | None:
        redis_client = await self._get_redis()
        if redis_client is not None:
            cached = await redis_client.get(key)
            if cached:
                return json.loads(cached)

        async with self._lock:
            item = self._memory.get(key)
            if not item:
                return None
            expires_at, value = item
            if expires_at < time.time():
                self._memory.pop(key, None)
                return None
            return value

    async def set(self, key: str, value: dict[str, Any], ttl_seconds: int) -> None:
        redis_client = await self._get_redis()
        if redis_client is not None:
            await redis_client.setex(key, ttl_seconds, json.dumps(value))
            return

        async with self._lock:
            self._memory[key] = (time.time() + ttl_seconds, value)


cache_backend = CacheBackend()


def _cache_key(url: str) -> str:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return f"phishguard:gsb:{digest}"


async def lookup_url(url: str) -> dict[str, Any]:
    if not settings.google_safe_browsing_api_key:
        return {
            "matched": False,
            "threat_type": None,
            "platform": None,
            "enabled": False,
        }

    cache_key = _cache_key(url)
    cached = await cache_backend.get(cache_key)
    if cached is not None:
        cached["cache_hit"] = True
        return cached

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={settings.google_safe_browsing_api_key}"
    )
    payload = {
        "client": {
            "clientId": "cybershield",
            "clientVersion": "1.0.0",
        },
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

    async with httpx.AsyncClient(timeout=settings.request_timeout_seconds, headers={"User-Agent": settings.user_agent}) as client:
        response = await client.post(endpoint, json=payload)
        response.raise_for_status()
        data = response.json()

    matches = data.get("matches") or []
    first_match = matches[0] if matches else {}
    result = {
        "matched": bool(matches),
        "threat_type": first_match.get("threatType"),
        "platform": first_match.get("platformType"),
        "enabled": True,
        "cache_hit": False,
    }
    await cache_backend.set(cache_key, result, settings.google_safe_browsing_cache_ttl_seconds)
    return result
