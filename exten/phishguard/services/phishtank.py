from __future__ import annotations

from typing import Any

import httpx

try:
    from ..config import get_settings
except ImportError:  # pragma: no cover - supports running from package root
    from config import get_settings


settings = get_settings()


async def check_url(url: str) -> dict[str, Any]:
    if not settings.phishtank_app_key:
        return {
            "in_database": False,
            "verified": False,
            "phish_id": None,
            "phish_detail_url": None,
            "enabled": False,
        }

    endpoint = "https://checkurl.phishtank.com/checkurl/"
    payload = {
        "url": url,
        "format": "json",
    }
    payload["app_key"] = settings.phishtank_app_key

    headers = {
        "User-Agent": settings.user_agent,
    }

    async with httpx.AsyncClient(timeout=settings.request_timeout_seconds, headers=headers) as client:
        response = await client.post(endpoint, data=payload)
        response.raise_for_status()
        data = response.json()

    results = data.get("results", {}) if isinstance(data, dict) else {}
    return {
        "in_database": bool(results.get("in_database")),
        "verified": bool(results.get("verified")),
        "phish_id": results.get("phish_id"),
        "phish_detail_url": results.get("phish_detail_page"),
        "enabled": True,
    }
