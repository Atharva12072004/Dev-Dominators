from __future__ import annotations

from typing import Any

import httpx

try:
    from ..config import get_settings
except ImportError:  # pragma: no cover - supports running from package root
    from config import get_settings


settings = get_settings()


async def lookup_url(url: str) -> dict[str, Any]:
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    headers = {"User-Agent": settings.user_agent}
    payload = {"url": url}

    async with httpx.AsyncClient(timeout=settings.request_timeout_seconds, headers=headers) as client:
        response = await client.post(endpoint, data=payload)
        response.raise_for_status()
        data = response.json()

    found = data.get("query_status") == "ok"
    return {
        "found": found,
        "status": data.get("url_status") if found else "unknown",
        "threat": data.get("threat") if found else None,
        "tags": data.get("tags") or [],
        "blacklists": data.get("blacklists") or {},
        "enabled": True,
    }
