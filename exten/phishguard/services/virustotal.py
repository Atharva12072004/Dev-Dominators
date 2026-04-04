from __future__ import annotations

import asyncio
import base64
from typing import Any

import httpx

try:
    from ..config import get_settings
except ImportError:  # pragma: no cover - supports running from package root
    from config import get_settings


settings = get_settings()


def _encode_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")


async def analyze_url(url: str) -> dict[str, Any]:
    if not settings.virustotal_api_key:
        return {
            "positives": 0,
            "total": 0,
            "permalink": None,
            "enabled": False,
            "rate_limited": False,
        }

    headers = {
        "accept": "application/json",
        "x-apikey": settings.virustotal_api_key,
        "User-Agent": settings.user_agent,
    }
    base_url = "https://www.virustotal.com/api/v3"

    async with httpx.AsyncClient(timeout=settings.request_timeout_seconds, headers=headers) as client:
        submit_response = await client.post(f"{base_url}/urls", data={"url": url})
        if submit_response.status_code == 429:
            return {
                "positives": 0,
                "total": 0,
                "permalink": None,
                "enabled": True,
                "rate_limited": True,
            }
        submit_response.raise_for_status()
        analysis_id = submit_response.json().get("data", {}).get("id")

        analysis_status = None
        for _ in range(2):
            if not analysis_id:
                break
            analysis_response = await client.get(f"{base_url}/analyses/{analysis_id}")
            if analysis_response.status_code == 429:
                return {
                    "positives": 0,
                    "total": 0,
                    "permalink": None,
                    "enabled": True,
                    "rate_limited": True,
                }
            analysis_response.raise_for_status()
            analysis_payload = analysis_response.json().get("data", {}).get("attributes", {})
            analysis_status = analysis_payload.get("status")
            if analysis_status == "completed":
                break
            await asyncio.sleep(0.75)

        url_id = _encode_url_id(url)
        report_response = await client.get(f"{base_url}/urls/{url_id}")
        report_response.raise_for_status()
        stats = report_response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

    positives = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
    total = int(sum(stats.values())) if stats else 0
    return {
        "positives": positives,
        "total": total,
        "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
        "enabled": True,
        "rate_limited": False,
        "analysis_status": analysis_status,
    }


async def analyze_file_hash(sha256_hash: str) -> dict[str, Any]:
    if not settings.virustotal_api_key:
        return {
            "found": False,
            "positives": 0,
            "total": 0,
            "permalink": None,
            "enabled": False,
            "rate_limited": False,
        }

    headers = {
        "accept": "application/json",
        "x-apikey": settings.virustotal_api_key,
        "User-Agent": settings.user_agent,
    }
    base_url = "https://www.virustotal.com/api/v3"

    async with httpx.AsyncClient(timeout=settings.request_timeout_seconds, headers=headers) as client:
        response = await client.get(f"{base_url}/files/{sha256_hash}")
        if response.status_code == 404:
            return {
                "found": False,
                "positives": 0,
                "total": 0,
                "permalink": f"https://www.virustotal.com/gui/file/{sha256_hash}",
                "enabled": True,
                "rate_limited": False,
            }
        if response.status_code == 429:
            return {
                "found": False,
                "positives": 0,
                "total": 0,
                "permalink": f"https://www.virustotal.com/gui/file/{sha256_hash}",
                "enabled": True,
                "rate_limited": True,
            }
        response.raise_for_status()
        stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

    positives = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
    total = int(sum(stats.values())) if stats else 0
    return {
        "found": bool(stats),
        "positives": positives,
        "total": total,
        "permalink": f"https://www.virustotal.com/gui/file/{sha256_hash}",
        "enabled": True,
        "rate_limited": False,
    }
