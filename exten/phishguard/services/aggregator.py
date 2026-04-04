from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from statistics import mean
from time import perf_counter
from typing import Any, Awaitable
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from ..config import get_settings
    from ..models.database import AsyncSessionLocal, ScanResult, WhitelistEntry
    from . import (
        attachment_analyzer,
        correlation,
        falcon_sandbox,
        google_safe_browsing,
        grok,
        heuristics,
        virustotal,
        yara_engine,
    )
except ImportError:  # pragma: no cover - supports running from package root
    from config import get_settings
    from models.database import AsyncSessionLocal, ScanResult, WhitelistEntry
    from services import (
        attachment_analyzer,
        correlation,
        falcon_sandbox,
        google_safe_browsing,
        grok,
        heuristics,
        virustotal,
        yara_engine,
    )


logger = logging.getLogger(__name__)
ENGINE_TIMEOUT_SECONDS = 5


def _settings():
    return get_settings()


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


def _weighted_signal(
    signal: str,
    normalized_score: float | int | None,
    weight: float,
    description: str,
    severity: str = "info",
) -> dict[str, Any] | None:
    if normalized_score is None or weight <= 0:
        return None
    try:
        score = max(0.0, min(100.0, float(normalized_score)))
    except (TypeError, ValueError):
        return None
    return {
        "signal": signal,
        "normalized_score": score,
        "weight": float(weight),
        "description": description,
        "severity": severity,
    }


def _fuse_weighted_signals(signals: list[dict[str, Any] | None]) -> tuple[float, list[dict[str, Any]]]:
    active = [item for item in signals if item and item.get("weight", 0) > 0]
    if not active:
        return 0.0, []

    total_weight = sum(float(item["weight"]) for item in active)
    fused_score = 0.0
    breakdown: list[dict[str, Any]] = []
    for item in active:
        contribution = (float(item["normalized_score"]) * float(item["weight"])) / total_weight
        fused_score += contribution
        breakdown.append(
            _score_item(
                str(item["signal"]),
                contribution,
                f"{item['description']} (normalized {int(round(float(item['normalized_score'])))} / 100, weight {round(float(item['weight']), 2)})",
                str(item.get("severity") or "info"),
            )
        )
    return round(min(fused_score, 100.0), 2), breakdown


def _normalized_vt_score(result: dict[str, Any] | None) -> float | None:
    if not isinstance(result, dict) or result.get("error") is not None:
        return None
    positives = int(result.get("positives", 0) or 0)
    total = int(result.get("total", 0) or 0)
    if positives <= 0 or total <= 0:
        return None
    ratio = positives / total
    return round(min(100.0, max(35.0, ratio * 140.0)), 2)


def _normalized_yara_score(result: dict[str, Any] | None) -> float | None:
    if not isinstance(result, dict) or not result.get("matched"):
        return None
    severity = str(result.get("severity", "medium")).lower()
    if severity == "high":
        return 90.0
    if severity == "medium":
        return 70.0
    return 45.0


def _normalized_falcon_score(result: dict[str, Any] | None) -> float | None:
    if not isinstance(result, dict) or not result.get("enabled"):
        return None
    threat_score = int(result.get("threat_score") or 0)
    verdict = str(result.get("verdict") or "").lower()
    if threat_score > 0:
        return float(min(100, max(threat_score, 45 if "suspicious" in verdict else 0)))
    if any(token in verdict for token in ["malware", "malicious"]):
        return 100.0
    if "phish" in verdict:
        return 88.0
    if "suspicious" in verdict:
        return 60.0
    return None


def _normalized_llm_score(result: dict[str, Any] | None) -> float | None:
    if not isinstance(result, dict):
        return None
    if result.get("enabled") is False or str(result.get("status") or "").lower() != "ok":
        return None
    score = result.get("phishing_text_score")
    if score is None:
        return None
    try:
        return max(0.0, min(100.0, float(score)))
    except (TypeError, ValueError):
        return None


async def _execute_engine(engine_name: str, task: Awaitable[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
    try:
        result = await asyncio.wait_for(task, timeout=ENGINE_TIMEOUT_SECONDS)
        return engine_name, result
    except asyncio.TimeoutError:
        logger.warning("engine_timeout", extra={"engine": engine_name})
        return engine_name, {"enabled": False, "error": "timeout"}
    except Exception as exc:  # pragma: no cover - depends on external services
        logger.warning("engine_failure", extra={"engine": engine_name, "error": str(exc)})
        return engine_name, {"enabled": False, "error": str(exc)}


def _severity_bonus(severity: str) -> int:
    if severity == "high":
        return 40
    if severity == "medium":
        return 25
    if severity == "low":
        return 10
    return 0


def _score_to_verdict(score: int) -> str:
    if score <= 30:
        return "safe"
    if score <= 60:
        return "suspicious"
    if score <= 85:
        return "phishing"
    return "malware"


def _falcon_positive(result: dict[str, Any] | None) -> bool:
    if not isinstance(result, dict) or not result.get("enabled"):
        return False
    if result.get("malicious"):
        return True
    verdict_text = str(result.get("verdict") or "").lower()
    threat_score = int(result.get("threat_score") or 0)
    return any(token in verdict_text for token in ["malicious", "phishing", "malware", "suspicious"]) or threat_score >= 70


def _falcon_points(result: dict[str, Any] | None, *, max_points: int) -> tuple[float, str]:
    if not isinstance(result, dict) or not result.get("enabled"):
        return 0.0, ""
    verdict_text = str(result.get("verdict") or "").strip()
    verdict_lower = verdict_text.lower()
    threat_score = int(result.get("threat_score") or 0)
    points = 0.0
    if "malware" in verdict_lower or "malicious" in verdict_lower:
        points = max(points, max_points)
    elif "phishing" in verdict_lower:
        points = max(points, max_points * 0.88)
    elif "suspicious" in verdict_lower:
        points = max(points, max_points * 0.55)
    if threat_score > 0:
        points = max(points, min(max_points, (threat_score / 100) * max_points))
    return round(points, 2), verdict_text or "unknown"


def _collect_falcon_results(*collections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for collection in collections:
        for item in collection or []:
            falcon_result = _artifact_falcon_result(item)
            if isinstance(falcon_result, dict):
                results.append(falcon_result)
            nested_url_scans = item.get("extracted_url_scans") if isinstance(item, dict) else None
            if isinstance(nested_url_scans, list):
                results.extend(_collect_falcon_results(nested_url_scans))
    return results


def _merge_limited_texts(*collections: list[Any], limit: int = 10) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for collection in collections:
        for item in collection or []:
            text = str(item or "").strip()
            if not text:
                continue
            normalized = text.lower()
            if normalized in seen:
                continue
            seen.add(normalized)
            merged.append(text)
            if len(merged) >= limit:
                return merged
    return merged


def _summarize_falcon_results(*collections: list[dict[str, Any]]) -> dict[str, Any] | None:
    falcon_results = _collect_falcon_results(*collections)
    if not falcon_results:
        return None

    enabled_results = [result for result in falcon_results if result.get("enabled")]
    if not enabled_results:
        first_result = falcon_results[0]
        return {
            "enabled": False,
            "provider": "falcon_sandbox",
            "status": first_result.get("status") or "disabled",
            "error": first_result.get("error"),
            "submission_type": "aggregated",
            "state": "no_completed_submissions",
            "completed": False,
            "verdict": None,
            "threat_score": 0,
            "threat_level": None,
            "malicious": False,
            "redirect_urls_count": 0,
            "related_submissions": len(falcon_results),
            "job_id": None,
            "environment_id": first_result.get("environment_id"),
            "environment_description": first_result.get("environment_description"),
            "hosts_count": 0,
            "domains_count": 0,
            "extracted_files_count": 0,
            "redirect_urls": [],
            "domains": [],
            "hosts": [],
            "extracted_files": [],
            "tags": [],
        }

    def _rank(result: dict[str, Any]) -> tuple[int, int]:
        malicious_rank = 1 if _falcon_positive(result) else 0
        threat_score = int(result.get("threat_score") or 0)
        return malicious_rank, threat_score

    strongest = max(enabled_results, key=_rank)
    redirect_urls = _merge_limited_texts(*[result.get("redirect_urls") or [] for result in enabled_results], limit=8)
    domains = _merge_limited_texts(*[result.get("domains") or [] for result in enabled_results], limit=10)
    hosts = _merge_limited_texts(*[result.get("hosts") or [] for result in enabled_results], limit=10)
    extracted_files = _merge_limited_texts(*[result.get("extracted_files") or [] for result in enabled_results], limit=10)
    unique_tags = sorted(
        {
            str(tag).strip()
            for result in enabled_results
            for tag in (result.get("tags") or [])
            if str(tag).strip()
        }
    )
    max_threat_score = max(int(result.get("threat_score") or 0) for result in enabled_results)
    malicious = any(_falcon_positive(result) for result in enabled_results)
    completed = any(bool(result.get("completed")) for result in enabled_results)
    strongest_status = str(strongest.get("status") or "").strip() or ("ok" if completed else "submitted")
    strongest_state = str(strongest.get("state") or "").strip() or ("aggregated" if completed else "submitted")

    return {
        "enabled": True,
        "provider": "falcon_sandbox",
        "status": "ok" if completed else strongest_status,
        "error": strongest.get("error"),
        "submission_type": "aggregated",
        "state": "aggregated" if completed else strongest_state,
        "completed": completed,
        "verdict": strongest.get("verdict") or ("malicious" if malicious else "clean"),
        "threat_score": max_threat_score,
        "threat_level": strongest.get("threat_level"),
        "malicious": malicious,
        "redirect_urls_count": max(
            len(redirect_urls),
            sum(int(result.get("redirect_urls_count") or 0) for result in enabled_results),
        ),
        "related_submissions": len(enabled_results),
        "job_id": strongest.get("job_id") if len(enabled_results) == 1 else "multiple",
        "environment_id": strongest.get("environment_id"),
        "environment_description": strongest.get("environment_description"),
        "hosts_count": max(len(hosts), sum(int(result.get("hosts_count") or 0) for result in enabled_results)),
        "domains_count": max(len(domains), sum(int(result.get("domains_count") or 0) for result in enabled_results)),
        "extracted_files_count": max(
            len(extracted_files),
            sum(int(result.get("extracted_files_count") or 0) for result in enabled_results),
        ),
        "redirect_urls": redirect_urls,
        "domains": domains,
        "hosts": hosts,
        "extracted_files": extracted_files,
        "tags": unique_tags,
    }


def _deduplicate_flags(flags: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduplicated: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in flags:
        key = (item.get("rule", ""), item.get("severity", ""), item.get("description", ""))
        deduplicated[key] = item
    return list(deduplicated.values())


def _deduplicate_breakdown(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduplicated: dict[tuple[str, float, str], dict[str, Any]] = {}
    for item in items:
        key = (
            str(item.get("signal", "")),
            round(float(item.get("points", 0.0)), 2),
            str(item.get("description", "")),
        )
        deduplicated[key] = item
    return list(deduplicated.values())


def _should_run_llm_enrichment(*, persist: bool, risk_score: int, content_type: str) -> bool:
    if not persist:
        return False
    return content_type in {"email", "chat"}


async def _maybe_generate_llm_analysis(
    *,
    persist: bool,
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
) -> dict[str, Any] | None:
    if not _should_run_llm_enrichment(persist=persist, risk_score=local_risk_score, content_type=content_type):
        return None
    return await grok.analyze_detection(
        content_type=content_type,
        source=source,
        primary_text=primary_text,
        local_verdict=local_verdict,
        local_risk_score=local_risk_score,
        local_confidence=local_confidence,
        flags=flags,
        score_breakdown=score_breakdown,
        urls=urls,
        subject=subject,
        sender=sender,
        context_label=context_label,
        extracted_artifacts=extracted_artifacts,
        campaign_key=campaign_key,
    )


def _calculate_explainability_score(flags: list[dict[str, Any]], engines: dict[str, Any]) -> float:
    completed_engines = sum(1 for result in engines.values() if isinstance(result, dict) and result.get("error") is None)
    engine_count = max(len(engines), 1)
    unique_rules = len({flag.get("rule", "") for flag in flags if flag.get("rule")})
    high_severity_count = sum(1 for flag in flags if flag.get("severity") == "high")
    score = (
        (completed_engines / engine_count) * 30
        + (min(len(flags), 8) / 8) * 35
        + (min(unique_rules, 6) / 6) * 20
        + (min(high_severity_count, 3) / 3) * 15
    )
    return round(min(score, 100.0), 2)


def _build_block_decision(
    *,
    risk_score: int,
    verdict: str,
    flags: list[dict[str, Any]],
    whitelisted: bool = False,
) -> dict[str, Any]:
    if whitelisted:
        return {
            "action": "allow",
            "block_recommended": False,
            "show_warning": False,
            "reason_summary": "Whitelisted domain allowed",
            "top_flags": ["whitelisted_domain"],
            "override_allowed": True,
        }

    top_flags = [flag.get("rule", "unknown") for flag in flags[:3]]
    top_descriptions = [flag.get("description", "") for flag in flags[:2] if flag.get("description")]
    if verdict == "malware" or risk_score >= 86:
        action = "block"
        block_recommended = True
        show_warning = True
        override_allowed = False
    elif verdict == "phishing" or risk_score >= 61:
        action = "block"
        block_recommended = True
        show_warning = True
        override_allowed = True
    elif verdict == "suspicious" or risk_score >= 31:
        action = "warn"
        block_recommended = False
        show_warning = True
        override_allowed = True
    else:
        action = "allow"
        block_recommended = False
        show_warning = False
        override_allowed = True

    if top_descriptions:
        reason_summary = "; ".join(top_descriptions)
    elif action == "allow":
        reason_summary = "No strong malicious indicators were detected"
    else:
        reason_summary = f"{verdict.title()} indicators detected"

    return {
        "action": action,
        "block_recommended": block_recommended,
        "show_warning": show_warning,
        "reason_summary": reason_summary,
        "top_flags": top_flags,
        "override_allowed": override_allowed,
    }


def _calculate_confidence(engine_results: dict[str, dict[str, Any]], risk_score: int) -> float:
    completed = sum(1 for result in engine_results.values() if result.get("error") is None)
    positive = sum(
        1
        for name, result in engine_results.items()
        if (
            (name == "google_safe_browsing" and result.get("matched"))
            or (name == "yara" and result.get("matched"))
            or (name == "heuristics" and result.get("score", 0) >= 50)
            or (name == "virustotal" and result.get("total", 0) > 0 and result.get("positives", 0) > 0)
            or (name == "falcon_sandbox" and _falcon_positive(result))
        )
    )
    coverage = completed / max(len(engine_results), 1)
    agreement = positive / max(completed, 1)
    distance_factor = abs(risk_score - 50) / 50 if risk_score != 50 else 0.0
    confidence = 0.35 + (coverage * 0.35) + (agreement * 0.15) + (distance_factor * 0.15)
    return round(min(max(confidence, 0.0), 0.99), 2)


def _calculate_attachment_confidence(
    *,
    engines: dict[str, Any],
    risk_score: int,
    risky_link_count: int,
) -> float:
    completed = sum(1 for result in engines.values() if isinstance(result, dict) and result.get("error") is None)
    positives = 0
    if engines.get("static_analysis", {}).get("score", 0) >= 40:
        positives += 1
    if engines.get("yara", {}).get("matched"):
        positives += 1
    if engines.get("virustotal", {}).get("positives", 0) > 0:
        positives += 1
    if risky_link_count:
        positives += 1
    if _falcon_positive(engines.get("falcon_sandbox")):
        positives += 1
    coverage = completed / max(len(engines), 1)
    agreement = positives / 5
    distance_factor = abs(risk_score - 50) / 50 if risk_score != 50 else 0.0
    confidence = 0.42 + (coverage * 0.25) + (agreement * 0.18) + (distance_factor * 0.15)
    return round(min(max(confidence, 0.0), 0.99), 2)


async def _is_whitelisted(db: AsyncSession, url: str) -> bool:
    hostname = (urlsplit(url).hostname or "").lower()
    if not hostname:
        return False

    direct_match = await db.execute(select(WhitelistEntry).where(WhitelistEntry.domain == hostname))
    if direct_match.scalar_one_or_none():
        return True

    parts = hostname.split(".")
    for index in range(1, len(parts) - 1):
        candidate = ".".join(parts[index:])
        query = await db.execute(select(WhitelistEntry).where(WhitelistEntry.domain == candidate))
        if query.scalar_one_or_none():
            return True
    return False


async def _store_scan_result(
    db: AsyncSession,
    *,
    url_or_content: str,
    content_type: str,
    source: str,
    risk_score: int,
    verdict: str,
    confidence: float,
    engines: dict[str, Any],
    flags: list[dict[str, Any]],
    score_breakdown: list[dict[str, Any]],
    detection_time_ms: int,
    explainability_score: float,
    recommended_action: str,
    block_recommended: bool,
    ai_generated_probability: float,
    llm_analysis: dict[str, Any] | None,
    ip_address: str | None,
    timestamp: datetime,
    campaign_key: str | None = None,
) -> ScanResult:
    record = ScanResult(
        url_or_content=url_or_content,
        content_type=content_type,
        source=source,
        risk_score=risk_score,
        verdict=verdict,
        confidence=confidence,
        gsb_result=engines.get("google_safe_browsing"),
        urlhaus_result=engines.get("urlhaus"),
        yara_result=engines.get("yara"),
        heuristics_result=engines.get("heuristics") or engines.get("static_analysis"),
        vt_result=engines.get("virustotal"),
        pt_result=engines.get("phishtank"),
        falcon_result=engines.get("falcon_sandbox"),
        llm_analysis=llm_analysis,
        flags=flags,
        score_breakdown=score_breakdown,
        detection_time_ms=detection_time_ms,
        explainability_score=explainability_score,
        recommended_action=recommended_action,
        block_recommended=block_recommended,
        ai_generated_probability=ai_generated_probability,
        timestamp=timestamp,
        ip_address=ip_address,
        campaign_key=campaign_key,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return record


async def _campaign_summary(db: AsyncSession, campaign_key: str | None) -> dict[str, Any] | None:
    return await correlation.get_campaign_summary(db, campaign_key)


def _summarize_chain(
    *,
    content_type: str,
    risky_link_count: int,
    risky_attachment_count: int = 0,
    nested_url_count: int = 0,
) -> str:
    parts = [f"{content_type.title()} root observed"]
    if risky_link_count:
        parts.append(f"{risky_link_count} risky linked artifact(s)")
    if risky_attachment_count:
        parts.append(f"{risky_attachment_count} risky attachment(s)")
    if nested_url_count:
        parts.append(f"{nested_url_count} nested URL indicator(s)")
    if len(parts) == 1:
        parts.append("no downstream malicious artifacts identified")
    return "; ".join(parts)


def _root_chain_step(label: str, step_type: str, risk_score: int, verdict: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "step_order": 0,
        "relation": "origin",
        "step_type": step_type,
        "label": label,
        "risk_score": risk_score,
        "verdict": verdict,
        "details": details or {},
    }


def _artifact_falcon_result(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    direct = item.get("falcon_result")
    if isinstance(direct, dict):
        return direct
    engines = item.get("engines")
    if isinstance(engines, dict):
        falcon_result = engines.get("falcon_sandbox")
        if isinstance(falcon_result, dict):
            return falcon_result
    return None


def _append_chain_step(
    steps: list[dict[str, Any]],
    *,
    step_order: int,
    relation: str,
    step_type: str,
    label: str,
    risk_score: int,
    verdict: str | None,
    details: dict[str, Any] | None = None,
) -> int:
    steps.append(
        {
            "step_order": step_order,
            "relation": relation,
            "step_type": step_type,
            "label": label,
            "risk_score": risk_score,
            "verdict": verdict,
            "details": details or {},
        }
    )
    return step_order + 1


def _extend_steps_with_falcon_artifacts(
    steps: list[dict[str, Any]],
    falcon_result: dict[str, Any] | None,
    *,
    start_index: int,
    derived_from: str,
) -> int:
    if not isinstance(falcon_result, dict):
        return start_index

    step_order = start_index
    threat_score = int(falcon_result.get("threat_score") or 0)
    verdict = falcon_result.get("verdict")
    base_details = {
        "provider": "falcon_sandbox",
        "derived_from": derived_from,
        "submission_type": falcon_result.get("submission_type"),
        "state": falcon_result.get("state"),
    }

    for redirect_url in falcon_result.get("redirect_urls") or []:
        step_order = _append_chain_step(
            steps,
            step_order=step_order,
            relation="redirects_to",
            step_type="url",
            label=str(redirect_url),
            risk_score=threat_score,
            verdict=verdict,
            details={**base_details, "artifact_type": "redirect_url"},
        )

    for domain in falcon_result.get("domains") or []:
        step_order = _append_chain_step(
            steps,
            step_order=step_order,
            relation="contacts_domain",
            step_type="domain",
            label=str(domain),
            risk_score=threat_score,
            verdict=verdict,
            details={**base_details, "artifact_type": "domain"},
        )

    for host in falcon_result.get("hosts") or []:
        step_order = _append_chain_step(
            steps,
            step_order=step_order,
            relation="contacts_host",
            step_type="host",
            label=str(host),
            risk_score=threat_score,
            verdict=verdict,
            details={**base_details, "artifact_type": "host"},
        )

    for extracted_file in falcon_result.get("extracted_files") or []:
        step_order = _append_chain_step(
            steps,
            step_order=step_order,
            relation="drops_file",
            step_type="file",
            label=str(extracted_file),
            risk_score=threat_score,
            verdict=verdict,
            details={**base_details, "artifact_type": "extracted_file"},
        )

    return step_order


def _extend_steps_with_urls(
    steps: list[dict[str, Any]],
    scanned_links: list[dict[str, Any]],
    *,
    start_index: int,
    relation: str,
) -> int:
    step_order = start_index
    for item in scanned_links:
        step_order = _append_chain_step(
            steps,
            step_order=step_order,
            relation=relation,
            step_type="url",
            label=item["url"],
            risk_score=int(item.get("risk_score", 0)),
            verdict=item.get("verdict"),
            details={
                "confidence": item.get("confidence"),
                "top_flags": item.get("block_decision", {}).get("top_flags", []),
            },
        )
        step_order = _extend_steps_with_falcon_artifacts(
            steps,
            _artifact_falcon_result(item),
            start_index=step_order,
            derived_from=item["url"],
        )
    return step_order


def _extend_steps_with_attachments(
    steps: list[dict[str, Any]],
    scanned_attachments: list[dict[str, Any]],
    *,
    start_index: int,
) -> int:
    step_order = start_index
    for attachment in scanned_attachments:
        step_order = _append_chain_step(
            steps,
            step_order=step_order,
            relation="contains_attachment",
            step_type="attachment",
            label=attachment["filename"],
            risk_score=int(attachment.get("risk_score", 0)),
            verdict=attachment.get("verdict"),
            details={
                "sha256": attachment.get("sha256"),
                "detected_type": attachment.get("detected_type"),
                "embedded_urls": attachment.get("extracted_urls", []),
            },
        )
        step_order = _extend_steps_with_falcon_artifacts(
            steps,
            _artifact_falcon_result(attachment),
            start_index=step_order,
            derived_from=attachment["filename"],
        )
        for extracted_url in attachment.get("extracted_url_scans", []):
            step_order = _append_chain_step(
                steps,
                step_order=step_order,
                relation="contains_url",
                step_type="url",
                label=extracted_url["url"],
                risk_score=int(extracted_url.get("risk_score", 0)),
                verdict=extracted_url.get("verdict"),
                details={
                    "confidence": extracted_url.get("confidence"),
                    "derived_from_attachment": attachment.get("filename"),
                },
            )
            step_order = _extend_steps_with_falcon_artifacts(
                steps,
                _artifact_falcon_result(extracted_url),
                start_index=step_order,
                derived_from=extracted_url["url"],
            )
    return step_order


async def scan_single_url(
    db: AsyncSession,
    *,
    url: str,
    source: str,
    analysis_mode: str = "standard",
    ip_address: str | None,
    html_content: str | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    started_at = perf_counter()
    timestamp = datetime.now(timezone.utc)
    if await _is_whitelisted(db, url):
        detection_time_ms = int((perf_counter() - started_at) * 1000)
        explainability_score = 100.0
        score_breakdown = [
            _score_item(
                "whitelisted_domain",
                0,
                "Domain is explicitly whitelisted and bypasses malicious scoring",
                "low",
            )
        ]
        block_decision = _build_block_decision(
            risk_score=0,
            verdict="safe",
            flags=[_flag("whitelisted_domain", "low", "Domain is present in the whitelist")],
            whitelisted=True,
        )
        result = {
            "url": url,
            "risk_score": 0,
            "verdict": "safe",
            "confidence": 0.99,
            "engines": {
                "google_safe_browsing": {"enabled": False, "skipped": True},
                "heuristics": {"enabled": False, "skipped": True},
                "virustotal": {"enabled": False, "skipped": True},
                **({"falcon_sandbox": {"enabled": False, "skipped": True}} if analysis_mode == "sandbox" else {}),
            },
            "falcon_result": None,
            "flags": [_flag("whitelisted_domain", "low", "Domain is present in the whitelist")],
            "score_breakdown": score_breakdown,
            "detection_time_ms": detection_time_ms,
            "explainability_score": explainability_score,
            "block_decision": block_decision,
            "ai_generated_probability": 0.0,
            "llm_analysis": None,
            "timestamp": timestamp,
            "whitelisted": True,
            "campaign": None,
        }
        if persist:
            await _store_scan_result(
                db,
                url_or_content=url,
                content_type="url",
                source=source,
                risk_score=result["risk_score"],
                verdict=result["verdict"],
                confidence=result["confidence"],
                engines=result["engines"],
                flags=result["flags"],
                score_breakdown=score_breakdown,
                detection_time_ms=detection_time_ms,
                explainability_score=explainability_score,
                recommended_action=block_decision["action"],
                block_recommended=block_decision["block_recommended"],
                ai_generated_probability=0.0,
                llm_analysis=None,
                ip_address=ip_address,
                timestamp=timestamp,
            )
        return result

    engine_tasks: list[Awaitable[tuple[str, dict[str, Any]]]] = [
        _execute_engine("google_safe_browsing", google_safe_browsing.lookup_url(url)),
        _execute_engine("heuristics", heuristics.analyze_url(url)),
        _execute_engine("virustotal", virustotal.analyze_url(url)),
    ]
    if analysis_mode == "sandbox":
        engine_tasks.append(_execute_engine("falcon_sandbox", falcon_sandbox.analyze_url(url)))
    engine_pairs = await asyncio.gather(*engine_tasks)
    engines = dict(engine_pairs)

    flags: list[dict[str, Any]] = []
    gsb_result = engines["google_safe_browsing"]
    heuristics_result = engines["heuristics"]
    vt_result = engines["virustotal"]
    falcon_result = engines.get("falcon_sandbox")

    if gsb_result.get("matched"):
        threat_type = gsb_result.get("threat_type") or "unknown"
        flags.append(_flag("google_safe_browsing_match", "high", f"Google Safe Browsing matched threat type {threat_type}"))
    heuristics_score = int(heuristics_result.get("score", 0))
    flags.extend(heuristics_result.get("flags", []))

    positives = int(vt_result.get("positives", 0))
    total = int(vt_result.get("total", 0))
    if total > 0 and positives > 0:
        flags.append(_flag("virustotal_positive", "high", f"VirusTotal detected the URL in {positives}/{total} engines"))
    falcon_points, falcon_verdict = _falcon_points(falcon_result, max_points=40)
    if analysis_mode == "sandbox" and falcon_points > 0:
        severity = "high" if falcon_points >= 30 else "medium"
        flags.append(
            _flag(
                "falcon_sandbox_detection",
                severity,
                f"Falcon Sandbox reported verdict '{falcon_verdict}' for the submitted URL",
            )
        )

    fused_score, score_breakdown = _fuse_weighted_signals(
        [
            _weighted_signal(
                "google_safe_browsing",
                100 if gsb_result.get("matched") else None,
                0.55 if analysis_mode != "sandbox" else 0.25,
                f"Google Safe Browsing matched threat type {gsb_result.get('threat_type') or 'unknown'}",
                "high",
            ),
            _weighted_signal(
                "virustotal",
                _normalized_vt_score(vt_result),
                0.30 if analysis_mode != "sandbox" else 0.15,
                f"VirusTotal flagged the URL in {positives}/{total} engines" if total > 0 else "VirusTotal URL reputation signal",
                "high",
            ),
            _weighted_signal(
                "heuristics",
                heuristics_score,
                0.15 if analysis_mode != "sandbox" else 0.10,
                f"Local URL heuristics scored the URL at {heuristics_score}/100",
                "medium" if heuristics_score >= 50 else "low",
            ),
            _weighted_signal(
                "falcon_sandbox",
                _normalized_falcon_score(falcon_result) if analysis_mode == "sandbox" else None,
                0.50,
                f"Falcon Sandbox returned verdict '{falcon_verdict or 'unknown'}'",
                "high" if _falcon_positive(falcon_result) else "medium",
            ),
        ]
    )

    final_score = int(round(fused_score))
    if gsb_result.get("matched"):
        final_score = max(final_score, 85)
    if total > 0 and positives > 0:
        vt_ratio = positives / total
        if vt_ratio >= 0.35:
            final_score = max(final_score, 78)
        elif vt_ratio >= 0.18:
            final_score = max(final_score, 65)
    if analysis_mode == "sandbox" and _falcon_positive(falcon_result):
        final_score = max(final_score, 82 if int((falcon_result or {}).get("threat_score") or 0) >= 80 else 72)
    if heuristics_score >= 55:
        final_score = max(final_score, heuristics_score)
    final_score = min(100, final_score)

    verdict = _score_to_verdict(final_score)
    confidence = _calculate_confidence(engines, final_score)
    deduplicated_flags = _deduplicate_flags(flags)
    deduplicated_breakdown = _deduplicate_breakdown(score_breakdown)
    detection_time_ms = int((perf_counter() - started_at) * 1000)
    explainability_score = _calculate_explainability_score(deduplicated_flags, engines)
    block_decision = _build_block_decision(
        risk_score=final_score,
        verdict=verdict,
        flags=deduplicated_flags,
    )
    ai_generated_probability = float(heuristics_result.get("ai_generated_probability", 0.0) or 0.0)
    campaign_key = None
    campaign = None
    llm_analysis = None

    result = {
        "url": url,
        "risk_score": final_score,
        "verdict": verdict,
        "confidence": confidence,
        "engines": engines,
        "falcon_result": falcon_result if analysis_mode == "sandbox" else None,
        "llm_analysis": None,
        "flags": deduplicated_flags,
        "score_breakdown": deduplicated_breakdown,
        "detection_time_ms": detection_time_ms,
        "explainability_score": explainability_score,
        "block_decision": block_decision,
        "ai_generated_probability": ai_generated_probability,
        "timestamp": timestamp,
        "whitelisted": False,
        "campaign": None,
    }

    if persist:
        if final_score >= 25:
            campaign_key = correlation.build_campaign_key(
                content_type="url",
                source=source,
                primary_text=url,
                urls=[url],
                flags=deduplicated_flags,
            )
        stored_record = await _store_scan_result(
            db,
            url_or_content=url,
            content_type="url",
            source=source,
            risk_score=final_score,
            verdict=verdict,
            confidence=confidence,
            engines=engines,
            flags=deduplicated_flags,
            score_breakdown=deduplicated_breakdown,
            detection_time_ms=detection_time_ms,
            explainability_score=explainability_score,
            recommended_action=block_decision["action"],
            block_recommended=block_decision["block_recommended"],
            ai_generated_probability=ai_generated_probability,
            llm_analysis=llm_analysis,
            ip_address=ip_address,
            timestamp=timestamp,
            campaign_key=campaign_key,
        )
        chain_steps = [
            _root_chain_step(
                url,
                "url",
                final_score,
                verdict,
                {"confidence": confidence, "top_flags": block_decision["top_flags"]},
            )
        ]
        if analysis_mode == "sandbox":
            _extend_steps_with_falcon_artifacts(
                chain_steps,
                falcon_result,
                start_index=1,
                derived_from=url,
            )
        await correlation.create_attack_chain(
            db,
            root_scan_id=stored_record.id,
            content_type="url",
            source=source,
            risk_score=final_score,
            verdict=verdict,
            summary=_summarize_chain(content_type="url", risky_link_count=1 if final_score >= 31 else 0),
            steps=chain_steps,
        )
        campaign = await _campaign_summary(db, campaign_key)
        result["campaign"] = campaign
    return result


async def scan_attachment_content(
    db: AsyncSession,
    *,
    attachment: dict[str, Any],
    source: str,
    ip_address: str | None,
    context_label: str | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    started_at = perf_counter()
    timestamp = datetime.now(timezone.utc)
    filename = str(attachment.get("filename") or "attachment.bin").strip() or "attachment.bin"
    mime_type = attachment.get("mime_type")
    content = attachment_analyzer.decode_attachment_payload(str(attachment.get("content_base64") or ""))

    static_analysis = attachment_analyzer.analyze_attachment(filename, content, mime_type)
    extracted_urls = static_analysis.get("extracted_urls", [])[: _settings().max_attachment_urls_to_scan]
    scanned_urls = (
        await asyncio.gather(
            *[
                _scan_url_in_isolated_session(
                    url=url,
                    source=source,
                    ip_address=ip_address,
                    persist=False,
                )
                for url in extracted_urls
            ]
        )
        if extracted_urls
        else []
    )

    yara_pair, vt_pair, falcon_pair = await asyncio.gather(
        _execute_engine(
            "yara",
            yara_engine.scan_content(
                f"attachment://{filename}",
                content[:250_000].decode("utf-8", errors="ignore"),
            ),
        ),
        _execute_engine("virustotal", virustotal.analyze_file_hash(str(static_analysis["sha256"]))),
        _execute_engine(
            "falcon_sandbox",
            falcon_sandbox.analyze_file(
                filename=filename,
                content=content,
                mime_type=static_analysis.get("mime_type"),
            ),
        ),
    )
    _, yara_result = yara_pair
    _, vt_result = vt_pair
    _, falcon_result = falcon_pair

    flags: list[dict[str, Any]] = list(static_analysis.get("flags", []))
    risky_url_count = sum(1 for item in scanned_urls if item.get("risk_score", 0) >= 40)
    extracted_url_max_score = max((item.get("risk_score", 0) for item in scanned_urls), default=0)

    if yara_result.get("matched"):
        yara_severity = str(yara_result.get("severity", "medium"))
        for rule_name in yara_result.get("rules_matched", []):
            flags.append(_flag("yara_rule_match", yara_severity, f"Attachment content matched YARA rule '{rule_name}'"))

    if vt_result.get("found") and int(vt_result.get("positives", 0)) > 0 and int(vt_result.get("total", 0)) > 0:
        positives = int(vt_result["positives"])
        total = int(vt_result["total"])
        flags.append(_flag("virustotal_file_hash_match", "high", f"VirusTotal flagged the file hash in {positives}/{total} engines"))
    else:
        positives = 0
        total = int(vt_result.get("total", 0) or 0)

    falcon_points, falcon_verdict = _falcon_points(falcon_result, max_points=35)
    if falcon_points > 0:
        severity = "high" if falcon_points >= 26 else "medium"
        flags.append(
            _flag(
                "falcon_sandbox_detection",
                severity,
                f"Falcon Sandbox reported verdict '{falcon_verdict}' for the submitted attachment",
            )
        )

    score_breakdown: list[dict[str, Any]] = []
    fused_score, fusion_breakdown = _fuse_weighted_signals(
        [
            _weighted_signal(
                "falcon_sandbox",
                _normalized_falcon_score(falcon_result),
                0.45,
                f"Falcon Sandbox returned verdict '{falcon_verdict or 'unknown'}'",
                "high" if _falcon_positive(falcon_result) else "medium",
            ),
            _weighted_signal(
                "virustotal_file_hash",
                _normalized_vt_score(vt_result),
                0.30,
                f"VirusTotal flagged the file hash in {positives}/{total} engines" if total > 0 else "VirusTotal hash reputation signal",
                "high",
            ),
            _weighted_signal(
                "static_attachment_analysis",
                float(static_analysis.get("score", 0.0)),
                0.15,
                f"Local attachment analysis scored the file at {int(round(float(static_analysis.get('score', 0.0))))}/100",
                "medium",
            ),
            _weighted_signal(
                "yara",
                _normalized_yara_score(yara_result),
                0.10,
                f"Attachment content matched {len(yara_result.get('rules_matched', []))} YARA rule(s)",
                str(yara_result.get("severity", "medium")).lower(),
            ),
        ]
    )
    score_breakdown.extend(fusion_breakdown)

    if risky_url_count:
        points = min(18, risky_url_count * 6)
        flags.append(
            _flag(
                "embedded_risky_urls",
                "high" if risky_url_count >= 2 else "medium",
                f"Attachment contains {risky_url_count} risky embedded URL(s)",
            )
        )
        score_breakdown.append(
            _score_item(
                "embedded_risky_urls",
                points,
                f"Attachment contains {risky_url_count} risky embedded URL(s)",
                "high" if risky_url_count >= 2 else "medium",
            )
        )

    final_score = min(
        100,
        max(
            int(round(fused_score)),
            extracted_url_max_score,
            int(round((fused_score * 0.8) + (extracted_url_max_score * 0.35))),
        ),
    )
    if _falcon_positive(falcon_result):
        final_score = max(final_score, 78)
    if total > 0 and positives > 0 and (positives / total) >= 0.25:
        final_score = max(final_score, 72)
    verdict = _score_to_verdict(final_score)
    engines = {
        "static_analysis": static_analysis,
        "yara": yara_result,
        "virustotal": vt_result,
        "falcon_sandbox": falcon_result,
    }
    deduplicated_flags = _deduplicate_flags(flags)
    deduplicated_breakdown = _deduplicate_breakdown(score_breakdown)
    detection_time_ms = int((perf_counter() - started_at) * 1000)
    explainability_score = _calculate_explainability_score(deduplicated_flags, engines)
    block_decision = _build_block_decision(
        risk_score=final_score,
        verdict=verdict,
        flags=deduplicated_flags,
    )
    confidence = _calculate_attachment_confidence(
        engines=engines,
        risk_score=final_score,
        risky_link_count=risky_url_count,
    )
    campaign_key = None
    campaign = None

    result = {
        "filename": filename,
        "sha256": static_analysis["sha256"],
        "mime_type": static_analysis.get("mime_type"),
        "detected_type": static_analysis.get("detected_type"),
        "extension": static_analysis.get("extension"),
        "file_size": int(static_analysis.get("file_size", 0)),
        "password_protected": bool(static_analysis.get("password_protected", False)),
        "contained_filenames": static_analysis.get("contained_filenames", []),
        "extracted_urls": extracted_urls,
        "extracted_url_scans": scanned_urls,
        "risk_score": final_score,
        "verdict": verdict,
        "confidence": confidence,
        "engines": engines,
        "falcon_result": falcon_result,
        "llm_analysis": None,
        "flags": deduplicated_flags,
        "score_breakdown": deduplicated_breakdown,
        "detection_time_ms": detection_time_ms,
        "explainability_score": explainability_score,
        "block_decision": block_decision,
        "ai_generated_probability": 0.0,
        "timestamp": timestamp,
        "campaign": None,
    }

    if persist:
        if final_score >= 25:
            campaign_key = correlation.build_campaign_key(
                content_type="attachment",
                source=source,
                primary_text=context_label or filename,
                urls=extracted_urls,
                flags=deduplicated_flags,
                attachment_hashes=[static_analysis["sha256"]],
            )
        stored_record = await _store_scan_result(
            db,
            url_or_content=filename,
            content_type="attachment",
            source=source,
            risk_score=final_score,
            verdict=verdict,
            confidence=confidence,
            engines=engines,
            flags=deduplicated_flags,
            score_breakdown=deduplicated_breakdown,
            detection_time_ms=detection_time_ms,
            explainability_score=explainability_score,
            recommended_action=block_decision["action"],
            block_recommended=block_decision["block_recommended"],
            ai_generated_probability=0.0,
            llm_analysis=None,
            ip_address=ip_address,
            timestamp=timestamp,
            campaign_key=campaign_key,
        )

        steps = [
            _root_chain_step(
                filename,
                "attachment",
                final_score,
                verdict,
                {
                    "sha256": static_analysis["sha256"],
                    "detected_type": static_analysis.get("detected_type"),
                    "context_label": context_label,
                },
            )
        ]
        next_index = _extend_steps_with_falcon_artifacts(
            steps,
            falcon_result,
            start_index=1,
            derived_from=filename,
        )
        _extend_steps_with_urls(steps, scanned_urls, start_index=next_index, relation="contains_url")
        await correlation.create_attack_chain(
            db,
            root_scan_id=stored_record.id,
            content_type="attachment",
            source=source,
            risk_score=final_score,
            verdict=verdict,
            summary=_summarize_chain(
                content_type="attachment",
                risky_link_count=sum(1 for item in scanned_urls if item.get("risk_score", 0) >= 31),
                nested_url_count=len(extracted_urls),
            ),
            steps=steps,
        )
        campaign = await _campaign_summary(db, campaign_key)
        result["campaign"] = campaign
    return result


async def scan_email_content(
    db: AsyncSession,
    *,
    content: str,
    subject: str | None,
    links: list[str],
    attachments: list[dict[str, Any]] | None,
    source: str,
    ip_address: str | None,
) -> dict[str, Any]:
    started_at = perf_counter()
    extracted_links = heuristics.extract_urls_from_text(content)
    unique_links = list(dict.fromkeys(links + extracted_links))[:20]
    limited_attachments = list(attachments or [])[: _settings().max_attachment_count]

    scanned_links, email_analysis, yara_pair, scanned_attachments = await asyncio.gather(
        asyncio.gather(
            *[
                _scan_url_in_isolated_session(
                    url=url,
                    source=source,
                    ip_address=ip_address,
                    persist=False,
                )
                for url in unique_links
            ]
        ),
        heuristics.analyze_email_content(content, subject),
        _execute_engine("yara", yara_engine.scan_content("email://message", content)),
        asyncio.gather(
            *[
                scan_attachment_content(
                    db,
                    attachment=attachment,
                    source=source,
                    ip_address=ip_address,
                    context_label=subject,
                    persist=False,
                )
                for attachment in limited_attachments
            ]
        ),
    )
    _, content_yara = yara_pair

    link_max_score = max((item["risk_score"] for item in scanned_links), default=0)
    attachment_max_score = max((item["risk_score"] for item in scanned_attachments), default=0)
    link_avg_confidence = mean([item["confidence"] for item in scanned_links]) if scanned_links else 0.0
    attachment_avg_confidence = mean([item["confidence"] for item in scanned_attachments]) if scanned_attachments else 0.0
    ai_generated_probability = float(email_analysis.get("ai_generated_probability", 0.0) or 0.0)
    risky_link_count = sum(1 for item in scanned_links if item.get("risk_score", 0) >= 40)
    risky_attachment_count = sum(1 for item in scanned_attachments if item.get("risk_score", 0) >= 40)

    flags: list[dict[str, Any]] = []
    flags.extend(email_analysis.get("flags", []))
    for item in scanned_links:
        flags.extend(item.get("flags", []))
    for item in scanned_attachments:
        flags.extend(item.get("flags", []))

    base_content_signals = [
        _weighted_signal(
            "email_heuristics",
            float(email_analysis.get("score", 0.0)),
            0.45,
            f"Local email heuristics scored the message at {int(round(float(email_analysis.get('score', 0.0))))}/100",
            "medium" if float(email_analysis.get("phishing_probability", 0.0)) >= 0.5 else "low",
        ),
        _weighted_signal(
            "ai_generated_patterns",
            ai_generated_probability * 100 if ai_generated_probability > 0 else None,
            0.15,
            "Local AI-fingerprint logic detected templated phishing-style language",
            "medium",
        ),
        _weighted_signal(
            "yara",
            _normalized_yara_score(content_yara),
            0.15,
            f"Email content matched {len(content_yara.get('rules_matched', []))} YARA rule(s)",
            str(content_yara.get("severity", "medium")).lower(),
        ),
    ]
    preliminary_content_score, preliminary_breakdown = _fuse_weighted_signals(base_content_signals)
    preliminary_combined_score = min(
        100,
        max(
            link_max_score,
            attachment_max_score,
            int(round(preliminary_content_score)),
            int(round((link_max_score * 0.30) + (attachment_max_score * 0.25) + (preliminary_content_score * 0.45))),
        ),
    )

    campaign_key = None
    if preliminary_combined_score >= 25:
        campaign_key = correlation.build_campaign_key(
            content_type="email",
            source=source,
            primary_text=content[:500],
            subject=subject,
            urls=[item["url"] for item in scanned_links] + [url for attachment in scanned_attachments for url in attachment.get("extracted_urls", [])],
            flags=_deduplicate_flags(flags),
            attachment_hashes=[attachment.get("sha256", "") for attachment in scanned_attachments if attachment.get("sha256")],
        )

    llm_analysis = await _maybe_generate_llm_analysis(
        persist=True,
        content_type="email",
        source=source,
        primary_text=content,
        local_verdict=_score_to_verdict(preliminary_combined_score),
        local_risk_score=preliminary_combined_score,
        local_confidence=round(max(0.35, (link_avg_confidence * 0.30) + (attachment_avg_confidence * 0.20) + (float(email_analysis["phishing_probability"]) * 0.35) + (ai_generated_probability * 0.15)), 2),
        flags=_deduplicate_flags(flags),
        score_breakdown=_deduplicate_breakdown(preliminary_breakdown),
        urls=[item["url"] for item in scanned_links] + [url for attachment in scanned_attachments for url in attachment.get("extracted_urls", [])],
        subject=subject,
        context_label=subject,
        extracted_artifacts=[attachment.get("filename", "") for attachment in scanned_attachments if attachment.get("filename")],
        campaign_key=campaign_key,
    )

    groq_score = _normalized_llm_score(llm_analysis)
    if groq_score is not None:
        groq_severity = "high" if groq_score >= 75 else "medium"
        flags.append(
            _flag(
                "groq_phishing_text_signal",
                groq_severity,
                f"Groq assessed the email text at {int(round(groq_score))}/100 for phishing likelihood",
            )
        )
        base_content_signals.append(
            _weighted_signal(
                "groq_phishing_text",
                groq_score,
                0.25,
                f"Groq assessed the email text at {int(round(groq_score))}/100 for phishing likelihood",
                groq_severity,
            )
        )

    combined_score = 0
    verdict = "safe"
    score_breakdown = []
    final_content_score, score_breakdown = _fuse_weighted_signals(base_content_signals)
    combined_score = min(
        100,
        max(
            link_max_score,
            attachment_max_score,
            int(round(final_content_score)),
            int(round((link_max_score * 0.30) + (attachment_max_score * 0.25) + (final_content_score * 0.45))),
        ),
    )
    verdict = _score_to_verdict(combined_score)

    if content_yara.get("matched"):
        yara_severity = str(content_yara.get("severity", "medium"))
        for rule_name in content_yara.get("rules_matched", []):
            flags.append(_flag("yara_rule_match", yara_severity, f"Email content matched YARA rule '{rule_name}'"))
    if len(extracted_links) > len(links):
        flags.append(_flag("inline_links_detected", "medium", "Additional URLs were extracted from the email body"))
    if risky_link_count:
        flags.append(
            _flag(
                "risky_embedded_links",
                "high" if risky_link_count >= 2 else "medium",
                f"Email contains {risky_link_count} risky embedded links",
            )
        )
        score_breakdown.append(
            _score_item(
                "embedded_links",
                min(12, risky_link_count * 4),
                f"Email contains {risky_link_count} risky embedded links",
                "high" if risky_link_count >= 2 else "medium",
            )
        )
    if risky_attachment_count:
        flags.append(
            _flag(
                "risky_attachments",
                "high" if risky_attachment_count >= 2 else "medium",
                f"Email contains {risky_attachment_count} risky attachment(s)",
            )
        )
        score_breakdown.append(
            _score_item(
                "attachments",
                min(18, risky_attachment_count * 6),
                f"Email contains {risky_attachment_count} risky attachment(s)",
                "high" if risky_attachment_count >= 2 else "medium",
            )
        )
    if link_max_score:
        score_breakdown.append(
            _score_item(
                "highest_link_risk",
                round(link_max_score * 0.35, 2),
                f"Highest embedded link risk score was {link_max_score}/100",
                "medium" if link_max_score < 61 else "high",
            )
        )
    if attachment_max_score:
        score_breakdown.append(
            _score_item(
                "highest_attachment_risk",
                round(attachment_max_score * 0.35, 2),
                f"Highest attachment risk score was {attachment_max_score}/100",
                "medium" if attachment_max_score < 61 else "high",
            )
        )

    confidence = round(
        min(
            0.99,
            max(
                0.35,
                (link_avg_confidence * 0.30)
                + (attachment_avg_confidence * 0.20)
                + (float(email_analysis["phishing_probability"]) * 0.20)
                + (ai_generated_probability * 0.10)
                + ((float(llm_analysis.get("confidence")) if isinstance(llm_analysis, dict) and llm_analysis.get("confidence") is not None else 0.0) * 0.20),
            ),
        ),
        2,
    )
    if content_yara.get("matched"):
        confidence = round(min(0.99, confidence + 0.05), 2)

    timestamp = datetime.now(timezone.utc)
    deduplicated_flags = _deduplicate_flags(flags)
    deduplicated_breakdown = _deduplicate_breakdown(score_breakdown)
    detection_time_ms = int((perf_counter() - started_at) * 1000)
    falcon_summary = _summarize_falcon_results(scanned_links, scanned_attachments)
    engines = {"yara": content_yara, "heuristics": email_analysis, "falcon_sandbox": falcon_summary}
    explainability_score = _calculate_explainability_score(deduplicated_flags, engines)
    block_decision = _build_block_decision(
        risk_score=combined_score,
        verdict=verdict,
        flags=deduplicated_flags,
    )
    campaign = None

    result = {
        "subject": subject,
        "risk_score": combined_score,
        "verdict": verdict,
        "confidence": confidence,
        "phishing_probability": float(email_analysis["phishing_probability"]),
        "ai_generated_probability": ai_generated_probability,
        "ai_fingerprint": email_analysis.get("ai_fingerprint"),
        "falcon_result": falcon_summary,
        "llm_analysis": None,
        "scanned_links": scanned_links,
        "scanned_attachments": scanned_attachments,
        "flags": deduplicated_flags,
        "score_breakdown": deduplicated_breakdown,
        "detection_time_ms": detection_time_ms,
        "explainability_score": explainability_score,
        "block_decision": block_decision,
        "timestamp": timestamp,
        "campaign": None,
    }

    if campaign_key is None and combined_score >= 25:
        campaign_key = correlation.build_campaign_key(
            content_type="email",
            source=source,
            primary_text=content[:500],
            subject=subject,
            urls=[item["url"] for item in scanned_links] + [url for attachment in scanned_attachments for url in attachment.get("extracted_urls", [])],
            flags=deduplicated_flags,
            attachment_hashes=[attachment.get("sha256", "") for attachment in scanned_attachments if attachment.get("sha256")],
        )

    stored_record = await _store_scan_result(
        db,
        url_or_content=content,
        content_type="email",
        source=source,
        risk_score=combined_score,
        verdict=verdict,
        confidence=confidence,
        engines=engines,
        flags=deduplicated_flags,
        score_breakdown=deduplicated_breakdown,
        detection_time_ms=detection_time_ms,
        explainability_score=explainability_score,
        recommended_action=block_decision["action"],
        block_recommended=block_decision["block_recommended"],
        ai_generated_probability=ai_generated_probability,
        llm_analysis=llm_analysis,
        ip_address=ip_address,
        timestamp=timestamp,
        campaign_key=campaign_key,
    )

    steps = [
        _root_chain_step(
            subject or "email_message",
            "email",
            combined_score,
            verdict,
            {
                "link_count": len(scanned_links),
                "attachment_count": len(scanned_attachments),
                "phishing_probability": float(email_analysis["phishing_probability"]),
            },
        )
    ]
    next_index = _extend_steps_with_urls(steps, scanned_links, start_index=1, relation="contains_link")
    _extend_steps_with_attachments(steps, scanned_attachments, start_index=next_index)
    await correlation.create_attack_chain(
        db,
        root_scan_id=stored_record.id,
        content_type="email",
        source=source,
        risk_score=combined_score,
        verdict=verdict,
        summary=_summarize_chain(
            content_type="email",
            risky_link_count=sum(1 for item in scanned_links if item.get("risk_score", 0) >= 31),
            risky_attachment_count=sum(1 for item in scanned_attachments if item.get("risk_score", 0) >= 31),
            nested_url_count=sum(len(item.get("extracted_urls", [])) for item in scanned_attachments),
        ),
        steps=steps,
    )
    campaign = await _campaign_summary(db, campaign_key)
    result["campaign"] = campaign
    result["llm_analysis"] = llm_analysis
    return result


async def scan_chat_content(
    db: AsyncSession,
    *,
    content: str,
    sender: str | None,
    links: list[str],
    attachments: list[dict[str, Any]] | None,
    source: str,
    ip_address: str | None,
) -> dict[str, Any]:
    started_at = perf_counter()
    extracted_links = heuristics.extract_urls_from_text(content)
    unique_links = list(dict.fromkeys(links + extracted_links))[:20]
    limited_attachments = list(attachments or [])[: _settings().max_attachment_count]

    scanned_links, chat_analysis, yara_pair, scanned_attachments = await asyncio.gather(
        asyncio.gather(
            *[
                _scan_url_in_isolated_session(
                    url=url,
                    source=source,
                    ip_address=ip_address,
                    persist=False,
                )
                for url in unique_links
            ]
        ),
        heuristics.analyze_chat_content(content),
        _execute_engine("yara", yara_engine.scan_content("chat://conversation", content)),
        asyncio.gather(
            *[
                scan_attachment_content(
                    db,
                    attachment=attachment,
                    source=source,
                    ip_address=ip_address,
                    context_label=sender,
                    persist=False,
                )
                for attachment in limited_attachments
            ]
        ),
    )
    _, content_yara = yara_pair

    link_max_score = max((item["risk_score"] for item in scanned_links), default=0)
    attachment_max_score = max((item["risk_score"] for item in scanned_attachments), default=0)
    link_avg_confidence = mean([item["confidence"] for item in scanned_links]) if scanned_links else 0.0
    attachment_avg_confidence = mean([item["confidence"] for item in scanned_attachments]) if scanned_attachments else 0.0
    ai_generated_probability = float(chat_analysis.get("ai_generated_probability", 0.0) or 0.0)
    risky_link_count = sum(1 for item in scanned_links if item.get("risk_score", 0) >= 40)
    risky_attachment_count = sum(1 for item in scanned_attachments if item.get("risk_score", 0) >= 40)

    flags: list[dict[str, Any]] = []
    flags.extend(chat_analysis.get("flags", []))
    for item in scanned_links:
        flags.extend(item.get("flags", []))
    for item in scanned_attachments:
        flags.extend(item.get("flags", []))

    base_content_signals = [
        _weighted_signal(
            "chat_heuristics",
            float(chat_analysis.get("score", 0.0)),
            0.45,
            f"Local chat heuristics scored the message at {int(round(float(chat_analysis.get('score', 0.0))))}/100",
            "medium" if float(chat_analysis.get("phishing_probability", 0.0)) >= 0.5 else "low",
        ),
        _weighted_signal(
            "ai_generated_patterns",
            ai_generated_probability * 100 if ai_generated_probability > 0 else None,
            0.15,
            "Local AI-fingerprint logic detected templated scam-style language",
            "medium",
        ),
        _weighted_signal(
            "yara",
            _normalized_yara_score(content_yara),
            0.15,
            f"Chat content matched {len(content_yara.get('rules_matched', []))} YARA rule(s)",
            str(content_yara.get("severity", "medium")).lower(),
        ),
    ]
    preliminary_content_score, preliminary_breakdown = _fuse_weighted_signals(base_content_signals)
    preliminary_combined_score = min(
        100,
        max(
            link_max_score,
            attachment_max_score,
            int(round(preliminary_content_score)),
            int(round((link_max_score * 0.30) + (attachment_max_score * 0.25) + (preliminary_content_score * 0.45))),
        ),
    )

    campaign_key = None
    if preliminary_combined_score >= 25:
        campaign_key = correlation.build_campaign_key(
            content_type="chat",
            source=source,
            primary_text=content[:500],
            sender=sender,
            urls=[item["url"] for item in scanned_links] + [url for attachment in scanned_attachments for url in attachment.get("extracted_urls", [])],
            flags=_deduplicate_flags(flags),
            attachment_hashes=[attachment.get("sha256", "") for attachment in scanned_attachments if attachment.get("sha256")],
        )

    llm_analysis = await _maybe_generate_llm_analysis(
        persist=True,
        content_type="chat",
        source=source,
        primary_text=content,
        local_verdict=_score_to_verdict(preliminary_combined_score),
        local_risk_score=preliminary_combined_score,
        local_confidence=round(max(0.35, (link_avg_confidence * 0.30) + (attachment_avg_confidence * 0.20) + (float(chat_analysis["phishing_probability"]) * 0.35) + (ai_generated_probability * 0.15)), 2),
        flags=_deduplicate_flags(flags),
        score_breakdown=_deduplicate_breakdown(preliminary_breakdown),
        urls=[item["url"] for item in scanned_links] + [url for attachment in scanned_attachments for url in attachment.get("extracted_urls", [])],
        sender=sender,
        context_label=sender,
        extracted_artifacts=[attachment.get("filename", "") for attachment in scanned_attachments if attachment.get("filename")],
        campaign_key=campaign_key,
    )

    groq_score = _normalized_llm_score(llm_analysis)
    if groq_score is not None:
        groq_severity = "high" if groq_score >= 75 else "medium"
        flags.append(
            _flag(
                "groq_phishing_text_signal",
                groq_severity,
                f"Groq assessed the chat text at {int(round(groq_score))}/100 for phishing likelihood",
            )
        )
        base_content_signals.append(
            _weighted_signal(
                "groq_phishing_text",
                groq_score,
                0.25,
                f"Groq assessed the chat text at {int(round(groq_score))}/100 for phishing likelihood",
                groq_severity,
            )
        )

    combined_score = 0
    verdict = "safe"
    score_breakdown = []
    final_content_score, score_breakdown = _fuse_weighted_signals(base_content_signals)
    combined_score = min(
        100,
        max(
            link_max_score,
            attachment_max_score,
            int(round(final_content_score)),
            int(round((link_max_score * 0.30) + (attachment_max_score * 0.25) + (final_content_score * 0.45))),
        ),
    )
    verdict = _score_to_verdict(combined_score)

    if content_yara.get("matched"):
        yara_severity = str(content_yara.get("severity", "medium"))
        for rule_name in content_yara.get("rules_matched", []):
            flags.append(_flag("yara_rule_match", yara_severity, f"Chat content matched YARA rule '{rule_name}'"))
    if len(extracted_links) > len(links):
        flags.append(_flag("inline_links_detected", "medium", "Additional URLs were extracted from the chat content"))
    if risky_link_count:
        flags.append(
            _flag(
                "risky_embedded_links",
                "high" if risky_link_count >= 2 else "medium",
                f"Chat contains {risky_link_count} risky embedded links",
            )
        )
        score_breakdown.append(
            _score_item(
                "embedded_links",
                min(12, risky_link_count * 4),
                f"Chat contains {risky_link_count} risky embedded links",
                "high" if risky_link_count >= 2 else "medium",
            )
        )
    if risky_attachment_count:
        flags.append(
            _flag(
                "risky_attachments",
                "high" if risky_attachment_count >= 2 else "medium",
                f"Chat contains {risky_attachment_count} risky attachment(s)",
            )
        )
        score_breakdown.append(
            _score_item(
                "attachments",
                min(18, risky_attachment_count * 6),
                f"Chat contains {risky_attachment_count} risky attachment(s)",
                "high" if risky_attachment_count >= 2 else "medium",
            )
        )
    if link_max_score:
        score_breakdown.append(
            _score_item(
                "highest_link_risk",
                round(link_max_score * 0.35, 2),
                f"Highest embedded link risk score was {link_max_score}/100",
                "medium" if link_max_score < 61 else "high",
            )
        )
    if attachment_max_score:
        score_breakdown.append(
            _score_item(
                "highest_attachment_risk",
                round(attachment_max_score * 0.35, 2),
                f"Highest attachment risk score was {attachment_max_score}/100",
                "medium" if attachment_max_score < 61 else "high",
            )
        )

    confidence = round(
        min(
            0.99,
            max(
                0.35,
                (link_avg_confidence * 0.30)
                + (attachment_avg_confidence * 0.20)
                + (float(chat_analysis["phishing_probability"]) * 0.20)
                + (ai_generated_probability * 0.10)
                + ((float(llm_analysis.get("confidence")) if isinstance(llm_analysis, dict) and llm_analysis.get("confidence") is not None else 0.0) * 0.20),
            ),
        ),
        2,
    )
    if content_yara.get("matched"):
        confidence = round(min(0.99, confidence + 0.05), 2)

    timestamp = datetime.now(timezone.utc)
    deduplicated_flags = _deduplicate_flags(flags)
    deduplicated_breakdown = _deduplicate_breakdown(score_breakdown)
    detection_time_ms = int((perf_counter() - started_at) * 1000)
    falcon_summary = _summarize_falcon_results(scanned_links, scanned_attachments)
    engines = {"heuristics": chat_analysis, "yara": content_yara, "falcon_sandbox": falcon_summary}
    explainability_score = _calculate_explainability_score(deduplicated_flags, engines)
    block_decision = _build_block_decision(
        risk_score=combined_score,
        verdict=verdict,
        flags=deduplicated_flags,
    )
    campaign = None

    result = {
        "sender": sender,
        "risk_score": combined_score,
        "verdict": verdict,
        "confidence": confidence,
        "phishing_probability": float(chat_analysis["phishing_probability"]),
        "ai_generated_probability": ai_generated_probability,
        "ai_fingerprint": chat_analysis.get("ai_fingerprint"),
        "falcon_result": falcon_summary,
        "llm_analysis": None,
        "scanned_links": scanned_links,
        "scanned_attachments": scanned_attachments,
        "flags": deduplicated_flags,
        "score_breakdown": deduplicated_breakdown,
        "detection_time_ms": detection_time_ms,
        "explainability_score": explainability_score,
        "block_decision": block_decision,
        "timestamp": timestamp,
        "campaign": None,
    }

    if campaign_key is None and combined_score >= 25:
        campaign_key = correlation.build_campaign_key(
            content_type="chat",
            source=source,
            primary_text=content[:500],
            sender=sender,
            urls=[item["url"] for item in scanned_links] + [url for attachment in scanned_attachments for url in attachment.get("extracted_urls", [])],
            flags=deduplicated_flags,
            attachment_hashes=[attachment.get("sha256", "") for attachment in scanned_attachments if attachment.get("sha256")],
        )

    stored_record = await _store_scan_result(
        db,
        url_or_content=content,
        content_type="chat",
        source=source,
        risk_score=combined_score,
        verdict=verdict,
        confidence=confidence,
        engines=engines,
        flags=deduplicated_flags,
        score_breakdown=deduplicated_breakdown,
        detection_time_ms=detection_time_ms,
        explainability_score=explainability_score,
        recommended_action=block_decision["action"],
        block_recommended=block_decision["block_recommended"],
        ai_generated_probability=ai_generated_probability,
        llm_analysis=llm_analysis,
        ip_address=ip_address,
        timestamp=timestamp,
        campaign_key=campaign_key,
    )

    steps = [
        _root_chain_step(
            sender or "chat_message",
            "chat",
            combined_score,
            verdict,
            {
                "link_count": len(scanned_links),
                "attachment_count": len(scanned_attachments),
                "phishing_probability": float(chat_analysis["phishing_probability"]),
            },
        )
    ]
    next_index = _extend_steps_with_urls(steps, scanned_links, start_index=1, relation="contains_link")
    _extend_steps_with_attachments(steps, scanned_attachments, start_index=next_index)
    await correlation.create_attack_chain(
        db,
        root_scan_id=stored_record.id,
        content_type="chat",
        source=source,
        risk_score=combined_score,
        verdict=verdict,
        summary=_summarize_chain(
            content_type="chat",
            risky_link_count=sum(1 for item in scanned_links if item.get("risk_score", 0) >= 31),
            risky_attachment_count=sum(1 for item in scanned_attachments if item.get("risk_score", 0) >= 31),
            nested_url_count=sum(len(item.get("extracted_urls", [])) for item in scanned_attachments),
        ),
        steps=steps,
    )
    campaign = await _campaign_summary(db, campaign_key)
    result["campaign"] = campaign
    result["llm_analysis"] = llm_analysis
    return result


async def scan_batch_urls(
    db: AsyncSession,
    *,
    urls: list[str],
    source: str,
    ip_address: str | None,
) -> list[dict[str, Any]]:
    return await asyncio.gather(
        *[
            _scan_url_in_isolated_session(
                url=url,
                source=source,
                ip_address=ip_address,
                persist=True,
            )
            for url in urls
        ]
    )


async def _scan_url_in_isolated_session(
    *,
    url: str,
    source: str,
    ip_address: str | None,
    persist: bool,
    analysis_mode: str = "standard",
) -> dict[str, Any]:
    async with AsyncSessionLocal() as session:
        return await scan_single_url(
            session,
            url=url,
            source=source,
            analysis_mode=analysis_mode,
            ip_address=ip_address,
            persist=persist,
        )
