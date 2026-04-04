import asyncio
import json
import logging
from typing import Optional

import httpx

from app.core.config import Settings
from app.models.schemas import ExplanationRequest, ScanResult

logger = logging.getLogger(__name__)
AI_PROVIDER_TIMEOUT_SECONDS = 20.0
PROVIDER_RETRY_STATUS_CODES = {408, 409, 425, 429, 500, 502, 503, 504}


class AIEnhancementService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def enrich_scan_result(
        self,
        result: ScanResult,
        text: Optional[str] = None,
        url: Optional[str] = None,
        preferred_provider: Optional[str] = None,
    ) -> ScanResult:
        explanation = await self.generate_explanation(
            ExplanationRequest(
                label=result.label,
                risk_score=result.risk_score,
                reasons=result.reasons,
                text=text,
                url=url,
                preferred_provider=preferred_provider,
            )
        )
        if explanation["explanation"]:
            result.ai_summary = explanation["explanation"]
            result.provider_used = explanation["provider_used"]
        return result

    async def assess_scan(
        self,
        *,
        text: Optional[str] = None,
        url: Optional[str] = None,
        attachment_context: Optional[dict] = None,
        source_type: str = "unified",
        rule_result: Optional[ScanResult] = None,
        partial_scan: bool = False,
    ) -> Optional[dict]:
        content = f"{text or ''} {url or ''}".strip()
        has_attachment_context = bool(attachment_context and attachment_context.get("attachments"))
        if len(content) < 4 and not has_attachment_context:
            return None

        providers = self._provider_order(None)
        if not providers:
            return None

        prompt = self._build_assessment_prompt(
            text=text,
            url=url,
            attachment_context=attachment_context,
            source_type=source_type,
            rule_result=rule_result,
            partial_scan=partial_scan,
        )

        for provider in providers:
            try:
                raw = await self._call_provider(provider, prompt)
                parsed = self._normalize_assessment(raw, provider)
                if parsed:
                    parsed["provider_used"] = provider
                    return parsed
            except Exception as exc:
                logger.warning("AI assessment provider %s unavailable: %s", provider, exc)
        return None

    async def generate_explanation(self, request: ExplanationRequest) -> dict:
        providers = self._provider_order(request.preferred_provider)
        prompt = self._build_prompt(request)

        for provider in providers:
            try:
                response = await self._call_provider(provider, prompt)
                if response:
                    return {
                        "explanation": response,
                        "provider_used": provider,
                    }
            except Exception as exc:
                logger.warning("AI provider %s unavailable: %s", provider, exc)

        return {
            "explanation": self._fallback_explanation(request),
            "provider_used": None,
        }

    def _provider_order(self, preferred_provider: Optional[str]) -> list[str]:
        available = []
        if preferred_provider:
            return [preferred_provider]
        if self.settings.grok_api_key:
            available.append("grok")
        if self.settings.gemini_api_key:
            available.append("gemini")
        if self.settings.openai_api_key:
            available.append("openai")
        return available

    async def _call_provider(self, provider: str, prompt: str) -> Optional[str]:
        if provider == "openai" and self.settings.openai_api_key:
            return await self._call_openai(prompt)
        if provider == "gemini" and self.settings.gemini_api_key:
            return await self._call_gemini(prompt)
        if provider == "grok" and self.settings.grok_api_key:
            return await self._call_grok(prompt)
        return None

    async def _call_openai(self, prompt: str) -> Optional[str]:
        headers = {
            "Authorization": f"Bearer {self.settings.openai_api_key}",
            "Content-Type": "application/json",
        }
        last_exc: Exception | None = None
        for attempt, model in enumerate(self._openai_models(), start=1):
            payload = {
                "model": model,
                "input": prompt,
            }
            try:
                async with httpx.AsyncClient(timeout=AI_PROVIDER_TIMEOUT_SECONDS, trust_env=False) as client:
                    response = await client.post(
                        "https://api.openai.com/v1/responses",
                        headers=headers,
                        json=payload,
                    )
                    response.raise_for_status()
                    data = response.json()
                logger.info("AI provider openai succeeded with model=%s", model)
                return data.get("output_text")
            except httpx.HTTPStatusError as exc:
                last_exc = exc
                if not self._should_retry_model(provider="openai", exc=exc):
                    raise
                logger.warning("OpenAI model %s unavailable (%s), trying next fallback", model, exc)
            except Exception as exc:
                last_exc = exc
                logger.warning("OpenAI model %s failed (%s), trying next fallback", model, exc)
            if attempt < len(self._openai_models()):
                await asyncio.sleep(0.6 * attempt)
        if last_exc:
            raise last_exc
        return None

    async def _call_gemini(self, prompt: str) -> Optional[str]:
        params = {"key": self.settings.gemini_api_key}
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        last_exc: Exception | None = None
        models = self._gemini_models()
        for attempt, model in enumerate(models, start=1):
            endpoint = (
                f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
            )
            try:
                async with httpx.AsyncClient(timeout=AI_PROVIDER_TIMEOUT_SECONDS, trust_env=False) as client:
                    response = await client.post(endpoint, params=params, json=payload)
                    response.raise_for_status()
                    data = response.json()
                candidates = data.get("candidates", [])
                if not candidates:
                    logger.warning("Gemini model %s returned no candidates", model)
                    continue
                logger.info("AI provider gemini succeeded with model=%s", model)
                return candidates[0]["content"]["parts"][0]["text"]
            except httpx.HTTPStatusError as exc:
                last_exc = exc
                if not self._should_retry_model(provider="gemini", exc=exc):
                    raise
                logger.warning("Gemini model %s unavailable (%s), trying next fallback", model, exc)
            except Exception as exc:
                last_exc = exc
                logger.warning("Gemini model %s failed (%s), trying next fallback", model, exc)
            if attempt < len(models):
                await asyncio.sleep(0.6 * attempt)
        if last_exc:
            raise last_exc
        return None

    async def _call_grok(self, prompt: str) -> Optional[str]:
        if self._is_groq_compatible_key():
            return await self._call_groq_cloud(prompt)

        headers = {
            "Authorization": f"Bearer {self.settings.grok_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.settings.grok_model,
            "messages": [
                {"role": "system", "content": "You explain phishing risk clearly."},
                {"role": "user", "content": prompt},
            ],
        }
        async with httpx.AsyncClient(timeout=AI_PROVIDER_TIMEOUT_SECONDS, trust_env=False) as client:
            response = await client.post(
                "https://api.x.ai/v1/chat/completions",
                headers=headers,
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
        choices = data.get("choices", [])
        if not choices:
            return None
        return choices[0]["message"]["content"]

    async def _call_groq_cloud(self, prompt: str) -> Optional[str]:
        headers = {
            "Authorization": f"Bearer {self.settings.grok_api_key}",
            "Content-Type": "application/json",
        }
        last_exc: Exception | None = None
        models = self._groq_models()
        for attempt, model in enumerate(models, start=1):
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": "You explain phishing risk clearly."},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.2,
                "response_format": {"type": "json_object"},
            }
            try:
                async with httpx.AsyncClient(timeout=AI_PROVIDER_TIMEOUT_SECONDS, trust_env=False) as client:
                    response = await client.post(
                        "https://api.groq.com/openai/v1/chat/completions",
                        headers=headers,
                        json=payload,
                    )
                    response.raise_for_status()
                    data = response.json()
                choices = data.get("choices", [])
                if not choices:
                    logger.warning("Groq model %s returned no choices", model)
                    continue
                logger.info("AI provider grok succeeded via Groq-compatible endpoint with model=%s", model)
                return choices[0]["message"]["content"]
            except httpx.HTTPStatusError as exc:
                last_exc = exc
                if not self._should_retry_model(provider="grok", exc=exc):
                    raise
                logger.warning("Groq model %s unavailable (%s), trying next fallback", model, exc)
            except Exception as exc:
                last_exc = exc
                logger.warning("Groq model %s failed (%s), trying next fallback", model, exc)
            if attempt < len(models):
                await asyncio.sleep(0.6 * attempt)
        if last_exc:
            raise last_exc
        return None

    def _openai_models(self) -> list[str]:
        return self._unique_non_empty(
            [
                self.settings.openai_model,
                "gpt-4.1-mini",
                "gpt-4.1-nano",
                "gpt-4o-mini",
            ]
        )

    def _gemini_models(self) -> list[str]:
        return self._unique_non_empty(
            [
                self.settings.gemini_model,
                "gemini-2.0-flash",
                "gemini-2.0-flash-lite",
                "gemini-1.5-flash",
            ]
        )

    def _groq_models(self) -> list[str]:
        configured = (self.settings.grok_model or "").strip()
        candidate_models = []
        if configured and not configured.startswith("grok-"):
            candidate_models.append(configured)
        candidate_models.extend(
            [
                "llama-3.1-8b-instant",
                "groq/compound",
                "qwen/qwen3-32b",
            ]
        )
        return self._unique_non_empty(candidate_models)

    def _is_groq_compatible_key(self) -> bool:
        return bool((self.settings.grok_api_key or "").strip().startswith("gsk_"))

    def _unique_non_empty(self, values: list[str]) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for value in values:
            normalized = (value or "").strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            ordered.append(normalized)
        return ordered

    def _should_retry_model(self, *, provider: str, exc: httpx.HTTPStatusError) -> bool:
        status_code = exc.response.status_code
        if status_code not in PROVIDER_RETRY_STATUS_CODES:
            return False
        if provider == "openai":
            message = exc.response.text.lower()
            return "insufficient_quota" in message or "rate" in message or status_code == 429
        if provider == "gemini":
            return status_code == 429 or status_code >= 500
        if provider == "grok":
            return status_code == 404 or status_code == 429 or status_code >= 500
        return status_code == 429 or status_code >= 500

    def _build_prompt(self, request: ExplanationRequest) -> str:
        payload = {
            "label": request.label,
            "risk_score": request.risk_score,
            "reasons": request.reasons,
            "text": request.text,
            "url": request.url,
        }
        return (
            "You are a cybersecurity assistant. Explain the phishing assessment in "
            "plain language for a mobile app user. Be concise, practical, and mention "
            "why the result was flagged. JSON input:\n"
            f"{json.dumps(payload, ensure_ascii=True)}"
        )

    def _build_assessment_prompt(
        self,
        *,
        text: Optional[str],
        url: Optional[str],
        attachment_context: Optional[dict],
        source_type: str,
        rule_result: Optional[ScanResult],
        partial_scan: bool,
    ) -> str:
        payload = {
            "source_type": source_type,
            "text": text,
            "url": url,
            "attachment_context": attachment_context,
            "partial_scan": partial_scan,
            "rule_risk_score": rule_result.risk_score if rule_result else None,
            "rule_reasons": rule_result.reasons if rule_result else [],
        }
        return (
            "You are a phishing detection engine. Review the content and return only valid JSON with this schema: "
            '{"risk_score": 0-100, "label": "safe|suspicious|phishing", "confidence": 0-1, '
            '"reasons": ["..."], "summary": "short explanation"}. '
            "Base the decision on phishing indicators like suspicious URLs, urgency, credential requests, "
            "reward scams, KYC/bank/payment bait, spoofing, risky attachments, and coercive call-to-action language. "
            "If the content is partial, lower confidence. Input:\n"
            f"{json.dumps(payload, ensure_ascii=True)}"
        )

    def _normalize_assessment(self, raw: Optional[str], provider: str) -> Optional[dict]:
        if not raw:
            return None
        raw = raw.strip()
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            start = raw.find("{")
            end = raw.rfind("}")
            if start == -1 or end == -1 or end <= start:
                logger.warning("AI assessment from %s returned non-JSON output", provider)
                return None
            try:
                parsed = json.loads(raw[start : end + 1])
            except json.JSONDecodeError:
                logger.warning("AI assessment from %s returned malformed JSON", provider)
                return None

        label = str(parsed.get("label", "")).lower()
        if label not in {"safe", "suspicious", "phishing"}:
            return None
        reasons = parsed.get("reasons") or []
        if not isinstance(reasons, list):
            reasons = [str(reasons)]
        try:
            risk_score = max(0, min(100, int(round(float(parsed.get("risk_score", 0))))))
            confidence = max(0.0, min(1.0, float(parsed.get("confidence", 0.5))))
        except (TypeError, ValueError):
            return None

        summary = str(parsed.get("summary") or "").strip() or None
        return {
            "risk_score": risk_score,
            "label": label,
            "confidence": confidence,
            "reasons": [str(reason) for reason in reasons if str(reason).strip()][:6],
            "summary": summary,
        }

    def _fallback_explanation(self, request: ExplanationRequest) -> str:
        reasons = ", ".join(request.reasons) if request.reasons else "No notable red flags"
        return (
            f"This item was classified as {request.label} with a risk score of "
            f"{request.risk_score}/100. Key reasons: {reasons}."
        )
