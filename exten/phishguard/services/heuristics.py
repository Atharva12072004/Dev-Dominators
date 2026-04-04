from __future__ import annotations

import asyncio
import logging
import math
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote, urlsplit

import tldextract

try:
    from ..ml.model_trainer import score_url as score_url_with_model
    from ..models.schemas import normalize_url
except ImportError:  # pragma: no cover - supports running from package root
    from ml.model_trainer import score_url as score_url_with_model
    from models.schemas import normalize_url


logger = logging.getLogger(__name__)

_extract = tldextract.TLDExtract(suffix_list_urls=None, cache_dir=None)

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click"}
SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
    "is.gd",
    "shorturl.at",
    "cutt.ly",
}
URL_KEYWORDS = {"login", "signin", "verify", "secure", "update", "confirm", "account", "bank", "paypal", "amazon", "ebay"}
BRAND_KEYWORDS = {"paypal", "amazon", "ebay", "bank", "microsoft", "google"}
OFFICIAL_BRAND_DOMAINS: dict[str, set[str]] = {
    "google": {"google.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "outlook.com", "live.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "paypal": {"paypal.com"},
    "ebay": {"ebay.com"},
}
LEETSPEAK_TRANSLATION = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    }
)
URGENCY_PATTERNS: dict[str, float] = {
    r"\bact now\b": 0.16,
    r"\blimited time\b": 0.14,
    r"\bexpire(?:s|d)?\b": 0.13,
    r"\bsuspended\b": 0.15,
    r"\bverify immediately\b": 0.18,
    r"\burgent\b": 0.12,
}
THREAT_PATTERNS: dict[str, float] = {
    r"\byour account will be\b": 0.2,
    r"\bunauthorized access\b": 0.22,
    r"\bconfirm your identity\b": 0.24,
    r"\bsecurity alert\b": 0.18,
    r"\bunusual activity\b": 0.18,
}
REQUEST_PATTERNS: dict[str, float] = {
    r"\benter your password\b": 0.28,
    r"\bclick here to login\b": 0.25,
    r"\blog in to avoid\b": 0.18,
    r"\breset your password\b": 0.12,
    r"\bverify your account\b": 0.16,
}
SUBJECT_PATTERNS: dict[str, float] = {
    r"\bpassword reset\b": 0.14,
    r"\baccount suspended\b": 0.22,
    r"\bverify your account\b": 0.22,
    r"\bsecurity notification\b": 0.16,
    r"\bpayment failed\b": 0.14,
}
AI_TEMPLATE_PATTERNS: dict[str, float] = {
    r"\bdear (customer|user|member|client)\b": 0.14,
    r"\bvalued customer\b": 0.12,
    r"\bkindly\b": 0.06,
    r"\bthis is an automated message\b": 0.15,
    r"\bimmediate action is required\b": 0.16,
    r"\bfailure to comply\b": 0.12,
    r"\bclick the secure link below\b": 0.18,
    r"\bdo not reply to this message\b": 0.1,
}
LLM_STYLE_PATTERNS: dict[str, tuple[float, str]] = {
    r"\b(for your security|to protect your account)\b": (0.08, "security_reassurance"),
    r"\b(as a precautionary measure|as part of our routine review)\b": (0.1, "institutional_framing"),
    r"\bplease review the information below\b": (0.12, "structured_instruction"),
    r"\bensure continued access\b": (0.12, "continuity_pressure"),
    r"\byour prompt attention\b": (0.1, "formal_urgency"),
    r"\bmaintain uninterrupted access\b": (0.12, "service_continuity_pressure"),
    r"\bwe have detected\b": (0.08, "generic_detection_claim"),
    r"\bfailure to (?:act|respond|comply)\b": (0.1, "compliance_warning"),
}
LLM_SIGNOFF_PATTERNS: dict[str, tuple[float, str]] = {
    r"\b(best regards|kind regards|sincerely|warm regards)\b": (0.05, "formal_signoff"),
    r"\b(support team|security team|billing department|customer care)\b": (0.06, "departmental_signature"),
}
CHAT_SCAM_PATTERNS: dict[str, float] = {
    r"\bshare (the )?otp\b": 0.28,
    r"\bsend me the code\b": 0.24,
    r"\bverify (the )?otp\b": 0.26,
    r"\botp (verification|required|needed|now)\b": 0.22,
    r"\burgent transfer\b": 0.18,
    r"\bpayment screenshot\b": 0.12,
    r"\bdownload (the )?apk\b": 0.3,
    r"\bverify your whatsapp\b": 0.22,
    r"\byour sim (?:will be|has been) (?:deactivated|blocked|suspended)\b": 0.34,
    r"\bsim (?:deactivated|blocked|suspended)\b": 0.28,
    r"\bcomplete (?:your )?kyc\b": 0.22,
    r"\bclick this link\b": 0.16,
    r"\bjoin this group\b": 0.08,
}


def _flag(rule: str, severity: str, description: str) -> dict[str, str]:
    return {
        "rule": rule,
        "severity": severity,
        "description": description,
    }


def _safe_ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _tokenize_words(value: str) -> list[str]:
    return re.findall(r"[a-zA-Z]{2,}", value.lower())


def _lexical_diversity(value: str) -> float:
    tokens = _tokenize_words(value)
    if not tokens:
        return 0.0
    return len(set(tokens)) / len(tokens)


def _sentence_lengths(value: str) -> list[int]:
    sentences = [segment.strip() for segment in re.split(r"[.!?]+", value) if segment.strip()]
    return [len(_tokenize_words(sentence)) for sentence in sentences if sentence]


def _uniform_sentence_structure_score(value: str) -> float:
    lengths = _sentence_lengths(value)
    if len(lengths) < 3:
        return 0.0
    mean_length = sum(lengths) / len(lengths)
    if mean_length == 0:
        return 0.0
    variance = sum((length - mean_length) ** 2 for length in lengths) / len(lengths)
    coefficient = math.sqrt(variance) / mean_length
    return max(0.0, 1.0 - min(coefficient, 1.0))


def _paragraph_lengths(value: str) -> list[int]:
    paragraphs = [segment.strip() for segment in re.split(r"(?:\r?\n){2,}", value) if segment.strip()]
    return [len(_tokenize_words(paragraph)) for paragraph in paragraphs if paragraph]


def _uniform_paragraph_structure_score(value: str) -> float:
    lengths = _paragraph_lengths(value)
    if len(lengths) < 2:
        return 0.0
    mean_length = sum(lengths) / len(lengths)
    if mean_length == 0:
        return 0.0
    variance = sum((length - mean_length) ** 2 for length in lengths) / len(lengths)
    coefficient = math.sqrt(variance) / mean_length
    return max(0.0, 1.0 - min(coefficient, 1.0))


def _sentence_openers(value: str) -> list[str]:
    sentences = [segment.strip() for segment in re.split(r"[.!?]+", value) if segment.strip()]
    openers: list[str] = []
    for sentence in sentences:
        tokens = _tokenize_words(sentence)
        if not tokens:
            continue
        openers.append(" ".join(tokens[:2]))
    return openers


def _repeated_sentence_opener_ratio(value: str) -> float:
    openers = _sentence_openers(value)
    if len(openers) < 3:
        return 0.0
    most_common_count = Counter(openers).most_common(1)[0][1]
    return round(_safe_ratio(most_common_count, len(openers)), 4)


def _keyword_density(value: str, keywords: list[str]) -> float:
    tokens = _tokenize_words(value)
    if not tokens:
        return 0.0
    hits = sum(value.lower().count(keyword) for keyword in keywords)
    return round(_safe_ratio(hits, len(tokens)), 4)


def _contraction_ratio(value: str) -> float:
    contractions = re.findall(r"\b\w+(?:'\w+)\b", value)
    words = _tokenize_words(value)
    if not words:
        return 0.0
    return round(_safe_ratio(len(contractions), len(words)), 4)


def _link_call_to_action_density(value: str) -> float:
    lowered = value.lower()
    cta_hits = sum(lowered.count(keyword) for keyword in ["click", "review", "verify", "confirm", "login", "respond", "reply", "download"])
    link_hits = lowered.count("http") + lowered.count("www.") + lowered.count("bit.ly") + lowered.count("tinyurl")
    words = _tokenize_words(value)
    if not words:
        return 0.0
    return round(_safe_ratio(cta_hits + link_hits, len(words)), 4)


async def _lookup_domain_age_days(domain: str) -> int | None:
    try:
        import whois
    except ImportError:
        return None

    try:
        record = await asyncio.wait_for(asyncio.to_thread(whois.whois, domain), timeout=1.5)
        creation_date = record.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return None
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - creation_date
        return max(delta.days, 0)
    except asyncio.TimeoutError:
        logger.warning("whois_lookup_timed_out", extra={"domain": domain})
        return None
    except Exception as exc:  # pragma: no cover - WHOIS stability depends on provider
        logger.warning("whois_lookup_failed", extra={"domain": domain, "error": str(exc)})
        return None


def _strip_candidate_delimiters(value: str) -> str:
    return value.strip().strip("()[]{}<>'\".,;:!?")


def _deobfuscate_candidate(value: str) -> str:
    candidate = value.strip()
    candidate = re.sub(r"^hxxps://", "https://", candidate, flags=re.IGNORECASE)
    candidate = re.sub(r"^hxxp://", "http://", candidate, flags=re.IGNORECASE)
    candidate = re.sub(r"\[\.\]|\(\.\)", ".", candidate)
    return candidate


def _normalize_brandish_text(value: str) -> str:
    return str(value or "").lower().translate(LEETSPEAK_TRANSLATION)


def _is_official_brand_domain(registered_domain: str, brand_hits: list[str]) -> bool:
    domain = str(registered_domain or "").lower().strip()
    if not domain or not brand_hits:
        return False
    for brand in brand_hits:
        allowed_domains = OFFICIAL_BRAND_DOMAINS.get(brand, set())
        if domain in allowed_domains:
            return True
    return False


def _looks_like_email_address(value: str) -> bool:
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value))


def _candidate_patterns() -> list[str]:
    return [
        r"""(?:(?:https?|hxxps?)://[^\s<>'"()]+)""",
        r"""(?<!@)\b(?:www\.)?[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9][a-z0-9-]{0,62})+(?:/[^\s<>'"()]+)?""",
        r"""(?<!@)\b[a-z0-9][a-z0-9-]{0,62}(?:\[\.\]|\(\.\)|\.)[a-z0-9][a-z0-9-]{0,62}(?:(?:\[\.\]|\(\.\)|\.)[a-z0-9][a-z0-9-]{0,62})+(?:/[^\s<>'"()]+)?""",
    ]


def extract_urls_from_text(content: str) -> list[str]:
    matches: list[str] = []
    for pattern in _candidate_patterns():
        matches.extend(re.findall(pattern, content, flags=re.IGNORECASE))

    hrefs = re.findall(r"""href=["']([^"']+)["']""", content, flags=re.IGNORECASE)
    discovered: list[str] = []
    for candidate in matches + hrefs:
        try:
            cleaned = _strip_candidate_delimiters(_deobfuscate_candidate(candidate))
            if not cleaned or _looks_like_email_address(cleaned):
                continue
            discovered.append(normalize_url(cleaned))
        except ValueError:
            continue
    return list(dict.fromkeys(discovered))


def analyze_ai_generated_content(content: str, channel: str = "message") -> dict[str, Any]:
    normalized = (content or "").lower()
    score = 0.0
    flags: list[dict[str, str]] = []
    markers_detected: list[str] = []
    matched_signals: list[dict[str, Any]] = []

    def add_signal(
        marker: str,
        weight: float,
        severity: str,
        rule: str,
        description: str,
    ) -> None:
        nonlocal score
        score += weight
        markers_detected.append(marker)
        flags.append(_flag(rule, severity, description))
        matched_signals.append(
            {
                "marker": marker,
                "weight": round(weight, 4),
                "severity": severity,
                "description": description,
            }
        )

    for pattern, weight in AI_TEMPLATE_PATTERNS.items():
        if re.search(pattern, normalized):
            marker = f"templated_phrase:{pattern}"
            add_signal(
                marker,
                weight,
                "medium",
                "ai_template_phrase",
                f"Templated social-engineering phrase detected: {pattern}",
            )

    for pattern, (weight, marker) in LLM_STYLE_PATTERNS.items():
        if re.search(pattern, normalized):
            add_signal(
                marker,
                weight,
                "medium",
                "llm_style_phrase",
                f"LLM-style phishing phrasing detected: {pattern}",
            )

    for pattern, (weight, marker) in LLM_SIGNOFF_PATTERNS.items():
        if re.search(pattern, normalized):
            add_signal(
                marker,
                weight,
                "low",
                "llm_formal_signoff",
                f"Formal sign-off pattern detected: {pattern}",
            )

    if re.search(r"(\{[^}]+\}|\[[^\]]+\]|<name>|<customer>)", content, flags=re.IGNORECASE):
        add_signal(
            "placeholder_tokens",
            0.2,
            "high",
            "ai_placeholder_tokens",
            "Content includes unresolved template placeholders",
        )

    imperative_hits = sum(
        normalized.count(token)
        for token in ["click", "verify", "confirm", "update", "login", "respond", "reply", "download"]
    )
    if imperative_hits >= 4:
        add_signal(
            "high_imperative_density",
            0.14,
            "medium",
            "ai_instruction_density",
            "Content contains dense imperative call-to-action language",
        )

    lexical_diversity = _lexical_diversity(content)
    if len(_tokenize_words(content)) >= 40:
        if lexical_diversity < 0.46:
            add_signal(
                "low_lexical_diversity",
                0.12,
                "medium",
                "ai_repetitive_language",
                "Content uses repetitive vocabulary common in templated scams",
            )

    uniformity = _uniform_sentence_structure_score(content)
    if uniformity >= 0.82:
        add_signal(
            "uniform_sentence_structure",
            0.14,
            "medium",
            "ai_uniform_structure",
            "Message uses highly uniform sentence structure",
        )

    paragraph_uniformity = _uniform_paragraph_structure_score(content)
    if paragraph_uniformity >= 0.84:
        add_signal(
            "uniform_paragraph_structure",
            0.1,
            "medium",
            "llm_uniform_paragraphs",
            "Message uses evenly sized paragraphs common in generated scam templates",
        )

    repeated_openers = _repeated_sentence_opener_ratio(content)
    if repeated_openers >= 0.5:
        add_signal(
            "repeated_sentence_openers",
            0.12,
            "medium",
            "llm_repeated_openers",
            "Multiple sentences begin with the same opener, suggesting templated generation",
        )

    contraction_ratio = _contraction_ratio(content)
    urgency_density = _keyword_density(content, ["urgent", "immediately", "promptly", "action", "security", "verify", "confirm"])
    politeness_density = _keyword_density(content, ["please", "kindly", "review", "ensure", "assist"])
    link_cta_density = _link_call_to_action_density(content)

    if len(_tokenize_words(content)) >= 60 and contraction_ratio <= 0.01 and urgency_density >= 0.04:
        add_signal(
            "overly_formal_urgent_tone",
            0.1,
            "medium",
            "llm_formal_urgency_mix",
            "Message combines polished formal tone with urgent security pressure",
        )

    if politeness_density >= 0.035 and link_cta_density >= 0.04:
        add_signal(
            "polite_cta_blend",
            0.1,
            "medium",
            "llm_polite_cta_blend",
            "Message blends polite helper language with dense action requests and link prompts",
        )

    if channel == "chat" and len(_tokenize_words(content)) >= 20 and normalized.count("http") + normalized.count("bit.ly") >= 1:
        add_signal(
            "chat_link_templating",
            0.08,
            "medium",
            "ai_chat_script",
            "Chat message resembles a templated lure with embedded link instructions",
        )

    if channel == "chat" and repeated_openers >= 0.34 and politeness_density >= 0.02 and imperative_hits >= 2:
        add_signal(
            "scripted_chat_sequence",
            0.1,
            "medium",
            "llm_scripted_chat_sequence",
            "Chat wording resembles a staged social-engineering script rather than organic conversation",
        )

    probability = max(0.0, min(score, 1.0))
    assessment = "high" if probability >= 0.7 else "medium" if probability >= 0.4 else "low"
    return {
        "ai_generated_probability": round(probability, 4),
        "flags": flags,
        "markers_detected": markers_detected,
        "fingerprint": {
            "assessment": assessment,
            "signal_count": len(matched_signals),
            "matched_signals": matched_signals,
            "style_scores": {
                "lexical_diversity": round(lexical_diversity, 4),
                "uniform_sentence_structure": round(uniformity, 4),
                "uniform_paragraph_structure": round(paragraph_uniformity, 4),
                "repeated_sentence_opener_ratio": repeated_openers,
                "imperative_density": round(_safe_ratio(imperative_hits, max(len(_tokenize_words(content)), 1)), 4),
                "urgency_density": urgency_density,
                "politeness_density": politeness_density,
                "contraction_ratio": contraction_ratio,
                "link_call_to_action_density": link_cta_density,
            },
        },
    }


async def analyze_url(url: str) -> dict[str, Any]:
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    decoded_url = unquote(url)
    decoded_lower = decoded_url.lower()
    normalized_brand_text = _normalize_brandish_text(f"{host}{path}")
    extract_result = _extract(host)
    registered_domain = ".".join(part for part in [extract_result.domain, extract_result.suffix] if part)

    score = 0.0
    flags: list[dict[str, str]] = []

    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        score += 20
        flags.append(_flag("ip_hostname", "high", "URL uses a raw IP address instead of a domain"))

    if len(url) > 150:
        score += 16
        flags.append(_flag("long_url", "medium", "URL length is unusually long"))
    elif len(url) > 75:
        score += 12
        flags.append(_flag("long_url", "medium", "URL length exceeds common phishing threshold"))

    if url.count(".") > 4:
        score += 5
        flags.append(_flag("many_dots", "low", "URL contains an unusually high number of dots"))
    if url.count("-") > 3:
        score += 5
        flags.append(_flag("many_hyphens", "medium", "URL contains many hyphens"))
    if url.count("_") > 1:
        score += 4
        flags.append(_flag("many_underscores", "low", "URL contains multiple underscores"))
    if "@" in url:
        score += 15
        flags.append(_flag("at_symbol", "high", "URL contains an @ symbol that may mask the actual destination"))

    tld = extract_result.suffix.lower()
    if tld in SUSPICIOUS_TLDS:
        score += 15
        flags.append(_flag("suspicious_tld", "medium", f"URL uses high-risk TLD '.{tld}'"))

    keyword_hits = [keyword for keyword in URL_KEYWORDS if keyword in decoded_lower]
    if keyword_hits:
        score += min(25, len(keyword_hits) * 5)
        flags.append(_flag("phishing_keywords", "medium", f"URL contains phishing-related keywords: {', '.join(keyword_hits)}"))
    brand_hits = [keyword for keyword in BRAND_KEYWORDS if keyword in normalized_brand_text]
    auth_hits = [keyword for keyword in {"login", "signin", "verify", "account", "secure", "reset"} if keyword in normalized_brand_text]
    official_brand_domain = _is_official_brand_domain(registered_domain, brand_hits)
    if brand_hits and len(auth_hits) >= 2 and not official_brand_domain:
        score += 18
        flags.append(_flag("brand_impersonation", "high", f"URL mixes brand terms with account/login language: {', '.join(sorted(set(brand_hits + auth_hits)))}"))
    direct_brand_hits = [keyword for keyword in BRAND_KEYWORDS if keyword in decoded_lower]
    spoofed_brand_hits = [keyword for keyword in brand_hits if keyword not in direct_brand_hits]
    if spoofed_brand_hits and not official_brand_domain:
        score += 12
        flags.append(_flag("brand_spoofing", "high", f"URL appears to spoof brand terms through character substitution: {', '.join(sorted(set(spoofed_brand_hits)))}"))

    subdomain_count = len([part for part in extract_result.subdomain.split(".") if part])
    if subdomain_count > 3:
        score += 8
        flags.append(_flag("deep_subdomain", "medium", "URL uses an unusually deep subdomain chain"))

    if parsed.port:
        score += 5
        flags.append(_flag("explicit_port", "medium", "URL includes an explicit port number"))

    encoded_count = url.lower().count("%")
    if encoded_count >= 3 or "%2f" in url.lower() or "%20" in url.lower():
        score += 8
        flags.append(_flag("encoded_obfuscation", "medium", "URL contains encoded characters often used for obfuscation"))

    if parsed.scheme.lower() != "https":
        score += 10
        flags.append(_flag("no_https", "medium", "URL does not use HTTPS"))
    else:
        score = max(score - 4, 0)

    if parsed.scheme.lower() != "https" and auth_hits and not official_brand_domain:
        score += 8
        flags.append(_flag("credential_lure_no_https", "high", "URL combines account/login language with insecure HTTP"))

    if registered_domain.lower() in SHORTENER_DOMAINS:
        score += 15
        flags.append(_flag("url_shortener", "medium", "URL uses a shortening service that hides the final domain"))

    domain_age_days = await _lookup_domain_age_days(registered_domain or host)
    if domain_age_days is not None:
        if domain_age_days < 90:
            score += 18
            flags.append(_flag("new_domain", "high", "Domain appears newly registered"))
        elif domain_age_days < 180:
            score += 10
            flags.append(_flag("recent_domain", "medium", "Domain appears recently registered"))

    entropy = _shannon_entropy(url)
    if entropy > 4.5:
        score += 8
        flags.append(_flag("high_entropy", "medium", "URL shows high randomness or obfuscation"))

    model_score = score_url_with_model(url)
    ml_probability = float(model_score["probability"])
    if ml_probability >= 0.8:
        score += 30
        flags.append(_flag("ml_high_risk", "high", "ML model strongly predicts phishing"))
    elif ml_probability >= 0.6:
        score += 16
        flags.append(_flag("ml_medium_risk", "medium", "ML model predicts elevated phishing risk"))

    if ml_probability >= 0.8 and (brand_hits or auth_hits) and parsed.scheme.lower() != "https" and not official_brand_domain:
        score += 10
        flags.append(_flag("high_risk_credential_combo", "high", "URL combines ML phishing signal, brand/login wording, and insecure delivery"))

    if official_brand_domain:
        score = max(score - 18, 0)
        flags.append(_flag("trusted_brand_domain", "low", f"URL belongs to an official trusted domain: {registered_domain}"))

    final_score = int(min(100, round(score)))
    return {
        "score": final_score,
        "flags": flags,
        "ml_probability": round(ml_probability, 4),
        "domain_age_days": domain_age_days,
        "entropy": round(entropy, 4),
        "features": {
            "url_length": len(url),
            "host": host,
            "subdomain_count": subdomain_count,
            "digit_ratio": round(_safe_ratio(sum(char.isdigit() for char in url), len(url)), 4),
            "hyphen_count": url.count("-"),
            "underscore_count": url.count("_"),
            "dot_count": url.count("."),
            "path_length": len(path),
        },
    }


async def analyze_email_content(content: str, subject: str | None = None) -> dict[str, Any]:
    body = content or ""
    subject_value = subject or ""
    normalized_body = body.lower()
    normalized_subject = subject_value.lower()

    score = 0.0
    flags: list[dict[str, str]] = []
    keywords_detected: list[str] = []

    for pattern, weight in URGENCY_PATTERNS.items():
        if re.search(pattern, normalized_body):
            score += weight
            keywords_detected.append(pattern)
            flags.append(_flag("urgency_language", "medium", f"Urgency phrase detected: {pattern}"))

    for pattern, weight in THREAT_PATTERNS.items():
        if re.search(pattern, normalized_body):
            score += weight
            keywords_detected.append(pattern)
            flags.append(_flag("threat_language", "high", f"Threat language detected: {pattern}"))

    for pattern, weight in REQUEST_PATTERNS.items():
        if re.search(pattern, normalized_body):
            score += weight
            keywords_detected.append(pattern)
            flags.append(_flag("credential_request", "high", f"Credential request detected: {pattern}"))

    for pattern, weight in SUBJECT_PATTERNS.items():
        if re.search(pattern, normalized_subject):
            score += weight
            flags.append(_flag("phishing_subject", "medium", f"Subject contains common phishing pattern: {pattern}"))

    extracted_links = extract_urls_from_text(body)
    if extracted_links:
        score += min(0.25, len(extracted_links) * 0.05)
        flags.append(_flag("embedded_links_detected", "medium", f"Email contains {len(extracted_links)} embedded or referenced links"))

    has_pressure_language = any(flag.get("rule") in {"urgency_language", "threat_language", "credential_request"} for flag in flags)
    if extracted_links and has_pressure_language:
        score += 0.18
        flags.append(_flag("email_lure_with_link", "high", "Email combines pressure language with a link or link-like reference"))

    shortener_hits = [
        domain for domain in SHORTENER_DOMAINS if domain in normalized_body
    ]
    if shortener_hits:
        score += 0.18
        flags.append(_flag("shortened_link_reference", "high", f"Email references URL shorteners: {', '.join(sorted(shortener_hits))}"))

    if re.search(r"hxxps?://|\[\.\]|\(\.\)", normalized_body):
        score += 0.18
        flags.append(_flag("obfuscated_url_text", "high", "Email contains obfuscated link text intended to evade detection"))

    anchor_matches = re.findall(
        r"""<a[^>]*href=["']([^"']+)["'][^>]*>(.*?)</a>""",
        body,
        flags=re.IGNORECASE | re.DOTALL,
    )
    for href, anchor_text in anchor_matches:
        visible_text = re.sub(r"<[^>]+>", " ", anchor_text).strip()
        visible_url_match = re.search(r"https?://[^\s<>'\"]+", visible_text, flags=re.IGNORECASE)
        if visible_url_match:
            try:
                displayed = urlsplit(normalize_url(visible_url_match.group(0))).hostname or ""
                actual = urlsplit(normalize_url(href)).hostname or ""
                if displayed and actual and displayed != actual:
                    score += 0.2
                    flags.append(_flag("link_text_mismatch", "high", "Anchor text domain does not match the linked domain"))
            except ValueError:
                continue

    if re.search(r"<form[^>]*>", body, flags=re.IGNORECASE) and re.search(
        r"<input[^>]+(?:password|email|user|login)",
        body,
        flags=re.IGNORECASE,
    ):
        score += 0.25
        flags.append(_flag("credential_form", "high", "Email contains an embedded credential collection form"))

    image_matches = re.findall(r"""<img[^>]*src=["']([^"']+)["']""", body, flags=re.IGNORECASE)
    tracker_like_images = [image for image in image_matches if "?" in image or "pixel" in image.lower() or "track" in image.lower()]
    if len(tracker_like_images) >= 3:
        score += 0.1
        flags.append(_flag("external_trackers", "medium", "Email references multiple external tracking images"))

    from_match = re.search(r"^from:\s*(.+)$", body, flags=re.IGNORECASE | re.MULTILINE)
    reply_to_match = re.search(r"^reply-to:\s*(.+)$", body, flags=re.IGNORECASE | re.MULTILINE)
    if from_match and reply_to_match and from_match.group(1).strip().lower() != reply_to_match.group(1).strip().lower():
        score += 0.15
        flags.append(_flag("reply_to_mismatch", "medium", "Reply-To differs from From address"))

    ai_analysis = analyze_ai_generated_content(body, channel="email")
    ai_probability = float(ai_analysis["ai_generated_probability"])
    if ai_probability >= 0.7:
        score += 0.15
    elif ai_probability >= 0.45:
        score += 0.08
    flags.extend(ai_analysis.get("flags", []))

    probability = max(0.0, min(score, 1.0))
    return {
        "phishing_probability": round(probability, 4),
        "ai_generated_probability": round(ai_probability, 4),
        "score": round(probability * 100, 2),
        "flags": flags,
        "keywords_detected": keywords_detected,
        "ai_markers": ai_analysis.get("markers_detected", []),
        "ai_fingerprint": ai_analysis.get("fingerprint", {}),
    }


async def analyze_chat_content(content: str) -> dict[str, Any]:
    body = content or ""
    normalized = body.lower()
    score = 0.0
    flags: list[dict[str, str]] = []
    keywords_detected: list[str] = []

    for pattern, weight in URGENCY_PATTERNS.items():
        if re.search(pattern, normalized):
            score += weight
            keywords_detected.append(pattern)
            flags.append(_flag("urgency_language", "medium", f"Urgency phrase detected: {pattern}"))

    for pattern, weight in THREAT_PATTERNS.items():
        if re.search(pattern, normalized):
            score += weight
            keywords_detected.append(pattern)
            flags.append(_flag("threat_language", "high", f"Threat language detected: {pattern}"))

    for pattern, weight in REQUEST_PATTERNS.items():
        if re.search(pattern, normalized):
            score += weight
            keywords_detected.append(pattern)
            flags.append(_flag("credential_request", "high", f"Credential request detected: {pattern}"))

    for pattern, weight in CHAT_SCAM_PATTERNS.items():
        if re.search(pattern, normalized):
            score += weight
            keywords_detected.append(pattern)
            flags.append(_flag("chat_scam_pattern", "high", f"WhatsApp/social-chat scam pattern detected: {pattern}"))

    extracted_links = extract_urls_from_text(body)
    if extracted_links:
        score += min(0.22, len(extracted_links) * 0.06)
        flags.append(_flag("chat_links_detected", "medium", f"Chat contains {len(extracted_links)} linked or link-like references"))

    shortener_hits = [
        domain for domain in SHORTENER_DOMAINS if domain in normalized
    ]
    if shortener_hits:
        score += 0.18
        flags.append(_flag("shortened_link_reference", "high", f"Chat references URL shorteners: {', '.join(sorted(shortener_hits))}"))

    if re.search(r"hxxps?://|\[\.\]|\(\.\)", normalized):
        score += 0.16
        flags.append(_flag("obfuscated_url_text", "high", "Chat contains obfuscated link text intended to evade detection"))

    if extracted_links and any(flag.get("rule") == "chat_scam_pattern" for flag in flags):
        score += 0.18
        flags.append(_flag("chat_lure_with_link", "high", "Chat combines scam language with a link or link-like reference"))

    has_pressure_language = any(flag.get("rule") in {"urgency_language", "threat_language", "credential_request"} for flag in flags)
    if extracted_links and has_pressure_language:
        score += 0.2
        flags.append(_flag("chat_pressure_with_link", "high", "Chat combines urgent or threatening language with a link"))

    if extracted_links and re.search(r"\b(?:otp|sim|kyc|verify|account|bank|password)\b", normalized):
        score += 0.14
        flags.append(_flag("credential_lure_with_link", "high", "Chat link is paired with credential, SIM, or account-verification language"))

    if re.search(r"\b(?:apk|exe|zip|rar)\b", normalized):
        score += 0.2
        flags.append(_flag("suspicious_attachment_reference", "high", "Chat content references risky downloadable files"))

    if re.search(r"\b(?:upi|bank transfer|gift card|crypto)\b", normalized) and re.search(r"\burgent|immediately|now\b", normalized):
        score += 0.18
        flags.append(_flag("payment_pressure", "high", "Chat combines payment instructions with urgency"))

    ai_analysis = analyze_ai_generated_content(body, channel="chat")
    ai_probability = float(ai_analysis["ai_generated_probability"])
    if ai_probability >= 0.7:
        score += 0.12
    elif ai_probability >= 0.45:
        score += 0.06
    flags.extend(ai_analysis.get("flags", []))

    probability = max(0.0, min(score, 1.0))
    return {
        "phishing_probability": round(probability, 4),
        "ai_generated_probability": round(ai_probability, 4),
        "score": round(probability * 100, 2),
        "flags": flags,
        "keywords_detected": keywords_detected,
        "ai_markers": ai_analysis.get("markers_detected", []),
        "ai_fingerprint": ai_analysis.get("fingerprint", {}),
    }
