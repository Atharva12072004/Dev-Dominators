import re


def _clamp(value: int, minimum: int = 0, maximum: int = 100) -> int:
    return max(minimum, min(maximum, value))


def _grammar_polish_score(text: str) -> float:
    sentences = [item.strip() for item in re.split(r"[.!?]+", text) if item.strip()]
    if len(sentences) < 2:
        return 0.0
    consistently_capitalized = sum(1 for sentence in sentences if re.match(r"^[A-Z]", sentence))
    return consistently_capitalized / max(1, len(sentences))


def analyze_ai_fingerprint(text: str) -> dict:
    content = (text or "").strip()
    if not content:
        return {
            "score": 0,
            "signals": [],
            "reasons": [],
        }

    score = 10
    signals: list[str] = []
    reasons: list[str] = []

    if re.search(r"^dear (customer|user|member|valued customer)", content, flags=re.IGNORECASE):
        score += 22
        signals.append("generic greeting")
        reasons.append("Local AI-fingerprint heuristics found a generic greeting often used in templated phishing.")

    if re.search(
        r"kindly|please be informed|we regret to inform|immediate attention|urgent action",
        content,
        flags=re.IGNORECASE,
    ):
        score += 14
        signals.append("template language")
        reasons.append("Local AI-fingerprint heuristics found polished template language common in AI-assisted scams.")

    if not re.search(r"\b[A-Z][a-z]+(?:\s[A-Z][a-z]+)?\b", re.sub(r"^Dear Customer", "", content, flags=re.IGNORECASE)):
        score += 12
        signals.append("lack of personalization")
        reasons.append("Local AI-fingerprint heuristics found little or no personalization in the message body.")

    if _grammar_polish_score(content) >= 0.8:
        score += 12
        signals.append("overly polished grammar")
        reasons.append("Local AI-fingerprint heuristics found unusually polished grammar and sentence structure.")

    if len(content) >= 120 and not re.search(r"[!]{2,}|[?]{2,}|[A-Z]{5,}", content):
        score += 10
        signals.append("consistent neutral tone")
        reasons.append("Local AI-fingerprint heuristics found a consistent polished tone with low emotional variation.")

    if re.search(
        r"verify your account|confirm your identity|secure your profile|update your records",
        content,
        flags=re.IGNORECASE,
    ):
        score += 16
        signals.append("reusable phishing template phrasing")
        reasons.append("Local AI-fingerprint heuristics found reusable phishing-template phrasing.")

    return {
        "score": _clamp(score),
        "signals": signals[:5],
        "reasons": reasons[:5],
    }
