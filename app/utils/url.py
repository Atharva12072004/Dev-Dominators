from urllib.parse import urlparse
import re


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
}

SUSPICIOUS_TERMS = {
    "login": ("Suspicious keyword found in URL", 10),
    "verify": ("Suspicious keyword found in URL", 12),
    "secure": ("Suspicious keyword found in URL", 8),
    "update": ("Suspicious keyword found in URL", 8),
    "account": ("Suspicious keyword found in URL", 8),
    "wallet": ("Suspicious keyword found in URL", 10),
    "free": ("Suspicious keyword found in URL", 8),
    "gift": ("Suspicious keyword found in URL", 8),
    "claim": ("Reward-claim wording detected in URL", 14),
    "reward": ("Reward-claim wording detected in URL", 14),
    "winner": ("Prize or winner wording detected in URL", 12),
    "prize": ("Prize or winner wording detected in URL", 12),
}

SUSPICIOUS_TLDS = {".click", ".top", ".xyz", ".live", ".gq", ".tk", ".buzz", ".loan"}
TRUSTED_BRANDS = {"google", "gmail", "bank", "paytm", "phonepe", "upi", "amazon", "instagram", "whatsapp"}


def analyze_url_indicators(url: str) -> tuple[int, list[str]]:
    parsed = urlparse(url)
    score = 0
    reasons: list[str] = []

    if parsed.scheme != "https":
        score += 20
        reasons.append("Missing HTTPS")

    hostname = (parsed.netloc or "").lower()
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()
    full_text = f"{hostname}{path}{query}"

    if hostname in SHORTENER_DOMAINS:
        score += 25
        reasons.append("Shortened link detected")

    if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 22
        reasons.append("Suspicious domain extension detected")

    if "@" in url or hostname.count("-") >= 2 or "--" in hostname:
        score += 15
        reasons.append("Suspicious URL pattern detected")

    if hostname.count(".") >= 3:
        score += 12
        reasons.append("Too many subdomains detected")

    if any(part.isdigit() for part in hostname.split(".")):
        score += 8
        reasons.append("Numeric domain segment detected")

    if any(char.isdigit() for char in hostname) and not hostname.replace(".", "").isdigit():
        score += 8
        reasons.append("Numeric characters in domain detected")

    if re.search(r"(login|verify|secure|update|reward|gift)[-_]?(account|wallet|bank|upi)", full_text):
        score += 14
        reasons.append("Credential or reward bait wording detected in URL")

    if any(brand in full_text for brand in TRUSTED_BRANDS) and not any(
        hostname.endswith(f".{brand}.com") or hostname == f"{brand}.com" or hostname.endswith(f"{brand}.in")
        for brand in TRUSTED_BRANDS
    ):
        score += 12
        reasons.append("Potential lookalike brand domain detected")

    for term, (reason, weight) in SUSPICIOUS_TERMS.items():
        if term in full_text:
            score += weight
            reasons.append(reason)

    if len(url) > 120:
        score += 8
        reasons.append("Unusually long URL")

    return min(score, 100), list(dict.fromkeys(reasons or ["No strong phishing indicators detected"]))
