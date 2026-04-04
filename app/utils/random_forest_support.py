import re
from urllib.parse import urlparse


def _clamp(value: int, minimum: int = 0, maximum: int = 100) -> int:
    return max(minimum, min(maximum, value))


def score_url_with_random_forest_support(url: str) -> tuple[int, list[str], dict]:
    parsed = urlparse(url)
    hostname = (parsed.netloc or "").lower()
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()
    full_text = f"{hostname}{path}{query}"

    features = {
        "no_https": parsed.scheme != "https",
        "shortener": hostname in {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"},
        "suspicious_tld": any(hostname.endswith(tld) for tld in {".click", ".top", ".xyz", ".live", ".gq", ".tk", ".buzz", ".loan"}),
        "lookalike_brand": any(
            brand in full_text
            for brand in {"google", "gmail", "bank", "paytm", "phonepe", "upi", "amazon", "instagram", "whatsapp"}
        ),
        "credential_terms": bool(re.search(r"login|verify|secure|update|account|wallet|bank|upi", full_text)),
        "reward_terms": bool(re.search(r"reward|gift|winner|prize|claim|bonus|subsidy|offer", full_text)),
        "too_many_subdomains": hostname.count(".") >= 3,
        "numeric_domain": any(part.isdigit() for part in hostname.split(".")) or any(char.isdigit() for char in hostname),
        "hyphen_heavy": hostname.count("-") >= 2 or "--" in hostname,
        "at_symbol": "@" in url,
        "long_url": len(url) > 120,
        "punycode": "xn--" in hostname,
        "query_bait": bool(re.search(r"(redirect|token|verify|login|session|continue|return)=", query)),
    }

    trees = [
        88 if features["shortener"] and (features["credential_terms"] or features["reward_terms"]) else 42 if features["shortener"] else 9,
        84 if features["suspicious_tld"] and features["lookalike_brand"] else 58 if features["suspicious_tld"] else 10,
        78 if features["no_https"] and features["credential_terms"] else 52 if features["no_https"] else 8,
        86 if features["too_many_subdomains"] and features["lookalike_brand"] else 46 if features["too_many_subdomains"] else 8,
        74 if features["numeric_domain"] and features["credential_terms"] else 36 if features["numeric_domain"] else 6,
        82 if features["hyphen_heavy"] and features["reward_terms"] else 48 if features["hyphen_heavy"] else 7,
        90 if features["punycode"] and features["lookalike_brand"] else 52 if features["punycode"] else 6,
        66 if features["query_bait"] and (features["credential_terms"] or features["reward_terms"]) else 28 if features["query_bait"] else 6,
        78 if features["at_symbol"] else 6,
        60 if features["long_url"] and (features["credential_terms"] or features["reward_terms"]) else 18 if features["long_url"] else 5,
    ]

    score = _clamp(round(sum(trees) / len(trees)))
    reasons: list[str] = []

    if score >= 68:
        reasons.append("Local RF support model ranked the URL as high risk based on combined domain and path features.")
    elif score >= 42:
        reasons.append("Local RF support model found multiple suspicious URL features that deserve caution.")

    if features["lookalike_brand"] and (features["credential_terms"] or features["reward_terms"]):
        reasons.append("Local RF support model detected likely brand-bait wording in the URL structure.")
    if features["shortener"]:
        reasons.append("Local RF support model detected a shortened link often used to hide final destinations.")
    if features["query_bait"]:
        reasons.append("Local RF support model detected redirect or session bait in the query string.")

    unique_reasons = list(dict.fromkeys(reasons))
    return score, unique_reasons[:4], features
