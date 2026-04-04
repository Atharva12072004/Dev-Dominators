from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlsplit

import tldextract


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
    "shorturl.at",
    "is.gd",
    "cutt.ly",
}
PHISHING_KEYWORDS = {"login", "signin", "verify", "secure", "update", "confirm", "account", "bank", "paypal"}
RISKY_FILE_EXTENSIONS = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".dll", ".zip", ".rar", ".iso"}

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "fragment_length",
    "digit_count",
    "digit_ratio",
    "letter_ratio",
    "special_ratio",
    "hyphen_count",
    "underscore_count",
    "at_count",
    "dot_count",
    "slash_count",
    "question_count",
    "ampersand_count",
    "equals_count",
    "percent_count",
    "https_flag",
    "port_flag",
    "ip_host_flag",
    "subdomain_depth",
    "suspicious_tld_flag",
    "shortener_flag",
    "keyword_hits",
    "entropy",
    "max_consecutive_digits",
    "token_count",
    "host_vowel_ratio",
    "unique_char_ratio",
    "punycode_flag",
    "double_slash_path_flag",
    "risky_extension_flag",
    "repeated_char_sequences",
    "query_param_count",
    "host_digit_ratio",
]


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def max_consecutive_digits(value: str) -> int:
    groups = re.findall(r"\d+", value)
    return max((len(group) for group in groups), default=0)


def repeated_char_sequences(value: str) -> int:
    return len(re.findall(r"(.)\1{2,}", value))


def safe_ratio(numerator: int | float, denominator: int | float) -> float:
    if not denominator:
        return 0.0
    return float(numerator) / float(denominator)


def extract_url_features(url: str) -> list[float]:
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    extract_result = _extract(host)
    registered_domain = ".".join(part for part in [extract_result.domain, extract_result.suffix] if part)

    digit_count = sum(char.isdigit() for char in url)
    letter_count = sum(char.isalpha() for char in url)
    special_count = sum(not char.isalnum() for char in url)
    query_param_count = query.count("=")
    token_count = len([token for token in re.split(r"[\W_]+", url) if token])
    keyword_hits = sum(1 for keyword in PHISHING_KEYWORDS if keyword in url.lower())

    risky_extension_flag = 1.0 if any(path.lower().endswith(ext) for ext in RISKY_FILE_EXTENSIONS) else 0.0
    ip_host_flag = 1.0 if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host or "") else 0.0
    punycode_flag = 1.0 if "xn--" in host else 0.0
    suspicious_tld_flag = 1.0 if extract_result.suffix.lower() in SUSPICIOUS_TLDS else 0.0
    shortener_flag = 1.0 if registered_domain.lower() in SHORTENER_DOMAINS else 0.0
    host_digit_ratio = safe_ratio(sum(char.isdigit() for char in host), len(host))
    host_vowel_ratio = safe_ratio(sum(char.lower() in "aeiou" for char in host), len(host))
    unique_char_ratio = safe_ratio(len(set(url)), len(url))
    subdomain_depth = len([part for part in extract_result.subdomain.split(".") if part])

    features = [
        float(len(url)),
        float(len(host)),
        float(len(path)),
        float(len(query)),
        float(len(fragment)),
        float(digit_count),
        safe_ratio(digit_count, len(url)),
        safe_ratio(letter_count, len(url)),
        safe_ratio(special_count, len(url)),
        float(url.count("-")),
        float(url.count("_")),
        float(url.count("@")),
        float(host.count(".")),
        float(url.count("/")),
        float(url.count("?")),
        float(url.count("&")),
        float(url.count("=")),
        float(url.count("%")),
        1.0 if parsed.scheme.lower() == "https" else 0.0,
        1.0 if parsed.port else 0.0,
        ip_host_flag,
        float(subdomain_depth),
        suspicious_tld_flag,
        shortener_flag,
        float(keyword_hits),
        shannon_entropy(url),
        float(max_consecutive_digits(url)),
        float(token_count),
        host_vowel_ratio,
        unique_char_ratio,
        punycode_flag,
        1.0 if "//" in path else 0.0,
        risky_extension_flag,
        float(repeated_char_sequences(url)),
        float(query_param_count),
        host_digit_ratio,
    ]
    return features
