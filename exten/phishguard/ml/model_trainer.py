from __future__ import annotations

import logging
from functools import lru_cache

from sklearn.ensemble import RandomForestClassifier

try:
    from .feature_extractor import extract_url_features
except ImportError:  # pragma: no cover - supports running from package root
    from ml.feature_extractor import extract_url_features


logger = logging.getLogger(__name__)

SAFE_URLS = [
    "https://www.google.com",
    "https://www.github.com",
    "https://www.microsoft.com",
    "https://www.amazon.com",
    "https://login.microsoftonline.com",
    "https://docs.python.org/3/",
    "https://support.apple.com",
    "https://www.linkedin.com/feed/",
    "https://www.cloudflare.com",
    "https://bankofamerica.com",
    "https://myaccount.google.com",
    "https://mail.yahoo.com",
]

PHISHING_URLS = [
    "http://paypal.verify-user-account-login.top/session/login.php",
    "http://192.168.1.20/secure-login/paypal/index.html",
    "https://amazon-security-check.gq/verify/update",
    "http://microsoft-support-alert.ml/office365/signin",
    "http://bit.ly/3securebanking",
    "http://account-confirmation-login.tk/auth",
    "https://google-docs-share.click/login?email=target@example.com",
    "http://secure-ebay-checkout.ga/verify/account",
    "http://xn--paypl-3ve.com/login",
    "http://free-prize.example.com/download.ps1",
    "http://update-bank-account.cf/confirm",
    "https://signin-office365-alert.xyz/auth/login",
]


@lru_cache
def get_trained_model() -> RandomForestClassifier:
    samples = SAFE_URLS + PHISHING_URLS
    labels = [0] * len(SAFE_URLS) + [1] * len(PHISHING_URLS)
    features = [extract_url_features(url) for url in samples]

    model = RandomForestClassifier(
        n_estimators=120,
        max_depth=8,
        min_samples_leaf=1,
        random_state=42,
    )
    model.fit(features, labels)
    logger.info("ml_model_trained", extra={"sample_count": len(samples)})
    return model


def score_url(url: str) -> dict[str, float | str]:
    model = get_trained_model()
    probability = float(model.predict_proba([extract_url_features(url)])[0][1])
    label = "phishing" if probability >= 0.5 else "safe"
    return {
        "probability": round(probability, 4),
        "label": label,
    }
