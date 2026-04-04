import re

from app.utils.url import analyze_url_indicators


URGENCY_PATTERNS = {
    r"\burgent\b": ("Urgency language detected", 16),
    r"\bimmediately\b": ("Urgency language detected", 14),
    r"\bverify\b": ("Verification pressure detected", 12),
    r"\bblocked\b|\bsuspended\b|\bdeactivated\b": ("Account threat language detected", 16),
    r"\baction required\b|\bfinal warning\b": ("Urgency language detected", 14),
}

REWARD_PATTERNS = {
    r"\bcongratulations\b": ("Reward bait detected", 18),
    r"\byou won\b|\blucky winner\b": ("Reward bait detected", 20),
    r"\breward\b|\bclaim now\b|\bclaim here\b": ("Reward bait detected", 18),
    r"\bcash prize\b|\bgift\b|\bbonus\b|\bjackpot\b": ("Prize or giveaway language detected", 16),
    r"(?:₹|rs\.?|inr)\s?\d+": ("Money bait detected", 14),
}

CREDENTIAL_PATTERNS = {
    r"\bbank\b|\baccount\b|\bwallet\b|\bupi\b": ("Financial or account-related language detected", 12),
    r"\botp\b|\bpassword\b|\blogin\b": ("Credential theft language detected", 14),
    r"\bkyc\b|\bverify account\b|\bconfirm identity\b": ("Identity verification pressure detected", 14),
    r"\bpayment\b|\binvoice\b|\brefund\b|\bdelivery\b|\bparcel\b": ("Common phishing bait theme detected", 10),
}

SPOOFING_PATTERNS = {
    r"\bofficial\b|\bcustomer care\b|\bsupport team\b|\bsecurity team\b": (
        "Possible sender impersonation wording detected",
        10,
    ),
    r"\bno-?reply\b|\bhelpdesk\b": ("Sender impersonation hint detected", 8),
}

ATTACHMENT_PATTERNS = {
    r"\battachment\b|\battached file\b|\bdownload file\b": ("Attachment delivery prompt detected", 10),
    r"\.apk\b|\.zip\b|\.rar\b|\.html\b": ("Potentially risky file type referenced", 12),
}

CALL_TO_ACTION_PATTERNS = {
    r"\bclick here\b|\btap here\b|\bopen now\b": ("Phishing call-to-action detected", 14),
    r"\bclaim here\b|\bclaim now\b": ("Suspicious action prompt detected", 14),
}

DEADLINE_PATTERNS = {
    r"\blimited time\b|\bexpires today\b|\blast chance\b": ("Urgent deadline pressure detected", 14),
    r"\bavoid suspension\b|\bwithin \d+ hours\b": ("Urgent deadline pressure detected", 14),
}

URL_REGEX = re.compile(r"https?://[^\s]+|www\.[^\s]+", re.IGNORECASE)


def analyze_text_indicators(text: str) -> tuple[int, list[str]]:
    lowered = text.lower()
    score = 0
    reasons: list[str] = []

    for pattern, (reason, weight) in URGENCY_PATTERNS.items():
        if re.search(pattern, lowered):
            score += weight
            reasons.append(reason)

    for pattern, (reason, weight) in REWARD_PATTERNS.items():
        if re.search(pattern, text, flags=re.IGNORECASE):
            score += weight
            reasons.append(reason)

    for pattern, (reason, weight) in CREDENTIAL_PATTERNS.items():
        if re.search(pattern, lowered):
            score += weight
            reasons.append(reason)

    for pattern, (reason, weight) in SPOOFING_PATTERNS.items():
        if re.search(pattern, lowered):
            score += weight
            reasons.append(reason)

    for pattern, (reason, weight) in ATTACHMENT_PATTERNS.items():
        if re.search(pattern, lowered):
            score += weight
            reasons.append(reason)

    for pattern, (reason, weight) in CALL_TO_ACTION_PATTERNS.items():
        if re.search(pattern, lowered):
            score += weight
            reasons.append(reason)

    for pattern, (reason, weight) in DEADLINE_PATTERNS.items():
        if re.search(pattern, lowered):
            score += weight
            reasons.append(reason)

    urls = URL_REGEX.findall(text)
    if urls:
        score += 8
        reasons.append("Embedded link detected in message")
        for url in urls:
            url_score, url_reasons = analyze_url_indicators(url)
            score += round(url_score * 0.65)
            reasons.extend(url_reasons)

    if re.search(r"\b\d{4,8}\b", lowered) and "otp" in lowered:
        score += 10
        reasons.append("OTP-related content detected")

    if re.search(r"\bshare otp\b|\bsend otp\b|\bconfirm password\b", lowered):
        score += 16
        reasons.append("Explicit credential or OTP harvesting phrase detected")

    if re.search(r"\bupdate kyc\b|\bcomplete kyc\b|\breactivate account\b", lowered):
        score += 14
        reasons.append("KYC or account reactivation scam pattern detected")

    if text.isupper() and len(text) > 12:
        score += 8
        reasons.append("Aggressive uppercase formatting detected")

    return min(score, 100), list(dict.fromkeys(reasons or ["No strong phishing indicators detected"]))
