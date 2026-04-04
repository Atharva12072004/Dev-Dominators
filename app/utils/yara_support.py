import re


def _decode_preview(content: bytes) -> str:
    preview = content[:240000]
    try:
        return preview.decode("utf-8", errors="ignore")
    except Exception:
        return preview.decode("latin-1", errors="ignore")


def score_rule_matches(matches: list[dict]) -> int:
    return max(0, min(100, sum(int(match.get("score", 0)) for match in matches)))


TEXT_RULES = [
    {
        "id": "credential_harvest_combo",
        "pattern": re.compile(r"(verify|login|password|otp).{0,60}(click here|open now|claim now|tap here)", re.IGNORECASE | re.DOTALL),
        "reason": "YARA support rules matched a credential-harvest style call to action.",
        "score": 18,
    },
    {
        "id": "gov_subsidy_lure",
        "pattern": re.compile(r"(subsidy|govt|government).{0,80}(claim|verify|release|credit)", re.IGNORECASE | re.DOTALL),
        "reason": "YARA support rules matched a government-benefit lure pattern.",
        "score": 16,
    },
    {
        "id": "reward_bait_lure",
        "pattern": re.compile(r"(you won|winner|prize|reward|jackpot|bonus).{0,80}(claim|click|open|collect)", re.IGNORECASE | re.DOTALL),
        "reason": "YARA support rules matched a reward-bait phishing pattern.",
        "score": 16,
    },
    {
        "id": "bank_kyc_pressure",
        "pattern": re.compile(r"(bank|upi|wallet|account).{0,80}(kyc|verify|blocked|suspended|reactivate)", re.IGNORECASE | re.DOTALL),
        "reason": "YARA support rules matched a banking or KYC pressure pattern.",
        "score": 18,
    },
    {
        "id": "invoice_attachment_lure",
        "pattern": re.compile(r"(invoice|payment|refund|parcel|delivery).{0,80}(attachment|download|zip|pdf|html)", re.IGNORECASE | re.DOTALL),
        "reason": "YARA support rules matched a delivery or invoice lure pattern tied to an attachment.",
        "score": 14,
    },
]


ATTACHMENT_TEXT_RULES = [
    {
        "id": "phishing_form_html",
        "pattern": re.compile(r"<form[^>]+(login|verify|password|otp|account)", re.IGNORECASE),
        "reason": "YARA support rules matched a phishing-form pattern inside the attachment.",
        "score": 22,
    },
    {
        "id": "script_dropper",
        "pattern": re.compile(r"powershell|cmd\.exe|wscript|cscript|frombase64string|downloadfile|start-process", re.IGNORECASE),
        "reason": "YARA support rules matched script or dropper behavior inside the attachment content.",
        "score": 20,
    },
    {
        "id": "credential_capture",
        "pattern": re.compile(r"login|signin|sign in|password|verify your account|confirm identity|otp", re.IGNORECASE),
        "reason": "YARA support rules matched credential-capture language inside the attachment.",
        "score": 16,
    },
    {
        "id": "openaction_url",
        "pattern": re.compile(r"/URI|/Launch|/OpenAction|/SubmitForm", re.IGNORECASE),
        "reason": "YARA support rules matched document actions that can trigger external navigation.",
        "score": 18,
    },
]


def scan_text_yara_support(text: str) -> list[dict]:
    content = (text or "").strip()
    if not content:
        return []
    matches = []
    for rule in TEXT_RULES:
        if rule["pattern"].search(content):
            matches.append(
                {
                    "id": rule["id"],
                    "reason": rule["reason"],
                    "score": rule["score"],
                }
            )
    return matches


def scan_attachment_yara_support(file_name: str, content: bytes) -> list[dict]:
    lower_name = (file_name or "").lower()
    preview = _decode_preview(content)
    matches = []
    for rule in ATTACHMENT_TEXT_RULES:
        if rule["pattern"].search(preview):
            matches.append(
                {
                    "id": rule["id"],
                    "reason": rule["reason"],
                    "score": rule["score"],
                }
            )

    if re.search(r"\.(pdf|docx|xlsx|txt)\.(exe|js|html|scr|ps1|bat|cmd)$", lower_name):
        matches.append(
            {
                "id": "double_extension_exec",
                "reason": "YARA support rules matched a double-extension executable lure in the filename.",
                "score": 18,
            }
        )
    if re.search(r"(invoice|payment|account|update|urgent|statement|verify)", lower_name):
        matches.append(
            {
                "id": "document_lure_name",
                "reason": "YARA support rules matched phishing-style lure wording in the attachment name.",
                "score": 12,
            }
        )

    unique_matches: list[dict] = []
    seen: set[str] = set()
    for match in matches:
        if match["id"] in seen:
            continue
        seen.add(match["id"])
        unique_matches.append(match)
    return unique_matches
