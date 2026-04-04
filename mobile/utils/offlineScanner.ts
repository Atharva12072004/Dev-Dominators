import { ScanPayload, ScanResult } from "@/utils/types";

const urgencyPatterns = [
  /urgent/i,
  /immediately/i,
  /act now/i,
  /verify now/i,
  /within \d+ (hours|minutes)/i,
  /blocked|suspended|deactivated/i,
  /final warning/i,
];

const rewardBaitPatterns = [
  /congratulations/i,
  /you won/i,
  /reward/i,
  /claim now/i,
  /claim here/i,
  /cash prize/i,
  /gift/i,
  /jackpot/i,
  /lucky winner/i,
  /(?:\u20B9|rs\.?|inr)\s?\d+/i,
];

const credentialPatterns = [
  /otp/i,
  /password/i,
  /kyc/i,
  /verify account/i,
  /bank/i,
  /payment/i,
  /upi/i,
  /wallet/i,
  /card/i,
  /login/i,
];

const threatPatterns = [
  /suspend(?:ed|ing)? account/i,
  /security alert/i,
  /fraud alert/i,
  /unauthorized/i,
  /failure to comply/i,
];

const spoofPatterns = [
  /\bfrom support\b/i,
  /\bofficial\b/i,
  /\bcustomer care\b/i,
  /\bsecurity team\b/i,
  /\bno-reply\b/i,
];

const attachmentPatterns = [
  /\.apk\b/i,
  /\.zip\b/i,
  /\.rar\b/i,
  /\.pdf\b/i,
  /attachment/i,
  /download file/i,
];

const suspiciousTlds = [".click", ".top", ".xyz", ".live", ".gq", ".tk", ".buzz", ".loan"];
const shortenedDomains = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"];
const suspiciousUrlTokens = [
  "claim",
  "reward",
  "verify",
  "update",
  "secure",
  "wallet",
  "login",
  "gift",
  "bonus",
  "prize",
  "winner",
];

const urlRegex = /https?:\/\/[^\s]+|www\.[^\s]+/gi;

function classify(score: number): ScanResult["label"] {
  if (score >= 70) {
    return "phishing";
  }
  if (score >= 35) {
    return "suspicious";
  }
  return "safe";
}

function isPartialScan(payload: ScanPayload) {
  return Boolean(payload.metadata?.groupedNotification || payload.metadata?.partialContent);
}

function scoreUrls(urls: string[]) {
  let score = 0;
  const reasons: string[] = [];

  urls.forEach((entry) => {
    const lowered = entry.toLowerCase();
    if (lowered.startsWith("http://")) {
      score += 18;
      reasons.push("Missing HTTPS");
    }
    if (shortenedDomains.some((domain) => lowered.includes(domain))) {
      score += 24;
      reasons.push("Shortened link detected");
    }
    if (/\d{1,3}(?:\.\d{1,3}){3}/.test(lowered)) {
      score += 12;
      reasons.push("Raw IP address detected in URL");
    }
    if (suspiciousTlds.some((tld) => lowered.includes(tld))) {
      score += 22;
      reasons.push("Suspicious domain extension detected");
    }
    if (lowered.includes("@") || lowered.split(".").length >= 4 || lowered.includes("--")) {
      score += 14;
      reasons.push("Suspicious URL structure detected");
    }
    suspiciousUrlTokens.forEach((token) => {
      if (lowered.includes(token)) {
        score += 8;
        reasons.push("Suspicious keyword found in URL");
      }
    });
  });

  return { score, reasons };
}

export function runOfflineScan(payload: ScanPayload): ScanResult {
  const text = `${payload.text || ""} ${payload.url || ""}`.trim();
  const loweredText = text.toLowerCase();
  const urls = [
    ...(payload.url ? [payload.url] : []),
    ...(payload.text?.match(urlRegex) || []),
  ];

  let score = 0;
  const reasons: string[] = [];

  urgencyPatterns.forEach((pattern) => {
    if (pattern.test(text)) {
      score += 14;
      reasons.push("Urgency or pressure language detected");
    }
  });

  rewardBaitPatterns.forEach((pattern) => {
    if (pattern.test(text)) {
      score += 18;
      reasons.push("Reward or prize bait detected");
    }
  });

  credentialPatterns.forEach((pattern) => {
    if (pattern.test(text)) {
      score += 12;
      reasons.push("Sensitive account or credential language detected");
    }
  });

  threatPatterns.forEach((pattern) => {
    if (pattern.test(text)) {
      score += 12;
      reasons.push("Threat or account-lock language detected");
    }
  });

  spoofPatterns.forEach((pattern) => {
    if (pattern.test(text)) {
      score += 8;
      reasons.push("Sender impersonation wording detected");
    }
  });

  attachmentPatterns.forEach((pattern) => {
    if (pattern.test(text)) {
      score += 10;
      reasons.push("Attachment or file-delivery risk hint detected");
    }
  });

  if (/click here|tap here|open now|claim here/i.test(text)) {
    score += 16;
    reasons.push("Call-to-action phishing phrase detected");
  }

  if (/parcel|delivery|refund|invoice|payment failed|kyc|bank account|otp|verify account/i.test(text)) {
    score += 12;
    reasons.push("Common phishing bait theme detected");
  }

  if (/limited time|expires today|last chance|avoid suspension/i.test(text)) {
    score += 14;
    reasons.push("Urgent deadline pressure detected");
  }

  if (/verify otp|share otp|send otp|confirm password|reset password/i.test(text)) {
    score += 16;
    reasons.push("Credential or OTP harvesting phrase detected");
  }

  if (/update kyc|complete kyc|bank account|upi id|payment failed|refund pending/i.test(text)) {
    score += 14;
    reasons.push("Financial scam or KYC bait detected");
  }

  if (/http:\/\//i.test(text) || /www\./i.test(text)) {
    score += 8;
    reasons.push("Embedded link detected in message");
  }

  const urlSignals = scoreUrls(urls);
  score += urlSignals.score;
  reasons.push(...urlSignals.reasons);

  if (loweredText.includes("whatsapp") && urls.length > 0) {
    score += 8;
    reasons.push("Messaging-app phishing pattern detected");
  }

  if (isPartialScan(payload)) {
    score = Math.min(100, score + 6);
    reasons.push("Partial notification metadata was scanned");
  }

  const riskScore = Math.min(score, 100);
  const label = classify(riskScore);
  const partialScan = isPartialScan(payload);
  const confidenceBase = partialScan ? riskScore / 140 : riskScore / 100;

  return {
    label,
    risk_score: riskScore,
    reasons: Array.from(
      new Set(reasons.length ? reasons : ["No strong phishing indicators detected"])
    ),
    confidence: Number(Math.min(0.98, Math.max(partialScan ? 0.18 : 0.25, confidenceBase)).toFixed(2)),
    source_type: payload.source_type,
    should_block: riskScore >= 65,
    provider_used: null,
    detection_mode: "rule",
    ai_summary:
      partialScan
        ? "Exact message content was not available, so CyberShield applied a lower-confidence partial scan."
        : label === "safe"
          ? "Local rule-based scan did not find strong phishing indicators."
          : "Offline fallback mode used local phishing heuristics because backend enrichment was unavailable.",
    analysis_mode: "offline",
    partial_scan: partialScan,
  };
}
