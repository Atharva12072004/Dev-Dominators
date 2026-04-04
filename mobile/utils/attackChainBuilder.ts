import { AttackChainModel, AttackStage, IntelligenceInput } from "@/utils/advancedIntelligenceTypes";

const urlRegex = /https?:\/\/[^\s)]+/gi;
const fakePageEvidenceRegex =
  /(fake login|fake page|phishing page|credential capture|credential harvest|browser redirect|redirected|login page|verification page|spoofed|submitform|openaction)/i;
const payloadEvidenceRegex =
  /(attachment|payload|download|macro|executable|script|archive|zip|docm|xlsm|pdf\.exe)/i;
const credentialishUrlRegex =
  /(login|sign-?in|verify|auth|secure|account|password|confirm|update|unlock|portal)/i;

function clamp(value: number, min = 0, max = 100) {
  return Math.max(min, Math.min(max, value));
}

function readRawText(input: IntelligenceInput["result"]) {
  return "raw_text" in input ? input.raw_text || input.preview || "" : "";
}

function readRawUrl(input: IntelligenceInput["result"]) {
  return "raw_url" in input ? input.raw_url || "" : "";
}

function attachmentNames(input: IntelligenceInput["result"]) {
  return (input.attachment_analysis?.attachments || []).map((item) => item.fileName);
}

function attachmentRisk(input: IntelligenceInput["result"]) {
  return input.attachment_analysis?.overallRiskScore || 0;
}

function attachmentItems(input: IntelligenceInput["result"]) {
  return input.attachment_analysis?.attachments || [];
}

function topReason(reasons: string[], fallback: string) {
  return reasons[0] || fallback;
}

function explainabilitySectionItems(result: IntelligenceInput["result"], key: string) {
  return result.explainability?.sections.find((section) => section.key === key)?.items || [];
}

function allEvidence(result: IntelligenceInput["result"]) {
  return [
    readRawText(result),
    readRawUrl(result),
    ...result.reasons,
    ...(result.attachment_analysis?.combinedReasons || []),
    ...(result.explainability?.overallReasons || []),
    ...(result.explainability?.sections || []).flatMap((section) => section.items),
  ]
    .filter(Boolean)
    .join(" ");
}

function readWeightedScore(node: unknown): number | null {
  if (!node || typeof node !== "object") {
    return null;
  }
  const weightedScore = (node as { weighted_score?: unknown }).weighted_score;
  return typeof weightedScore === "number" ? clamp(weightedScore) : null;
}

function textScore(result: IntelligenceInput["result"]) {
  const intel = result.threat_intel;
  if (intel && typeof intel === "object") {
    const category = (intel as { category?: unknown }).category;
    if (category === "text") {
      return readWeightedScore(intel);
    }
    if (category === "unified") {
      return readWeightedScore((intel as { text_components?: unknown }).text_components);
    }
  }
  return result.base_risk_score ?? null;
}

function urlScore(result: IntelligenceInput["result"]) {
  const intel = result.threat_intel;
  if (intel && typeof intel === "object") {
    const category = (intel as { category?: unknown }).category;
    if (category === "url") {
      return readWeightedScore(intel);
    }
    if (category === "unified") {
      return readWeightedScore((intel as { url_components?: unknown }).url_components);
    }
  }
  return null;
}

function confidenceForStage(baseConfidence: number, status: AttackStage["status"], floor: number) {
  if (status === "observed") {
    return clamp(Math.round(baseConfidence * 100), Math.round(floor * 100), 96) / 100;
  }
  if (status === "simulated") {
    return clamp(Math.round(baseConfidence * 72), Math.max(18, Math.round((floor - 0.08) * 100)), 72) / 100;
  }
  return clamp(Math.round(baseConfidence * 48), 18, 48) / 100;
}

function stageWeight(status: AttackStage["status"]) {
  if (status === "observed") {
    return 1;
  }
  if (status === "simulated") {
    return 0.55;
  }
  return 0.25;
}

function extractUrls(result: IntelligenceInput["result"]) {
  const explicit = readRawUrl(result);
  const fromText = readRawText(result).match(urlRegex) || [];
  const fromReasons = result.reasons.flatMap((reason) => reason.match(urlRegex) || []);
  return Array.from(new Set([explicit, ...fromText, ...fromReasons].filter(Boolean)));
}

export function buildAttackChain(input: IntelligenceInput): AttackChainModel {
  const rawText = readRawText(input.result);
  const urls = extractUrls(input.result);
  const attachments = attachmentNames(input.result);
  const attachmentDetails = attachmentItems(input.result);
  const reasons = input.result.reasons;
  const evidence = allEvidence(input.result);
  const emailReasons = explainabilitySectionItems(input.result, "email");
  const urlReasons = explainabilitySectionItems(input.result, "url").filter(
    (item) => !/^Submitted URL:/i.test(item)
  );
  const attachmentReasons = explainabilitySectionItems(input.result, "attachment");
  const phishingCue = /verify|account|login|bank|password|urgent|suspend|click/i.test(
    `${rawText} ${reasons.join(" ")}`
  );
  const attachmentBehaviors = attachmentDetails.flatMap((item) =>
    (item.dynamicIndicators || []).map((indicator) => indicator.behavior)
  );
  const urlLooksCredentialish = urls.some((url) => credentialishUrlRegex.test(url));
  const hasObservedPageEvidence = fakePageEvidenceRegex.test(
    `${urlReasons.join(" ")} ${attachmentReasons.join(" ")} ${evidence}`
  )
    || urlLooksCredentialish
    || attachmentBehaviors.includes("browser-open")
    || attachmentBehaviors.includes("credential-capture");
  const hasPayloadEvidence = payloadEvidenceRegex.test(
    `${attachmentReasons.join(" ")} ${reasons.join(" ")} ${evidence}`
  )
    || attachmentBehaviors.includes("payload-download")
    || attachmentBehaviors.includes("execution")
    || attachmentBehaviors.includes("system-modification");
  const observedEmail = Boolean(rawText.trim());
  const observedUrl = urls.length > 0 || urlReasons.length > 0;
  const observedAttachment = attachments.length > 0;
  const baseTextScore = textScore(input.result);
  const baseUrlScore = urlScore(input.result);

  const emailStatus: AttackStage["status"] = observedEmail ? "observed" : "simulated";
  const emailRiskScore = observedEmail
    ? clamp(baseTextScore ?? Math.round((input.result.base_risk_score ?? input.result.risk_score) * 0.85), 18, 100)
    : clamp(phishingCue ? 26 : 18, 0, 100);

  const emailStage: AttackStage = {
    key: "email",
    title: "Email / Message",
    riskScore: emailRiskScore,
    confidence: confidenceForStage(input.result.confidence, emailStatus, 0.28),
    reason: observedEmail
      ? topReason(emailReasons.length > 0 ? emailReasons : reasons, "Message content seeded the phishing chain.")
      : "No message body was available, so the opening lure is simulated from the current threat context.",
    status: emailStatus,
    detail: observedEmail
      ? "A message lure is present and can be used as the entry point for the attack flow."
      : "The chain begins with a realistic email or chat lure reconstructed from the observed threat indicators.",
  };

  const urlStatus: AttackStage["status"] = observedUrl ? "observed" : phishingCue ? "simulated" : "missing";
  const urlRiskScore = observedUrl
    ? clamp(
        baseUrlScore ??
          Math.max(
            urls.length > 0 ? 32 : 0,
            urlReasons.length > 0 ? 36 : 0,
            /safe browsing|virus ?total|falcon sandbox|redirect|domain/i.test(urlReasons.join(" "))
              ? Math.min(input.result.risk_score, 72)
              : 0
          ),
        16,
        100
      )
    : urlStatus === "simulated"
      ? clamp(phishingCue ? 24 : 18, 0, 100)
      : 12;

  const urlStage: AttackStage = {
    key: "url",
    title: "Link / Redirect",
    riskScore: urlRiskScore,
    confidence: confidenceForStage(input.result.confidence, urlStatus, 0.32),
    reason:
      urls.length > 0
        ? `Observed link: ${urls[0]}`
        : urlReasons.length > 0
          ? topReason(urlReasons, "URL-based phishing indicators were observed.")
          : "No direct URL was captured, so a likely redirect step is simulated from the phishing pattern.",
    status: urlStatus,
    detail: observedUrl
      ? "The attack path includes a live link that can move the victim to the next stage."
      : urlStatus === "simulated"
        ? "Most phishing chains pivot through a redirect, so a realistic URL stage is inferred."
        : "No link or redirect stage was observed in the current scan.",
  };

  const pageStatus: AttackStage["status"] = hasObservedPageEvidence
    ? "observed"
    : observedUrl
      ? "simulated"
      : "missing";
  const pageRiskScore = hasObservedPageEvidence
    ? clamp(Math.max(Math.round(urlRiskScore * 0.9), 52), 0, 100)
    : pageStatus === "simulated"
      ? clamp(Math.max(Math.round(urlRiskScore * 0.62), phishingCue ? 34 : 24), 0, 100)
      : 14;

  const pageStage: AttackStage = {
    key: "page",
    title: "Fake Page",
    riskScore: pageRiskScore,
    confidence: confidenceForStage(input.result.confidence, pageStatus, 0.3),
    reason: hasObservedPageEvidence
      ? topReason(
          [
            ...urlReasons,
            ...attachmentReasons,
            ...reasons,
            ...(urlLooksCredentialish
              ? [
                  "The observed URL contains login or verification wording typical of a credential-harvesting page.",
                ]
              : []),
            ...(attachmentBehaviors.includes("credential-capture")
              ? ["Attachment behavior indicates a credential capture flow after opening."]
              : []),
            ...(attachmentBehaviors.includes("browser-open")
              ? ["Attachment behavior indicates a browser redirect toward an external page."]
              : []),
          ].filter((item) => fakePageEvidenceRegex.test(item) || /credential|login|verify|browser redirect/i.test(item)),
          "Observed indicators suggest a spoofed verification or login page."
        )
      : pageStatus === "simulated"
        ? "A spoofed verification or login page is inferred as the next stage after the observed lure."
        : "No landing-page evidence was observed, so this step remains hypothetical.",
    status: pageStatus,
    detail:
      pageStatus === "missing"
        ? "No fake-page interaction was visible in the current scan output."
        : "This stage represents the page where a user would likely be asked to trust, verify, or sign in.",
  };

  const attachmentStatus: AttackStage["status"] = observedAttachment
    ? "observed"
    : hasPayloadEvidence || observedUrl
      ? "simulated"
      : "missing";
  const attachmentRiskScore = observedAttachment
    ? clamp(Math.max(attachmentRisk(input.result), 12), 0, 100)
    : attachmentStatus === "simulated"
      ? clamp(hasPayloadEvidence ? 24 : 16, 0, 100)
      : 8;

  const attachmentStage: AttackStage = {
    key: "attachment",
    title: "Attachment / Payload",
    riskScore: attachmentRiskScore,
    confidence: confidenceForStage(input.result.confidence, attachmentStatus, 0.28),
    reason: observedAttachment
      ? `${attachments[0]} is part of the observed chain.`
      : attachmentStatus === "simulated"
        ? "A payload handoff is plausible from the observed phishing flow, but it was not directly captured."
        : "No attachment or payload stage was observed.",
    status: attachmentStatus,
    detail: observedAttachment
      ? "The attachment or payload stage is grounded in the current scan result."
      : attachmentStatus === "simulated"
        ? "A payload handoff is common in multi-stage phishing, so the final stage is projected."
        : "The current scan does not show any delivered attachment or final payload.",
  };

  const stages = [emailStage, urlStage, pageStage, attachmentStage];
  const weightedRisk =
    stages.reduce((total, stage) => total + stage.riskScore * stageWeight(stage.status), 0) /
    stages.reduce((total, stage) => total + stageWeight(stage.status), 0);
  const overallRisk = clamp(Math.round((weightedRisk * 0.6) + (input.result.risk_score * 0.4)));
  const observedStages = stages.filter((stage) => stage.status === "observed").length;

  return {
    stages,
    overallRisk,
    summary:
      overallRisk >= 70 && observedStages >= 2
        ? "The current indicators line up into a high-confidence phishing chain from lure to payload."
        : overallRisk >= 45
          ? "The threat follows a believable staged phishing flow, but some transitions are still inferred rather than directly observed."
          : "The chain remains mostly reconstructed from partial evidence, so it should be read as a hypothesis layer rather than a confirmed full attack path.",
  };
}
