import { CampaignCluster, IntelligenceInput } from "@/utils/advancedIntelligenceTypes";
import { AttachmentAnalysisItem } from "@/utils/attachmentAnalysisTypes";
import { ProtectionLog } from "@/utils/types";

function normalizeDomain(url: string | null | undefined) {
  if (!url) {
    return null;
  }
  try {
    const parsed = new URL(url.startsWith("http") ? url : `https://${url}`);
    return parsed.hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return null;
  }
}

function tokenize(value: string) {
  return value
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .map((token) => token.trim())
    .filter((token) => token.length >= 4);
}

function similarity(a: string[], b: string[]) {
  if (a.length === 0 || b.length === 0) {
    return 0;
  }
  const left = new Set(a);
  const right = new Set(b);
  const overlap = Array.from(left).filter((item) => right.has(item)).length;
  return overlap / Math.max(left.size, right.size, 1);
}

function attachmentSignature(log: ProtectionLog | IntelligenceInput["result"]) {
  return (log.attachment_analysis?.attachments || [])
    .map((item: AttachmentAnalysisItem) => `${item.fileName.toLowerCase()}|${item.fileType.toLowerCase()}`)
    .sort();
}

function previewText(log: ProtectionLog | IntelligenceInput["result"]) {
  return "preview" in log ? log.preview || "" : "";
}

function rawUrl(log: ProtectionLog | IntelligenceInput["result"]) {
  return "raw_url" in log ? log.raw_url || "" : "";
}

function campaignName(domain: string | null, preview: string, attachments: string[]) {
  if (/bank|verify|account|login/i.test(`${domain || ""} ${preview}`)) {
    return "Fake Bank Login";
  }
  if (attachments.some((item) => /invoice|statement|account|update/i.test(item))) {
    return "Document Delivery Lure";
  }
  if (domain) {
    return `Campaign around ${domain}`;
  }
  return "Emerging Phishing Cluster";
}

export function buildCampaignCluster(input: IntelligenceInput): CampaignCluster | null {
  const currentDomain = normalizeDomain(rawUrl(input.result));
  const currentPreviewTokens = tokenize(previewText(input.result) || input.result.ai_summary || "");
  const currentAttachments = attachmentSignature(input.result);

  const matching = input.logs.filter((log) => {
    const domainScore = currentDomain && normalizeDomain(log.raw_url) === currentDomain ? 1 : 0;
    const previewScore = similarity(currentPreviewTokens, tokenize(log.preview || log.ai_summary || ""));
    const attachmentScore = similarity(currentAttachments, attachmentSignature(log));
    return domainScore >= 1 || previewScore >= 0.45 || attachmentScore >= 0.45;
  });

  const totalAttacks = matching.length + 1;
  const combinedIndicators = Array.from(
    new Set(
      [
        ...input.result.reasons.slice(0, 4),
        ...matching.flatMap((log) => log.reasons.slice(0, 2)),
      ].filter(Boolean)
    )
  ).slice(0, 5);

  if (totalAttacks <= 1 && !currentDomain && currentAttachments.length === 0) {
    return null;
  }

  const maxRisk = Math.max(
    input.result.risk_score,
    ...matching.map((log) => log.risk_score),
    input.result.attachment_analysis?.overallRiskScore || 0
  );

  return {
    campaign: campaignName(currentDomain, previewText(input.result), currentAttachments),
    totalAttacks,
    commonDomain: currentDomain,
    riskLevel: maxRisk >= 70 ? "high" : maxRisk >= 40 ? "medium" : "low",
    sharedIndicators: combinedIndicators,
    matchingThreatIds: matching.map((log) => log.id),
  };
}
