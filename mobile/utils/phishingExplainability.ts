import {
  AttachmentAnalysisItem,
  AttachmentAnalysisSummary,
  AttachmentInput,
  AttachmentRiskLevel,
  ExplainabilityReport,
} from "@/utils/attachmentAnalysisTypes";
import { bucketBaseReasons, formatReasonSection } from "@/utils/ReasonFormatter";
import { simulateDynamicAttachmentSandbox } from "@/utils/DynamicAttachmentSandbox";
import { scanAttachmentStatically } from "@/utils/StaticAttachmentScanner";
import { ScanPayload, ScanResult } from "@/utils/types";

function clamp(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, value));
}

function riskLevelFromScore(score: number): AttachmentRiskLevel {
  if (score >= 90) {
    return "critical";
  }
  if (score >= 70) {
    return "high";
  }
  if (score >= 40) {
    return "medium";
  }
  return "low";
}

function attachmentSummaryLine(attachment: AttachmentAnalysisItem) {
  return `${attachment.fileName}: ${attachment.finalRiskScore}/100 ${attachment.finalRiskLevel} risk`;
}

export function analyzeAttachments(attachments: AttachmentInput[]): AttachmentAnalysisSummary | null {
  if (attachments.length === 0) {
    return null;
  }

  const analyzed = attachments.map<AttachmentAnalysisItem>((attachment) => {
    const staticAnalysis = scanAttachmentStatically(attachment);
    const dynamicAnalysis = simulateDynamicAttachmentSandbox({
      attachmentId: attachment.id,
      fileName: attachment.fileName,
      fileType: staticAnalysis.fileType,
      notes: attachment.notes,
      staticIndicators: staticAnalysis.indicators,
    });
    const finalRiskScore = clamp(
      Math.round(staticAnalysis.staticRiskScore * 0.45 + dynamicAnalysis.dynamicRiskScore * 0.55),
      0,
      100
    );
    const finalRiskLevel = riskLevelFromScore(finalRiskScore);
    const explanationSummary =
      finalRiskScore >= 70
        ? `${attachment.fileName} looks dangerous because both static indicators and simulated behavior point to phishing delivery.`
        : finalRiskScore >= 40
          ? `${attachment.fileName} shows multiple suspicious signals and should be reviewed carefully before opening.`
          : `${attachment.fileName} shows limited suspicious behavior in the current demo analysis.`;

    return {
      id: attachment.id,
      fileName: attachment.fileName,
      fileType: staticAnalysis.fileType,
      fileTypeLabel: staticAnalysis.fileTypeLabel,
      staticRiskScore: staticAnalysis.staticRiskScore,
      dynamicRiskScore: dynamicAnalysis.dynamicRiskScore,
      finalRiskScore,
      finalRiskLevel,
      staticIndicators: staticAnalysis.indicators,
      dynamicIndicators: dynamicAnalysis.dynamicIndicators,
      timeline: dynamicAnalysis.timeline,
      explanationSummary,
      simulated: true,
    };
  });

  const combinedReasons = analyzed.flatMap((attachment) => [
    ...attachment.staticIndicators.map((indicator) => `${attachment.fileName}: ${indicator.title}`),
    ...attachment.dynamicIndicators.map(
      (indicator) => `${attachment.fileName}: ${indicator.title} (simulated)`
    ),
  ]);

  const overallRiskScore = clamp(
    Math.round(
      analyzed.reduce((total, attachment) => total + attachment.finalRiskScore, 0) / analyzed.length
    ),
    0,
    100
  );

  return {
    attachments: analyzed,
    overallRiskScore,
    overallRiskLevel: riskLevelFromScore(overallRiskScore),
    staticReasonCount: analyzed.reduce(
      (total, attachment) => total + attachment.staticIndicators.length,
      0
    ),
    dynamicReasonCount: analyzed.reduce(
      (total, attachment) => total + attachment.dynamicIndicators.length,
      0
    ),
    combinedReasons,
    simulated: true,
  };
}

export function buildExplainabilityReport(params: {
  result: ScanResult;
  attachmentAnalysis: AttachmentAnalysisSummary | null;
  payload?: ScanPayload;
}): ExplainabilityReport {
  const { result, attachmentAnalysis, payload } = params;
  const reasonBuckets = bucketBaseReasons(result.reasons);
  const payloadText = payload?.text?.trim();
  const payloadUrl = payload?.url?.trim();
  const attachmentReasons = attachmentAnalysis?.combinedReasons || [];
  const sections = [
    formatReasonSection("Email / Message reasons", "email", reasonBuckets.email),
    formatReasonSection("URL reasons", "url", [
      ...reasonBuckets.url,
      ...(payloadUrl ? [`Submitted URL: ${payloadUrl}`] : []),
    ]),
    formatReasonSection("Attachment reasons", "attachment", [
      ...reasonBuckets.file,
      ...attachmentReasons,
    ]),
    formatReasonSection("Final decision reasons", "final", reasonBuckets.other),
  ].filter(Boolean) as ExplainabilityReport["sections"];

  const summaryParts = [
    result.label === "phishing"
      ? "Core detection already flags this as phishing."
      : result.label === "suspicious"
        ? "Core detection already marks this as suspicious."
        : "Core detection leans safe before attachment uplift.",
    attachmentAnalysis
      ? `Attachment analysis contributed ${attachmentAnalysis.overallRiskScore}/100 ${attachmentAnalysis.overallRiskLevel} risk in the demo sandbox.`
      : "No attachments were supplied for supplemental analysis.",
    payloadText ? "Message text was included in the explainability pass." : null,
    payloadUrl ? "A URL was included in the explainability pass." : null,
  ].filter(Boolean);

  return {
    riskScore: result.risk_score,
    baseRiskScore: result.base_risk_score ?? result.risk_score,
    confidence: result.confidence,
    finalLabel: result.label,
    summary: summaryParts.join(" "),
    overallReasons: [
      ...result.reasons,
      ...(attachmentAnalysis?.attachments.map(attachmentSummaryLine) || []),
    ],
    sections,
  };
}

export function enhanceScanResultWithAttachmentAnalysis(params: {
  result: ScanResult;
  payload: ScanPayload;
}) {
  const { result, payload } = params;
  const rawAttachments = (payload.metadata?.attachments as AttachmentInput[] | undefined) || [];
  const attachmentAnalysis = analyzeAttachments(rawAttachments);
  const baseRiskScore = result.risk_score;
  const uplift =
    attachmentAnalysis && attachmentAnalysis.overallRiskScore > 0
      ? Math.round(Math.max(8, attachmentAnalysis.overallRiskScore * 0.3))
      : 0;
  const riskScore = clamp(baseRiskScore + uplift, 0, 100);
  const label =
    riskScore >= 80 ? "phishing" : riskScore >= 45 ? "suspicious" : result.label;
  const shouldBlock = result.should_block || riskScore >= 85;
  const reasons = Array.from(
    new Set([
      ...result.reasons,
      ...(attachmentAnalysis?.combinedReasons || []),
      ...(attachmentAnalysis
        ? [
            `Attachment analysis added ${uplift} risk points based on static and simulated dynamic findings.`,
          ]
        : []),
    ])
  );
  const confidence = clamp(
    Math.max(result.confidence, attachmentAnalysis ? attachmentAnalysis.overallRiskScore / 100 : 0),
    0.2,
    0.99
  );

  const enhancedResult: ScanResult = {
    ...result,
    label,
    risk_score: riskScore,
    should_block: shouldBlock,
    confidence,
    reasons,
    base_risk_score: baseRiskScore,
    attachment_analysis: attachmentAnalysis,
    explainability: undefined,
  };

  enhancedResult.explainability = buildExplainabilityReport({
    result: enhancedResult,
    attachmentAnalysis,
    payload,
  });

  if (attachmentAnalysis) {
    const existingSummary = result.ai_summary ? `${result.ai_summary} ` : "";
    enhancedResult.ai_summary = `${existingSummary}Attachment analysis: ${attachmentAnalysis.overallRiskScore}/100 ${attachmentAnalysis.overallRiskLevel} risk with simulated sandbox findings.`;
  }

  return enhancedResult;
}
