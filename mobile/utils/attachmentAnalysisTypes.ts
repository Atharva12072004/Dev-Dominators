export type AttachmentRiskLevel = "low" | "medium" | "high" | "critical";

export interface AttachmentInput {
  id: string;
  fileName: string;
  declaredType?: string | null;
  notes?: string | null;
}

export interface AttachmentStaticIndicator {
  id: string;
  title: string;
  detail: string;
  severity: AttachmentRiskLevel;
  category:
    | "file-type"
    | "filename"
    | "embedded-link"
    | "macro"
    | "archive"
    | "obfuscation";
}

export interface AttachmentDynamicIndicator {
  id: string;
  title: string;
  detail: string;
  severity: AttachmentRiskLevel;
  behavior:
    | "browser-open"
    | "network-call"
    | "execution"
    | "credential-capture"
    | "payload-download"
    | "system-modification";
  simulated: true;
}

export interface AttachmentTimelineStep {
  id: string;
  label: string;
  detail: string;
  severity: AttachmentRiskLevel;
  simulated: true;
}

export interface AttachmentAnalysisItem {
  id: string;
  fileName: string;
  fileType: string;
  fileTypeLabel: string;
  staticRiskScore: number;
  dynamicRiskScore: number;
  finalRiskScore: number;
  finalRiskLevel: AttachmentRiskLevel;
  staticIndicators: AttachmentStaticIndicator[];
  dynamicIndicators: AttachmentDynamicIndicator[];
  timeline: AttachmentTimelineStep[];
  explanationSummary: string;
  simulated: true;
}

export interface AttachmentAnalysisSummary {
  attachments: AttachmentAnalysisItem[];
  overallRiskScore: number;
  overallRiskLevel: AttachmentRiskLevel;
  staticReasonCount: number;
  dynamicReasonCount: number;
  combinedReasons: string[];
  simulated: true;
}

export interface ExplainabilitySection {
  key: string;
  title: string;
  items: string[];
}

export interface ExplainabilityReport {
  riskScore: number;
  baseRiskScore: number;
  confidence: number;
  finalLabel: "safe" | "suspicious" | "phishing";
  summary: string;
  overallReasons: string[];
  sections: ExplainabilitySection[];
}
