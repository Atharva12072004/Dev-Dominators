import { AttachmentRiskLevel } from "@/utils/attachmentAnalysisTypes";
import { ProtectionLog, ScanResult } from "@/utils/types";

export type AttackStageKey = "email" | "url" | "page" | "attachment";

export interface AttackStage {
  key: AttackStageKey;
  title: string;
  riskScore: number;
  confidence: number;
  reason: string;
  status: "observed" | "simulated" | "missing";
  detail: string;
}

export interface AttackChainModel {
  stages: AttackStage[];
  overallRisk: number;
  summary: string;
}

export interface CampaignCluster {
  campaign: string;
  totalAttacks: number;
  commonDomain: string | null;
  riskLevel: AttachmentRiskLevel;
  sharedIndicators: string[];
  matchingThreatIds: string[];
}

export interface AIPhishingAssessment {
  aiGeneratedLikelihood: number;
  signals: string[];
  rationale: string;
}

export interface SimulationEvent {
  id: string;
  stageKey: AttackStageKey;
  title: string;
  detail: string;
  severity: AttachmentRiskLevel;
  icon: "mail" | "link" | "page" | "lock" | "file" | "download";
}

export interface AdvancedInsightsModel {
  chain: AttackChainModel;
  campaign: CampaignCluster | null;
  aiPhishing: AIPhishingAssessment | null;
  simulation: SimulationEvent[];
}

export interface IntelligenceInput {
  result: ScanResult | ProtectionLog;
  logs: ProtectionLog[];
}
