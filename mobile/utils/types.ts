import { AttachmentAnalysisSummary, ExplainabilityReport } from "@/utils/attachmentAnalysisTypes";

export type ScanLabel = "safe" | "suspicious" | "phishing";
export type ScanSourceType =
  | "text"
  | "sms"
  | "email"
  | "url"
  | "notification"
  | "browser"
  | "unified"
  | "gmail";

export type ThreatStatus = "pending" | "safe" | "suspicious" | "blocked" | "ignored";

export interface ScanResult {
  label: ScanLabel;
  risk_score: number;
  reasons: string[];
  confidence: number;
  source_type: ScanSourceType;
  should_block: boolean;
  provider_used?: string | null;
  ai_summary?: string | null;
  analysis_mode?: "online" | "offline";
  detection_mode?: "ai" | "rule" | "hybrid";
  local_fallback_risk_score?: number;
  analysis_error?: string | null;
  partial_scan?: boolean;
  base_risk_score?: number;
  attachment_analysis?: AttachmentAnalysisSummary | null;
  explainability?: ExplainabilityReport | null;
  threat_intel?: Record<string, unknown> | null;
}

export interface ScanPayload {
  text?: string;
  url?: string;
  source_type: ScanSourceType;
  use_ai?: boolean;
  metadata?: Record<string, unknown>;
}

export interface AttachmentFileUpload {
  id: string;
  name: string;
  uri: string;
  mimeType?: string | null;
  size?: number | null;
}

export interface ProtectionLog extends ScanResult {
  id: string;
  status: ThreatStatus;
  source_app?: string | null;
  created_at: string;
  preview: string;
  raw_text?: string | null;
  raw_url?: string | null;
  external_id?: string | null;
}

export interface PermissionState {
  notifications: boolean;
  sms: boolean;
  appMonitoring: boolean;
  gmail: boolean;
}

export interface SelectableApp {
  id: string;
  name: string;
  category: string;
  riskLevel: "low" | "medium" | "high";
  packageName?: string;
}

export interface GmailConnection {
  connected: boolean;
  email: string | null;
  watchConfigured: boolean;
  accessToken?: string | null;
  status?: "connected" | "not_connected" | "error" | "syncing" | "connecting";
  errorMessage?: string | null;
  lastHistoryId?: string | null;
  lastSyncAt?: string | null;
}

export interface NativeRealtimeEvent {
  source_type: "sms" | "notification";
  source_app?: string | null;
  text: string;
  preview: string;
  timestamp: string;
  url?: string | null;
  external_id?: string | null;
  is_grouped?: boolean;
  content_available?: boolean;
}
