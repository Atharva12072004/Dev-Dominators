export type ThreatStatus = "pending" | "suspicious" | "blocked" | "ignored" | "safe";

export interface ScanTextRequest {
  text: string;
  source_type: "text" | "sms" | "email" | "notification";
  metadata?: Record<string, unknown>;
  use_ai?: boolean;
}

export interface ScanUrlRequest {
  url: string;
  source_type: "url" | "browser";
  metadata?: Record<string, unknown>;
  use_ai?: boolean;
}

export interface UnifiedScanRequest {
  text?: string;
  url?: string;
  source_type: "unified" | "sms" | "email" | "notification" | "browser";
  metadata?: Record<string, unknown>;
  use_ai?: boolean;
}

export interface ThreatScanResponse {
  label: "safe" | "suspicious" | "phishing";
  risk_score: number;
  reasons: string[];
  confidence: number;
  source_type: string;
  should_block: boolean;
  provider_used?: string | null;
  ai_summary?: string | null;
  detection_mode?: "ai" | "rule" | "hybrid";
  partial_scan?: boolean;
  threat_intel?: Record<string, unknown> | null;
}

export interface GmailSyncRequest {
  cursor?: string | null;
  max_results?: number;
}
