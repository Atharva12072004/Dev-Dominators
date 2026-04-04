export type ProtectionSource =
  | "gmail"
  | "sms"
  | "notification"
  | "browser"
  | "manual"
  | "social_notification";

export type ProtectionDecision = "pending" | "suspicious" | "blocked" | "ignored" | "safe";

export interface ProtectionEvent {
  id: string;
  source: ProtectionSource;
  sourceApp?: string | null;
  preview: string;
  fullText?: string | null;
  url?: string | null;
  riskScore: number;
  reasons: string[];
  decision: ProtectionDecision;
  createdAt: string;
}

