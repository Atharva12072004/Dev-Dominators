export type ProtectionEventStatus = "pending" | "suspicious" | "blocked" | "ignored" | "safe";

export interface ProtectionEventRecord {
  id: string;
  sourceType: string;
  sourceApp?: string | null;
  preview: string;
  riskScore: number;
  reasons: string[];
  status: ProtectionEventStatus;
  rawUrl?: string | null;
  createdAt: string;
}

