import { getDatabase, initializeDatabase } from "@/storage/database";
import { ProtectionLog, ThreatStatus } from "@/utils/types";

function mapRow(row: any): ProtectionLog {
  return {
    id: String(row.id),
    status: row.status as ThreatStatus,
    source_app: row.source_app,
    preview: row.preview,
    raw_text: row.raw_text,
    raw_url: row.raw_url,
    external_id: row.external_id,
    created_at: row.created_at,
    label: row.label,
    risk_score: row.risk_score,
    reasons: JSON.parse(row.reasons || "[]"),
    confidence: row.confidence ?? Math.min(0.99, Math.max(0.15, row.risk_score / 100)),
    source_type: row.source_type,
    should_block: !!row.should_block,
    provider_used: row.provider_used,
    ai_summary: row.ai_summary,
    analysis_mode: row.analysis_mode || "offline",
    detection_mode: row.detection_mode || "rule",
    partial_scan: !!row.partial_scan,
    base_risk_score: row.base_risk_score ?? undefined,
    attachment_analysis: row.attachment_analysis ? JSON.parse(row.attachment_analysis) : null,
    explainability: row.explainability ? JSON.parse(row.explainability) : null,
  };
}

export interface UpsertProtectionLogInput {
  externalId?: string | null;
  sourceType: string;
  sourceApp?: string | null;
  preview: string;
  rawText?: string | null;
  rawUrl?: string | null;
  label: "safe" | "suspicious" | "phishing";
  riskScore: number;
  reasons: string[];
  status: ThreatStatus;
  shouldBlock: boolean;
  analysisMode: "online" | "offline";
  detectionMode?: "ai" | "rule" | "hybrid";
  providerUsed?: string | null;
  aiSummary?: string | null;
  partialScan?: boolean;
  baseRiskScore?: number;
  attachmentAnalysis?: unknown;
  explainability?: unknown;
}

export class ProtectionEventRepository {
  async initialize() {
    await initializeDatabase();
  }

  async listRecent(limit = 10): Promise<ProtectionLog[]> {
    const db = await getDatabase();
    const rows = await db.getAllAsync(
      `
      SELECT *
      FROM protection_events
      ORDER BY created_at DESC
      LIMIT ?
      `,
      [limit]
    );
    return rows.map(mapRow);
  }

  async listAll(): Promise<ProtectionLog[]> {
    const db = await getDatabase();
    const rows = await db.getAllAsync(
      `
      SELECT *
      FROM protection_events
      ORDER BY created_at DESC
      `
    );
    return rows.map(mapRow);
  }

  async save(input: UpsertProtectionLogInput): Promise<ProtectionLog | null> {
    const db = await getDatabase();
    const id =
      input.externalId ||
      `${input.sourceType}:${Date.now()}:${Math.random().toString(36).slice(2, 8)}`;

    await db.runAsync(
      `
      INSERT OR REPLACE INTO protection_events (
        id, external_id, source_type, source_app, preview, raw_text, raw_url, label,
        risk_score, reasons, status, should_block, analysis_mode, detection_mode, partial_scan,
        provider_used, ai_summary, base_risk_score, attachment_analysis, explainability, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(
        (SELECT created_at FROM protection_events WHERE id = ?), ?
      ))
      `,
      [
        id,
        input.externalId || null,
        input.sourceType,
        input.sourceApp || null,
        input.preview.slice(0, 200),
        input.rawText || null,
        input.rawUrl || null,
        input.label,
        input.riskScore,
        JSON.stringify(input.reasons),
        input.status,
        input.shouldBlock ? 1 : 0,
        input.analysisMode,
        input.detectionMode || "rule",
        input.partialScan ? 1 : 0,
        input.providerUsed || null,
        input.aiSummary || null,
        input.baseRiskScore ?? null,
        input.attachmentAnalysis ? JSON.stringify(input.attachmentAnalysis) : null,
        input.explainability ? JSON.stringify(input.explainability) : null,
        id,
        new Date().toISOString(),
      ]
    );

    return this.getById(id);
  }

  async getById(id: string): Promise<ProtectionLog | null> {
    const db = await getDatabase();
    const row = await db.getFirstAsync(`SELECT * FROM protection_events WHERE id = ?`, [id]);
    return row ? mapRow(row) : null;
  }

  async getByExternalId(externalId: string): Promise<ProtectionLog | null> {
    const db = await getDatabase();
    const row = await db.getFirstAsync(`SELECT * FROM protection_events WHERE external_id = ?`, [externalId]);
    return row ? mapRow(row) : null;
  }

  async updateStatus(id: string, status: ThreatStatus): Promise<void> {
    const db = await getDatabase();
    await db.runAsync(`UPDATE protection_events SET status = ? WHERE id = ?`, [status, id]);
  }

  async findRecentDuplicate(
    sourceType: string,
    sourceApp: string | null | undefined,
    preview: string,
    withinSeconds = 240
  ): Promise<ProtectionLog | null> {
    const db = await getDatabase();
    const threshold = new Date(Date.now() - withinSeconds * 1000).toISOString();
    const row = await db.getFirstAsync(
      `
      SELECT *
      FROM protection_events
      WHERE source_type = ?
        AND COALESCE(source_app, '') = COALESCE(?, '')
        AND preview = ?
        AND created_at >= ?
      ORDER BY created_at DESC
      LIMIT 1
      `,
      [sourceType, sourceApp || "", preview.slice(0, 200), threshold]
    );
    return row ? mapRow(row) : null;
  }
}

export const protectionEventRepository = new ProtectionEventRepository();
