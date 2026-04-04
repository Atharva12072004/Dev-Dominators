import { gmailRepository } from "@/repositories/gmailRepository";
import { ProtectionLog, ScanResult } from "@/utils/types";

const emailUrlRegex = /https?:\/\/[^\s]+|www\.[^\s]+/gi;

export function extractUrlsFromEmail(content: string) {
  return Array.from(new Set(content.match(emailUrlRegex) || []));
}

export function parseGmailMessage(event: any): {
  messageId: string | null;
  preview: string;
  rawText?: string;
  rawUrl?: string;
  result: ScanResult;
  status: ProtectionLog["status"];
} {
  const messageId =
    typeof event.external_id === "string" && event.external_id.startsWith("gmail:")
      ? event.external_id.replace(/^gmail:/, "")
      : null;
  const rawText = event.raw_text || event.content_preview || "";
  const urls = extractUrlsFromEmail(rawText);

  return {
    messageId,
    preview: event.content_preview || "Gmail message",
    rawText,
    rawUrl: event.raw_url || urls[0],
    result: {
      label: event.label,
      risk_score: event.risk_score,
      reasons: event.reasons || [],
      confidence: event.confidence ?? 0.9,
      source_type: "gmail",
      should_block: Boolean(event.should_block),
      analysis_mode: "online",
      detection_mode: event.detection_mode || "hybrid",
      provider_used: event.provider_used,
      ai_summary: event.ai_summary,
      partial_scan: Boolean(event.partial_scan),
    },
    status: event.status,
  };
}

export async function fetchNewGmailMessages(email: string, maxResults = 10) {
  return gmailRepository.sync(email, maxResults);
}
