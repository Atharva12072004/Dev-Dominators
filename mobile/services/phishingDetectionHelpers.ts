import { scanRepository } from "@/repositories/scanRepository";
import { runOfflineScan } from "@/utils/offlineScanner";
import { ScanPayload, ScanResult } from "@/utils/types";

function normalizeAiResult(result: Awaited<ReturnType<typeof scanRepository.scanUnified>>): ScanResult {
  return {
    ...result,
    source_type: result.source_type as ScanResult["source_type"],
  };
}

export async function runAiPhishingAnalysis(payload: ScanPayload): Promise<ScanResult | null> {
  if (!payload.url && (!payload.text || payload.text.trim().length < 4)) {
    return null;
  }

  if (payload.source_type === "browser" || payload.source_type === "url") {
    const response = await scanRepository.scanUrl({
      url: payload.url || "",
      source_type: payload.source_type === "browser" ? "browser" : "url",
      use_ai: true,
      metadata: payload.metadata,
    });
    return normalizeAiResult(response);
  }

  const response = await scanRepository.scanUnified({
    text: payload.text,
    url: payload.url,
    source_type:
      payload.source_type === "gmail"
        ? "email"
        : (payload.source_type as "unified" | "sms" | "email" | "notification" | "browser"),
    use_ai: true,
    metadata: payload.metadata,
  });
  return normalizeAiResult(response);
}

export function runRuleBasedPhishingAnalysis(payload: ScanPayload) {
  return runOfflineScan(payload);
}

export function mergeDetectionResults(aiResult: ScanResult | null, ruleResult: ScanResult) {
  if (!aiResult) {
    return ruleResult;
  }

  const mergedReasons = Array.from(new Set([...(aiResult.reasons || []), ...(ruleResult.reasons || [])]));
  const mergedScore = Math.max(aiResult.risk_score, Math.round(aiResult.risk_score * 0.8 + ruleResult.risk_score * 0.2));

  return {
    ...aiResult,
    risk_score: Math.min(100, mergedScore),
    reasons: mergedReasons,
    detection_mode: aiResult.detection_mode || "hybrid",
    local_fallback_risk_score: ruleResult.risk_score,
    partial_scan: aiResult.partial_scan ?? ruleResult.partial_scan,
  } satisfies ScanResult;
}
