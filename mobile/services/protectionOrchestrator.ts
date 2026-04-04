import { ScanPayload, ScanResult } from "@/utils/types";
import { debugLogger } from "@/services/debugLogger";
import {
  mergeDetectionResults,
  runAiPhishingAnalysis,
  runRuleBasedPhishingAnalysis,
} from "@/services/phishingDetectionHelpers";

export class ProtectionOrchestrator {
  async scanWithFallback(payload: ScanPayload) {
    const localResult = runRuleBasedPhishingAnalysis(payload);
    const shouldUseAi = Boolean(payload.use_ai ?? true);

    try {
      debugLogger.info("orchestrator", "Attempting backend scan", {
        sourceType: payload.source_type,
        hasText: Boolean(payload.text),
        hasUrl: Boolean(payload.url),
        shouldUseAi,
        metadata: payload.metadata,
      });
      const aiResult = shouldUseAi ? await runAiPhishingAnalysis(payload) : null;
      const remoteResult = mergeDetectionResults(aiResult, localResult);

      return {
        ...remoteResult,
        source_type: payload.source_type,
        analysis_mode: "online" as const,
        detection_mode: remoteResult.detection_mode || (shouldUseAi ? "hybrid" : "rule"),
        partial_scan: remoteResult.partial_scan ?? Boolean(payload.metadata?.partialContent),
        local_fallback_risk_score: localResult.risk_score,
      } as ScanResult;
    } catch (error) {
      debugLogger.warn("orchestrator", "Backend enrichment unavailable, using offline result", {
        payload,
        error,
      });
      return localResult;
    }
  }
}

export const protectionOrchestrator = new ProtectionOrchestrator();
