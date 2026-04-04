import { useState } from "react";
import NetInfo from "@react-native-community/netinfo";

import { apiService, getApiErrorMessage } from "@/services/api";
import { useAppData } from "@/hooks/useAppData";
import { debugLogger } from "@/services/debugLogger";
import { enhanceScanResultWithAttachmentAnalysis } from "@/utils/phishingExplainability";
import { runOfflineScan } from "@/utils/offlineScanner";
import { AttachmentFileUpload, ScanPayload, ScanResult } from "@/utils/types";

function deriveStatus(result: ScanResult): "safe" | "suspicious" | "pending" {
  if (result.label === "safe") {
    return "safe";
  }
  return result.risk_score >= 70 ? "pending" : "suspicious";
}

export function useScanner() {
  const {
    saveThreat,
    setLastScanResult,
    setPendingWarningThreatId,
    setSelectedThreatId,
  } = useAppData();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function storeResult(payload: ScanPayload, result: ScanResult) {
    const saved = await saveThreat({
      sourceType: payload.source_type,
      sourceApp: payload.source_type === "browser" ? "chrome" : undefined,
      preview: payload.text || payload.url || "Manual scan",
      rawText: payload.text,
      rawUrl: payload.url,
      result,
      status: deriveStatus(result),
    });

    if (saved) {
      await setSelectedThreatId(saved.id);
      if (result.should_block && result.label === "phishing") {
        await setPendingWarningThreatId(saved.id);
      }
    }
  }

  async function runUnifiedScan(payload: ScanPayload): Promise<ScanResult> {
    setIsLoading(true);
    setError(null);
    const connectivity = await NetInfo.fetch();
    const canReachInternet = Boolean(
      connectivity.isConnected && connectivity.isInternetReachable !== false
    );

    try {
      if (!canReachInternet) {
        throw new Error("No internet connection available. Using offline protection.");
      }
      debugLogger.info("scan", "Manual unified scan started", payload);
      const realAttachmentFiles = (payload.metadata?.attachment_files as AttachmentFileUpload[] | undefined) || [];
      const result =
        realAttachmentFiles.length > 0
          ? await apiService.scanAttachment(payload, realAttachmentFiles)
          : enhanceScanResultWithAttachmentAnalysis({
              result: await apiService.scanUnified(payload),
              payload,
            });
      await setLastScanResult(result);
      await storeResult(payload, result);
      debugLogger.info("scan", "Manual unified scan completed online", result);
      return result;
    } catch (scanError) {
      const offlineResult = enhanceScanResultWithAttachmentAnalysis({
        result: runOfflineScan(payload),
        payload,
      });
      const errorMessage = getApiErrorMessage(scanError);
      offlineResult.analysis_error = errorMessage;
      offlineResult.ai_summary = `${offlineResult.ai_summary} Backend note: ${errorMessage}`;
      await setLastScanResult(offlineResult);
      await storeResult(payload, offlineResult);
      setError(errorMessage);
      debugLogger.warn("scan", "Manual unified scan fell back offline", {
        payload,
        errorMessage,
        offlineResult,
      });
      return offlineResult;
    } finally {
      setIsLoading(false);
    }
  }

  async function runUrlScan(payload: ScanPayload): Promise<ScanResult> {
    setIsLoading(true);
    setError(null);
    const connectivity = await NetInfo.fetch();
    const canReachInternet = Boolean(
      connectivity.isConnected && connectivity.isInternetReachable !== false
    );

    try {
      if (!canReachInternet) {
        throw new Error("No internet connection available. Using offline protection.");
      }
      debugLogger.info("scan", "URL scan started", payload);
      const result = enhanceScanResultWithAttachmentAnalysis({
        result: await apiService.scanUrl(payload),
        payload,
      });
      await setLastScanResult(result);
      await storeResult(payload, result);
      debugLogger.info("scan", "URL scan completed online", result);
      return result;
    } catch (scanError) {
      const offlineResult = enhanceScanResultWithAttachmentAnalysis({
        result: runOfflineScan(payload),
        payload,
      });
      const errorMessage = getApiErrorMessage(scanError);
      offlineResult.analysis_error = errorMessage;
      offlineResult.ai_summary = `${offlineResult.ai_summary} Backend note: ${errorMessage}`;
      await setLastScanResult(offlineResult);
      await storeResult(payload, offlineResult);
      setError(errorMessage);
      debugLogger.warn("scan", "URL scan fell back offline", {
        payload,
        errorMessage,
        offlineResult,
      });
      return offlineResult;
    } finally {
      setIsLoading(false);
    }
  }

  return {
    isLoading,
    error,
    clearError: () => setError(null),
    runUnifiedScan,
    runUrlScan,
  };
}
