import { useMemo } from "react";

import { AttachmentAnalysisSummary, ExplainabilityReport } from "@/utils/attachmentAnalysisTypes";
import { ProtectionLog, ScanResult } from "@/utils/types";

export function useAttachmentAnalysis(result: ScanResult | ProtectionLog | null) {
  return useMemo<{
    attachmentAnalysis: AttachmentAnalysisSummary | null;
    explainability: ExplainabilityReport | null;
  }>(
    () => ({
      attachmentAnalysis: result?.attachment_analysis || null,
      explainability: result?.explainability || null,
    }),
    [result]
  );
}
