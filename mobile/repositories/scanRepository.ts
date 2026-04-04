import {
  GmailSyncRequest,
  ScanTextRequest,
  ScanUrlRequest,
  ThreatScanResponse,
  UnifiedScanRequest,
} from "@/api/contracts";
import { apiClient } from "@/api/client";

export class ScanRepository {
  async scanText(payload: ScanTextRequest): Promise<ThreatScanResponse> {
    const response = await apiClient.post<ThreatScanResponse>("/scan/text", payload, {
      timeout: 30000,
    });
    return response.data;
  }

  async scanUrl(payload: ScanUrlRequest): Promise<ThreatScanResponse> {
    const response = await apiClient.post<ThreatScanResponse>("/scan/url", payload, {
      timeout: 30000,
    });
    return response.data;
  }

  async scanUnified(payload: UnifiedScanRequest): Promise<ThreatScanResponse> {
    const response = await apiClient.post<ThreatScanResponse>("/scan/unified", payload, {
      timeout: 30000,
    });
    return response.data;
  }

  async syncGmail(payload: GmailSyncRequest) {
    const response = await apiClient.post("/gmail/sync", payload);
    return response.data;
  }

  async fetchLogs() {
    const response = await apiClient.get("/logs");
    return response.data;
  }
}

export const scanRepository = new ScanRepository();
