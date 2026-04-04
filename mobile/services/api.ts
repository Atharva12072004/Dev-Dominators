import axios from "axios";
import { EncodingType, readAsStringAsync } from "expo-file-system/legacy";

import { appConfig } from "@/utils/config";
import { AttachmentFileUpload, ScanPayload, ScanResult } from "@/utils/types";

const api = axios.create({
  baseURL: appConfig.apiBaseUrl,
  timeout: 3500,
  headers: {
    "Content-Type": "application/json",
  },
});

export const apiService = {
  async scanAttachment(payload: ScanPayload, files: AttachmentFileUpload[]): Promise<ScanResult> {
    const attachments = await Promise.all(
      files.map(async (file) => ({
        file_name: file.name,
        mime_type: file.mimeType ?? undefined,
        size: file.size ?? undefined,
        content_base64: await readAsStringAsync(file.uri, { encoding: EncodingType.Base64 }),
      }))
    );

    const response = await api.post<ScanResult>(
      "/scan/attachment",
      {
        ...payload,
        use_ai: true,
        attachments,
      },
      {
        timeout: 60000,
      }
    );
    return {
      ...response.data,
      analysis_mode: "online",
      detection_mode: response.data.detection_mode || "rule",
      partial_scan: response.data.partial_scan ?? Boolean(payload.metadata?.partialContent),
    };
  },
  async scanUnified(payload: ScanPayload): Promise<ScanResult> {
    const response = await api.post<ScanResult>(
      "/scan/unified",
      {
        ...payload,
        use_ai: payload.use_ai ?? Boolean(payload.url || (payload.text && payload.text.trim().length >= 4)),
      },
      {
        timeout: 30000,
      }
    );
    return {
      ...response.data,
      analysis_mode: "online",
      detection_mode: response.data.detection_mode || "hybrid",
      partial_scan: response.data.partial_scan ?? Boolean(payload.metadata?.partialContent),
    };
  },
  async scanUrl(payload: ScanPayload): Promise<ScanResult> {
    const response = await api.post<ScanResult>(
      "/scan/url",
      {
        ...payload,
        use_ai: payload.use_ai ?? true,
      },
      {
        timeout: 30000,
      }
    );
    return {
      ...response.data,
      analysis_mode: "online",
      detection_mode: response.data.detection_mode || "hybrid",
      partial_scan: response.data.partial_scan ?? Boolean(payload.metadata?.partialContent),
    };
  },
  async getHealth() {
    const response = await api.get("/health");
    return response.data;
  },
  async getLogs() {
    const response = await api.get("/logs");
    return response.data;
  },
};

export function getApiErrorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    if (error.code === "ECONNABORTED") {
      return "Backend scan timed out, so CyberShield used offline protection.";
    }
    if (!error.response) {
      return `Could not reach the backend at ${appConfig.apiBaseUrl}. Check device/network connectivity.`;
    }
    return (
      error.response?.data?.detail ||
      error.message ||
      "We could not reach the CyberShield AI backend."
    );
  }

  return "Something went wrong while scanning.";
}
