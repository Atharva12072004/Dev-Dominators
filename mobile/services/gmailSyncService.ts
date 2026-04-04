import { fetchNewGmailMessages, parseGmailMessage } from "@/services/gmailMessageHelpers";
import { refreshBackendGmailSession } from "@/services/gmailAuthService";
import { localNotificationService } from "@/services/localNotificationService";
import { debugLogger } from "@/services/debugLogger";
import { scanDedupService } from "@/services/scanDedupService";
import { protectionEventRepository } from "@/repositories/protectionEventRepository";
import { GmailConnection, ThreatStatus } from "@/utils/types";

interface SyncCallbacks {
  saveThreat: (input: {
    externalId?: string | null;
    sourceType: string;
    sourceApp?: string | null;
    preview: string;
    rawText?: string | null;
    rawUrl?: string | null;
    result: any;
    status: ThreatStatus;
  }) => Promise<any>;
  setLastScanResult: (result: any) => Promise<void>;
  setPendingWarningThreatId: (id: string | null) => Promise<void>;
  refreshLogs: () => Promise<void>;
  setGmailConnection: (connection: GmailConnection) => Promise<void>;
}

export async function syncGmailThreats(
  gmailConnection: GmailConnection,
  callbacks: SyncCallbacks,
  maxResults = 5
) {
  if (!gmailConnection.connected || !gmailConnection.email) {
    await callbacks.setGmailConnection({
      ...gmailConnection,
      status: "error",
      errorMessage: "Connect Gmail before running sync.",
    });
    return { syncedCount: 0, suspiciousCount: 0 };
  }

  await callbacks.setGmailConnection({
    ...gmailConnection,
    status: "syncing",
    errorMessage: null,
    });

  try {
    let activeConnection = gmailConnection;
    let result;

    try {
      const refreshedConnection = await refreshBackendGmailSession(gmailConnection, "silent");
      activeConnection = {
        ...gmailConnection,
        ...refreshedConnection,
        status: "syncing",
        errorMessage: null,
      };
      await callbacks.setGmailConnection(activeConnection);
    } catch (refreshError) {
      debugLogger.warn("gmail", "Silent Gmail token refresh failed", refreshError);
    }

    result = await fetchNewGmailMessages(activeConnection.email || gmailConnection.email, maxResults);
    if (!result.success) {
      throw new Error(
        result.message ||
          "Gmail sync failed. Reconnect Gmail and try again."
      );
      }

      for (const event of result.events || []) {
      const parsed = parseGmailMessage(event);
      const existingThreat =
        event.external_id ? await protectionEventRepository.getByExternalId(event.external_id) : null;

      if (parsed.messageId && scanDedupService.hasProcessedGmailMessageId(parsed.messageId)) {
        debugLogger.info("gmail", "Skipping already processed Gmail message", {
          messageId: parsed.messageId,
        });
        continue;
      }

      const saved = await callbacks.saveThreat({
        externalId: event.external_id || undefined,
        sourceType: "gmail",
        sourceApp: "gmail",
        preview: parsed.preview,
        rawText: parsed.rawText,
        rawUrl: parsed.rawUrl,
        result: parsed.result,
        status: existingThreat?.status || parsed.status,
      });

      if (!existingThreat) {
        await callbacks.setLastScanResult(parsed.result);
      }
      if (parsed.messageId) {
        scanDedupService.markProcessedGmailMessageId(parsed.messageId);
      }
      if (saved && !existingThreat && parsed.result.risk_score >= 70) {
        await callbacks.setPendingWarningThreatId(saved.id);
      }
      if (saved && !existingThreat && parsed.result.risk_score >= 55) {
        await localNotificationService.notifySuspiciousThreat(saved);
      }
    }

    await callbacks.refreshLogs();
    await callbacks.setGmailConnection({
      ...activeConnection,
      status: "connected",
      errorMessage: null,
      watchConfigured: result.watch_configured ?? activeConnection.watchConfigured,
      lastHistoryId: result.last_history_id ?? activeConnection.lastHistoryId ?? null,
      lastSyncAt: new Date().toISOString(),
      accessToken: null,
    });
    return {
      syncedCount: result.synced_count,
      suspiciousCount: result.suspicious_count,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Gmail sync failed.";
    await callbacks.setGmailConnection({
      ...gmailConnection,
      connected: /reconnect gmail/i.test(message) ? false : gmailConnection.connected,
      status: "error",
      errorMessage: message,
    });
    throw error;
  }
}
