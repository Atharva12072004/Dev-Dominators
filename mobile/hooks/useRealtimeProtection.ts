import { useEffect } from "react";
import { AppState, NativeEventEmitter, Platform } from "react-native";

import { cyberShieldAndroidModule } from "@/native/androidBridge";
import { useAppData } from "@/hooks/useAppData";
import { protectionEventRepository } from "@/repositories/protectionEventRepository";
import { debugLogger } from "@/services/debugLogger";
import { localNotificationService } from "@/services/localNotificationService";
import {
  buildNotificationPreview,
  isGroupedNotification,
  isIgnoredNotificationPackage,
  normalizeNotificationSource,
  normalizeNotificationSourceType,
} from "@/services/notificationHelpers";
import { protectionOrchestrator } from "@/services/protectionOrchestrator";
import { scanDedupService } from "@/services/scanDedupService";
import { buildGroupedNotificationSubtitle } from "@/utils/notificationParsing";
import { NativeRealtimeEvent } from "@/utils/types";

const androidEventEmitter =
  Platform.OS === "android" && cyberShieldAndroidModule
    ? new NativeEventEmitter(cyberShieldAndroidModule as never)
    : null;

export function useRealtimeProtection() {
  const {
    hydrated,
    permissions,
    selectedApps,
    saveThreat,
    setLastScanResult,
    setPendingWarningThreatId,
    refreshLogs,
  } = useAppData();

  useEffect(() => {
    if (!hydrated || !androidEventEmitter) {
      return;
    }

    async function handleEvent(event: NativeRealtimeEvent) {
      if (event.source_type === "notification" && isIgnoredNotificationPackage(event.source_app)) {
        return;
      }

      const normalizedSourceType = normalizeNotificationSourceType(event);
      const normalizedSourceApp = normalizeNotificationSource(event.source_app, normalizedSourceType);
      const normalizedEvent = {
        ...event,
        source_type: normalizedSourceType,
      } as NativeRealtimeEvent;
      const groupedNotification = isGroupedNotification(normalizedEvent);
      const preview = buildNotificationPreview(normalizedEvent);
      const rawText = groupedNotification
        ? [event.text?.trim(), buildGroupedNotificationSubtitle()].filter(Boolean).join("\n\n")
        : event.text;
      debugLogger.info("realtime", "Message received", {
        ...event,
        normalizedSourceType,
        normalizedSourceApp,
      });
      if (event.source_app === "com.google.android.gm") {
        debugLogger.info("gmail-notification", "Gmail notification received by JS pipeline", {
          externalId: event.external_id,
          preview,
          isGroupedNotification: groupedNotification,
          contentAvailable: event.content_available,
        });
        debugLogger.info(
          "gmail-notification",
          "Skipping Gmail Android notification content scan. Gmail API remains the source of truth."
        );
        return;
      }
      if (event.source_type === "notification" && !permissions.notifications) {
        return;
      }
      if (normalizedSourceType === "sms" && !permissions.sms && !permissions.notifications) {
        return;
      }
      if (normalizedSourceType === "sms") {
        const smsMatched = selectedApps.length === 0 || selectedApps.includes("messages");
        if (!smsMatched) {
          return;
        }
      }
      if (event.source_type === "notification" && normalizedSourceType !== "sms" && event.source_app) {
        const matched =
          selectedApps.length === 0 ||
          selectedApps.some((appId) => {
            if (appId === "gmail" && event.source_app === "com.google.android.gm") return true;
            if (appId === "chrome" && event.source_app === "com.android.chrome") return true;
            if (appId === "whatsapp" && event.source_app === "com.whatsapp") return true;
            if (appId === "telegram" && event.source_app === "org.telegram.messenger") return true;
            if (appId === "instagram" && event.source_app === "com.instagram.android") return true;
            return false;
          });
        if (!matched) {
          return;
        }
      }

      if (event.external_id && scanDedupService.hasProcessedNotificationKey(event.external_id)) {
        debugLogger.info("realtime", "Notification key already processed", {
          externalId: event.external_id,
          sourceApp: normalizedSourceApp,
        });
        return;
      }

      if (
        scanDedupService.isDuplicate(
          normalizedSourceType,
          normalizedSourceApp,
          rawText,
          event.url,
          event.external_id
        )
      ) {
        debugLogger.info("realtime", "Duplicate message skipped", {
          sourceType: event.source_type,
          sourceApp: normalizedSourceApp,
          preview: event.preview,
        });
        return;
      }

      if (event.external_id) {
        const existingThreat = await protectionEventRepository.getByExternalId(event.external_id);
        if (existingThreat) {
          debugLogger.info("realtime", "Existing persisted notification skipped", {
            threatId: existingThreat.id,
            externalId: event.external_id,
          });
          return;
        }
      } else {
        const recentDuplicate = await protectionEventRepository.findRecentDuplicate(
          normalizedSourceType,
          normalizedSourceApp,
          preview
        );
        if (recentDuplicate) {
          debugLogger.info("realtime", "Recent persisted duplicate skipped", {
            threatId: recentDuplicate.id,
          });
          return;
        }
      }

      debugLogger.info("realtime", "Detection started", {
        sourceType: normalizedSourceType,
        sourceApp: normalizedSourceApp,
      });
      try {
        const result = await protectionOrchestrator.scanWithFallback({
          text: rawText,
          url: event.url || undefined,
          source_type: normalizedSourceType,
          use_ai: true,
          metadata: {
            groupedNotification: groupedNotification,
            partialContent: groupedNotification,
            sourceApp: normalizedSourceApp,
            originalContentAvailable: event.content_available !== false,
            notificationFallback: event.source_type === "notification" && normalizedSourceType === "sms",
          },
        });
        debugLogger.info("realtime", "Detection result", result);

        await setLastScanResult(result);
        const saved = await saveThreat({
          externalId: event.external_id,
          sourceType: normalizedSourceType,
          sourceApp: normalizedSourceApp,
          preview,
          rawText,
          rawUrl: event.url || undefined,
          result,
          status:
            result.label === "safe" ? "safe" : result.risk_score >= 70 ? "pending" : "suspicious",
        });

        scanDedupService.markProcessed(
          normalizedSourceType,
          normalizedSourceApp,
          rawText,
          event.url,
          event.external_id
        );
        if (event.external_id) {
          scanDedupService.markProcessedNotificationKey(event.external_id);
        }

        if (saved && result.risk_score >= 70) {
          await setPendingWarningThreatId(saved.id);
        }
        if (saved && result.risk_score >= 55) {
          await localNotificationService.notifySuspiciousThreat(saved);
        }
        debugLogger.info("realtime", "Save to protection log complete", {
          threatId: saved?.id,
          status: saved?.status,
        });
        await refreshLogs();
      } catch (error) {
        debugLogger.error("realtime", "Realtime processing failed", error);
      }
    }

    const smsSub = androidEventEmitter.addListener("smsReceived", handleEvent);
    const notificationSub = androidEventEmitter.addListener("notificationReceived", handleEvent);

    const appStateSub = AppState.addEventListener("change", async (state) => {
      if (state === "active") {
        await refreshLogs();
      }
    });

    cyberShieldAndroidModule?.startRealtimeProtection?.().catch(() => undefined);

    return () => {
      smsSub.remove();
      notificationSub.remove();
      appStateSub.remove();
      cyberShieldAndroidModule?.stopRealtimeProtection?.().catch(() => undefined);
    };
  }, [
    hydrated,
    permissions.notifications,
    permissions.sms,
    refreshLogs,
    saveThreat,
    selectedApps,
    setLastScanResult,
    setPendingWarningThreatId,
  ]);
}
