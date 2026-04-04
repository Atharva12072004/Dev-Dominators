import * as Notifications from "expo-notifications";

import { debugLogger } from "@/services/debugLogger";
import { stableHash } from "@/utils/hash";
import { getThreatSourceLabel } from "@/utils/sourceLabels";
import { ProtectionLog } from "@/utils/types";

Notifications.setNotificationHandler({
  handleNotification: async () => ({
    shouldShowAlert: true,
    shouldPlaySound: true,
    shouldSetBadge: false,
    shouldShowBanner: true,
    shouldShowList: true,
  }),
});

class LocalNotificationService {
  private notifiedKeys = new Set<string>();
  private permissionRequested = false;

  async ensurePermissions() {
    if (this.permissionRequested) {
      return;
    }
    this.permissionRequested = true;
    try {
      const current = await Notifications.getPermissionsAsync();
      if (!current.granted) {
        await Notifications.requestPermissionsAsync();
      }
      const channel = await Notifications.setNotificationChannelAsync("threat-alerts", {
        name: "Threat Alerts",
        importance: Notifications.AndroidImportance.HIGH,
        vibrationPattern: [0, 250, 120, 250],
        lockscreenVisibility: Notifications.AndroidNotificationVisibility.PUBLIC,
      });
      debugLogger.info("notification", "Notification channel ready", channel);
    } catch (error) {
      debugLogger.warn("notification", "Notification permission initialization failed", error);
    }
  }

  async notifySuspiciousThreat(threat: ProtectionLog) {
    const fingerprint = stableHash(
      `${threat.source_type}|${threat.source_app || ""}|${threat.preview}|${threat.risk_score}`
    );
    if (this.notifiedKeys.has(fingerprint)) {
      return;
    }

    this.notifiedKeys.add(fingerprint);
    try {
      await this.ensurePermissions();
      const sourceLabel = getThreatSourceLabel(threat);
      const title = threat.partial_scan
        ? `Group Notification from ${sourceLabel}`
        : "Suspicious Message Detected";
      const body = threat.partial_scan
        ? "Exact message content not available. Partial scan applied."
        : `${sourceLabel}: ${threat.risk_score}% risk - ${threat.reasons[0] || "Potential phishing detected"}`;

      await Notifications.scheduleNotificationAsync({
        content: {
          title,
          body,
          data: {
            threatId: threat.id,
            sourceType: threat.source_type,
            sourceApp: threat.source_app,
          },
        },
        identifier: fingerprint,
        trigger: null,
      });
      debugLogger.info("notification", "Local suspicious-content alert scheduled", {
        threatId: threat.id,
        partialScan: threat.partial_scan,
      });
    } catch (error) {
      debugLogger.warn("notification", "Failed to schedule local alert", error);
    }
  }
}

export const localNotificationService = new LocalNotificationService();
