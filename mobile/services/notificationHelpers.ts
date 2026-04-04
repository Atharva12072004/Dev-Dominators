import { getSourceLabel } from "@/utils/sourceLabels";
import { buildGroupedNotificationTitle, isGroupedNotificationText } from "@/utils/notificationParsing";
import { NativeRealtimeEvent } from "@/utils/types";

export const smsNotificationPackages = [
  "com.google.android.apps.messaging",
  "com.android.mms",
  "com.samsung.android.messaging",
  "com.miui.mms",
  "com.microsoft.android.smsorganizer",
  "com.truecaller",
];

const ignoredNotificationPackages = [
  "android",
  "com.android.systemui",
];

export function isSmsNotificationPackage(sourceApp?: string | null) {
  if (!sourceApp) {
    return false;
  }
  const normalized = sourceApp.toLowerCase();
  return smsNotificationPackages.includes(normalized);
}

export function isIgnoredNotificationPackage(sourceApp?: string | null) {
  if (!sourceApp) {
    return false;
  }
  return ignoredNotificationPackages.includes(sourceApp.toLowerCase());
}

export function isGroupedNotification(event: NativeRealtimeEvent) {
  return Boolean(
    event.source_type === "notification" &&
      (event.is_grouped || event.content_available === false || isGroupedNotificationText(event.text || ""))
  );
}

export function normalizeNotificationSource(sourceApp?: string | null, sourceType?: string | null) {
  if (sourceType === "sms" || isSmsNotificationPackage(sourceApp)) {
    return "Messages";
  }
  return getSourceLabel(sourceType, sourceApp);
}

export function normalizeNotificationSourceType(event: NativeRealtimeEvent): NativeRealtimeEvent["source_type"] {
  if (event.source_type === "notification" && isSmsNotificationPackage(event.source_app)) {
    return "sms";
  }
  return event.source_type;
}

export function buildNotificationPreview(event: NativeRealtimeEvent) {
  const normalizedSource = normalizeNotificationSource(event.source_app, event.source_type);
  if (isGroupedNotification(event)) {
    const summary = (event.text || "").trim();
    const title = buildGroupedNotificationTitle(normalizedSource, event.source_type);
    return summary ? `${title}: ${summary}`.slice(0, 180) : title;
  }
  return event.preview;
}
