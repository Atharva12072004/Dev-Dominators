import { ProtectionLog, ScanSourceType } from "@/utils/types";

const packageLabelMap: Record<string, string> = {
  "com.whatsapp": "WhatsApp",
  "org.telegram.messenger": "Telegram",
  "com.android.chrome": "Chrome",
  "com.instagram.android": "Instagram",
  "com.google.android.gm": "Gmail",
  "com.google.android.apps.messaging": "Messages",
  "com.android.mms": "Messages",
  "com.samsung.android.messaging": "Messages",
  "com.miui.mms": "Messages",
  "com.microsoft.android.smsorganizer": "Messages",
  "com.truecaller": "Messages",
};

export function getSourceLabel(
  sourceType?: ScanSourceType | string | null,
  sourceApp?: string | null
) {
  const rawSource = (sourceApp || sourceType || "").trim();
  if (!rawSource) {
    return "Unknown";
  }

  const normalized = rawSource.toLowerCase();
  if (packageLabelMap[normalized]) {
    return packageLabelMap[normalized];
  }

  if (normalized === "sms" || normalized === "messages" || normalized === "message") {
    return "Messages";
  }
  if (normalized === "gmail" || normalized === "email") {
    return "Gmail";
  }
  if (normalized === "browser" || normalized === "url" || normalized === "chrome") {
    return "Chrome";
  }
  if (normalized === "notification") {
    return "Protected App";
  }

  return rawSource
    .split(".")
    .pop()
    ?.replace(/[-_]/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase()) || rawSource;
}

export function getThreatSourceLabel(threat: Pick<ProtectionLog, "source_type" | "source_app">) {
  return getSourceLabel(threat.source_type, threat.source_app);
}
