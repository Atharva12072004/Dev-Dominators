import { Platform } from "react-native";

export const platformCapabilities = {
  isAndroid: Platform.OS === "android",
  isIOS: Platform.OS === "ios",
  gmailOAuth: true,
  gmailSync: true,
  smsRealtime: Platform.OS === "android",
  notificationMonitoring: Platform.OS === "android",
  accessibilityGuard: Platform.OS === "android",
  overlayWarning: Platform.OS === "android",
  universalBrowserIntercept: false,
  appOwnedBrowserGuard: true,
};

