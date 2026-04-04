import { NativeModules, Platform } from "react-native";

// Placeholder bridge for custom native Android modules that will be available only in
// Expo development builds after `expo prebuild` and native implementation.
export interface CyberShieldAndroidModule {
  getNotificationAccessStatus?: () => Promise<boolean>;
  getSmsAccessStatus?: () => Promise<boolean>;
  getAccessibilityAccessStatus?: () => Promise<boolean>;
  openNotificationAccessSettings?: () => Promise<void>;
  openAccessibilitySettings?: () => Promise<void>;
  startRealtimeProtection?: () => Promise<void>;
  stopRealtimeProtection?: () => Promise<void>;
}

export const cyberShieldAndroidModule: CyberShieldAndroidModule | null =
  Platform.OS === "android" ? (NativeModules.CyberShieldAndroidModule as CyberShieldAndroidModule) : null;

