import AsyncStorage from "@react-native-async-storage/async-storage";

import { GmailConnection, PermissionState, ScanResult } from "@/utils/types";

const storageKeys = {
  permissions: "cybershield.permissions",
  selectedApps: "cybershield.selectedApps",
  lastScanResult: "cybershield.lastScanResult",
  setupComplete: "cybershield.setupComplete",
  gmailConnection: "cybershield.gmailConnection",
};

async function readJsonValue<T>(key: string, fallback: T): Promise<T> {
  const raw = await AsyncStorage.getItem(key);
  if (!raw) {
    return fallback;
  }

  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

async function writeJsonValue<T>(key: string, value: T): Promise<void> {
  await AsyncStorage.setItem(key, JSON.stringify(value));
}

export const storage = {
  keys: storageKeys,
  getPermissions: () =>
    readJsonValue<PermissionState>(storageKeys.permissions, {
      notifications: false,
      sms: false,
      appMonitoring: false,
      gmail: false,
    }),
  setPermissions: (permissions: PermissionState) =>
    writeJsonValue(storageKeys.permissions, permissions),
  getSelectedApps: () => readJsonValue<string[]>(storageKeys.selectedApps, []),
  setSelectedApps: (appIds: string[]) => writeJsonValue(storageKeys.selectedApps, appIds),
  getLastScanResult: () => readJsonValue<ScanResult | null>(storageKeys.lastScanResult, null),
  setLastScanResult: (result: ScanResult | null) =>
    writeJsonValue(storageKeys.lastScanResult, result),
  getSetupComplete: () => readJsonValue<boolean>(storageKeys.setupComplete, false),
  setSetupComplete: (value: boolean) => writeJsonValue(storageKeys.setupComplete, value),
  getGmailConnection: () =>
    readJsonValue<GmailConnection>(storageKeys.gmailConnection, {
      connected: false,
      email: null,
      watchConfigured: false,
      accessToken: null,
      status: "not_connected",
      errorMessage: null,
      lastHistoryId: null,
      lastSyncAt: null,
    }),
  setGmailConnection: (value: GmailConnection) =>
    writeJsonValue(storageKeys.gmailConnection, value),
};
