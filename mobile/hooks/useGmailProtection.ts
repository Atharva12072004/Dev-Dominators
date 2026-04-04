import { useEffect, useRef, useState } from "react";
import { Platform } from "react-native";
import {
  isErrorWithCode,
  statusCodes,
} from "@react-native-google-signin/google-signin";
import axios from "axios";

import { useAppData } from "@/hooks/useAppData";
import { gmailRepository } from "@/repositories/gmailRepository";
import {
  configureGoogleSignin,
  disconnectGoogleSession,
  refreshBackendGmailSession,
} from "@/services/gmailAuthService";
import { debugLogger } from "@/services/debugLogger";
import { syncGmailThreats } from "@/services/gmailSyncService";
import { appConfig } from "@/utils/config";

function toReadableGoogleError(error: unknown) {
  if (axios.isAxiosError(error)) {
    if (!error.response) {
      return `Google sign-in succeeded, but CyberShield could not reach the backend at ${appConfig.apiBaseUrl}. Start the FastAPI server and set EXPO_PUBLIC_API_BASE_URL to your PC's LAN IP.`;
    }
    return String(error.response.data?.detail || error.message || "Backend request failed.");
  }
  if (isErrorWithCode(error)) {
    if (error.code === statusCodes.SIGN_IN_CANCELLED) {
      return "Google sign-in was cancelled.";
    }
    if (error.code === statusCodes.IN_PROGRESS) {
      return "Google sign-in is already in progress.";
    }
    if (error.code === statusCodes.PLAY_SERVICES_NOT_AVAILABLE) {
      return "Google Play Services is unavailable or outdated on this device.";
    }
  }
  const message = error instanceof Error ? error.message : String(error ?? "");
  if (/non-recoverable sign in failure/i.test(message) || /api exception/i.test(message)) {
    return "Google sign-in failed due to Android OAuth configuration. Verify the Android OAuth client uses package `com.anonymous.cybershieldai` and SHA-1 `5E:8F:16:06:2E:A3:CD:2C:4A:0D:54:78:76:BA:A6:F3:8C:AB:F6:25`, and keep EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID set to the Web client ID.";
  }
  return error instanceof Error ? error.message : "Google sign-in failed.";
}

export function useGmailProtection() {
  const {
    gmailConnection,
    setGmailConnection,
    saveThreat,
    refreshLogs,
    setLastScanResult,
    setPendingWarningThreatId,
  } = useAppData();
  const [isConnecting, setIsConnecting] = useState(false);
  const gmailConnectionRef = useRef(gmailConnection);
  const isAndroid = Platform.OS === "android";
  const isConfigured = Boolean(appConfig.googleWebClientId);

  useEffect(() => {
    gmailConnectionRef.current = gmailConnection;
  }, [gmailConnection]);

  useEffect(() => {
    configureGoogleSignin();
    debugLogger.info("gmail", "Configured native Google Sign-In", {
      platform: Platform.OS,
      hasWebClientId: Boolean(appConfig.googleWebClientId),
      hasAndroidClientId: Boolean(appConfig.googleAndroidClientId),
    });
  }, []);

  useEffect(() => {
    if (gmailConnectionRef.current.status === "connecting" && !isConnecting) {
      void setGmailConnection({
        ...gmailConnectionRef.current,
        status: gmailConnectionRef.current.connected ? "connected" : "not_connected",
        errorMessage: gmailConnectionRef.current.errorMessage || null,
      });
    }
  }, [isConnecting, setGmailConnection]);

  async function connectGmail() {
    if (!isAndroid) {
      throw new Error("Native Gmail sign-in is currently supported on Android development builds.");
    }
    if (!isConfigured) {
      throw new Error(
        "Set EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID in mobile/.env. Native Google Sign-In uses the Web client ID plus your Android SHA-1 setup."
      );
    }

    setIsConnecting(true);
    await setGmailConnection({
      ...gmailConnectionRef.current,
      status: "connecting",
      errorMessage: null,
    });

    try {
      const connection = await refreshBackendGmailSession(gmailConnectionRef.current, "interactive");

      await setGmailConnection({
        ...connection,
        status: "connecting",
        errorMessage: null,
        accessToken: null,
      });

      const watchResult = connection.email
        ? await gmailRepository.setupWatch(connection.email)
        : { watch_configured: false, message: "Connected, but email lookup failed." };

      await setGmailConnection({
        ...connection,
        watchConfigured: Boolean(watchResult.watch_configured),
        lastHistoryId: connection.lastHistoryId ?? null,
        lastSyncAt: gmailConnectionRef.current.lastSyncAt ?? null,
        accessToken: null,
        status: "connected",
        errorMessage: watchResult.watch_configured ? null : watchResult.message || null,
      });
    } catch (error) {
      const errorMessage = toReadableGoogleError(error);
      debugLogger.error("gmail", "Native Gmail connect failed", {
        error,
        rawMessage: error instanceof Error ? error.message : String(error ?? ""),
        errorMessage,
      });
      await setGmailConnection({
        connected: false,
        email: null,
        watchConfigured: false,
        accessToken: null,
        status: "error",
        errorMessage,
        lastHistoryId: null,
        lastSyncAt: gmailConnectionRef.current.lastSyncAt ?? null,
      });
      throw new Error(errorMessage);
    } finally {
      setIsConnecting(false);
    }
  }

  async function syncGmail() {
    return syncGmailThreats(gmailConnectionRef.current, {
      saveThreat,
      setLastScanResult,
      setPendingWarningThreatId,
      refreshLogs,
      setGmailConnection,
    });
  }

  async function disconnectGmail() {
    await disconnectGoogleSession();
    await setGmailConnection({
      connected: false,
      email: null,
      watchConfigured: false,
      accessToken: null,
      status: "not_connected",
      errorMessage: null,
      lastHistoryId: null,
      lastSyncAt: gmailConnectionRef.current.lastSyncAt ?? null,
    });
  }

  return {
    gmailConnection,
    isConfigured,
    isConnecting,
    connectGmail,
    disconnectGmail,
    syncGmail,
  };
}
