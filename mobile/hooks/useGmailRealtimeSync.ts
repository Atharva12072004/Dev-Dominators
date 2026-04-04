import { useEffect, useRef } from "react";
import { AppState } from "react-native";

import { useAppData } from "@/hooks/useAppData";
import { debugLogger } from "@/services/debugLogger";
import { syncGmailThreats } from "@/services/gmailSyncService";

const POLL_INTERVAL_MS = 5_000;
const FAILURE_BACKOFF_MS = 15_000;

export function useGmailRealtimeSync() {
  const {
    gmailConnection,
    saveThreat,
    setLastScanResult,
    setPendingWarningThreatId,
    refreshLogs,
    setGmailConnection,
  } = useAppData();
  const syncingRef = useRef(false);
  const nextAllowedSyncAtRef = useRef(0);

  useEffect(() => {
    if (!gmailConnection.connected || !gmailConnection.email) {
      return;
    }

    let isMounted = true;

    const runSync = async () => {
      if (!isMounted || syncingRef.current) {
        return;
      }
      const now = Date.now();
      if (now < nextAllowedSyncAtRef.current) {
        return;
      }
      syncingRef.current = true;
      try {
        const result = await syncGmailThreats(
          gmailConnection,
          {
            saveThreat,
            setLastScanResult,
            setPendingWarningThreatId,
            refreshLogs,
            setGmailConnection,
          },
          10
        );
        nextAllowedSyncAtRef.current = 0;
        debugLogger.info("gmail-realtime", "Gmail API sync completed", result);
      } catch (error) {
        nextAllowedSyncAtRef.current = Date.now() + FAILURE_BACKOFF_MS;
        debugLogger.warn("gmail-realtime", "Gmail API sync failed", error);
      } finally {
        syncingRef.current = false;
      }
    };

    void runSync();
    const interval = setInterval(() => {
      void runSync();
    }, POLL_INTERVAL_MS);

    const appStateSubscription = AppState.addEventListener("change", (state) => {
      if (state === "active") {
        void runSync();
      }
    });

    return () => {
      isMounted = false;
      clearInterval(interval);
      appStateSubscription.remove();
    };
  }, [
    gmailConnection,
    refreshLogs,
    saveThreat,
    setGmailConnection,
    setLastScanResult,
    setPendingWarningThreatId,
  ]);
}
