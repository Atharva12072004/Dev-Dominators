import { createContext, PropsWithChildren, useContext, useEffect, useMemo, useState } from "react";

import { protectionEventRepository } from "@/repositories/protectionEventRepository";
import { allowedProtectedAppIds } from "@/utils/mockData";
import { storage } from "@/utils/storage";
import { GmailConnection, PermissionState, ProtectionLog, ScanResult, ThreatStatus } from "@/utils/types";

interface SaveThreatInput {
  externalId?: string | null;
  sourceType: string;
  sourceApp?: string | null;
  preview: string;
  rawText?: string | null;
  rawUrl?: string | null;
  result: ScanResult;
  status: ThreatStatus;
}

interface AppDataContextValue {
  hydrated: boolean;
  hasCompletedSetup: boolean;
  permissions: PermissionState;
  selectedApps: string[];
  logs: ProtectionLog[];
  gmailConnection: GmailConnection;
  lastScanResult: ScanResult | null;
  selectedThreat: ProtectionLog | null;
  pendingWarningThreat: ProtectionLog | null;
  togglePermission: (key: keyof PermissionState) => Promise<void>;
  toggleAppSelection: (appId: string) => void;
  saveSelectedApps: () => Promise<void>;
  saveThreat: (input: SaveThreatInput) => Promise<ProtectionLog | null>;
  refreshLogs: () => Promise<void>;
  setLastScanResult: (result: ScanResult | null) => Promise<void>;
  setSelectedThreatId: (id: string | null) => Promise<void>;
  setPendingWarningThreatId: (id: string | null) => Promise<void>;
  setGmailConnection: (connection: GmailConnection) => Promise<void>;
}

const AppDataContext = createContext<AppDataContextValue | null>(null);

function sanitizeSelectedApps(appIds: string[]) {
  const unique = Array.from(new Set(appIds));
  return unique.filter((appId) => allowedProtectedAppIds.includes(appId));
}

export function AppDataProvider({ children }: PropsWithChildren) {
  const [hydrated, setHydrated] = useState(false);
  const [hasCompletedSetup, setHasCompletedSetup] = useState(false);
  const [permissions, setPermissions] = useState<PermissionState>({
    notifications: false,
    sms: false,
    appMonitoring: false,
    gmail: false,
  });
  const [selectedApps, setSelectedApps] = useState<string[]>([]);
  const [logs, setLogs] = useState<ProtectionLog[]>([]);
  const [gmailConnection, setGmailConnectionState] = useState<GmailConnection>({
    connected: false,
    email: null,
    watchConfigured: false,
    accessToken: null,
    status: "not_connected",
    errorMessage: null,
  });
  const [lastScanResult, setLastScanResultState] = useState<ScanResult | null>(null);
  const [selectedThreatId, setSelectedThreatIdState] = useState<string | null>(null);
  const [pendingWarningThreatId, setPendingWarningThreatIdState] = useState<string | null>(null);

  useEffect(() => {
    async function hydrate() {
      await protectionEventRepository.initialize();
      const [storedPermissions, storedApps, recentLogs, storedLastScan, setupComplete, gmail] =
        await Promise.all([
          storage.getPermissions(),
          storage.getSelectedApps(),
          protectionEventRepository.listAll(),
          storage.getLastScanResult(),
          storage.getSetupComplete(),
          storage.getGmailConnection(),
        ]);
      const sanitizedApps = sanitizeSelectedApps(storedApps);

      setPermissions(storedPermissions);
      setSelectedApps(sanitizedApps);
      setLogs(recentLogs);
      setLastScanResultState(storedLastScan);
      setHasCompletedSetup(setupComplete);
      setGmailConnectionState(gmail);
      if (sanitizedApps.length !== storedApps.length) {
        await storage.setSelectedApps(sanitizedApps);
      }
      setHydrated(true);
    }

    hydrate();
  }, []);

  async function togglePermission(key: keyof PermissionState) {
    let nextValue: PermissionState = permissions;
    setPermissions((current) => {
      nextValue = { ...current, [key]: !current[key] };
      return nextValue;
    });
    await storage.setPermissions(nextValue);
  }

  function toggleAppSelection(appId: string) {
    if (!allowedProtectedAppIds.includes(appId)) {
      return;
    }
    setSelectedApps((current) =>
      current.includes(appId)
        ? current.filter((id) => id !== appId)
        : sanitizeSelectedApps([...current, appId])
    );
  }

  async function saveSelectedApps() {
    const sanitizedApps = sanitizeSelectedApps(selectedApps);
    setSelectedApps(sanitizedApps);
    await storage.setSelectedApps(sanitizedApps);
    await storage.setSetupComplete(true);
    setHasCompletedSetup(true);
  }

  async function refreshLogs() {
    const nextLogs = await protectionEventRepository.listAll();
    setLogs(nextLogs);
  }

  async function saveThreat(input: SaveThreatInput): Promise<ProtectionLog | null> {
    const saved = await protectionEventRepository.save({
      externalId: input.externalId,
      sourceType: input.sourceType,
      sourceApp: input.sourceApp,
      preview: input.preview,
      rawText: input.rawText,
      rawUrl: input.rawUrl,
      label: input.result.label,
      riskScore: input.result.risk_score,
      reasons: input.result.reasons,
      status: input.status,
      shouldBlock: input.result.should_block,
      analysisMode: input.result.analysis_mode || "offline",
      detectionMode: input.result.detection_mode,
      providerUsed: input.result.provider_used,
      aiSummary: input.result.ai_summary,
      partialScan: input.result.partial_scan,
      baseRiskScore: input.result.base_risk_score,
      attachmentAnalysis: input.result.attachment_analysis,
      explainability: input.result.explainability,
    });
    await refreshLogs();
    return saved;
  }

  async function setLastScanResult(result: ScanResult | null) {
    setLastScanResultState(result);
    await storage.setLastScanResult(result);
  }

  async function setSelectedThreatId(id: string | null) {
    setSelectedThreatIdState(id);
  }

  async function setPendingWarningThreatId(id: string | null) {
    setPendingWarningThreatIdState(id);
  }

  async function setGmailConnection(connection: GmailConnection) {
    setGmailConnectionState(connection);
    await storage.setGmailConnection(connection);
  }

  const selectedThreat = logs.find((item) => item.id === selectedThreatId) || null;
  const pendingWarningThreat = logs.find((item) => item.id === pendingWarningThreatId) || null;

  const value = useMemo(
    () => ({
      hydrated,
      hasCompletedSetup,
      permissions,
      selectedApps,
      logs,
      gmailConnection,
      lastScanResult,
      selectedThreat,
      pendingWarningThreat,
      togglePermission,
      toggleAppSelection,
      saveSelectedApps,
      saveThreat,
      refreshLogs,
      setLastScanResult,
      setSelectedThreatId,
      setPendingWarningThreatId,
      setGmailConnection,
    }),
    [
      hydrated,
      hasCompletedSetup,
      permissions,
      selectedApps,
      logs,
      gmailConnection,
      lastScanResult,
      selectedThreat,
      pendingWarningThreat,
    ]
  );

  return <AppDataContext.Provider value={value}>{children}</AppDataContext.Provider>;
}

export function useAppData() {
  const context = useContext(AppDataContext);
  if (!context) {
    throw new Error("useAppData must be used inside AppDataProvider");
  }
  return context;
}
