import { useState } from "react";
import { StyleSheet, Text, View } from "react-native";

import { CyberCard } from "@/components/CyberCard";
import { PrimaryButton } from "@/components/PrimaryButton";
import { RiskScoreRing } from "@/components/RiskScoreRing";
import { ScreenContainer } from "@/components/ScreenContainer";
import { StatusChip } from "@/components/StatusChip";
import { useGmailProtection } from "@/hooks/useGmailProtection";
import { theme } from "@/utils/theme";

export function GmailConnectScreen() {
  const [message, setMessage] = useState<string | null>(null);
  const {
    gmailConnection,
    connectGmail,
    disconnectGmail,
    syncGmail,
    isConfigured,
    isConnecting,
  } = useGmailProtection();
  const status = gmailConnection.status || (gmailConnection.connected ? "connected" : "not_connected");
  const statusLabel =
    status === "connected"
      ? "Connected"
      : isConnecting || status === "connecting"
        ? "Connecting"
      : status === "syncing"
          ? "Connecting"
          : status === "error"
            ? "Error"
            : "Not connected";

  async function handleSync() {
    try {
      const result = await syncGmail();
      setMessage(
        result.syncedCount === 0
          ? "No new Gmail messages were found since the last sync."
          : `Synced ${result.syncedCount} messages, flagged ${result.suspiciousCount} suspicious.`
      );
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Gmail sync failed.");
    }
  }

  async function handleConnect() {
    try {
      await connectGmail();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Gmail connection failed.");
    }
  }

  async function handleDisconnect() {
    try {
      await disconnectGmail();
      setMessage("Google session cleared. Tap Connect Gmail to choose another account.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Gmail disconnect failed.");
    }
  }

  return (
    <ScreenContainer
      title="Connect Gmail"
      subtitle="Sign in with Google, sync recent mail, and feed suspicious Gmail messages into the same protection log as SMS and app alerts."
      showBottomNav
      footer={
        <View style={styles.footerActions}>
          {gmailConnection.connected ? (
            <PrimaryButton
              label="Switch Account"
              onPress={handleDisconnect}
              variant="secondary"
              disabled={isConnecting || status === "syncing"}
            />
          ) : null}
          <PrimaryButton
            label={
              gmailConnection.connected
                ? "Sync Gmail Now"
                : isConnecting
                  ? "Connecting..."
                  : "Connect Gmail"
            }
            onPress={gmailConnection.connected ? handleSync : handleConnect}
            disabled={isConnecting || status === "syncing"}
          />
        </View>
      }
      headerSlot={
        <View style={styles.statusRow}>
          <StatusChip
            label={statusLabel}
            tone={
              status === "connected"
                ? "success"
                : status === "error"
                  ? "danger"
                  : status === "syncing" || isConnecting || status === "connecting"
                    ? "warning"
                    : "neutral"
            }
          />
        </View>
      }
    >
      <CyberCard
        title="Gmail Protection"
        subtitle={
          gmailConnection.connected
            ? `Connected as ${gmailConnection.email || "your Google account"}`
            : "Gmail protection signs in with Google OAuth and sends inbox messages through the CyberShield scanning pipeline."
        }
      >
        <View style={styles.summaryRow}>
          <View style={styles.summaryCopy}>
            <Text style={styles.helper}>
              {gmailConnection.connected
                ? gmailConnection.watchConfigured
                  ? "Near-real-time Gmail watch is active and inbox sync is ready."
                  : "Gmail is connected. Gmail API polling is active while the app is open, usually every 5 seconds when watch setup is unavailable."
                : "Use your Google account to enable Gmail scanning inside the shared threat pipeline."}
            </Text>
            {gmailConnection.lastSyncAt ? (
              <Text style={styles.helper}>Last Gmail API sync: {new Date(gmailConnection.lastSyncAt).toLocaleString()}</Text>
            ) : null}
            {gmailConnection.errorMessage ? (
              <Text style={styles.errorText}>{gmailConnection.errorMessage}</Text>
            ) : null}
          </View>
          <RiskScoreRing score={gmailConnection.connected ? 72 : 18} size={78} label="State" />
        </View>
      </CyberCard>

      <CyberCard
        title="What Happens After Sign-In"
        subtitle="CyberShield AI connects your Gmail account, syncs recent messages through the backend, and saves suspicious email events into Protection Logs as Gmail threats."
      />

      {!isConfigured ? (
        <Text style={styles.warningText}>
          Add `EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID` to `mobile/.env`, and make sure your Android OAuth client in Google Cloud has the correct package name and SHA-1.
        </Text>
      ) : null}
      {message ? <Text style={styles.message}>{message}</Text> : null}
    </ScreenContainer>
  );
}

const styles = StyleSheet.create({
  statusRow: {
    marginTop: theme.spacing.xs,
  },
  footerActions: {
    gap: theme.spacing.sm,
  },
  summaryRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: theme.spacing.md,
  },
  summaryCopy: {
    flex: 1,
    gap: theme.spacing.sm,
  },
  helper: {
    color: theme.colors.textSecondary,
    lineHeight: 21,
  },
  errorText: {
    color: theme.colors.danger,
    lineHeight: 20,
  },
  warningText: {
    color: theme.colors.warning,
    lineHeight: 21,
  },
  message: {
    color: theme.colors.textSecondary,
    lineHeight: 21,
  },
});
