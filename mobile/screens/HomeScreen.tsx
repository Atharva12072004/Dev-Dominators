import { Pressable, StyleSheet, Text, View } from "react-native";
import { useRouter } from "expo-router";
import { useState } from "react";

import { CyberCard } from "@/components/CyberCard";
import { AppLogo } from "@/components/AppLogo";
import { PrimaryButton } from "@/components/PrimaryButton";
import { RiskScoreRing } from "@/components/RiskScoreRing";
import { ScreenContainer } from "@/components/ScreenContainer";
import { StatusChip } from "@/components/StatusChip";
import { useAppData } from "@/hooks/useAppData";
import { useGmailProtection } from "@/hooks/useGmailProtection";
import { routes } from "@/navigation/routes";
import { getThreatSourceLabel } from "@/utils/sourceLabels";
import { theme } from "@/utils/theme";

function DashboardLink({
  title,
  description,
  onPress,
}: {
  title: string;
  description: string;
  onPress: () => void;
}) {
  return (
    <Pressable style={styles.linkCard} onPress={onPress}>
      <Text style={styles.linkTitle}>{title}</Text>
      <Text style={styles.linkDescription}>{description}</Text>
    </Pressable>
  );
}

export function HomeScreen() {
  const router = useRouter();
  const { permissions, selectedApps, logs, gmailConnection, refreshLogs, setSelectedThreatId } =
    useAppData();
  const { syncGmail } = useGmailProtection();
  const enabledCount = Object.values(permissions).filter(Boolean).length;
  const recentLogs = logs.slice(0, 3);
  const [refreshing, setRefreshing] = useState(false);

  async function handleRefresh() {
    setRefreshing(true);
    try {
      await refreshLogs();
      if (gmailConnection.connected) {
        await syncGmail().catch(() => undefined);
      }
    } finally {
      setRefreshing(false);
    }
  }

  return (
    <ScreenContainer
      title="Protection Dashboard"
      subtitle="Monitor your security posture, scan content manually, and block suspicious browser links."
      headerSlot={<AppLogo compact />}
      refreshing={refreshing}
      onRefresh={handleRefresh}
      showBottomNav
    >
      <CyberCard
        title="Protection Status"
        subtitle="Your current monitoring profile"
        rightSlot={<StatusChip label={enabledCount >= 2 ? "Protected" : "Partial"} tone={enabledCount >= 2 ? "success" : "warning"} />}
      >
        <View style={styles.metricsRow}>
          <View style={styles.metricBox}>
            <Text style={styles.metricValue}>{enabledCount}/4</Text>
            <Text style={styles.metricLabel}>Permissions Active</Text>
          </View>
          <View style={styles.metricBox}>
            <Text style={styles.metricValue}>{selectedApps.length}</Text>
            <Text style={styles.metricLabel}>Apps Protected</Text>
          </View>
          <View style={styles.metricBox}>
            <Text style={styles.metricValue}>{logs.length}</Text>
            <Text style={styles.metricLabel}>Recent Logs</Text>
          </View>
        </View>
        <PrimaryButton label="Run Manual Scan" onPress={() => router.push(routes.manualScan)} />
      </CyberCard>

      <DashboardLink
        title="Gmail Protection"
        description={
          gmailConnection.connected
            ? `Connected as ${gmailConnection.email}${gmailConnection.lastSyncAt ? ` - last API sync ${new Date(gmailConnection.lastSyncAt).toLocaleTimeString()}` : ""}`
            : "Connect Gmail and enable near-real-time inbox sync."
        }
        onPress={() => router.push(routes.gmailConnect)}
      />
      <CyberCard title="Recent Threats" subtitle="Latest real detections from your full protection history">
        {recentLogs.length === 0 ? (
          <Text style={styles.emptyText}>No recent threats yet. New SMS, Gmail, and notification detections will appear here.</Text>
        ) : (
          recentLogs.map((log) => (
            <Pressable
              key={log.id}
              style={styles.recentRow}
              onPress={async () => {
                await setSelectedThreatId(log.id);
                router.push(routes.result);
              }}
            >
              <View style={styles.recentCopy}>
                <Text style={styles.recentTitle}>{getThreatSourceLabel(log)}</Text>
                <Text style={styles.recentPreview} numberOfLines={2}>
                  {log.preview}
                </Text>
              </View>
              <RiskScoreRing score={log.risk_score} size={70} />
            </Pressable>
          ))
        )}
      </CyberCard>
      <DashboardLink
        title="Protection Logs"
        description="Review persistent Gmail, SMS, notification, and browser threat events."
        onPress={() => router.push(routes.protectionLogs)}
      />
      <DashboardLink
        title="Browser Security"
        description="Check a link before opening it in the device browser."
        onPress={() => router.push(routes.browserSecurity)}
      />
      <DashboardLink
        title="App Selection"
        description="Adjust which apps CyberShield AI should watch most closely."
        onPress={() => router.push(routes.appSelection)}
      />
      <DashboardLink
        title="Settings"
        description="Manage native protection capabilities and platform-specific availability."
        onPress={() => router.push(routes.settings)}
      />
    </ScreenContainer>
  );
}

const styles = StyleSheet.create({
  metricsRow: {
    flexDirection: "row",
    gap: theme.spacing.sm,
  },
  metricBox: {
    flex: 1,
    backgroundColor: theme.colors.backgroundSecondary,
    borderRadius: theme.radius.md,
    padding: theme.spacing.md,
    gap: 4,
  },
  metricValue: {
    color: theme.colors.textPrimary,
    fontSize: 24,
    fontWeight: "800",
  },
  metricLabel: {
    color: theme.colors.textSecondary,
    fontSize: 12,
    lineHeight: 18,
  },
  linkCard: {
    backgroundColor: theme.colors.card,
    borderRadius: theme.radius.lg,
    padding: theme.spacing.lg,
    borderWidth: 1,
    borderColor: theme.colors.border,
    gap: theme.spacing.xs,
  },
  linkTitle: {
    color: theme.colors.textPrimary,
    fontSize: 18,
    fontWeight: "700",
  },
  linkDescription: {
    color: theme.colors.textSecondary,
    lineHeight: 20,
  },
  recentRow: {
    flexDirection: "row",
    gap: theme.spacing.md,
    alignItems: "center",
    backgroundColor: theme.colors.backgroundSecondary,
    borderRadius: theme.radius.md,
    padding: theme.spacing.md,
  },
  recentCopy: {
    flex: 1,
    gap: 4,
  },
  recentTitle: {
    color: theme.colors.textPrimary,
    fontWeight: "700",
    textTransform: "capitalize",
  },
  recentPreview: {
    color: theme.colors.textSecondary,
    lineHeight: 20,
  },
  emptyText: {
    color: theme.colors.textSecondary,
    lineHeight: 22,
  },
});
