import { Pressable, StyleSheet, Text, View } from "react-native";
import { useLocalSearchParams, useRouter } from "expo-router";
import { useState } from "react";

import { CyberCard } from "@/components/CyberCard";
import { EmptyState } from "@/components/EmptyState";
import { PrimaryButton } from "@/components/PrimaryButton";
import { RiskScoreRing } from "@/components/RiskScoreRing";
import { ScreenContainer } from "@/components/ScreenContainer";
import { StatusChip } from "@/components/StatusChip";
import { useAppData } from "@/hooks/useAppData";
import { routes } from "@/navigation/routes";
import { getThreatSourceLabel } from "@/utils/sourceLabels";
import { theme } from "@/utils/theme";

export function ProtectionLogsScreen() {
  const router = useRouter();
  const params = useLocalSearchParams<{ all?: string }>();
  const { logs, setSelectedThreatId, refreshLogs } = useAppData();
  const showAll = params.all === "1";
  const displayLogs = showAll ? logs : logs.slice(0, 10);
  const [refreshing, setRefreshing] = useState(false);

  async function handleRefresh() {
    setRefreshing(true);
    try {
      await refreshLogs();
    } finally {
      setRefreshing(false);
    }
  }

  return (
    <ScreenContainer
      title="Protection Logs"
      subtitle="Persistent Gmail, SMS, notification, browser, and manual scan history."
      onRefresh={handleRefresh}
      refreshing={refreshing}
      showBottomNav
    >
      {logs.length === 0 ? (
        <EmptyState
          title="No logs saved yet"
          message="Scan something from Manual Scan or Browser Security to populate this history."
        />
      ) : (
        displayLogs.map((log) => {
          const tone =
            log.label === "phishing"
              ? "danger"
              : log.label === "suspicious"
                ? "warning"
                : "success";

          return (
            <Pressable
              key={log.id}
              onPress={async () => {
                await setSelectedThreatId(log.id);
                router.push(routes.result);
              }}
            >
              <CyberCard
                title={getThreatSourceLabel(log)}
                subtitle={new Date(log.created_at).toLocaleString()}
                rightSlot={<StatusChip label={log.label} tone={tone} />}
              >
                <View style={styles.cardTopRow}>
                  <View style={styles.logCopy}>
                    <Text style={styles.metaLabel}>Content</Text>
                    <Text style={styles.contentText}>{log.raw_text || log.raw_url || log.preview}</Text>
                    <Text style={styles.timeText}>{new Date(log.created_at).toLocaleString()}</Text>
                  </View>
                  <RiskScoreRing score={log.risk_score} size={62} />
                </View>
                <View style={styles.detailsGrid}>
                  <View style={styles.detailRow}>
                    <Text style={styles.metaLabel}>Risk Percent</Text>
                    <Text style={styles.detailValue}>{log.risk_score}%</Text>
                  </View>
                  {log.reasons.slice(0, 4).map((reason, index) => (
                    <View key={`${log.id}-${index}`} style={styles.reasonRow}>
                      <Text style={styles.metaLabel}>Reason {index + 1}</Text>
                      <Text style={styles.reasonValue}>{reason}</Text>
                    </View>
                  ))}
                </View>
              </CyberCard>
            </Pressable>
          );
        })
      )}
      {!showAll && logs.length > 10 ? (
        <PrimaryButton
          label="See All Protection Logs"
          onPress={() => router.replace(`${routes.protectionLogs}?all=1`)}
          variant="secondary"
        />
      ) : null}
    </ScreenContainer>
  );
}

const styles = StyleSheet.create({
  cardTopRow: {
    flexDirection: "row",
    gap: theme.spacing.md,
    alignItems: "center",
  },
  logCopy: {
    flex: 1,
    gap: theme.spacing.xs,
  },
  metaLabel: {
    color: theme.colors.textMuted,
    fontSize: 11,
    fontWeight: "700",
    letterSpacing: 0.8,
    textTransform: "uppercase",
  },
  contentText: {
    color: theme.colors.textPrimary,
    fontSize: 15,
    lineHeight: 22,
  },
  timeText: {
    color: theme.colors.textSecondary,
    fontSize: 12,
  },
  detailsGrid: {
    gap: theme.spacing.sm,
  },
  detailRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    gap: theme.spacing.md,
  },
  detailValue: {
    color: theme.colors.textPrimary,
    fontWeight: "700",
  },
  reasonRow: {
    gap: 4,
  },
  reasonValue: {
    color: theme.colors.textSecondary,
    lineHeight: 20,
  },
});
