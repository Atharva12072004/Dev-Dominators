import { StyleSheet, Text, View } from "react-native";

import { CyberCard } from "@/components/CyberCard";
import { CampaignCluster } from "@/utils/advancedIntelligenceTypes";
import { theme } from "@/utils/theme";

function tone(level: CampaignCluster["riskLevel"]) {
  if (level === "high") {
    return theme.colors.danger;
  }
  if (level === "medium") {
    return theme.colors.warning;
  }
  return theme.colors.success;
}

export function CampaignClusterPanel({ cluster }: { cluster: CampaignCluster | null }) {
  if (!cluster) {
    return null;
  }

  return (
    <CyberCard
      title="Campaign Cluster"
      subtitle="In-memory campaign grouping across similar phishing attempts."
    >
      <View style={styles.headerRow}>
        <View style={styles.copy}>
          <Text style={styles.title}>{cluster.campaign}</Text>
          <Text style={styles.subtitle}>
            {cluster.commonDomain ? `Shared domain: ${cluster.commonDomain}` : "Domain inferred from shared patterns"}
          </Text>
        </View>
        <View style={[styles.riskPill, { borderColor: tone(cluster.riskLevel) }]}>
          <Text style={[styles.riskText, { color: tone(cluster.riskLevel) }]}>{cluster.riskLevel.toUpperCase()}</Text>
        </View>
      </View>

      <View style={styles.metrics}>
        <View style={styles.metricBox}>
          <Text style={styles.metricValue}>{cluster.totalAttacks}</Text>
          <Text style={styles.metricLabel}>Related attacks</Text>
        </View>
        <View style={styles.metricBox}>
          <Text style={styles.metricValue}>{cluster.sharedIndicators.length}</Text>
          <Text style={styles.metricLabel}>Shared indicators</Text>
        </View>
      </View>

      <View style={styles.indicatorBlock}>
        {cluster.sharedIndicators.map((indicator) => (
          <View key={indicator} style={styles.reasonRow}>
            <View style={styles.dot} />
            <Text style={styles.reason}>{indicator}</Text>
          </View>
        ))}
      </View>
    </CyberCard>
  );
}

const styles = StyleSheet.create({
  headerRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    gap: theme.spacing.sm,
    alignItems: "flex-start",
  },
  copy: {
    flex: 1,
    gap: 4,
  },
  title: {
    color: theme.colors.textPrimary,
    fontWeight: "800",
    fontSize: 17,
  },
  subtitle: {
    color: theme.colors.textSecondary,
    lineHeight: 20,
  },
  riskPill: {
    borderWidth: 1,
    borderRadius: 999,
    paddingHorizontal: theme.spacing.sm,
    paddingVertical: 6,
  },
  riskText: {
    fontWeight: "800",
    fontSize: 12,
  },
  metrics: {
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
    fontWeight: "800",
    fontSize: 22,
  },
  metricLabel: {
    color: theme.colors.textMuted,
    fontSize: 12,
  },
  indicatorBlock: {
    gap: theme.spacing.sm,
    backgroundColor: theme.colors.backgroundSecondary,
    borderRadius: theme.radius.md,
    padding: theme.spacing.md,
  },
  reasonRow: {
    flexDirection: "row",
    gap: theme.spacing.sm,
    alignItems: "flex-start",
  },
  dot: {
    width: 8,
    height: 8,
    marginTop: 6,
    borderRadius: 999,
    backgroundColor: theme.colors.accent,
  },
  reason: {
    flex: 1,
    color: theme.colors.textSecondary,
    lineHeight: 20,
  },
});
