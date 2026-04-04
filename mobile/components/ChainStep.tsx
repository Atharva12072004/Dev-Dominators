import { StyleSheet, Text, View } from "react-native";

import { AttackStage } from "@/utils/advancedIntelligenceTypes";
import { theme } from "@/utils/theme";

function tone(score: number) {
  if (score >= 70) {
    return theme.colors.danger;
  }
  if (score >= 40) {
    return theme.colors.warning;
  }
  return theme.colors.success;
}

export function ChainStep({
  stage,
  active,
}: {
  stage: AttackStage;
  active: boolean;
}) {
  return (
    <View style={[styles.card, active && styles.activeCard]}>
      <View style={styles.header}>
        <Text style={styles.title}>{stage.title}</Text>
        <View style={[styles.scorePill, { borderColor: tone(stage.riskScore) }]}>
          <Text style={[styles.scoreText, { color: tone(stage.riskScore) }]}>{stage.riskScore}/100</Text>
        </View>
      </View>
      <Text style={styles.reason}>{stage.reason}</Text>
      <View style={styles.metaRow}>
        <Text style={styles.metaLabel}>{stage.status.toUpperCase()}</Text>
        <Text style={styles.metaValue}>{Math.round(stage.confidence * 100)}% confidence</Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    gap: theme.spacing.sm,
    padding: theme.spacing.md,
    borderRadius: theme.radius.md,
    backgroundColor: theme.colors.backgroundSecondary,
    borderWidth: 1,
    borderColor: theme.colors.border,
    minWidth: 220,
  },
  activeCard: {
    borderColor: theme.colors.accent,
    shadowColor: theme.colors.shadow,
    shadowOpacity: 0.35,
    shadowRadius: 18,
    shadowOffset: { width: 0, height: 8 },
    elevation: 4,
  },
  header: {
    flexDirection: "row",
    justifyContent: "space-between",
    gap: theme.spacing.sm,
    alignItems: "center",
  },
  title: {
    flex: 1,
    color: theme.colors.textPrimary,
    fontWeight: "700",
    fontSize: 15,
  },
  scorePill: {
    borderWidth: 1,
    borderRadius: 999,
    paddingHorizontal: theme.spacing.sm,
    paddingVertical: 6,
  },
  scoreText: {
    fontWeight: "800",
  },
  reason: {
    color: theme.colors.textSecondary,
    lineHeight: 20,
  },
  metaRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    gap: theme.spacing.sm,
  },
  metaLabel: {
    color: theme.colors.textMuted,
    fontSize: 12,
    fontWeight: "700",
  },
  metaValue: {
    color: theme.colors.textPrimary,
    fontSize: 12,
    fontWeight: "700",
  },
});
