import { StyleSheet, Text, View } from "react-native";

import { CyberCard } from "@/components/CyberCard";
import { ExplainabilityReport } from "@/utils/attachmentAnalysisTypes";
import { theme } from "@/utils/theme";

export function ExplainabilityPanel({
  report,
}: {
  report: ExplainabilityReport | null;
}) {
  if (!report) {
    return null;
  }

  return (
    <CyberCard
      title="Explainability"
      subtitle="Human-readable reasons behind the final phishing decision."
    >
      <View style={styles.metricRow}>
        <View style={styles.metricCard}>
          <Text style={styles.metricValue}>{report.riskScore}/100</Text>
          <Text style={styles.metricLabel}>Final Risk Score</Text>
        </View>
        <View style={styles.metricCard}>
          <Text style={styles.metricValue}>{Math.round(report.confidence * 100)}%</Text>
          <Text style={styles.metricLabel}>Confidence</Text>
        </View>
        <View style={styles.metricCard}>
          <Text style={styles.metricValue}>{report.baseRiskScore}/100</Text>
          <Text style={styles.metricLabel}>Base Scan Score</Text>
        </View>
      </View>

      <View style={styles.summaryCard}>
        <Text style={styles.summaryTitle}>Final explanation summary</Text>
        <Text style={styles.summaryText}>{report.summary}</Text>
      </View>

      {report.sections.map((section) => (
        <View key={section.key} style={styles.section}>
          <Text style={styles.sectionTitle}>{section.title}</Text>
          {section.items.map((item) => (
            <View key={`${section.key}-${item}`} style={styles.reasonRow}>
              <View style={styles.reasonDot} />
              <Text style={styles.reasonText}>{item}</Text>
            </View>
          ))}
        </View>
      ))}

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Overall decision summary</Text>
        {report.overallReasons.map((reason) => (
          <View key={reason} style={styles.reasonRow}>
            <View style={styles.reasonDot} />
            <Text style={styles.reasonText}>{reason}</Text>
          </View>
        ))}
      </View>
    </CyberCard>
  );
}

const styles = StyleSheet.create({
  metricRow: {
    flexDirection: "row",
    gap: theme.spacing.sm,
  },
  metricCard: {
    flex: 1,
    backgroundColor: theme.colors.backgroundSecondary,
    borderRadius: theme.radius.md,
    padding: theme.spacing.md,
    gap: 4,
  },
  metricValue: {
    color: theme.colors.textPrimary,
    fontSize: 22,
    fontWeight: "800",
  },
  metricLabel: {
    color: theme.colors.textSecondary,
    fontSize: 12,
  },
  summaryCard: {
    backgroundColor: "#081321",
    borderRadius: theme.radius.md,
    padding: theme.spacing.md,
    gap: theme.spacing.xs,
  },
  summaryTitle: {
    color: theme.colors.textPrimary,
    fontWeight: "700",
    fontSize: 15,
  },
  summaryText: {
    color: theme.colors.textSecondary,
    lineHeight: 21,
  },
  section: {
    gap: theme.spacing.sm,
    backgroundColor: theme.colors.backgroundSecondary,
    borderRadius: theme.radius.md,
    padding: theme.spacing.md,
  },
  sectionTitle: {
    color: theme.colors.textPrimary,
    fontWeight: "700",
    fontSize: 15,
  },
  reasonRow: {
    flexDirection: "row",
    gap: theme.spacing.sm,
    alignItems: "flex-start",
  },
  reasonDot: {
    width: 8,
    height: 8,
    borderRadius: 999,
    backgroundColor: theme.colors.accent,
    marginTop: 6,
  },
  reasonText: {
    flex: 1,
    color: theme.colors.textSecondary,
    lineHeight: 20,
  },
});
