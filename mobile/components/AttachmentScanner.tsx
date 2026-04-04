import { useEffect, useState } from "react";
import { StyleSheet, Text, View } from "react-native";

import { CyberCard } from "@/components/CyberCard";
import { AttachmentAnalysisItem, AttachmentAnalysisSummary, AttachmentRiskLevel } from "@/utils/attachmentAnalysisTypes";
import { theme } from "@/utils/theme";

function riskToneColor(level: AttachmentRiskLevel) {
  if (level === "critical") {
    return theme.colors.danger;
  }
  if (level === "high") {
    return "#FF7A59";
  }
  if (level === "medium") {
    return theme.colors.warning;
  }
  return theme.colors.success;
}

function Timeline({ attachment }: { attachment: AttachmentAnalysisItem }) {
  const [visibleSteps, setVisibleSteps] = useState(1);

  useEffect(() => {
    setVisibleSteps(1);
    if (attachment.timeline.length <= 1) {
      return;
    }
    const intervalId = setInterval(() => {
      setVisibleSteps((current) => {
        if (current >= attachment.timeline.length) {
          clearInterval(intervalId);
          return current;
        }
        return current + 1;
      });
    }, 260);
    return () => clearInterval(intervalId);
  }, [attachment.id, attachment.timeline.length]);

  return (
    <View style={styles.timeline}>
      {attachment.timeline.slice(0, visibleSteps).map((step) => (
        <View key={step.id} style={styles.timelineRow}>
          <View style={[styles.timelineDot, { backgroundColor: riskToneColor(step.severity) }]} />
          <View style={styles.timelineCopy}>
            <Text style={styles.timelineLabel}>{step.label}</Text>
            <Text style={styles.timelineDetail}>{step.detail}</Text>
          </View>
        </View>
      ))}
    </View>
  );
}

export function AttachmentScanner({
  analysis,
}: {
  analysis: AttachmentAnalysisSummary | null;
}) {
  if (!analysis || analysis.attachments.length === 0) {
    return null;
  }

  return (
    <CyberCard
      title="Attachment Analysis"
      subtitle="Static checks and simulated sandbox behavior are shown separately for each attachment."
    >
      <View style={styles.summaryRow}>
        <View style={styles.metricBox}>
          <Text style={styles.metricValue}>{analysis.overallRiskScore}/100</Text>
          <Text style={styles.metricLabel}>Attachment Risk</Text>
        </View>
        <View style={styles.metricBox}>
          <Text style={styles.metricValue}>{analysis.staticReasonCount}</Text>
          <Text style={styles.metricLabel}>Static Signals</Text>
        </View>
        <View style={styles.metricBox}>
          <Text style={styles.metricValue}>{analysis.dynamicReasonCount}</Text>
          <Text style={styles.metricLabel}>Simulated Behaviors</Text>
        </View>
      </View>

      {analysis.attachments.map((attachment) => (
        <View key={attachment.id} style={styles.attachmentBlock}>
          <View style={styles.attachmentHeader}>
            <View style={styles.attachmentCopy}>
              <Text style={styles.attachmentName}>{attachment.fileName}</Text>
              <Text style={styles.attachmentType}>{attachment.fileTypeLabel}</Text>
            </View>
            <View
              style={[
                styles.riskPill,
                { borderColor: riskToneColor(attachment.finalRiskLevel) },
              ]}
            >
              <Text
                style={[
                  styles.riskPillText,
                  { color: riskToneColor(attachment.finalRiskLevel) },
                ]}
              >
                {attachment.finalRiskScore}/100
              </Text>
            </View>
          </View>

          <View style={styles.dualGrid}>
            <View style={styles.analysisColumn}>
              <Text style={styles.sectionTitle}>Static analysis</Text>
              {attachment.staticIndicators.map((indicator) => (
                <View key={indicator.id} style={styles.signalRow}>
                  <View
                    style={[
                      styles.signalDot,
                      { backgroundColor: riskToneColor(indicator.severity) },
                    ]}
                  />
                  <View style={styles.signalCopy}>
                    <Text style={styles.signalTitle}>{indicator.title}</Text>
                    <Text style={styles.signalDetail}>{indicator.detail}</Text>
                  </View>
                </View>
              ))}
            </View>

            <View style={styles.analysisColumn}>
              <Text style={styles.sectionTitle}>Dynamic sandbox simulation</Text>
              {attachment.dynamicIndicators.length > 0 ? (
                attachment.dynamicIndicators.map((indicator) => (
                  <View key={indicator.id} style={styles.signalRow}>
                    <View
                      style={[
                        styles.signalDot,
                        { backgroundColor: riskToneColor(indicator.severity) },
                      ]}
                    />
                    <View style={styles.signalCopy}>
                      <Text style={styles.signalTitle}>{indicator.title}</Text>
                      <Text style={styles.signalDetail}>{indicator.detail}</Text>
                    </View>
                  </View>
                ))
              ) : (
                <Text style={styles.emptyCopy}>
                  No dangerous runtime behavior was simulated for this attachment.
                </Text>
              )}
            </View>
          </View>

          <View style={styles.timelinePanel}>
            <Text style={styles.sectionTitle}>Simulated execution timeline</Text>
            <Timeline attachment={attachment} />
          </View>

          <Text style={styles.attachmentSummary}>{attachment.explanationSummary}</Text>
        </View>
      ))}
    </CyberCard>
  );
}

const styles = StyleSheet.create({
  summaryRow: {
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
    fontSize: 22,
    fontWeight: "800",
  },
  metricLabel: {
    color: theme.colors.textSecondary,
    fontSize: 12,
  },
  attachmentBlock: {
    gap: theme.spacing.md,
    padding: theme.spacing.md,
    borderRadius: theme.radius.md,
    backgroundColor: theme.colors.backgroundSecondary,
  },
  attachmentHeader: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    gap: theme.spacing.md,
  },
  attachmentCopy: {
    flex: 1,
    gap: 4,
  },
  attachmentName: {
    color: theme.colors.textPrimary,
    fontWeight: "700",
    fontSize: 16,
  },
  attachmentType: {
    color: theme.colors.textSecondary,
  },
  riskPill: {
    paddingHorizontal: theme.spacing.md,
    paddingVertical: theme.spacing.xs,
    borderRadius: 999,
    borderWidth: 1,
    backgroundColor: theme.colors.card,
  },
  riskPillText: {
    fontWeight: "800",
  },
  dualGrid: {
    gap: theme.spacing.md,
  },
  analysisColumn: {
    gap: theme.spacing.sm,
    backgroundColor: "#091120",
    borderRadius: theme.radius.md,
    padding: theme.spacing.md,
  },
  sectionTitle: {
    color: theme.colors.textPrimary,
    fontWeight: "700",
    fontSize: 15,
  },
  signalRow: {
    flexDirection: "row",
    gap: theme.spacing.sm,
    alignItems: "flex-start",
  },
  signalDot: {
    width: 9,
    height: 9,
    borderRadius: 999,
    marginTop: 6,
  },
  signalCopy: {
    flex: 1,
    gap: 2,
  },
  signalTitle: {
    color: theme.colors.textPrimary,
    fontWeight: "600",
  },
  signalDetail: {
    color: theme.colors.textSecondary,
    lineHeight: 20,
  },
  timelinePanel: {
    gap: theme.spacing.sm,
    backgroundColor: "#08101D",
    borderRadius: theme.radius.md,
    padding: theme.spacing.md,
  },
  timeline: {
    gap: theme.spacing.sm,
  },
  timelineRow: {
    flexDirection: "row",
    gap: theme.spacing.sm,
    alignItems: "flex-start",
  },
  timelineDot: {
    width: 10,
    height: 10,
    borderRadius: 999,
    marginTop: 6,
  },
  timelineCopy: {
    flex: 1,
    gap: 2,
  },
  timelineLabel: {
    color: theme.colors.textPrimary,
    fontWeight: "700",
  },
  timelineDetail: {
    color: theme.colors.textSecondary,
    lineHeight: 20,
  },
  attachmentSummary: {
    color: theme.colors.textPrimary,
    lineHeight: 21,
    backgroundColor: theme.colors.card,
    borderRadius: theme.radius.md,
    padding: theme.spacing.md,
  },
  emptyCopy: {
    color: theme.colors.textSecondary,
    lineHeight: 20,
  },
});
