import { StyleSheet, Text, View } from "react-native";

import { CyberCard } from "@/components/CyberCard";
import { RiskScoreRing } from "@/components/RiskScoreRing";
import { StatusChip } from "@/components/StatusChip";
import { getSourceLabel } from "@/utils/sourceLabels";
import { theme } from "@/utils/theme";
import { ProtectionLog, ScanResult } from "@/utils/types";

interface ResultSummaryCardProps {
  result: ScanResult | ProtectionLog;
}

function looksLikeHtml(value: string) {
  const trimmed = value.trim().toLowerCase();
  return trimmed.startsWith("<!doctype") || trimmed.startsWith("<html") || /<body[\s>]/i.test(trimmed);
}

export function ResultSummaryCard({ result }: ResultSummaryCardProps) {
  const tone =
    result.label === "phishing"
      ? "danger"
      : result.label === "suspicious"
        ? "warning"
        : "success";
  const sourceLabel = getSourceLabel(result.source_type, "source_app" in result ? result.source_app : null);
  const rawText = "raw_text" in result ? result.raw_text || "" : "";
  const safeContent = rawText && !looksLikeHtml(rawText) ? rawText : null;
  const previewContent = "preview" in result ? result.preview : null;
  const detailContent = result.partial_scan
    ? "Exact message content not available. Partial scan applied."
    : safeContent || ("raw_url" in result && result.raw_url) || previewContent || result.reasons[0];
  const providerNote =
    result.partial_scan
      ? `Group Notification from ${sourceLabel}`
      : result.provider_used && result.analysis_mode === "online"
        ? `Backend-enhanced scan via ${result.provider_used}`
        : result.detection_mode === "hybrid" && result.analysis_mode === "online"
          ? "AI + rule-based detection completed"
          : result.detection_mode === "ai"
            ? "AI detection completed"
            : result.analysis_mode === "online"
              ? "Backend-enhanced scan completed"
              : "Local phishing heuristics applied";

  return (
    <CyberCard
      title="Threat Analysis"
      subtitle={providerNote}
      rightSlot={<StatusChip label={result.label} tone={tone} />}
    >
      <View style={styles.center}>
        <RiskScoreRing score={result.risk_score} />
      </View>

      <View style={styles.infoBlock}>
        <View style={styles.infoRow}>
          <Text style={styles.infoLabel}>Source</Text>
          <Text style={styles.infoValue}>{sourceLabel}</Text>
        </View>
        {"status" in result && result.status ? (
          <View style={styles.infoRow}>
            <Text style={styles.infoLabel}>Status</Text>
            <Text style={styles.infoValue}>{result.status.toUpperCase()}</Text>
          </View>
        ) : null}
        {detailContent ? (
          <View style={styles.inlineContent}>
            <Text style={styles.infoLabel}>{result.partial_scan ? "Scan coverage" : "Detected content"}</Text>
            <Text style={styles.contentText}>{detailContent}</Text>
          </View>
        ) : null}
        {result.detection_mode ? (
          <View style={styles.infoRow}>
            <Text style={styles.infoLabel}>Detection mode</Text>
            <Text style={styles.infoValue}>{result.detection_mode.toUpperCase()}</Text>
          </View>
        ) : null}
        <View style={styles.infoRow}>
          <Text style={styles.infoLabel}>Confidence</Text>
          <Text style={styles.infoValue}>{Math.round(result.confidence * 100)}%</Text>
        </View>
      </View>

      <View style={styles.reasonBlock}>
        <Text style={styles.sectionTitle}>Signals used</Text>
        {result.reasons.map((reason) => (
          <View key={reason} style={styles.reasonRow}>
            <View style={styles.reasonDot} />
            <Text style={styles.reasonText}>{reason}</Text>
          </View>
        ))}
      </View>

      {result.ai_summary ? <Text style={styles.summary}>{result.ai_summary}</Text> : null}
      {result.analysis_error ? <Text style={styles.warning}>{result.analysis_error}</Text> : null}
    </CyberCard>
  );
}

const styles = StyleSheet.create({
  center: {
    alignItems: "center",
    marginVertical: theme.spacing.sm,
  },
  infoBlock: {
    backgroundColor: theme.colors.backgroundSecondary,
    borderRadius: theme.radius.md,
    padding: theme.spacing.md,
    gap: theme.spacing.sm,
  },
  infoRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    gap: theme.spacing.md,
    alignItems: "center",
  },
  infoLabel: {
    color: theme.colors.textMuted,
    fontSize: 12,
    textTransform: "uppercase",
    letterSpacing: 0.8,
    fontWeight: "700",
  },
  infoValue: {
    flex: 1,
    textAlign: "right",
    color: theme.colors.textPrimary,
    fontWeight: "700",
  },
  inlineContent: {
    gap: theme.spacing.xs,
  },
  reasonBlock: {
    gap: theme.spacing.sm,
  },
  sectionTitle: {
    color: theme.colors.textPrimary,
    fontWeight: "700",
    fontSize: 16,
  },
  reasonRow: {
    flexDirection: "row",
    gap: theme.spacing.sm,
    alignItems: "flex-start",
  },
  reasonDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    backgroundColor: theme.colors.accent,
    marginTop: 6,
  },
  reasonText: {
    flex: 1,
    color: theme.colors.textSecondary,
    lineHeight: 20,
  },
  summary: {
    color: theme.colors.textPrimary,
    lineHeight: 21,
    backgroundColor: theme.colors.backgroundSecondary,
    borderRadius: theme.radius.md,
    padding: theme.spacing.md,
  },
  contentText: {
    color: theme.colors.textPrimary,
    lineHeight: 22,
  },
  warning: {
    color: theme.colors.warning,
    lineHeight: 20,
  },
});
