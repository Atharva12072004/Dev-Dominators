import { StyleSheet, Text, View } from "react-native";

import { CyberCard } from "@/components/CyberCard";
import { SimulationEvent } from "@/utils/advancedIntelligenceTypes";
import { theme } from "@/utils/theme";

function iconGlyph(icon: SimulationEvent["icon"]) {
  const glyphs: Record<SimulationEvent["icon"], string> = {
    mail: "@",
    link: "->",
    page: "[]",
    lock: "**",
    file: "F",
    download: "D",
  };
  return glyphs[icon];
}

function tone(severity: SimulationEvent["severity"]) {
  if (severity === "high" || severity === "critical") {
    return theme.colors.danger;
  }
  if (severity === "medium") {
    return theme.colors.warning;
  }
  return theme.colors.success;
}

export function SimulationTimeline({
  visibleSteps,
  activeStepIndex,
}: {
  visibleSteps: SimulationEvent[];
  activeStepIndex: number;
}) {
  return (
    <CyberCard
      title="Enhanced Simulation"
      subtitle="Safe sandbox-like timeline showing how the phishing flow could unfold."
    >
      {visibleSteps.length > 0 ? (
        <View style={styles.timeline}>
          {visibleSteps.map((step, index) => (
            <View
              key={step.id}
              style={[
                styles.stepCard,
                index === activeStepIndex && styles.activeStep,
              ]}
            >
              <View style={[styles.iconBubble, { backgroundColor: tone(step.severity) }]}>
                <Text style={styles.iconGlyph}>{iconGlyph(step.icon)}</Text>
              </View>
              <View style={styles.copy}>
                <Text style={styles.title}>{step.title}</Text>
                <Text style={styles.detail}>{step.detail}</Text>
              </View>
            </View>
          ))}
        </View>
      ) : (
        <View style={styles.emptyState}>
          <Text style={styles.emptyTitle}>Simulation ready</Text>
          <Text style={styles.emptyCopy}>
            Start Simulation to replay the staged attack path step by step.
          </Text>
        </View>
      )}
    </CyberCard>
  );
}

const styles = StyleSheet.create({
  timeline: {
    gap: theme.spacing.sm,
  },
  stepCard: {
    flexDirection: "row",
    gap: theme.spacing.md,
    padding: theme.spacing.md,
    borderRadius: theme.radius.md,
    backgroundColor: theme.colors.backgroundSecondary,
    borderWidth: 1,
    borderColor: theme.colors.border,
  },
  activeStep: {
    borderColor: theme.colors.accent,
    backgroundColor: "#102142",
  },
  iconBubble: {
    width: 34,
    height: 34,
    borderRadius: 999,
    alignItems: "center",
    justifyContent: "center",
  },
  iconGlyph: {
    color: theme.colors.background,
    fontWeight: "800",
  },
  copy: {
    flex: 1,
    gap: 4,
  },
  title: {
    color: theme.colors.textPrimary,
    fontWeight: "700",
  },
  detail: {
    color: theme.colors.textSecondary,
    lineHeight: 20,
  },
  emptyState: {
    padding: theme.spacing.md,
    borderRadius: theme.radius.md,
    backgroundColor: theme.colors.backgroundSecondary,
    gap: 4,
  },
  emptyTitle: {
    color: theme.colors.textPrimary,
    fontWeight: "700",
  },
  emptyCopy: {
    color: theme.colors.textSecondary,
    lineHeight: 20,
  },
});
