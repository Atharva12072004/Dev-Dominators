import { StyleSheet, Text, View } from "react-native";

import { AttackChain } from "@/components/AttackChain";
import { CampaignClusterPanel } from "@/components/CampaignClusterPanel";
import { CyberCard } from "@/components/CyberCard";
import { PrimaryButton } from "@/components/PrimaryButton";
import { SimulationTimeline } from "@/components/SimulationTimeline";
import { useAttackChain } from "@/hooks/useAttackChain";
import { ProtectionLog, ScanResult } from "@/utils/types";
import { theme } from "@/utils/theme";

export function AdvancedInsightsPanel({
  result,
  logs,
}: {
  result: ScanResult | ProtectionLog | null;
  logs: ProtectionLog[];
}) {
  const {
    insights,
    isSimulating,
    activeStageKey,
    activeStepIndex,
    showCampaign,
    setShowCampaign,
    startSimulation,
    resetSimulation,
    visibleSimulationSteps,
  } = useAttackChain(result ? { result, logs } : null);

  if (!insights || !result) {
    return null;
  }

  return (
    <View style={styles.stack}>
      <CyberCard
        title="Advanced Insights"
        subtitle="Attack chaining, campaign clustering, AI-phishing heuristics, and sandbox-like simulation layered on top of the current result."
      >
        <View style={styles.headerControls}>
          <PrimaryButton
            label={showCampaign ? "Hide Campaign View" : "Toggle Campaign View"}
            onPress={() => setShowCampaign(!showCampaign)}
            variant="secondary"
          />
        </View>

        <View style={styles.aiLikelihoodCard}>
          <Text style={styles.aiTitle}>AI-Generated Phishing Likelihood</Text>
          <Text style={styles.aiScore}>
            {insights.aiPhishing ? `${insights.aiPhishing.aiGeneratedLikelihood}%` : "Unavailable"}
          </Text>
          <Text style={styles.aiRationale}>
            {insights.aiPhishing?.rationale ||
              "There was not enough message text to estimate AI-generated phishing style reliably."}
          </Text>
          {insights.aiPhishing?.signals.length ? (
            <View style={styles.signalWrap}>
              {insights.aiPhishing.signals.map((signal) => (
                <View key={signal} style={styles.signalChip}>
                  <Text style={styles.signalChipText}>{signal}</Text>
                </View>
              ))}
            </View>
          ) : null}
        </View>
      </CyberCard>

      <AttackChain
        chain={insights.chain}
        activeStageKey={activeStageKey}
        onStart={startSimulation}
        onReset={resetSimulation}
        isSimulating={isSimulating}
      />

      <SimulationTimeline
        visibleSteps={visibleSimulationSteps}
        activeStepIndex={activeStepIndex}
      />

      {showCampaign ? <CampaignClusterPanel cluster={insights.campaign} /> : null}
    </View>
  );
}

const styles = StyleSheet.create({
  stack: {
    gap: theme.spacing.md,
  },
  headerControls: {
    alignItems: "flex-start",
  },
  aiLikelihoodCard: {
    gap: theme.spacing.sm,
    backgroundColor: "#0A1224",
    borderRadius: theme.radius.md,
    padding: theme.spacing.md,
  },
  aiTitle: {
    color: theme.colors.textPrimary,
    fontSize: 15,
    fontWeight: "700",
  },
  aiScore: {
    color: theme.colors.textPrimary,
    fontSize: 30,
    fontWeight: "900",
  },
  aiRationale: {
    color: theme.colors.textSecondary,
    lineHeight: 20,
  },
  signalWrap: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: theme.spacing.sm,
  },
  signalChip: {
    backgroundColor: theme.colors.accentSoft,
    borderRadius: 999,
    paddingHorizontal: theme.spacing.sm,
    paddingVertical: 6,
  },
  signalChipText: {
    color: theme.colors.textPrimary,
    fontSize: 12,
    fontWeight: "700",
  },
});
