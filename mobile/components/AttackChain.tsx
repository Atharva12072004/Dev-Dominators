import { ScrollView, StyleSheet, Text, View } from "react-native";

import { ChainStep } from "@/components/ChainStep";
import { CyberCard } from "@/components/CyberCard";
import { PrimaryButton } from "@/components/PrimaryButton";
import { AttackChainModel, AttackStageKey } from "@/utils/advancedIntelligenceTypes";
import { theme } from "@/utils/theme";

export function AttackChain({
  chain,
  activeStageKey,
  onStart,
  onReset,
  isSimulating,
}: {
  chain: AttackChainModel | null;
  activeStageKey: AttackStageKey | null;
  onStart: () => void;
  onReset: () => void;
  isSimulating: boolean;
}) {
  if (!chain) {
    return null;
  }

  return (
    <CyberCard
      title="Attack Chain"
      subtitle="Email -> Link -> Fake Page -> Payload flow built from observed and simulated stages."
    >
      <View style={styles.buttonRow}>
        <PrimaryButton
          label={isSimulating ? "Simulation Running..." : "Start Simulation"}
          onPress={onStart}
          disabled={isSimulating}
        />
        <PrimaryButton label="Reset" onPress={onReset} variant="secondary" />
      </View>

      <ScrollView horizontal showsHorizontalScrollIndicator={false} contentContainerStyle={styles.chainRow}>
        {chain.stages.map((stage, index) => (
          <View key={stage.key} style={styles.chainUnit}>
            <ChainStep stage={stage} active={activeStageKey === stage.key} />
            {index < chain.stages.length - 1 ? <Text style={styles.arrow}>{"->"}</Text> : null}
          </View>
        ))}
      </ScrollView>

      <View style={styles.summaryBanner}>
        <Text style={styles.summaryTitle}>Chain summary</Text>
        <Text style={styles.summaryText}>{chain.summary}</Text>
      </View>
    </CyberCard>
  );
}

const styles = StyleSheet.create({
  buttonRow: {
    flexDirection: "row",
    gap: theme.spacing.sm,
  },
  chainRow: {
    gap: theme.spacing.sm,
    paddingRight: theme.spacing.sm,
  },
  chainUnit: {
    flexDirection: "row",
    alignItems: "center",
    gap: theme.spacing.sm,
  },
  arrow: {
    color: theme.colors.accent,
    fontSize: 24,
    fontWeight: "800",
  },
  summaryBanner: {
    backgroundColor: "#0A1224",
    borderRadius: theme.radius.md,
    padding: theme.spacing.md,
    gap: theme.spacing.xs,
  },
  summaryTitle: {
    color: theme.colors.textPrimary,
    fontSize: 15,
    fontWeight: "700",
  },
  summaryText: {
    color: theme.colors.textSecondary,
    lineHeight: 20,
  },
});
