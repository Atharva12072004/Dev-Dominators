import { StyleSheet, View } from "react-native";
import { useRouter } from "expo-router";

import { AdvancedInsightsPanel } from "@/components/AdvancedInsightsPanel";
import { AttachmentScanner } from "@/components/AttachmentScanner";
import { EmptyState } from "@/components/EmptyState";
import { ExplainabilityPanel } from "@/components/ExplainabilityPanel";
import { PrimaryButton } from "@/components/PrimaryButton";
import { ResultSummaryCard } from "@/components/ResultSummaryCard";
import { ScreenContainer } from "@/components/ScreenContainer";
import { useAttachmentAnalysis } from "@/hooks/useAttachmentAnalysis";
import { useAppData } from "@/hooks/useAppData";
import { routes } from "@/navigation/routes";
import { theme } from "@/utils/theme";

export function ResultScreen() {
  const router = useRouter();
  const { lastScanResult, logs, selectedThreat } = useAppData();
  const result = selectedThreat || lastScanResult;
  const { attachmentAnalysis, explainability } = useAttachmentAnalysis(result);

  return (
    <ScreenContainer
      title="Threat Details"
      subtitle="Review the latest risk assessment, reasons, and decision state."
      showBottomNav
      footer={
        <View style={styles.footerActions}>
          <PrimaryButton label="Back to Dashboard" onPress={() => router.replace(routes.home)} />
        </View>
      }
    >
      {result ? (
        <View style={styles.contentStack}>
          <ResultSummaryCard result={result} />
          <AttachmentScanner analysis={attachmentAnalysis} />
          <ExplainabilityPanel report={explainability} />
          <AdvancedInsightsPanel result={result} logs={logs} />
        </View>
      ) : (
        <EmptyState
          title="No scan result yet"
          message="Run a manual scan or browser check first, and the result will appear here."
        />
      )}
    </ScreenContainer>
  );
}

const styles = StyleSheet.create({
  footerActions: {
    gap: theme.spacing.sm,
  },
  contentStack: {
    gap: theme.spacing.md,
  },
});
