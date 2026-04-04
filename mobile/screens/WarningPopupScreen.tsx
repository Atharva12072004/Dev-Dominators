import { ScrollView, StyleSheet, Text, View } from "react-native";
import { useRouter } from "expo-router";
import { SafeAreaView, useSafeAreaInsets } from "react-native-safe-area-context";

import { PrimaryButton } from "@/components/PrimaryButton";
import { RiskScoreRing } from "@/components/RiskScoreRing";
import { useAppData } from "@/hooks/useAppData";
import { routes } from "@/navigation/routes";
import { getThreatSourceLabel } from "@/utils/sourceLabels";
import { theme } from "@/utils/theme";

export function WarningPopupScreen() {
  const router = useRouter();
  const insets = useSafeAreaInsets();
  const { pendingWarningThreat, setPendingWarningThreatId, setSelectedThreatId } = useAppData();
  const isUrlThreat = Boolean(pendingWarningThreat?.raw_url);

  async function handleContinue() {
    if (pendingWarningThreat) {
      await setSelectedThreatId(pendingWarningThreat.id);
    }
    await setPendingWarningThreatId(null);
    router.replace(routes.result);
  }

  return (
    <SafeAreaView style={styles.container} edges={["top", "bottom"]}>
      <ScrollView
        style={styles.scroll}
        contentContainerStyle={[
          styles.scrollContent,
          {
            paddingTop: Math.max(theme.spacing.lg, insets.top + theme.spacing.sm),
            paddingBottom: theme.spacing.xxl + 120 + Math.max(theme.spacing.md, insets.bottom),
          },
        ]}
        showsVerticalScrollIndicator={false}
      >
        <View style={styles.panel}>
          <Text style={styles.kicker}>Threat Alert</Text>
          <Text style={styles.title}>
            {isUrlThreat ? "MALICIOUS LINK DETECTED" : "SUSPICIOUS MESSAGE DETECTED"}
          </Text>
          <Text style={styles.message}>
            {isUrlThreat
              ? "CyberShield AI believes this link could be a phishing attempt. Opening it may expose your data or credentials."
              : "CyberShield AI believes this message matches phishing behavior. Proceed carefully before trusting links or requests in it."}
          </Text>
          {pendingWarningThreat ? (
            <>
              <View style={styles.ringWrap}>
                <RiskScoreRing score={pendingWarningThreat.risk_score} size={104} />
              </View>
              <Text style={styles.url}>{pendingWarningThreat.preview}</Text>
              <Text style={styles.meta}>
                Source: {getThreatSourceLabel(pendingWarningThreat)} - Risk: {pendingWarningThreat.risk_score}%
              </Text>
              {pendingWarningThreat.reasons.map((reason) => (
                <Text key={reason} style={styles.reason}>
                  - {reason}
                </Text>
              ))}
            </>
          ) : null}
        </View>
      </ScrollView>
      <View
        style={[
          styles.actions,
          {
            paddingBottom: Math.max(theme.spacing.md, insets.bottom),
          },
        ]}
      >
        <PrimaryButton
          label={isUrlThreat ? "Review Threat Details" : "Continue"}
          onPress={handleContinue}
        />
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#12070B",
  },
  scroll: {
    flex: 1,
  },
  scrollContent: {
    paddingHorizontal: theme.spacing.lg,
  },
  panel: {
    backgroundColor: "#2B0F16",
    borderRadius: theme.radius.xl,
    borderWidth: 1,
    borderColor: "#6E1D2B",
    padding: theme.spacing.xl,
    gap: theme.spacing.lg,
  },
  kicker: {
    color: theme.colors.warning,
    textTransform: "uppercase",
    letterSpacing: 1.5,
    fontWeight: "800",
  },
  title: {
    color: theme.colors.textPrimary,
    fontSize: 30,
    lineHeight: 36,
    fontWeight: "900",
  },
  message: {
    color: theme.colors.textSecondary,
    fontSize: 16,
    lineHeight: 24,
  },
  ringWrap: {
    alignItems: "center",
  },
  url: {
    color: theme.colors.textPrimary,
    backgroundColor: "#1B0A0F",
    borderRadius: theme.radius.md,
    padding: theme.spacing.md,
  },
  actions: {
    paddingHorizontal: theme.spacing.lg,
    paddingTop: theme.spacing.sm,
    gap: theme.spacing.sm,
    backgroundColor: "#12070B",
  },
  meta: {
    color: theme.colors.textSecondary,
  },
  reason: {
    color: theme.colors.textPrimary,
    lineHeight: 22,
  },
});
