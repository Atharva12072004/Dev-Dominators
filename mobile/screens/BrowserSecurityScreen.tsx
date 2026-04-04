import { useState } from "react";
import * as Linking from "expo-linking";
import { StyleSheet, Text, TextInput, View } from "react-native";
import { useRouter } from "expo-router";

import { CyberCard } from "@/components/CyberCard";
import { PrimaryButton } from "@/components/PrimaryButton";
import { ScreenContainer } from "@/components/ScreenContainer";
import { useAppData } from "@/hooks/useAppData";
import { useScanner } from "@/hooks/useScanner";
import { routes } from "@/navigation/routes";
import { theme } from "@/utils/theme";

export function BrowserSecurityScreen() {
  const router = useRouter();
  const { setPendingWarningThreatId } = useAppData();
  const { isLoading, error, runUrlScan } = useScanner();
  const [url, setUrl] = useState("");

  async function handleCheck() {
    const result = await runUrlScan({
      url: url.trim(),
      source_type: "browser",
      use_ai: true,
    });

    if (result.should_block && result.label === "phishing") {
      router.push(routes.warning);
      return;
    }

    await Linking.openURL(url.trim());
    router.push(routes.result);
  }

  return (
    <ScreenContainer
      title="Browser Security"
      subtitle="Check a link before opening it. The mobile client can call this screen before handing URLs to the browser."
      showBottomNav
      footer={
        <PrimaryButton
          label={isLoading ? "Checking..." : "Check URL"}
          onPress={handleCheck}
          disabled={isLoading || !url.trim()}
        />
      }
    >
      <CyberCard title="Target URL" subtitle="Paste a suspicious or unknown link">
        <TextInput
          value={url}
          onChangeText={setUrl}
          placeholder="https://example.com/login"
          placeholderTextColor={theme.colors.textMuted}
          autoCapitalize="none"
          keyboardType="url"
          style={styles.input}
        />
      </CyberCard>
      <View style={styles.tipBox}>
        <Text style={styles.tipTitle}>Integration note</Text>
        <Text style={styles.tipText}>
          In production, intercept outbound links, call `/scan/url`, and only continue if
          `should_block` is false.
        </Text>
      </View>
      {error ? (
        <View style={styles.banner}>
          <Text style={styles.bannerTitle}>Local protection active</Text>
          <Text style={styles.bannerText}>{error}</Text>
        </View>
      ) : null}
    </ScreenContainer>
  );
}

const styles = StyleSheet.create({
  input: {
    backgroundColor: theme.colors.backgroundSecondary,
    borderRadius: theme.radius.md,
    borderWidth: 1,
    borderColor: theme.colors.border,
    paddingHorizontal: theme.spacing.md,
    paddingVertical: theme.spacing.md,
    color: theme.colors.textPrimary,
    fontSize: 15,
  },
  tipBox: {
    backgroundColor: theme.colors.card,
    borderRadius: theme.radius.md,
    borderWidth: 1,
    borderColor: theme.colors.border,
    padding: theme.spacing.md,
    gap: 6,
  },
  tipTitle: {
    color: theme.colors.textPrimary,
    fontWeight: "700",
  },
  tipText: {
    color: theme.colors.textSecondary,
    lineHeight: 21,
  },
  banner: {
    backgroundColor: "#3B2412",
    borderRadius: theme.radius.md,
    padding: theme.spacing.md,
    gap: 4,
  },
  bannerTitle: {
    color: theme.colors.warning,
    fontWeight: "700",
  },
  bannerText: {
    color: theme.colors.textPrimary,
    lineHeight: 20,
  },
});
