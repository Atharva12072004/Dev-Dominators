import { useEffect } from "react";
import { StyleSheet, Text, View } from "react-native";
import { useRouter } from "expo-router";

import { AppLogo } from "@/components/AppLogo";
import { LoaderPulse } from "@/components/LoaderPulse";
import { useAppData } from "@/hooks/useAppData";
import { routes } from "@/navigation/routes";
import { theme } from "@/utils/theme";

export function SplashScreen() {
  const router = useRouter();
  const { hydrated, hasCompletedSetup } = useAppData();

  useEffect(() => {
    if (!hydrated) {
      return;
    }

    const timeout = setTimeout(() => {
      router.replace(hasCompletedSetup ? routes.home : routes.permissions);
    }, 1800);

    return () => clearTimeout(timeout);
  }, [hasCompletedSetup, hydrated, router]);

  return (
    <View style={styles.container}>
      <AppLogo />
      <Text style={styles.tagline}>AI-powered protection for links, messages, and apps.</Text>
      <LoaderPulse />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: theme.colors.background,
    alignItems: "center",
    justifyContent: "center",
    gap: theme.spacing.xl,
    paddingHorizontal: theme.spacing.xl,
  },
  tagline: {
    textAlign: "center",
    color: theme.colors.textSecondary,
    fontSize: 16,
    lineHeight: 24,
  },
});

