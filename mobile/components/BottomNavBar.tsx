import { usePathname, useRouter } from "expo-router";
import { Pressable, StyleSheet, Text, View } from "react-native";

import { routes } from "@/navigation/routes";
import { theme } from "@/utils/theme";

const tabs = [
  { label: "Dashboard", route: routes.home },
  { label: "Scan", route: routes.manualScan },
  { label: "Protection Log", route: routes.protectionLogs },
  { label: "Account", route: routes.settings },
];

export function BottomNavBar() {
  const router = useRouter();
  const pathname = usePathname();

  return (
    <View style={styles.container}>
      {tabs.map((tab) => {
        const active = pathname === tab.route;
        return (
          <Pressable key={tab.route} style={styles.tab} onPress={() => router.replace(tab.route)}>
            <Text style={[styles.label, active && styles.activeLabel]}>{tab.label}</Text>
            <View style={[styles.dot, active && styles.activeDot]} />
          </Pressable>
        );
      })}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flexDirection: "row",
    backgroundColor: theme.colors.card,
    borderRadius: theme.radius.lg,
    borderWidth: 1,
    borderColor: theme.colors.border,
    paddingVertical: 10,
    paddingHorizontal: 8,
    gap: 6,
  },
  tab: {
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
    gap: 6,
    paddingVertical: 8,
    borderRadius: theme.radius.md,
  },
  label: {
    color: theme.colors.textMuted,
    fontSize: 12,
    fontWeight: "700",
    textAlign: "center",
  },
  activeLabel: {
    color: theme.colors.textPrimary,
  },
  dot: {
    width: 6,
    height: 6,
    borderRadius: 3,
    backgroundColor: "transparent",
  },
  activeDot: {
    backgroundColor: theme.colors.accent,
  },
});
