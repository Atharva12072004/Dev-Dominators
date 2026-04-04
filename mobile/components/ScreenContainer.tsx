import { PropsWithChildren, ReactNode } from "react";
import { RefreshControl, ScrollView, StyleSheet, Text, View } from "react-native";
import { SafeAreaView, useSafeAreaInsets } from "react-native-safe-area-context";

import { BottomNavBar } from "@/components/BottomNavBar";
import { theme } from "@/utils/theme";

interface ScreenContainerProps extends PropsWithChildren {
  title: string;
  subtitle?: string;
  footer?: ReactNode;
  scrollEnabled?: boolean;
  refreshing?: boolean;
  onRefresh?: () => void;
  showBottomNav?: boolean;
  headerSlot?: ReactNode;
}

export function ScreenContainer({
  title,
  subtitle,
  footer,
  children,
  scrollEnabled = true,
  refreshing = false,
  onRefresh,
  showBottomNav = false,
  headerSlot,
}: ScreenContainerProps) {
  const insets = useSafeAreaInsets();
  const footerReserve = footer ? 88 : 0;
  const bottomNavReserve = showBottomNav ? 108 : 0;

  const content = (
    <View
      style={[
        styles.inner,
        {
          paddingTop: Math.max(theme.spacing.lg, insets.top + theme.spacing.sm),
        },
      ]}
    >
      <View style={styles.header}>
        <Text style={styles.title}>{title}</Text>
        {subtitle ? <Text style={styles.subtitle}>{subtitle}</Text> : null}
        {headerSlot}
      </View>
      {children}
    </View>
  );

  return (
    <SafeAreaView style={styles.safeArea} edges={["top", "bottom"]}>
      {scrollEnabled ? (
        <ScrollView
          contentContainerStyle={[
            styles.scrollContent,
            {
              paddingBottom:
                theme.spacing.xxl + insets.bottom + footerReserve + bottomNavReserve,
            },
          ]}
          showsVerticalScrollIndicator={false}
          keyboardShouldPersistTaps="handled"
          refreshControl={
            onRefresh ? <RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor={theme.colors.accent} /> : undefined
          }
        >
          {content}
        </ScrollView>
      ) : (
        content
      )}
      {footer ? (
        <View
          style={[
            styles.footer,
            {
              paddingBottom: Math.max(theme.spacing.sm, insets.bottom),
            },
          ]}
        >
          {footer}
        </View>
      ) : null}
      {showBottomNav ? (
        <View
          style={[
            styles.bottomNavWrap,
            {
              paddingBottom: Math.max(theme.spacing.lg, insets.bottom),
            },
          ]}
        >
          <BottomNavBar />
        </View>
      ) : null}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: theme.colors.background,
  },
  scrollContent: {
    flexGrow: 1,
  },
  inner: {
    paddingHorizontal: theme.spacing.lg,
    gap: theme.spacing.md,
  },
  header: {
    gap: theme.spacing.xs,
    marginBottom: theme.spacing.sm,
  },
  title: {
    fontSize: 28,
    fontWeight: "800",
    color: theme.colors.textPrimary,
  },
  subtitle: {
    fontSize: 15,
    lineHeight: 22,
    color: theme.colors.textSecondary,
  },
  footer: {
    paddingHorizontal: theme.spacing.lg,
    paddingBottom: theme.spacing.sm,
    paddingTop: theme.spacing.sm,
    backgroundColor: theme.colors.background,
  },
  bottomNavWrap: {
    paddingHorizontal: theme.spacing.lg,
    paddingBottom: theme.spacing.lg,
    backgroundColor: theme.colors.background,
  },
});
