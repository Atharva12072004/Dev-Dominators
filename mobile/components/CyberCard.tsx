import { PropsWithChildren, ReactNode } from "react";
import { StyleSheet, Text, View } from "react-native";

import { theme } from "@/utils/theme";

interface CyberCardProps extends PropsWithChildren {
  title?: string;
  subtitle?: string;
  rightSlot?: ReactNode;
}

export function CyberCard({ title, subtitle, rightSlot, children }: CyberCardProps) {
  return (
    <View style={styles.card}>
      {(title || subtitle || rightSlot) && (
        <View style={styles.header}>
          <View style={styles.headerText}>
            {title ? <Text style={styles.title}>{title}</Text> : null}
            {subtitle ? <Text style={styles.subtitle}>{subtitle}</Text> : null}
          </View>
          {rightSlot}
        </View>
      )}
      {children}
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: theme.colors.card,
    borderRadius: theme.radius.lg,
    padding: theme.spacing.lg,
    borderWidth: 1,
    borderColor: theme.colors.border,
    gap: theme.spacing.md,
  },
  header: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    gap: theme.spacing.md,
  },
  headerText: {
    flex: 1,
    gap: 4,
  },
  title: {
    fontSize: 18,
    fontWeight: "700",
    color: theme.colors.textPrimary,
  },
  subtitle: {
    fontSize: 14,
    color: theme.colors.textSecondary,
    lineHeight: 20,
  },
});

