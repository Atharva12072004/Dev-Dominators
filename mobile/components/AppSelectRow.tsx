import { Pressable, StyleSheet, Text, View } from "react-native";

import { StatusChip } from "@/components/StatusChip";
import { theme } from "@/utils/theme";
import { SelectableApp } from "@/utils/types";

interface AppSelectRowProps {
  app: SelectableApp;
  selected: boolean;
  onPress: () => void;
}

export function AppSelectRow({ app, selected, onPress }: AppSelectRowProps) {
  const tone =
    app.riskLevel === "high" ? "danger" : app.riskLevel === "medium" ? "warning" : "success";

  return (
    <Pressable style={[styles.row, selected && styles.rowSelected]} onPress={onPress}>
      <View style={styles.checkbox}>{selected ? <View style={styles.checkboxInner} /> : null}</View>
      <View style={styles.content}>
        <Text style={styles.name}>{app.name}</Text>
        <Text style={styles.meta}>{app.category}</Text>
      </View>
      <StatusChip label={app.riskLevel} tone={tone} />
    </Pressable>
  );
}

const styles = StyleSheet.create({
  row: {
    flexDirection: "row",
    alignItems: "center",
    gap: theme.spacing.md,
    backgroundColor: theme.colors.card,
    borderRadius: theme.radius.md,
    borderWidth: 1,
    borderColor: theme.colors.border,
    padding: theme.spacing.md,
  },
  rowSelected: {
    borderColor: theme.colors.accent,
    backgroundColor: theme.colors.cardElevated,
  },
  checkbox: {
    width: 24,
    height: 24,
    borderRadius: 8,
    borderWidth: 2,
    borderColor: theme.colors.accent,
    alignItems: "center",
    justifyContent: "center",
  },
  checkboxInner: {
    width: 12,
    height: 12,
    borderRadius: 4,
    backgroundColor: theme.colors.accent,
  },
  content: {
    flex: 1,
    gap: 2,
  },
  name: {
    color: theme.colors.textPrimary,
    fontSize: 16,
    fontWeight: "700",
  },
  meta: {
    color: theme.colors.textSecondary,
    fontSize: 13,
  },
});

