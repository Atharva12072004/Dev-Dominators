import { StyleSheet, Text, View } from "react-native";

import { theme } from "@/utils/theme";

interface StatusChipProps {
  label: string;
  tone?: "neutral" | "success" | "warning" | "danger";
}

export function StatusChip({ label, tone = "neutral" }: StatusChipProps) {
  return (
    <View style={[styles.chip, chipStyles[tone]]}>
      <Text style={styles.text}>{label}</Text>
    </View>
  );
}

const chipStyles = StyleSheet.create({
  neutral: { backgroundColor: theme.colors.accentSoft },
  success: { backgroundColor: "#0E3A2A" },
  warning: { backgroundColor: "#473211" },
  danger: { backgroundColor: "#4B1820" },
});

const styles = StyleSheet.create({
  chip: {
    alignSelf: "flex-start",
    paddingHorizontal: 12,
    paddingVertical: 7,
    borderRadius: 999,
  },
  text: {
    color: theme.colors.textPrimary,
    fontSize: 12,
    fontWeight: "700",
    textTransform: "uppercase",
  },
});

