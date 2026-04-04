import { StyleSheet, Text, View } from "react-native";

import { CyberCard } from "@/components/CyberCard";
import { PrimaryButton } from "@/components/PrimaryButton";
import { StatusChip } from "@/components/StatusChip";
import { theme } from "@/utils/theme";

interface PermissionCardProps {
  title: string;
  description: string;
  enabled: boolean;
  onToggle: () => void;
}

export function PermissionCard({
  title,
  description,
  enabled,
  onToggle,
}: PermissionCardProps) {
  return (
    <CyberCard
      title={title}
      subtitle={description}
      rightSlot={<StatusChip label={enabled ? "Enabled" : "Disabled"} tone={enabled ? "success" : "warning"} />}
    >
      <View style={styles.footer}>
        <Text style={styles.helper}>
          {enabled
            ? "Monitoring is active for this permission."
            : "Tap below to simulate enabling this permission."}
        </Text>
        <PrimaryButton
          label={enabled ? "Disable" : "Enable"}
          onPress={onToggle}
          variant={enabled ? "secondary" : "primary"}
        />
      </View>
    </CyberCard>
  );
}

const styles = StyleSheet.create({
  footer: {
    gap: theme.spacing.md,
  },
  helper: {
    color: theme.colors.textSecondary,
    fontSize: 14,
    lineHeight: 20,
  },
});

