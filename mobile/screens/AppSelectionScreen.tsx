import { StyleSheet, View } from "react-native";
import { useRouter } from "expo-router";

import { AppSelectRow } from "@/components/AppSelectRow";
import { CyberCard } from "@/components/CyberCard";
import { PrimaryButton } from "@/components/PrimaryButton";
import { ScreenContainer } from "@/components/ScreenContainer";
import { useAppData } from "@/hooks/useAppData";
import { routes } from "@/navigation/routes";
import { mockApps } from "@/utils/mockData";
import { theme } from "@/utils/theme";

export function AppSelectionScreen() {
  const router = useRouter();
  const { selectedApps, toggleAppSelection, saveSelectedApps } = useAppData();

  async function handleSave() {
    await saveSelectedApps();
    router.replace(routes.home);
  }

  return (
    <ScreenContainer
      title="Select Protected Apps"
      subtitle="Choose the sources CyberShield AI should prioritize for real-time protection."
      footer={
        <PrimaryButton
          label="Save Selected Apps"
          onPress={handleSave}
          disabled={selectedApps.length === 0}
        />
      }
    >
      <CyberCard title="Protected Apps" subtitle={`${selectedApps.length} app(s) selected`}>
        <View style={styles.list}>
          {mockApps.map((app) => (
            <AppSelectRow
              key={app.id}
              app={app}
              selected={selectedApps.includes(app.id)}
              onPress={() => toggleAppSelection(app.id)}
            />
          ))}
        </View>
      </CyberCard>
    </ScreenContainer>
  );
}

const styles = StyleSheet.create({
  list: {
    gap: theme.spacing.sm,
  },
});
