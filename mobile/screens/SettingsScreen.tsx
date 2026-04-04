import { ScreenContainer } from "@/components/ScreenContainer";
import { AppLogo } from "@/components/AppLogo";
import { CyberCard } from "@/components/CyberCard";
import { platformCapabilities } from "@/services/platformCapabilityService";
import { cyberShieldAndroidModule } from "@/native/androidBridge";
import { PrimaryButton } from "@/components/PrimaryButton";
import { useAppData } from "@/hooks/useAppData";
import { View } from "react-native";

export function SettingsScreen() {
  const { gmailConnection } = useAppData();

  return (
    <ScreenContainer
      title="Settings"
      subtitle="Capability-aware settings will separate Android real-time protections from iOS fallback-only features."
      headerSlot={<AppLogo compact />}
      showBottomNav
    >
      <CyberCard
        title="Platform Profile"
        subtitle={`SMS real-time: ${platformCapabilities.smsRealtime ? "available" : "unavailable"} - Notification monitoring: ${platformCapabilities.notificationMonitoring ? "available" : "unavailable"}`}
      />
      <CyberCard
        title="Gmail Account"
        subtitle={gmailConnection.connected ? `Connected as ${gmailConnection.email}` : "No Gmail account connected"}
      />
      <CyberCard
        title="Native Build Requirement"
        subtitle="Advanced protections require an Expo development build and custom native Android modules."
      />
      <View style={{ gap: 12 }}>
        <PrimaryButton
          label="Open Notification Access"
          onPress={() => cyberShieldAndroidModule?.openNotificationAccessSettings?.()}
          variant="secondary"
        />
        <PrimaryButton
          label="Open Accessibility Settings"
          onPress={() => cyberShieldAndroidModule?.openAccessibilitySettings?.()}
          variant="secondary"
        />
      </View>
    </ScreenContainer>
  );
}
