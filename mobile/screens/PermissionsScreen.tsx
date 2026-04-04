import { useRouter } from "expo-router";

import { PermissionCard } from "@/components/PermissionCard";
import { PrimaryButton } from "@/components/PrimaryButton";
import { ScreenContainer } from "@/components/ScreenContainer";
import { useAppData } from "@/hooks/useAppData";
import { routes } from "@/navigation/routes";

export function PermissionsScreen() {
  const router = useRouter();
  const { permissions, togglePermission } = useAppData();

  return (
    <ScreenContainer
      title="Permissions"
      subtitle="Enable the device capabilities CyberShield AI uses for notifications, SMS, Gmail sync, and monitored app activity."
      footer={<PrimaryButton label="Continue" onPress={() => router.push(routes.appSelection)} />}
    >
      <PermissionCard
        title="Notifications"
        description="Scan incoming notification text for suspicious language and phishing links."
        enabled={permissions.notifications}
        onToggle={() => togglePermission("notifications")}
      />
      <PermissionCard
        title="SMS Monitoring"
        description="Monitor incoming text messages and scan them for phishing, reward bait, and suspicious links."
        enabled={permissions.sms}
        onToggle={() => togglePermission("sms")}
      />
      <PermissionCard
        title="App Monitoring"
        description="Scan notification content from selected apps where risky links and phishing prompts may appear."
        enabled={permissions.appMonitoring}
        onToggle={() => togglePermission("appMonitoring")}
      />
      <PermissionCard
        title="Gmail Sync"
        description="Enable Gmail OAuth-based inbox protection and near-real-time sync."
        enabled={permissions.gmail}
        onToggle={() => togglePermission("gmail")}
      />
    </ScreenContainer>
  );
}
