import { Stack, useRouter } from "expo-router";
import { StatusBar } from "expo-status-bar";
import { useEffect, useRef } from "react";
import * as Notifications from "expo-notifications";
import { SafeAreaProvider } from "react-native-safe-area-context";

import { AppDataProvider } from "@/hooks/useAppData";
import { useAppData } from "@/hooks/useAppData";
import { useGmailRealtimeSync } from "@/hooks/useGmailRealtimeSync";
import { useRealtimeProtection } from "@/hooks/useRealtimeProtection";
import { routes } from "@/navigation/routes";
import { localNotificationService } from "@/services/localNotificationService";
import { theme } from "@/utils/theme";

function RuntimeBootstrap() {
  const router = useRouter();
  const { pendingWarningThreat, setSelectedThreatId } = useAppData();
  const lastWarningThreatIdRef = useRef<string | null>(null);

  useRealtimeProtection();
  useGmailRealtimeSync();

  useEffect(() => {
    localNotificationService.ensurePermissions().catch(() => undefined);
    const subscription = Notifications.addNotificationResponseReceivedListener((response) => {
      const threatId = response.notification.request.content.data?.threatId;
      if (typeof threatId === "string") {
        setSelectedThreatId(threatId).catch(() => undefined);
        router.push(routes.result);
      }
    });

    return () => subscription.remove();
  }, [router, setSelectedThreatId]);

  useEffect(() => {
    if (!pendingWarningThreat) {
      lastWarningThreatIdRef.current = null;
      return;
    }

    if (lastWarningThreatIdRef.current !== pendingWarningThreat.id) {
      lastWarningThreatIdRef.current = pendingWarningThreat.id;
      router.push(routes.warning);
    }
  }, [pendingWarningThreat, router]);

  return null;
}

export default function RootLayout() {
  return (
    <SafeAreaProvider>
      <AppDataProvider>
        <RuntimeBootstrap />
        <StatusBar style="light" />
        <Stack
          screenOptions={{
            headerShown: false,
            contentStyle: { backgroundColor: theme.colors.background },
            animation: "slide_from_right",
          }}
        >
          <Stack.Screen name="warning" options={{ presentation: "fullScreenModal" }} />
        </Stack>
      </AppDataProvider>
    </SafeAreaProvider>
  );
}
