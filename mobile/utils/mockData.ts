import { SelectableApp } from "@/utils/types";

export const mockApps: SelectableApp[] = [
  { id: "gmail", name: "Gmail", category: "Email", riskLevel: "high", packageName: "com.google.android.gm" },
  { id: "messages", name: "Messages", category: "SMS", riskLevel: "high" },
  { id: "whatsapp", name: "WhatsApp", category: "Messaging", riskLevel: "medium", packageName: "com.whatsapp" },
  { id: "telegram", name: "Telegram", category: "Messaging", riskLevel: "medium", packageName: "org.telegram.messenger" },
  { id: "chrome", name: "Chrome", category: "Browser", riskLevel: "high", packageName: "com.android.chrome" },
  { id: "instagram", name: "Instagram", category: "Social", riskLevel: "low", packageName: "com.instagram.android" },
];

export const allowedProtectedAppIds = mockApps.map((app) => app.id);
