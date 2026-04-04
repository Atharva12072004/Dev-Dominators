export const appConfig = {
  appName: "CyberShield AI",
  apiBaseUrl:
    process.env.EXPO_PUBLIC_API_BASE_URL?.trim() || "http://192.168.1.10:8000",
  googleWebClientId: process.env.EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID?.trim() || "",
  googleAndroidClientId: process.env.EXPO_PUBLIC_GOOGLE_ANDROID_CLIENT_ID?.trim() || "",
};
