import { Image, ImageStyle, StyleSheet, Text, View, ViewStyle } from "react-native";

import { theme } from "@/utils/theme";

interface AppLogoProps {
  compact?: boolean;
}

export function AppLogo({ compact = false }: AppLogoProps) {
  const imageStyle: ImageStyle = compact ? styles.compactImage : styles.image;
  const frameStyle: ViewStyle = compact ? styles.compactFrame : styles.frame;
  return (
    <View style={styles.container}>
      <View style={frameStyle}>
        <Image
          source={require("../assets/images/logo.png")}
          style={imageStyle}
          resizeMode="contain"
        />
      </View>
      {!compact ? <Text style={styles.title}>CyberShield AI</Text> : null}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    alignItems: "center",
    gap: theme.spacing.md,
  },
  frame: {
    width: 116,
    height: 116,
    borderRadius: 32,
    borderWidth: 2,
    borderColor: theme.colors.accent,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: theme.colors.cardElevated,
    padding: 14,
    shadowColor: theme.colors.accent,
    shadowOpacity: 0.2,
    shadowRadius: 16,
    shadowOffset: { width: 0, height: 8 },
    elevation: 6,
  },
  compactFrame: {
    width: 78,
    height: 78,
    borderRadius: 22,
    borderWidth: 1,
    borderColor: theme.colors.border,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: theme.colors.card,
    padding: 10,
  },
  image: {
    width: "100%",
    height: "100%",
  },
  compactImage: {
    width: "100%",
    height: "100%",
  },
  title: {
    color: theme.colors.textPrimary,
    fontSize: 24,
    fontWeight: "800",
  },
});
