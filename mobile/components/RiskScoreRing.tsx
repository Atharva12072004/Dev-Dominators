import { StyleSheet, Text, View } from "react-native";

import { theme } from "@/utils/theme";

interface RiskScoreRingProps {
  score: number;
  size?: number;
  label?: string;
}

function getTone(score: number) {
  if (score >= 70) {
    return theme.colors.danger;
  }
  if (score >= 35) {
    return theme.colors.warning;
  }
  return theme.colors.success;
}

export function RiskScoreRing({ score, size = 120, label }: RiskScoreRingProps) {
  const tone = getTone(score);
  const innerSize = size - 18;
  const scoreFontSize = Math.max(16, Math.round(size * 0.22));
  const captionFontSize = Math.max(9, Math.round(size * 0.1));

  return (
    <View style={styles.wrapper}>
      <View
        style={[
          styles.outer,
          {
            width: size,
            height: size,
            borderRadius: size / 2,
            borderColor: tone,
            shadowColor: tone,
          },
        ]}
      >
        <View
          style={[
            styles.inner,
            {
              width: innerSize,
              height: innerSize,
              borderRadius: innerSize / 2,
            },
          ]}
        >
          <Text style={[styles.score, { fontSize: scoreFontSize, lineHeight: scoreFontSize + 2 }]}>
            {score}%
          </Text>
          <Text
            style={[styles.caption, { fontSize: captionFontSize, lineHeight: captionFontSize + 2 }]}
          >
            {label || "Risk"}
          </Text>
        </View>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  wrapper: {
    alignItems: "center",
    justifyContent: "center",
  },
  outer: {
    borderWidth: 8,
    alignItems: "center",
    justifyContent: "center",
    shadowOpacity: 0.22,
    shadowRadius: 18,
    shadowOffset: { width: 0, height: 8 },
    elevation: 8,
  },
  inner: {
    backgroundColor: theme.colors.backgroundSecondary,
    alignItems: "center",
    justifyContent: "center",
    gap: 1,
    paddingHorizontal: 4,
  },
  score: {
    color: theme.colors.textPrimary,
    fontWeight: "900",
    textAlign: "center",
  },
  caption: {
    color: theme.colors.textSecondary,
    fontWeight: "700",
    textTransform: "uppercase",
    textAlign: "center",
  },
});
