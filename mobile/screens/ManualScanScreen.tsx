import { useState } from "react";
import { StyleSheet, Text, TextInput, View } from "react-native";
import { useRouter } from "expo-router";

import { AttachmentInputCard } from "@/components/AttachmentInputCard";
import { CyberCard } from "@/components/CyberCard";
import { PrimaryButton } from "@/components/PrimaryButton";
import { ScreenContainer } from "@/components/ScreenContainer";
import { useScanner } from "@/hooks/useScanner";
import { routes } from "@/navigation/routes";
import { parseAttachmentInput } from "@/utils/attachmentInputParser";
import { theme } from "@/utils/theme";
import { AttachmentFileUpload } from "@/utils/types";

export function ManualScanScreen() {
  const router = useRouter();
  const { isLoading, error, runUnifiedScan } = useScanner();
  const [text, setText] = useState("");
  const [url, setUrl] = useState("");
  const [attachments, setAttachments] = useState("");
  const [realFiles, setRealFiles] = useState<AttachmentFileUpload[]>([]);

  async function handleScan() {
    const parsedAttachments = parseAttachmentInput(attachments);
    const result = await runUnifiedScan({
      text: text.trim() || undefined,
      url: url.trim() || undefined,
      source_type: "unified",
      use_ai: true,
      metadata:
        parsedAttachments.length > 0 || realFiles.length > 0
          ? {
              attachments: parsedAttachments,
              attachment_files: realFiles,
            }
          : undefined,
    });

    if (result) {
      router.replace(routes.home);
    }
  }

  return (
    <ScreenContainer
      title="Manual Scan"
      subtitle="Paste suspicious text, a URL, or both. The app will try the backend first, then fall back to local rules if needed."
      showBottomNav
      footer={
        <PrimaryButton
          label={isLoading ? "Scanning..." : "Scan Content"}
          onPress={handleScan}
          disabled={isLoading || (!text.trim() && !url.trim() && !attachments.trim() && realFiles.length === 0)}
        />
      }
    >
      <CyberCard title="Text Content" subtitle="SMS, email text, app notification, or chat message">
        <TextInput
          multiline
          value={text}
          onChangeText={setText}
          placeholder="Paste message content here"
          placeholderTextColor={theme.colors.textMuted}
          style={[styles.input, styles.textArea]}
        />
      </CyberCard>
      <CyberCard title="URL" subtitle="Optional link to include in the same scan">
        <TextInput
          value={url}
          onChangeText={setUrl}
          placeholder="https://example.com"
          placeholderTextColor={theme.colors.textMuted}
          autoCapitalize="none"
          keyboardType="url"
          style={styles.input}
        />
      </CyberCard>
      <AttachmentInputCard
        value={attachments}
        onChangeText={setAttachments}
        realFiles={realFiles}
        onRealFilesChange={setRealFiles}
      />
      {error ? (
        <View style={styles.banner}>
          <Text style={styles.bannerTitle}>Local protection active</Text>
          <Text style={styles.bannerText}>{error}</Text>
        </View>
      ) : null}
    </ScreenContainer>
  );
}

const styles = StyleSheet.create({
  input: {
    backgroundColor: theme.colors.backgroundSecondary,
    borderRadius: theme.radius.md,
    borderWidth: 1,
    borderColor: theme.colors.border,
    paddingHorizontal: theme.spacing.md,
    paddingVertical: theme.spacing.md,
    color: theme.colors.textPrimary,
    fontSize: 15,
  },
  textArea: {
    minHeight: 140,
    textAlignVertical: "top",
  },
  banner: {
    backgroundColor: "#3B2412",
    borderRadius: theme.radius.md,
    padding: theme.spacing.md,
    gap: 4,
  },
  bannerTitle: {
    color: theme.colors.warning,
    fontWeight: "700",
  },
  bannerText: {
    color: theme.colors.textPrimary,
    lineHeight: 20,
  },
});
