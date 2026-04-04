import { useState } from "react";
import { Alert, Pressable, StyleSheet, Text, TextInput, View } from "react-native";

import { CyberCard } from "@/components/CyberCard";
import { PrimaryButton } from "@/components/PrimaryButton";
import { pickAttachmentSelection } from "@/utils/fileAttachmentPicker";
import { theme } from "@/utils/theme";
import { AttachmentFileUpload } from "@/utils/types";

interface AttachmentInputCardProps {
  value: string;
  onChangeText: (value: string) => void;
  realFiles: AttachmentFileUpload[];
  onRealFilesChange: (files: AttachmentFileUpload[]) => void;
}

export function AttachmentInputCard({
  value,
  onChangeText,
  realFiles,
  onRealFilesChange,
}: AttachmentInputCardProps) {
  const [notes, setNotes] = useState("");
  const [isPickingFiles, setIsPickingFiles] = useState(false);
  const attachmentLines = value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  function handleRemoveAttachment(indexToRemove: number) {
    const lineToRemove = attachmentLines[indexToRemove];
    const fileNameToRemove = lineToRemove.split("||")[0]?.trim().toLowerCase();
    onChangeText(attachmentLines.filter((_, index) => index !== indexToRemove).join("\n"));
    if (fileNameToRemove) {
      onRealFilesChange(realFiles.filter((file) => file.name.toLowerCase() !== fileNameToRemove));
    }
  }

  async function handlePickFiles() {
    try {
      setIsPickingFiles(true);
      const picked = await pickAttachmentSelection();
      if (picked.files.length === 0) {
        return;
      }

      const trimmedNotes = notes.trim();
      const nextLines = [
        ...attachmentLines,
        ...picked.files.map((file) =>
          trimmedNotes ? `${file.name} || ${trimmedNotes}` : file.name
        ),
      ];
      const existingFiles = new Map(realFiles.map((file) => [file.id, file]));
      picked.files.forEach((file) => existingFiles.set(file.id, file));
      onChangeText([...new Set(nextLines)].join("\n"));
      onRealFilesChange(Array.from(existingFiles.values()));
      setNotes("");
    } catch {
      Alert.alert(
        "File picker unavailable",
        "CyberShield could not open the device file picker right now. Please try again."
      );
    } finally {
      setIsPickingFiles(false);
    }
  }

  return (
    <CyberCard
      title="Attachment Analysis"
      subtitle="Add real files and optional metadata for static analysis and safe sandbox simulation."
    >
      <View style={styles.formBlock}>
        <TextInput
          value={notes}
          onChangeText={setNotes}
          placeholder="Optional metadata, for example embedded login link, urgent bank verification"
          placeholderTextColor={theme.colors.textMuted}
          multiline
          style={[styles.input, styles.notesInput]}
        />
        <PrimaryButton
          label={isPickingFiles ? "Opening Picker..." : "Add Attachment"}
          onPress={handlePickFiles}
          disabled={isPickingFiles}
          variant="secondary"
        />
      </View>

      {attachmentLines.length > 0 ? (
        <View style={styles.attachmentList}>
          {attachmentLines.map((line, index) => (
            <View key={`${line}-${index}`} style={styles.attachmentRow}>
              <Text style={styles.attachmentText}>{line}</Text>
              <Pressable onPress={() => handleRemoveAttachment(index)} style={styles.removeChip}>
                <Text style={styles.removeChipText}>Remove</Text>
              </Pressable>
            </View>
          ))}
        </View>
      ) : null}

      {realFiles.length > 0 ? (
        <View style={styles.realFilesBlock}>
          <Text style={styles.sectionLabel}>Attached real files</Text>
          {realFiles.map((file) => (
            <View key={file.id} style={styles.realFileRow}>
              <Text style={styles.attachmentText}>
                {file.name}
                {typeof file.size === "number" ? ` | ${Math.max(1, Math.round(file.size / 1024))} KB` : ""}
              </Text>
            </View>
          ))}
        </View>
      ) : null}

      <Text style={styles.helpText}>
        Add a real file, then optionally include metadata like `opens browser`,
        `embedded login link`, or `password protected archive` to enrich the analysis.
      </Text>
    </CyberCard>
  );
}

const styles = StyleSheet.create({
  formBlock: {
    gap: theme.spacing.sm,
  },
  input: {
    minHeight: 110,
    textAlignVertical: "top",
    backgroundColor: theme.colors.backgroundSecondary,
    borderRadius: theme.radius.md,
    borderWidth: 1,
    borderColor: theme.colors.border,
    paddingHorizontal: theme.spacing.md,
    paddingVertical: theme.spacing.md,
    color: theme.colors.textPrimary,
    fontSize: 14,
    lineHeight: 22,
  },
  notesInput: {
    minHeight: 84,
  },
  attachmentList: {
    gap: theme.spacing.sm,
  },
  realFilesBlock: {
    gap: theme.spacing.sm,
  },
  sectionLabel: {
    color: theme.colors.textSecondary,
    fontWeight: "700",
  },
  attachmentRow: {
    backgroundColor: theme.colors.backgroundSecondary,
    borderRadius: theme.radius.md,
    borderWidth: 1,
    borderColor: theme.colors.border,
    padding: theme.spacing.md,
    gap: theme.spacing.sm,
  },
  realFileRow: {
    backgroundColor: theme.colors.backgroundSecondary,
    borderRadius: theme.radius.md,
    borderWidth: 1,
    borderColor: theme.colors.border,
    padding: theme.spacing.md,
  },
  attachmentText: {
    color: theme.colors.textPrimary,
    lineHeight: 20,
  },
  removeChip: {
    alignSelf: "flex-start",
    paddingHorizontal: theme.spacing.sm,
    paddingVertical: 6,
    borderRadius: 999,
    backgroundColor: "#3A1630",
  },
  removeChipText: {
    color: "#FF9BC2",
    fontWeight: "700",
    fontSize: 12,
  },
  helpText: {
    color: theme.colors.textSecondary,
    lineHeight: 20,
  },
});
