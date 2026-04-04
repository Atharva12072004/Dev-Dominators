import { getSourceLabel } from "@/utils/sourceLabels";

const groupedSummaryPatterns = [
  /^\d+\s+messages?$/i,
  /^\d+\s+new messages?$/i,
  /^\d+\s+messages?\s+from\s+.+$/i,
  /^\d+\s+new messages?\s+from\s+.+$/i,
  /^\d+\s+chats?$/i,
  /^\d+\s+new notifications?$/i,
];

export function isGroupedNotificationText(text: string) {
  const normalized = text.trim();
  if (!normalized) {
    return false;
  }
  return groupedSummaryPatterns.some((pattern) => pattern.test(normalized));
}

export function buildGroupedNotificationTitle(sourceApp?: string | null, sourceType?: string | null) {
  const sourceLabel = getSourceLabel(sourceType, sourceApp);
  return `Group Notification from ${sourceLabel}`;
}

export function buildGroupedNotificationSubtitle() {
  return "Exact message content not available. Partial scan applied.";
}
