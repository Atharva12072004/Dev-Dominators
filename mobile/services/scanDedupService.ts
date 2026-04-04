import { stableHash } from "@/utils/hash";

const CACHE_WINDOW_MS = 4 * 60 * 1000;

class ScanDedupService {
  private seen = new Map<string, number>();
  private processedGmailMessageIds = new Map<string, number>();
  private processedNotificationKeys = new Map<string, number>();

  private canonicalSourceType(sourceType: string, sourceApp: string | null | undefined) {
    const normalizedType = sourceType.toLowerCase();
    const normalizedApp = (sourceApp || "").trim().toLowerCase();
    if (
      normalizedType === "sms" ||
      normalizedApp === "messages" ||
      normalizedApp === "com.google.android.apps.messaging" ||
      normalizedApp === "com.android.mms" ||
      normalizedApp === "com.samsung.android.messaging" ||
      normalizedApp === "com.miui.mms" ||
      normalizedApp === "com.microsoft.android.smsorganizer"
    ) {
      return "messages";
    }
    return normalizedType;
  }

  private prune(map: Map<string, number>, now: number) {
    for (const [entryKey, timestamp] of map.entries()) {
      if (now - timestamp > CACHE_WINDOW_MS) {
        map.delete(entryKey);
      }
    }
  }

  buildKey(
    sourceType: string,
    sourceApp: string | null | undefined,
    content: string,
    url?: string | null,
    externalId?: string | null
  ): string {
    const canonicalSourceType = this.canonicalSourceType(sourceType, sourceApp);
    const normalized = `${content.trim().toLowerCase()}|${(url || "").trim().toLowerCase()}`;

    if (canonicalSourceType === "messages") {
      return `${canonicalSourceType}:${stableHash(normalized)}`;
    }

    if (externalId) {
      return `${canonicalSourceType}:${sourceApp || "unknown"}:${externalId}`;
    }
    return `${canonicalSourceType}:${sourceApp || "unknown"}:${stableHash(normalized)}`;
  }

  isDuplicate(
    sourceType: string,
    sourceApp: string | null | undefined,
    content: string,
    url?: string | null,
    externalId?: string | null
  ): boolean {
    const now = Date.now();
    const key = this.buildKey(sourceType, sourceApp, content, url, externalId);

    this.prune(this.seen, now);

    const previous = this.seen.get(key);
    if (previous && now - previous < CACHE_WINDOW_MS) {
      return true;
    }

    this.seen.set(key, now);
    return false;
  }

  markProcessed(
    sourceType: string,
    sourceApp: string | null | undefined,
    content: string,
    url?: string | null,
    externalId?: string | null
  ) {
    this.seen.set(this.buildKey(sourceType, sourceApp, content, url, externalId), Date.now());
  }

  hasProcessedGmailMessageId(messageId: string) {
    const now = Date.now();
    this.prune(this.processedGmailMessageIds, now);
    return this.processedGmailMessageIds.has(messageId);
  }

  markProcessedGmailMessageId(messageId: string) {
    this.processedGmailMessageIds.set(messageId, Date.now());
  }

  hasProcessedNotificationKey(key: string) {
    const now = Date.now();
    this.prune(this.processedNotificationKeys, now);
    return this.processedNotificationKeys.has(key);
  }

  markProcessedNotificationKey(key: string) {
    this.processedNotificationKeys.set(key, Date.now());
  }
}

export const scanDedupService = new ScanDedupService();
