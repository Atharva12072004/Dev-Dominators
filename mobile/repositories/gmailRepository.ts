import { apiClient } from "@/api/client";
import { GmailConnection } from "@/utils/types";

export interface GmailConnectPayload {
  access_token: string;
  refresh_token?: string | null;
  email?: string | null;
  expires_at?: number | null;
}

export class GmailRepository {
  async connect(payload: GmailConnectPayload): Promise<GmailConnection> {
    const response = await apiClient.post("/gmail/connect", payload);
    return {
      connected: response.data.connected,
      email: response.data.email,
      watchConfigured: response.data.watch_configured,
      accessToken: null,
      lastHistoryId: response.data.last_history_id ?? null,
      lastSyncAt: null,
    };
  }

  async setupWatch(email: string) {
    const response = await apiClient.post("/gmail/watch/setup", { email });
    return response.data;
  }

  async sync(email: string, maxResults = 10) {
    const response = await apiClient.post("/gmail/sync", {
      email,
      max_results: maxResults,
    }, {
      timeout: 60000,
    });
    return response.data;
  }
}

export const gmailRepository = new GmailRepository();
