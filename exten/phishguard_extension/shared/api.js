/**
 * PhishGuard AI — Backend API helpers
 * All fetch calls to the real FastAPI backend go through here.
 */

const API = (() => {
  /* ------------------------------------------------------------------ */
  /*  Internal helpers                                                   */
  /* ------------------------------------------------------------------ */

  const LOCAL_DEV_API_KEY = 'change-me';

  function normalizeBackendUrl(value) {
    const raw = typeof value === 'string' ? value.trim() : '';
    const baseCandidate = raw || 'http://127.0.0.1:8000';
    const fallback = /^[a-z][a-z0-9+.-]*:\/\//i.test(baseCandidate) ? baseCandidate : `http://${baseCandidate}`;
    try {
      const parsed = new URL(fallback);
      if (parsed.hostname === '0.0.0.0') {
        parsed.hostname = '127.0.0.1';
      }
      return parsed.toString().replace(/\/+$/, '');
    } catch (_) {
      return fallback.replace(/\/+$/, '');
    }
  }

  function normalizeApiKey(value) {
    const raw = typeof value === 'string' ? value.trim() : '';
    return raw || LOCAL_DEV_API_KEY;
  }

  function formatApiError(status, text) {
    if (status === 401) {
      return 'Authentication failed. Open CYBERSHIELD options and set the API key to match the backend API_SECRET_KEY.';
    }
    return `HTTP ${status}: ${text || 'Request failed'}`;
  }

  async function _getConfig() {
    const data = await chrome.storage.sync.get({
      backendUrl: 'http://127.0.0.1:8000',
      apiKey: LOCAL_DEV_API_KEY
    });
    return {
      baseUrl: normalizeBackendUrl(data.backendUrl),
      apiKey: normalizeApiKey(data.apiKey)
    };
  }

  function _headers(apiKey) {
    return {
      'Content-Type': 'application/json',
      'X-API-Key': normalizeApiKey(apiKey)
    };
  }

  function buildCandidateBaseUrls(baseUrl) {
    const normalized = normalizeBackendUrl(baseUrl);
    const candidates = [normalized];

    try {
      const parsed = new URL(normalized);
      const originalHost = parsed.hostname;
      const loopbackHosts = ['127.0.0.1', 'localhost'];
      loopbackHosts.forEach((host) => {
        if (host === originalHost) return;
        const next = new URL(parsed.toString());
        next.hostname = host;
        candidates.push(next.toString().replace(/\/+$/, ''));
      });
    } catch (_) {}

    return [...new Set(candidates)];
  }

  async function performFetch(url, options, apiKey, auth, timeout) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const resp = await fetch(url, {
        ...options,
        headers: auth ? _headers(apiKey) : { 'Content-Type': 'application/json' },
        signal: controller.signal
      });
      if (!resp.ok) {
        const text = await resp.text().catch(() => '');
        throw new Error(formatApiError(resp.status, text || resp.statusText));
      }
      return await resp.json();
    } finally {
      clearTimeout(timer);
    }
  }

  async function _fetch(path, options = {}, { timeout = 15000, auth = true } = {}) {
    const { baseUrl, apiKey } = await _getConfig();
    const candidates = buildCandidateBaseUrls(baseUrl);
    let lastError = null;

    for (const candidate of candidates) {
      try {
        return await performFetch(`${candidate}${path}`, options, apiKey, auth, timeout);
      } catch (err) {
        if (err?.name === 'AbortError') throw new Error('Request timed out');
        lastError = err;
        if (!(err instanceof TypeError)) {
          throw err;
        }
      }
    }

    throw lastError || new Error('Request failed');
  }

  /* ------------------------------------------------------------------ */
  /*  Public API                                                         */
  /* ------------------------------------------------------------------ */

  /** GET /health — unprotected */
  function health() {
    return _fetch('/health', { method: 'GET' }, { auth: false, timeout: 8000 });
  }

  /** POST /api/v1/scan/url */
  function scanUrl(url, source = 'browser', analysis_mode = 'standard') {
    return _fetch('/api/v1/scan/url', {
      method: 'POST',
      body: JSON.stringify({ url, source, analysis_mode })
    });
  }

  /** POST /api/v1/scan/email */
  function scanEmail({ content, links = [], attachments = [], subject = null, source = 'email' }) {
    return _fetch('/api/v1/scan/email', {
      method: 'POST',
      body: JSON.stringify({ content, links, attachments, subject, source })
    }, { timeout: 60000 });
  }

  /** POST /api/v1/scan/chat */
  function scanChat({ content, links = [], attachments = [], sender = null, source = 'whatsapp' }) {
    return _fetch('/api/v1/scan/chat', {
      method: 'POST',
      body: JSON.stringify({ content, links, attachments, sender, source })
    }, { timeout: 60000 });
  }

  /** POST /api/v1/scan/batch */
  function scanBatch(urls, source = 'manual') {
    return _fetch('/api/v1/scan/batch', {
      method: 'POST',
      body: JSON.stringify({ urls, source })
    });
  }

  /** POST /api/v1/scan/attachment */
  function scanAttachment({ attachment, source = 'manual', context_label = null }) {
    return _fetch('/api/v1/scan/attachment', {
      method: 'POST',
      body: JSON.stringify({ attachment, source, context_label })
    }, { timeout: 60000 });
  }

  /** GET /api/v1/history */
  function getHistory({ page = 1, limit = 20, risk_level, source, date_from, date_to, search } = {}) {
    const params = new URLSearchParams();
    params.set('page', page);
    params.set('limit', limit);
    if (risk_level) params.set('risk_level', risk_level);
    if (source) params.set('source', source);
    if (date_from) params.set('date_from', date_from);
    if (date_to) params.set('date_to', date_to);
    if (search) params.set('search', search);
    return _fetch(`/api/v1/history?${params.toString()}`);
  }

  /** GET /api/v1/history/{id} */
  function getHistoryDetail(id) {
    return _fetch(`/api/v1/history/${id}`);
  }

  /** DELETE /api/v1/history/{id} */
  function deleteHistoryItem(id) {
    return _fetch(`/api/v1/history/${id}`, { method: 'DELETE' });
  }

  /** DELETE /api/v1/history/all */
  function clearHistory() {
    return _fetch('/api/v1/history/all', { method: 'DELETE' });
  }

  /** POST /api/v1/history/{id}/feedback */
  function submitFeedback(id, actual_verdict, notes = null) {
    return _fetch(`/api/v1/history/${id}/feedback`, {
      method: 'POST',
      body: JSON.stringify({ actual_verdict, notes })
    });
  }

  /** GET /api/v1/stats */
  function getStats() {
    return _fetch('/api/v1/stats');
  }

  /** POST /api/v1/whitelist */
  function createWhitelistEntry(domain) {
    return _fetch('/api/v1/whitelist', {
      method: 'POST',
      body: JSON.stringify({ domain })
    });
  }

  /** GET /api/v1/whitelist */
  function getWhitelist() {
    return _fetch('/api/v1/whitelist');
  }

  /** DELETE /api/v1/whitelist/{domain} */
  function deleteWhitelistEntry(domain) {
    return _fetch(`/api/v1/whitelist/${encodeURIComponent(domain)}`, { method: 'DELETE' });
  }

  return {
    health,
    scanUrl,
    scanEmail,
    scanChat,
    scanAttachment,
    scanBatch,
    getHistory,
    getHistoryDetail,
    deleteHistoryItem,
    clearHistory,
    submitFeedback,
    getStats,
    createWhitelistEntry,
    getWhitelist,
    deleteWhitelistEntry
  };
})();

if (typeof globalThis !== 'undefined') globalThis.PhishGuardAPI = API;
