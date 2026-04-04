/**
 * PhishGuard AI — chrome.storage helpers
 */

const Storage = (() => {
  const DEFAULT_API_KEY = 'change-me';

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
    return raw || DEFAULT_API_KEY;
  }

  function normalizePartialSettings(partial = {}) {
    const normalized = { ...partial };
    if ('backendUrl' in normalized) {
      normalized.backendUrl = normalizeBackendUrl(normalized.backendUrl);
    }
    if ('apiKey' in normalized) {
      normalized.apiKey = normalizeApiKey(normalized.apiKey);
    }
    return normalized;
  }

  /* ------------------------------------------------------------------ */
  /*  Default settings                                                   */
  /* ------------------------------------------------------------------ */
  const DEFAULTS = {
    backendUrl: 'http://127.0.0.1:8000',
    apiKey: DEFAULT_API_KEY,
    autoMonitoring: true,
    linkMonitoring: true,
    emailMonitoring: true,
    whatsappMonitoring: true,
    notificationsEnabled: true,
    warningThreshold: 50,        // risk_score >= this triggers warning behaviour
    directNavWarning: 'warn',    // 'warn' | 'block' | 'allow'
    proceedOverride: true,       // allow user to click "proceed anyway"
    theme: 'dark',               // 'dark' | 'light' | 'system'
    cacheRetentionDays: 7
  };

  /* ------------------------------------------------------------------ */
  /*  Settings                                                           */
  /* ------------------------------------------------------------------ */

  async function getSettings() {
    const settings = await chrome.storage.sync.get(DEFAULTS);
    return {
      ...settings,
      backendUrl: normalizeBackendUrl(settings.backendUrl),
      apiKey: normalizeApiKey(settings.apiKey)
    };
  }

  function saveSettings(partial) {
    return chrome.storage.sync.set(normalizePartialSettings(partial));
  }

  /* ------------------------------------------------------------------ */
  /*  Recent activity feed  (local, max 50 items)                        */
  /* ------------------------------------------------------------------ */

  async function getRecentActivity() {
    const { recentActivity = [] } = await chrome.storage.local.get('recentActivity');
    return recentActivity;
  }

  async function addRecentActivity(item) {
    const items = await getRecentActivity();
    items.unshift({
      ...item,
      _ts: Date.now()
    });
    if (items.length > 50) items.length = 50;
    return chrome.storage.local.set({ recentActivity: items });
  }

  async function clearRecentActivity() {
    return chrome.storage.local.set({ recentActivity: [] });
  }

  /* ------------------------------------------------------------------ */
  /*  Detailed scan cache  (local, keyed by URL or content hash)         */
  /* ------------------------------------------------------------------ */

  async function getScanCache() {
    const { scanCache = {} } = await chrome.storage.local.get('scanCache');
    return scanCache;
  }

  async function cacheScanResult(key, result) {
    const cache = await getScanCache();
    cache[key] = { ...result, _cachedAt: Date.now() };
    // enforce max 200 entries
    const keys = Object.keys(cache);
    if (keys.length > 200) {
      const sorted = keys.sort((a, b) => (cache[a]._cachedAt || 0) - (cache[b]._cachedAt || 0));
      for (let i = 0; i < keys.length - 200; i++) delete cache[sorted[i]];
    }
    return chrome.storage.local.set({ scanCache: cache });
  }

  async function getCachedScan(key) {
    const cache = await getScanCache();
    return cache[key] || null;
  }

  async function clearScanCache() {
    return chrome.storage.local.set({ scanCache: {} });
  }

  /* ------------------------------------------------------------------ */
  /*  Proceed-once overrides   { url: timestamp }                        */
  /* ------------------------------------------------------------------ */

  async function getProceedOverrides() {
    const { proceedOverrides = {} } = await chrome.storage.local.get('proceedOverrides');
    return proceedOverrides;
  }

  async function setProceedOverride(url, durationMs = 300000) {
    const overrides = await getProceedOverrides();
    overrides[url] = Date.now() + durationMs;
    return chrome.storage.local.set({ proceedOverrides: overrides });
  }

  async function hasProceedOverride(url) {
    const overrides = await getProceedOverrides();
    if (overrides[url] && overrides[url] > Date.now()) return true;
    return false;
  }

  /* ------------------------------------------------------------------ */
  /*  Notification cooldowns   { key: timestamp }                        */
  /* ------------------------------------------------------------------ */

  async function getNotifCooldowns() {
    const { notifCooldowns = {} } = await chrome.storage.local.get('notifCooldowns');
    return notifCooldowns;
  }

  async function setNotifCooldown(key, durationMs = 60000) {
    const cds = await getNotifCooldowns();
    cds[key] = Date.now() + durationMs;
    return chrome.storage.local.set({ notifCooldowns: cds });
  }

  async function isOnCooldown(key) {
    const cds = await getNotifCooldowns();
    return cds[key] && cds[key] > Date.now();
  }

  /* ------------------------------------------------------------------ */
  /*  Current-tab state   { tabId, url, result }                         */
  /* ------------------------------------------------------------------ */

  function setCurrentTabState(state) {
    return chrome.storage.session.set({ currentTabState: state });
  }

  async function getCurrentTabState() {
    const { currentTabState = null } = await chrome.storage.session.get('currentTabState');
    return currentTabState;
  }

  /* ------------------------------------------------------------------ */
  /*  Local retention cleanup                                            */
  /* ------------------------------------------------------------------ */

  async function cleanExpiredData() {
    const settings = await getSettings();
    const maxAge = (settings.cacheRetentionDays || 7) * 86400000;
    const now = Date.now();

    // Clean scan cache
    const cache = await getScanCache();
    let changed = false;
    for (const k of Object.keys(cache)) {
      if (now - (cache[k]._cachedAt || 0) > maxAge) {
        delete cache[k];
        changed = true;
      }
    }
    if (changed) await chrome.storage.local.set({ scanCache: cache });

    // Clean proceed overrides
    const overrides = await getProceedOverrides();
    let oChanged = false;
    for (const k of Object.keys(overrides)) {
      if (overrides[k] < now) {
        delete overrides[k];
        oChanged = true;
      }
    }
    if (oChanged) await chrome.storage.local.set({ proceedOverrides: overrides });

    // Clean notification cooldowns
    const cds = await getNotifCooldowns();
    let cChanged = false;
    for (const k of Object.keys(cds)) {
      if (cds[k] < now) {
        delete cds[k];
        cChanged = true;
      }
    }
    if (cChanged) await chrome.storage.local.set({ notifCooldowns: cds });

    // Trim recent activity older than retention
    const activity = await getRecentActivity();
    const filtered = activity.filter(a => now - (a._ts || 0) < maxAge);
    if (filtered.length !== activity.length) {
      await chrome.storage.local.set({ recentActivity: filtered });
    }
  }

  return {
    DEFAULTS,
    getSettings,
    saveSettings,
    getRecentActivity,
    addRecentActivity,
    clearRecentActivity,
    getScanCache,
    cacheScanResult,
    getCachedScan,
    clearScanCache,
    getProceedOverrides,
    setProceedOverride,
    hasProceedOverride,
    getNotifCooldowns,
    setNotifCooldown,
    isOnCooldown,
    setCurrentTabState,
    getCurrentTabState,
    cleanExpiredData
  };
})();

if (typeof globalThis !== 'undefined') globalThis.PhishGuardStorage = Storage;
