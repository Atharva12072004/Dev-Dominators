/**
 * PhishGuard AI — Background Service Worker (MV3)
 *
 * Responsibilities:
 *  - Handle API calls on behalf of content scripts & popup
 *  - Maintain current-tab state
 *  - Maintain recent activity feed & scan cache
 *  - Manage proceed overrides & notification cooldowns
 *  - Send browser notifications
 *  - Navigate to warning page when block is required
 *  - Periodic cleanup of expired local data
 */

/* -------------------------------------------------------------------- */
/*  Inline shared helpers  (service workers can't import content scripts */
/*  but we duplicate the minimal API / Storage surface we need)          */
/* -------------------------------------------------------------------- */

// ---- API helpers ----
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
    ['127.0.0.1', 'localhost'].forEach((host) => {
      if (host === originalHost) return;
      const next = new URL(parsed.toString());
      next.hostname = host;
      candidates.push(next.toString().replace(/\/+$/, ''));
    });
  } catch (_) {}
  return [...new Set(candidates)];
}

async function performApiFetch(url, options, apiKey, auth, timeout) {
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

async function _apiFetch(path, options = {}, { timeout = 15000, auth = true } = {}) {
  const { baseUrl, apiKey } = await _getConfig();
  const candidates = buildCandidateBaseUrls(baseUrl);
  let lastError = null;
  for (const candidate of candidates) {
    try {
      return await performApiFetch(`${candidate}${path}`, options, apiKey, auth, timeout);
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

// ---- Storage helpers ----
const DEFAULTS = {
  backendUrl: 'http://127.0.0.1:8000',
  apiKey: LOCAL_DEV_API_KEY,
  autoMonitoring: true,
  linkMonitoring: true,
  emailMonitoring: true,
  whatsappMonitoring: true,
  notificationsEnabled: true,
  warningThreshold: 50,
  directNavWarning: 'warn',
  proceedOverride: true,
  theme: 'dark',
  cacheRetentionDays: 7
};

const EMAIL_MONITOR_MATCHES = [
  'https://mail.google.com/*',
  'https://outlook.live.com/*',
  'https://outlook.office.com/*'
];

const WHATSAPP_MONITOR_MATCHES = [
  'https://web.whatsapp.com/*'
];

const MAX_SCAN_LINKS = 20;
const AUTO_PAGE_SCAN_CACHE_TTL_MS = 5 * 60 * 1000;
const tabNavigationScans = new Map();

async function getSettings() {
  const settings = await chrome.storage.sync.get(DEFAULTS);
  return {
    ...settings,
    backendUrl: normalizeBackendUrl(settings.backendUrl),
    apiKey: normalizeApiKey(settings.apiKey)
  };
}

async function getRecentActivity() {
  const { recentActivity = [] } = await chrome.storage.local.get('recentActivity');
  return recentActivity;
}

async function addRecentActivity(item) {
  const items = await getRecentActivity();
  items.unshift({ ...item, _ts: Date.now() });
  if (items.length > 50) items.length = 50;
  return chrome.storage.local.set({ recentActivity: items });
}

async function cacheScanResult(key, result) {
  const { scanCache = {} } = await chrome.storage.local.get('scanCache');
  scanCache[key] = { ...result, _cachedAt: Date.now() };
  const keys = Object.keys(scanCache);
  if (keys.length > 200) {
    const sorted = keys.sort((a, b) => (scanCache[a]._cachedAt || 0) - (scanCache[b]._cachedAt || 0));
    for (let i = 0; i < keys.length - 200; i++) delete scanCache[sorted[i]];
  }
  return chrome.storage.local.set({ scanCache });
}

async function getCachedScanResult(key) {
  const { scanCache = {} } = await chrome.storage.local.get('scanCache');
  return scanCache[key] || null;
}

async function hasProceedOverride(url) {
  const { proceedOverrides = {} } = await chrome.storage.local.get('proceedOverrides');
  return proceedOverrides[url] && proceedOverrides[url] > Date.now();
}

async function setProceedOverride(url, durationMs = 300000) {
  const { proceedOverrides = {} } = await chrome.storage.local.get('proceedOverrides');
  proceedOverrides[url] = Date.now() + durationMs;
  return chrome.storage.local.set({ proceedOverrides });
}

async function isOnNotifCooldown(key) {
  const { notifCooldowns = {} } = await chrome.storage.local.get('notifCooldowns');
  return notifCooldowns[key] && notifCooldowns[key] > Date.now();
}

async function setNotifCooldown(key, durationMs = 60000) {
  const { notifCooldowns = {} } = await chrome.storage.local.get('notifCooldowns');
  notifCooldowns[key] = Date.now() + durationMs;
  return chrome.storage.local.set({ notifCooldowns });
}

async function setCurrentTabState(state) {
  return chrome.storage.session.set({ currentTabState: state });
}

function hashText(value) {
  const input = String(value || '');
  let hash = 0;
  for (let index = 0; index < input.length; index += 1) {
    hash = ((hash << 5) - hash) + input.charCodeAt(index);
    hash |= 0;
  }
  return String(hash);
}

function previewText(value, max = 72) {
  const input = String(value || '').replace(/\s+/g, ' ').trim();
  if (!input) return '';
  return input.length > max ? `${input.slice(0, max - 3)}...` : input;
}

function shouldKeepScanLink(value) {
  const raw = String(value || '').trim();
  if (!raw) return false;
  try {
    const url = new URL(raw);
    const href = url.toString().toLowerCase();
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
    if (/\.(png|jpg|jpeg|gif|webp|svg|ico)(?:[?#]|$)/i.test(url.pathname)) return false;
    if (href.includes('googleusercontent.com') && /\/s\d+-d-e1-ft/.test(href)) return false;
    return true;
  } catch (_) {
    return false;
  }
}

function rankScanLink(value) {
  const href = String(value || '').toLowerCase();
  let score = 0;
  if (href.includes('/url=')) score += 3;
  if (href.includes('/login')) score += 2;
  if (href.includes('/signin')) score += 2;
  if (href.includes('/verify')) score += 2;
  if (href.includes('/reset')) score += 2;
  if (href.includes('/account')) score += 1;
  if (href.includes('/view')) score += 1;
  if (href.includes('?')) score += 1;
  return score;
}

function sanitizeLinksForScan(links) {
  const deduped = [...new Set((Array.isArray(links) ? links : []).map((item) => String(item || '').trim()))]
    .filter(shouldKeepScanLink);
  deduped.sort((left, right) => rankScanLink(right) - rankScanLink(left));
  return deduped.slice(0, MAX_SCAN_LINKS);
}

function isScannableHttpUrl(value) {
  const raw = String(value || '').trim();
  return raw.startsWith('http://') || raw.startsWith('https://');
}

function isFreshScanCacheEntry(entry, ttlMs = AUTO_PAGE_SCAN_CACHE_TTL_MS) {
  return !!(entry && entry._cachedAt && (Date.now() - entry._cachedAt) <= ttlMs);
}

async function notifyPageWarning(tabId, url, result) {
  try {
    return await chrome.tabs.sendMessage(tabId, {
      action: 'showPageWarning',
      payload: { url, result }
    });
  } catch (_) {
    return null;
  }
}

async function autoScanPageUrl(tabId, url, { force = false } = {}) {
  if (!isScannableHttpUrl(url)) return;

  const settings = await getSettings();
  if (!settings.autoMonitoring || !settings.linkMonitoring || settings.directNavWarning === 'allow') {
    return;
  }

  if (await hasProceedOverride(url)) {
    return;
  }

  const previousKey = tabNavigationScans.get(tabId);
  if (!force && previousKey === url) {
    return;
  }
  tabNavigationScans.set(tabId, url);

  let result = await getCachedScanResult(url);
  if (!isFreshScanCacheEntry(result)) {
    result = await _apiFetch('/api/v1/scan/url', {
      method: 'POST',
      body: JSON.stringify({ url, source: 'direct_navigation' })
    });
    await cacheScanResult(url, result);
    await addRecentActivity({
      type: 'url',
      url: result.url || url,
      verdict: result.verdict,
      risk_score: result.risk_score,
      source: 'direct_navigation'
    });
  }

  await setCurrentTabState({ tabId, url, result, contentType: 'url' });

  const bd = result?.block_decision;
  if (!bd || !bd.show_warning) {
    return;
  }

  if (settings.directNavWarning === 'block' && result.risk_score >= settings.warningThreshold) {
    navigateToWarning(tabId, result);
    await showNotification('🚫 Threat Blocked', `${url} was blocked — ${result.verdict}`, url);
    return;
  }

  if (settings.directNavWarning === 'warn') {
    await notifyPageWarning(tabId, url, result);
    await showNotification('⚠️ Risky Page', `${url} — ${result.verdict} (${result.risk_score}/100)`, url);
  }
}

// ---- Cleanup ----
async function cleanExpiredData() {
  const settings = await getSettings();
  const maxAge = (settings.cacheRetentionDays || 7) * 86400000;
  const now = Date.now();

  const { scanCache = {} } = await chrome.storage.local.get('scanCache');
  let cacheChanged = false;
  for (const k of Object.keys(scanCache)) {
    if (now - (scanCache[k]._cachedAt || 0) > maxAge) { delete scanCache[k]; cacheChanged = true; }
  }
  if (cacheChanged) await chrome.storage.local.set({ scanCache });

  const { proceedOverrides = {} } = await chrome.storage.local.get('proceedOverrides');
  let oChanged = false;
  for (const k of Object.keys(proceedOverrides)) {
    if (proceedOverrides[k] < now) { delete proceedOverrides[k]; oChanged = true; }
  }
  if (oChanged) await chrome.storage.local.set({ proceedOverrides });

  const { notifCooldowns = {} } = await chrome.storage.local.get('notifCooldowns');
  let nChanged = false;
  for (const k of Object.keys(notifCooldowns)) {
    if (notifCooldowns[k] < now) { delete notifCooldowns[k]; nChanged = true; }
  }
  if (nChanged) await chrome.storage.local.set({ notifCooldowns });

  const { recentActivity = [] } = await chrome.storage.local.get('recentActivity');
  const filtered = recentActivity.filter(a => now - (a._ts || 0) < maxAge);
  if (filtered.length !== recentActivity.length) await chrome.storage.local.set({ recentActivity: filtered });
}

async function injectScriptIntoTabs(matches, files) {
  const tabs = await chrome.tabs.query({ url: matches });
  for (const tab of tabs) {
    if (!tab.id || !tab.url) continue;
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files
      });
    } catch (_) {
      // Ignore restricted tabs or already-unavailable tabs.
    }
  }
}

async function ensureMonitorScriptsInOpenTabs() {
  await injectScriptIntoTabs(EMAIL_MONITOR_MATCHES, ['content_scripts/email_monitor.js']);
  await injectScriptIntoTabs(WHATSAPP_MONITOR_MATCHES, ['content_scripts/whatsapp_monitor.js']);
}

async function reloadMonitorTabs() {
  const tabs = await chrome.tabs.query({
    url: [...EMAIL_MONITOR_MATCHES, ...WHATSAPP_MONITOR_MATCHES]
  });
  for (const tab of tabs) {
    if (!tab.id) continue;
    try {
      await chrome.tabs.reload(tab.id);
    } catch (_) {
      // Ignore tabs that disappeared mid-loop.
    }
  }
}


/* -------------------------------------------------------------------- */
/*  Alarm-based periodic cleanup                                         */
/* -------------------------------------------------------------------- */

chrome.alarms.create('pg-cleanup', { periodInMinutes: 60 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'pg-cleanup') {
    cleanExpiredData().catch(console.error);
  }
});

chrome.runtime.onStartup.addListener(() => {
  ensureMonitorScriptsInOpenTabs().catch(console.error);
});


/* -------------------------------------------------------------------- */
/*  Tab tracking — update current-tab state on tab change                */
/* -------------------------------------------------------------------- */

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    await setCurrentTabState({ tabId, url: tab.url || '', result: null });
    if (isScannableHttpUrl(tab.url || '')) {
      await autoScanPageUrl(tabId, tab.url || '', { force: true });
    }
  } catch (_) { /* tab may not exist */ }
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    tabNavigationScans.delete(tabId);
    if (isScannableHttpUrl(changeInfo.url)) {
      await autoScanPageUrl(tabId, changeInfo.url, { force: true });
    }
  }
  if (changeInfo.url && tab && tab.active) {
    await setCurrentTabState({ tabId, url: tab.url || '', result: null });
  }
  if (changeInfo.status === 'complete' && tab && isScannableHttpUrl(tab.url || '')) {
    await autoScanPageUrl(tabId, tab.url || '');
  }
});


/* -------------------------------------------------------------------- */
/*  Notification helper                                                  */
/* -------------------------------------------------------------------- */

async function showNotification(title, message, url) {
  const settings = await getSettings();
  if (!settings.notificationsEnabled) return;

  const cooldownKey = `notif:${url || message}`;
  if (await isOnNotifCooldown(cooldownKey)) return;
  await setNotifCooldown(cooldownKey, 60000);

  chrome.notifications.create(`pg-${Date.now()}`, {
    type: 'basic',
    iconUrl: chrome.runtime.getURL('assets/icon128.png'),
    title,
    message,
    priority: 2
  });
}


/* -------------------------------------------------------------------- */
/*  Warning page navigation                                              */
/* -------------------------------------------------------------------- */

function navigateToWarning(tabId, scanResult) {
  const params = new URLSearchParams({
    url: scanResult.url || '',
    verdict: scanResult.verdict || '',
    risk_score: String(scanResult.risk_score || 0),
    reason: scanResult.block_decision?.reason_summary || '',
    override: String(scanResult.block_decision?.override_allowed ?? false),
    flags: JSON.stringify(scanResult.block_decision?.top_flags || [])
  });
  const warningUrl = chrome.runtime.getURL(`warning/warning.html?${params.toString()}`);
  chrome.tabs.update(tabId, { url: warningUrl });
}


/* -------------------------------------------------------------------- */
/*  Message handler — content scripts & popup talk to us here            */
/* -------------------------------------------------------------------- */

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  handleMessage(msg, sender).then(sendResponse).catch(err => {
    sendResponse({ error: err.message || 'Unknown error' });
  });
  return true; // keep channel open for async
});

async function handleMessage(msg, sender) {
  const { action, payload } = msg;

  switch (action) {
    /* ---- Scan URL ---- */
    case 'scanUrl': {
      const settings = await getSettings();
      const url = payload.url;
      const source = payload.source || 'browser';
      const analysisMode = payload.analysis_mode || 'standard';

      // Check proceed override
      if (await hasProceedOverride(url)) {
        return { overridden: true };
      }

      const result = await _apiFetch('/api/v1/scan/url', {
        method: 'POST',
        body: JSON.stringify({ url, source, analysis_mode: analysisMode })
      });

      // Cache & activity
      await cacheScanResult(url, result);
      await addRecentActivity({
        type: 'url',
        url: result.url,
        verdict: result.verdict,
        risk_score: result.risk_score,
        source
      });

      // Update current tab state if from active tab
      if (sender.tab) {
        await setCurrentTabState({ tabId: sender.tab.id, url, result });
      }

      // Handle block decision
      const bd = result.block_decision;
      if (bd) {
        if (bd.action === 'block' && result.risk_score >= settings.warningThreshold) {
          if (sender.tab) navigateToWarning(sender.tab.id, result);
          await showNotification('🚫 Threat Blocked', `${url} was blocked — ${result.verdict}`, url);
          return { ...result, _action: 'block' };
        }
        if (bd.action === 'warn' || bd.show_warning) {
          await showNotification('⚠️ Suspicious Link', `${url} — ${result.verdict} (${result.risk_score}/100)`, url);
          return { ...result, _action: 'warn' };
        }
      }

      return { ...result, _action: 'allow' };
    }

    /* ---- Scan Email ---- */
    case 'scanEmail': {
      const sanitizedPayload = {
        ...payload,
        links: sanitizeLinksForScan(payload.links)
      };
      const result = await _apiFetch('/api/v1/scan/email', {
        method: 'POST',
        body: JSON.stringify(sanitizedPayload)
      });
      await cacheScanResult(`email:${hashText(`${sanitizedPayload.subject || ''}|${sanitizedPayload.content || ''}`)}`, result);
      if (Array.isArray(result.scanned_links)) {
        for (const item of result.scanned_links) {
          if (item && item.url) await cacheScanResult(item.url, item);
        }
      }

      await addRecentActivity({
        type: 'email',
        url: sanitizedPayload.subject || previewText(sanitizedPayload.content, 72) || 'Email scan',
        verdict: result.verdict,
        risk_score: result.risk_score,
        source: 'email'
      });

      if (sender.tab) {
        await setCurrentTabState({
          tabId: sender.tab.id,
          url: sender.tab.url || '',
          result,
          contentType: 'email'
        });
      }

      if (result.risk_score >= 40) {
        await showNotification('✉️ Email Alert', `Risky email detected — ${result.verdict}`, payload.subject);
      }

      return result;
    }

    /* ---- Scan Chat ---- */
    case 'scanChat': {
      const sanitizedPayload = {
        ...payload,
        links: sanitizeLinksForScan(payload.links)
      };
      const result = await _apiFetch('/api/v1/scan/chat', {
        method: 'POST',
        body: JSON.stringify(sanitizedPayload)
      });
      await cacheScanResult(`chat:${hashText(`${sanitizedPayload.sender || ''}|${sanitizedPayload.content || ''}`)}`, result);
      if (Array.isArray(result.scanned_links)) {
        for (const item of result.scanned_links) {
          if (item && item.url) await cacheScanResult(item.url, item);
        }
      }

      await addRecentActivity({
        type: 'chat',
        url: sanitizedPayload.sender || previewText(sanitizedPayload.content, 72) || 'Chat scan',
        verdict: result.verdict,
        risk_score: result.risk_score,
        source: 'whatsapp'
      });

      if (sender.tab) {
        await setCurrentTabState({
          tabId: sender.tab.id,
          url: sender.tab.url || '',
          result,
          contentType: 'chat'
        });
      }

      if (result.risk_score >= 40) {
        await showNotification('💬 Chat Alert', `Suspicious chat content — ${result.verdict}`, payload.sender);
      }

      return result;
    }

    /* ---- Scan Batch ---- */
    case 'scanBatch': {
      const result = await _apiFetch('/api/v1/scan/batch', {
        method: 'POST',
        body: JSON.stringify({ urls: payload.urls, source: payload.source || 'manual' })
      });

      if (Array.isArray(result)) {
        for (const r of result) {
          await cacheScanResult(r.url, r);
          await addRecentActivity({
            type: 'url',
            url: r.url,
            verdict: r.verdict,
            risk_score: r.risk_score,
            source: payload.source || 'manual'
          });
        }
      }

      return result;
    }

    /* ---- Get settings ---- */
    case 'getSettings': {
      return getSettings();
    }

    /* ---- Get current tab state ---- */
    case 'getCurrentTabState': {
      const { currentTabState = null } = await chrome.storage.session.get('currentTabState');
      return currentTabState;
    }

    /* ---- Get recent activity ---- */
    case 'getRecentActivity': {
      return getRecentActivity();
    }

    /* ---- Get cached scan ---- */
    case 'getCachedScan': {
      return getCachedScanResult(payload.key);
    }

    /* ---- Set proceed override ---- */
    case 'setProceedOverride': {
      await setProceedOverride(payload.url, payload.duration || 300000);
      return { ok: true };
    }

    /* ---- Check proceed override ---- */
    case 'hasProceedOverride': {
      const has = await hasProceedOverride(payload.url);
      return { overridden: has };
    }

    /* ---- Open dashboard ---- */
    case 'openDashboard': {
      chrome.tabs.create({ url: chrome.runtime.getURL('dashboard/dashboard.html') });
      return { ok: true };
    }

    /* ---- Open options ---- */
    case 'openOptions': {
      chrome.runtime.openOptionsPage();
      return { ok: true };
    }

    /* ---- Health check ---- */
    case 'healthCheck': {
      return _apiFetch('/health', { method: 'GET' }, { auth: false, timeout: 8000 });
    }

    default:
      return { error: `Unknown action: ${action}` };
  }
}


/* -------------------------------------------------------------------- */
/*  On install / update — set defaults                                   */
/* -------------------------------------------------------------------- */

chrome.runtime.onInstalled.addListener(async (details) => {
  const existing = await chrome.storage.sync.get(null);
  const toSet = {};
  for (const [k, v] of Object.entries(DEFAULTS)) {
    if (existing[k] === undefined) toSet[k] = v;
  }
  if (!existing.apiKey || !String(existing.apiKey).trim()) {
    toSet.apiKey = LOCAL_DEV_API_KEY;
  }
  if (!existing.backendUrl || !String(existing.backendUrl).trim()) {
    toSet.backendUrl = DEFAULTS.backendUrl;
  }
  if (Object.keys(toSet).length) await chrome.storage.sync.set(toSet);

  if (details.reason === 'update') {
    await reloadMonitorTabs().catch(() => {});
  } else {
    await ensureMonitorScriptsInOpenTabs().catch(() => {});
  }

  if (details.reason === 'install') {
    // Open options on first install to configure backend
    chrome.tabs.create({ url: chrome.runtime.getURL('options/options.html') });
  }
});


/* -------------------------------------------------------------------- */
/*  Badge icon update based on current tab state                         */
/* -------------------------------------------------------------------- */

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'session' && changes.currentTabState) {
    const state = changes.currentTabState.newValue;
    if (state && state.result) {
      const v = state.result.verdict;
      const colors = { safe: '#22c55e', suspicious: '#f59e0b', phishing: '#ef4444', malware: '#ef4444' };
      const labels = { safe: '✓', suspicious: '!', phishing: '✕', malware: '☠' };
      chrome.action.setBadgeBackgroundColor({ color: colors[v] || '#6b7280' });
      chrome.action.setBadgeText({ text: labels[v] || '' });
    } else {
      chrome.action.setBadgeText({ text: '' });
    }
  }
});

console.log('[CYBERSHIELD] Service worker loaded');
ensureMonitorScriptsInOpenTabs().catch(() => {});
