/**
 * PhishGuard AI - Link Interceptor Content Script
 * Runs on all HTTP/HTTPS pages.
 * Intercepts anchor clicks for real-time URL scanning.
 */

(() => {
  'use strict';

  const CACHE_TTL_MS = 10 * 60 * 1000;
  let settings = null;
  let shieldEl = null;
  let lastPageWarningKey = '';

  async function init() {
    settings = await chrome.runtime.sendMessage({ action: 'getSettings' });
    if (!settings || !settings.autoMonitoring || !settings.linkMonitoring) return;

    injectStyles();
    injectShield();
    document.addEventListener('click', onLinkClick, true);
    document.addEventListener('auxclick', onLinkClick, true);
    document.addEventListener('keydown', onLinkKeydown, true);
  }

  function injectShield() {
    if (document.getElementById('pg-shield')) return;
    shieldEl = document.createElement('div');
    shieldEl.id = 'pg-shield';
    shieldEl.innerHTML = `
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    `;
    Object.assign(shieldEl.style, {
      position: 'fixed',
      bottom: '16px',
      right: '16px',
      width: '36px',
      height: '36px',
      borderRadius: '50%',
      background: 'linear-gradient(135deg, #1e293b 0%, #0f172a 100%)',
      color: '#22c55e',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: '2147483647',
      cursor: 'pointer',
      boxShadow: '0 2px 12px rgba(0,0,0,0.4)',
      border: '1px solid rgba(34,197,94,0.25)',
      transition: 'all 0.3s ease',
      opacity: '0.7',
      fontFamily: 'system-ui, -apple-system, sans-serif'
    });

    shieldEl.addEventListener('mouseenter', () => {
      shieldEl.style.opacity = '1';
      shieldEl.style.transform = 'scale(1.1)';
    });
    shieldEl.addEventListener('mouseleave', () => {
      shieldEl.style.opacity = '0.7';
      shieldEl.style.transform = 'scale(1)';
    });
    shieldEl.title = 'CYBERSHIELD - Active';

    if (document.body) {
      document.body.appendChild(shieldEl);
    } else {
      document.addEventListener('DOMContentLoaded', () => document.body.appendChild(shieldEl));
    }
  }

  function setShieldState(state) {
    if (!shieldEl) return;
    const colors = {
      scanning: '#3b82f6',
      safe: '#22c55e',
      warning: '#f59e0b',
      danger: '#ef4444'
    };
    shieldEl.style.color = colors[state] || '#22c55e';
    shieldEl.style.animation = state === 'scanning' ? 'pg-pulse 1s ease infinite' : 'none';
  }

  function injectStyles() {
    if (document.getElementById('pg-interceptor-styles')) return;
    const style = document.createElement('style');
    style.id = 'pg-interceptor-styles';
    style.textContent = `
      @keyframes pg-pulse { 0%,100% { opacity: 0.7; } 50% { opacity: 1; } }
      @keyframes pg-fadeIn { from { opacity: 0; } to { opacity: 1; } }
      @keyframes pg-slideUp { from { transform: translateY(20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }

      .pg-modal-overlay {
        position: fixed;
        inset: 0;
        z-index: 2147483646;
        background: rgba(0,0,0,0.65);
        backdrop-filter: blur(4px);
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        animation: pg-fadeIn 0.2s ease;
      }

      .pg-modal {
        background: linear-gradient(145deg, #1e2230 0%, #181b23 100%);
        color: #e8eaed;
        border-radius: 16px;
        padding: 28px;
        max-width: 440px;
        width: 90%;
        box-shadow: 0 16px 48px rgba(0,0,0,0.5);
        border: 1px solid rgba(255,255,255,0.06);
        animation: pg-slideUp 0.25s ease;
      }

      .pg-modal h3 {
        margin: 0 0 8px;
        font-size: 18px;
        font-weight: 700;
      }

      .pg-modal p {
        margin: 6px 0;
        font-size: 13px;
        color: #9ca3af;
        line-height: 1.5;
      }

      .pg-modal-url {
        background: rgba(255,255,255,0.04);
        border-radius: 8px;
        padding: 8px 12px;
        font-size: 12px;
        color: #6b7280;
        word-break: break-all;
        margin: 12px 0;
        border: 1px solid rgba(255,255,255,0.04);
      }

      .pg-modal-flags {
        margin: 12px 0;
        max-height: 120px;
        overflow-y: auto;
      }

      .pg-modal-flag {
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 4px 0;
        font-size: 12px;
        color: #9ca3af;
      }

      .pg-modal-flag-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        flex-shrink: 0;
      }

      .pg-modal-actions {
        display: flex;
        gap: 10px;
        margin-top: 18px;
      }

      .pg-modal-btn {
        flex: 1;
        padding: 10px 16px;
        border: none;
        border-radius: 10px;
        font-size: 13px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.2s ease;
      }

      .pg-modal-btn-safe {
        background: #22c55e;
        color: #fff;
      }

      .pg-modal-btn-safe:hover {
        background: #16a34a;
      }

      .pg-modal-btn-proceed {
        background: rgba(255,255,255,0.06);
        color: #9ca3af;
        border: 1px solid rgba(255,255,255,0.08);
      }

      .pg-modal-btn-proceed:hover {
        background: rgba(255,255,255,0.1);
        color: #e8eaed;
      }

      .pg-scanning-toast {
        position: fixed;
        bottom: 64px;
        right: 16px;
        z-index: 2147483646;
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        color: #e8eaed;
        padding: 10px 18px;
        border-radius: 10px;
        font-size: 12px;
        font-family: system-ui, sans-serif;
        box-shadow: 0 4px 20px rgba(0,0,0,0.4);
        border: 1px solid rgba(59,130,246,0.2);
        display: flex;
        align-items: center;
        gap: 8px;
        animation: pg-slideUp 0.2s ease;
      }

      .pg-scanning-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #3b82f6;
        animation: pg-pulse 0.8s ease infinite;
      }
    `;
    (document.head || document.documentElement).appendChild(style);
  }

  function findNavigableElement(event) {
    const path = typeof event.composedPath === 'function' ? event.composedPath() : [];
    for (const item of path) {
      if (!item || typeof item !== 'object' || !item.matches) continue;
      if (item.matches('a[href], area[href]')) return item;
      if (item.matches('[data-href], [data-url]')) return item;
    }

    const target = event.target;
    if (target && typeof target.closest === 'function') {
      return target.closest('a[href], area[href], [data-href], [data-url]');
    }
    return null;
  }

  function getNavigationTarget(element) {
    if (!element) return { url: '', target: '' };
    const href = element.getAttribute?.('href') || element.dataset?.href || element.dataset?.url || '';
    return {
      url: href,
      target: element.getAttribute?.('target') || '',
    };
  }

  function shouldHandleMouseEvent(event) {
    if (event.type === 'auxclick') return event.button === 1;
    if (event.type !== 'click') return false;
    return event.button === 0;
  }

  async function onLinkClick(event) {
    if (!shouldHandleMouseEvent(event)) return;
    const navigable = findNavigableElement(event);
    if (!navigable) return;

    const nav = getNavigationTarget(navigable);
    const normalizedUrl = normalizeClickedUrl(nav.url);
    if (!normalizedUrl || (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://'))) return;

    try {
      const linkUrl = new URL(normalizedUrl);
      if (linkUrl.origin === location.origin && linkUrl.pathname === location.pathname && linkUrl.hash) return;
    } catch (_) {
      return;
    }

    event.preventDefault();
    event.stopPropagation();
    if (typeof event.stopImmediatePropagation === 'function') event.stopImmediatePropagation();

    try {
      const overrideResp = await chrome.runtime.sendMessage({ action: 'hasProceedOverride', payload: { url: normalizedUrl } });
      if (overrideResp && overrideResp.overridden) {
        openNavigation(normalizedUrl, nav.target, event);
        return;
      }
    } catch (_) {}

    const cachedResult = await getCachedResult(normalizedUrl);
    if (cachedResult) {
      await applyScanResult(normalizedUrl, cachedResult, nav.target, event);
      return;
    }

    const toast = showScanningToast();
    setShieldState('scanning');

    try {
      const result = await chrome.runtime.sendMessage({
        action: 'scanUrl',
        payload: { url: normalizedUrl, source: 'browser' }
      });

      removeScanningToast(toast);

      if (!result || result.error) {
        showPassiveErrorToast(describeScanFailure(result?.error));
        setShieldState('safe');
        openNavigation(normalizedUrl, nav.target, event);
        return;
      }

      await applyScanResult(normalizedUrl, result, nav.target, event);
    } catch (err) {
      removeScanningToast(toast);
      setShieldState('safe');
      showPassiveErrorToast(describeScanFailure(err?.message));
      openNavigation(normalizedUrl, nav.target, event);
    }
  }

  async function onLinkKeydown(event) {
    if (event.key !== 'Enter') return;
    const navigable = findNavigableElement(event);
    if (!navigable) return;
    await onLinkClick({
      type: 'click',
      button: 0,
      target: event.target,
      ctrlKey: event.ctrlKey,
      metaKey: event.metaKey,
      shiftKey: event.shiftKey,
      preventDefault: () => event.preventDefault(),
      stopPropagation: () => event.stopPropagation(),
      stopImmediatePropagation: () => {
        if (typeof event.stopImmediatePropagation === 'function') event.stopImmediatePropagation();
      },
      composedPath: () => (typeof event.composedPath === 'function' ? event.composedPath() : [event.target]),
    });
  }

  function normalizeClickedUrl(rawUrl) {
    if (!rawUrl) return '';

    try {
      const parsed = new URL(rawUrl, location.href);
      const hostname = parsed.hostname.toLowerCase();

      if (hostname === 'www.google.com' && parsed.pathname === '/url') {
        return parsed.searchParams.get('q') || parsed.searchParams.get('url') || rawUrl;
      }

      if (hostname === 'safelinks.protection.outlook.com') {
        return parsed.searchParams.get('url') || rawUrl;
      }

      if (hostname === 'mail.google.com' && parsed.searchParams.get('q')) {
        return parsed.searchParams.get('q') || rawUrl;
      }

      return parsed.toString();
    } catch (_) {
      return rawUrl;
    }
  }

  async function getCachedResult(url) {
    try {
      const cached = await chrome.runtime.sendMessage({ action: 'getCachedScan', payload: { key: url } });
      if (!cached || !cached._cachedAt) return null;
      if ((Date.now() - cached._cachedAt) > CACHE_TTL_MS) return null;
      return cached;
    } catch (_) {
      return null;
    }
  }

  async function applyScanResult(url, result, target, triggerEvent = null) {
    if (result.overridden) {
      setShieldState('safe');
      openNavigation(url, target, triggerEvent);
      return;
    }

    const action = result._action || result.block_decision?.action || 'allow';
    if (action === 'block') {
      setShieldState('danger');
      return;
    }

    if (action === 'warn') {
      setShieldState('warning');
      showWarningModal(url, result, target, triggerEvent);
      return;
    }

    setShieldState('safe');
    openNavigation(url, target, triggerEvent);
  }

  function openNavigation(url, target, triggerEvent = null) {
    const openInNewTab = target === '_blank'
      || !!triggerEvent?.ctrlKey
      || !!triggerEvent?.metaKey
      || !!triggerEvent?.shiftKey
      || triggerEvent?.type === 'auxclick';

    if (!openInNewTab && (!target || target === '_self')) {
      window.location.assign(url);
      return;
    }
    window.open(url, target || '_blank');
  }

  function showScanningToast() {
    const el = document.createElement('div');
    el.className = 'pg-scanning-toast';
    el.innerHTML = '<div class="pg-scanning-dot"></div>Scanning link...';
    document.body.appendChild(el);
    return el;
  }

  function removeScanningToast(el) {
    if (el && el.parentNode) el.remove();
  }

  function showPassiveErrorToast(message) {
    const existing = document.getElementById('pg-scan-error');
    if (existing) existing.remove();

    const el = document.createElement('div');
    el.id = 'pg-scan-error';
    el.className = 'pg-scanning-toast';
    el.style.border = '1px solid rgba(239,68,68,0.25)';
    el.innerHTML = `<div class="pg-scanning-dot" style="background:#ef4444;animation:none"></div>${escapeHtml(message)}`;
    document.body.appendChild(el);
    setTimeout(() => { if (el.parentNode) el.remove(); }, 5000);
  }

  function showWarningModal(url, result, target, triggerEvent = null) {
    const existing = document.querySelector('.pg-modal-overlay');
    if (existing) existing.remove();

    const blockDecision = result.block_decision || {};
    const overlay = document.createElement('div');
    overlay.className = 'pg-modal-overlay';

    const verdictColor = {
      safe: '#22c55e',
      suspicious: '#f59e0b',
      phishing: '#ef4444',
      malware: '#ef4444'
    };
    const color = verdictColor[result.verdict] || '#f59e0b';
    const title = result.risk_score >= 61 ? 'Dangerous Link Detected' : 'Suspicious Link Detected';

    const flagsHtml = Array.isArray(blockDecision.top_flags) && blockDecision.top_flags.length
      ? `<div class="pg-modal-flags">${blockDecision.top_flags.map((flag) => `
          <div class="pg-modal-flag"><div class="pg-modal-flag-dot" style="background:${color}"></div>${escapeHtml(flag)}</div>
        `).join('')}</div>`
      : '';

    overlay.innerHTML = `
      <div class="pg-modal">
        <h3 style="color:${color}">${escapeHtml(title)}</h3>
        <p>${escapeHtml(blockDecision.reason_summary || `This link has been flagged as ${result.verdict}.`)}</p>
        <div class="pg-modal-url">${escapeHtml(url)}</div>
        <p>Risk Score: <strong style="color:${color}">${result.risk_score}/100</strong> · Verdict: <strong style="color:${color}">${escapeHtml(result.verdict)}</strong></p>
        ${flagsHtml}
        <div class="pg-modal-actions">
          <button class="pg-modal-btn pg-modal-btn-safe" id="pg-modal-back">Go Back to Safety</button>
          ${blockDecision.override_allowed !== false ? '<button class="pg-modal-btn pg-modal-btn-proceed" id="pg-modal-proceed">Proceed Anyway</button>' : ''}
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    overlay.querySelector('#pg-modal-back').addEventListener('click', () => {
      overlay.remove();
      setShieldState('safe');
    });

    const proceedBtn = overlay.querySelector('#pg-modal-proceed');
    if (proceedBtn) {
      proceedBtn.addEventListener('click', async () => {
        overlay.remove();
        setShieldState('safe');
        try {
          await chrome.runtime.sendMessage({ action: 'setProceedOverride', payload: { url, duration: 300000 } });
        } catch (_) {}
        openNavigation(url, target, triggerEvent);
      });
    }

    overlay.addEventListener('click', (event) => {
      if (event.target === overlay) {
        overlay.remove();
        setShieldState('safe');
      }
    });
  }

  function leaveCurrentPage() {
    try {
      if (window.history.length > 1) {
        window.history.back();
        return;
      }
    } catch (_) {}
    window.location.replace('about:blank');
  }

  function showCurrentPageWarning(url, result) {
    const warningKey = `${url}|${result?.risk_score || 0}|${result?.verdict || ''}`;
    const existing = document.querySelector('.pg-modal-overlay.pg-current-page-risk');
    if (existing && lastPageWarningKey === warningKey) return;
    if (existing) existing.remove();
    lastPageWarningKey = warningKey;

    const blockDecision = result.block_decision || {};
    const overlay = document.createElement('div');
    overlay.className = 'pg-modal-overlay pg-current-page-risk';

    const verdictColor = {
      safe: '#22c55e',
      suspicious: '#f59e0b',
      phishing: '#ef4444',
      malware: '#ef4444'
    };
    const color = verdictColor[result.verdict] || '#f59e0b';
    const title = result.risk_score >= 61 ? 'Dangerous Page Detected' : 'Suspicious Page Detected';
    const flagsHtml = Array.isArray(blockDecision.top_flags) && blockDecision.top_flags.length
      ? `<div class="pg-modal-flags">${blockDecision.top_flags.map((flag) => `
          <div class="pg-modal-flag"><div class="pg-modal-flag-dot" style="background:${color}"></div>${escapeHtml(flag)}</div>
        `).join('')}</div>`
      : '';

    overlay.innerHTML = `
      <div class="pg-modal">
        <h3 style="color:${color}">${escapeHtml(title)}</h3>
        <p>${escapeHtml(blockDecision.reason_summary || `This page has been flagged as ${result.verdict}.`)}</p>
        <div class="pg-modal-url">${escapeHtml(url)}</div>
        <p>Risk Score: <strong style="color:${color}">${result.risk_score}/100</strong> · Verdict: <strong style="color:${color}">${escapeHtml(result.verdict)}</strong></p>
        ${flagsHtml}
        <div class="pg-modal-actions">
          <button class="pg-modal-btn pg-modal-btn-safe" id="pg-page-leave">Leave This Page</button>
          ${blockDecision.override_allowed !== false ? '<button class="pg-modal-btn pg-modal-btn-proceed" id="pg-page-stay">Stay Anyway</button>' : ''}
        </div>
      </div>
    `;

    document.body.appendChild(overlay);
    setShieldState(result.risk_score >= 61 ? 'danger' : 'warning');

    overlay.querySelector('#pg-page-leave').addEventListener('click', () => {
      overlay.remove();
      lastPageWarningKey = '';
      leaveCurrentPage();
    });

    const stayBtn = overlay.querySelector('#pg-page-stay');
    if (stayBtn) {
      stayBtn.addEventListener('click', async () => {
        overlay.remove();
        setShieldState('safe');
        try {
          await chrome.runtime.sendMessage({ action: 'setProceedOverride', payload: { url, duration: 300000 } });
        } catch (_) {}
      });
    }
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.action !== 'showPageWarning') return;
    const payload = message.payload || {};
    try {
      showCurrentPageWarning(payload.url || location.href, payload.result || {});
      sendResponse({ ok: true });
    } catch (err) {
      sendResponse({ ok: false, error: err?.message || 'warning_failed' });
    }
    return true;
  });

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
  }

  function describeScanFailure(message) {
    if (/Authentication failed/i.test(message || '')) {
      return 'CYBERSHIELD could not verify this link because the extension API key does not match the backend.';
    }
    return 'CYBERSHIELD scan is temporarily unavailable.';
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
