/**
 * PhishGuard AI - Email Monitor Content Script
 * Runs on Gmail and Outlook Web.
 */

(() => {
  'use strict';

  try {
    if (typeof window.__pgEmailMonitorCleanup === 'function') {
      window.__pgEmailMonitorCleanup();
    }
  } catch (_) {}

  const SCAN_DEBOUNCE_MS = 1200;
  const RESCAN_INTERVAL_MS = 4000;
  const scannedFingerprints = new Set();
  let debounceTimer = null;
  let intervalId = null;
  let settings = null;
  let observer = null;
  let lastFingerprint = '';
  let lastVisibleMessageKey = '';
  let started = false;

  function onDocumentClick() {
    scheduleScan();
  }

  function onHistoryChange() {
    scheduleScan();
  }

  function onVisibilityChange() {
    if (document.visibilityState === 'visible') {
      scheduleScan();
    }
  }

  async function init() {
    if (started) return;
    started = true;
    settings = await chrome.runtime.sendMessage({ action: 'getSettings' });
    if (!settings || !settings.autoMonitoring || !settings.emailMonitoring) return;

    injectStyles();
    startObserver();
    document.addEventListener('click', onDocumentClick, true);
    window.addEventListener('popstate', onHistoryChange);
    document.addEventListener('visibilitychange', onVisibilityChange);
    intervalId = window.setInterval(() => {
      scheduleScan();
    }, RESCAN_INTERVAL_MS);
    scheduleScan();
  }

  function cleanup() {
    clearTimeout(debounceTimer);
    if (intervalId) {
      clearInterval(intervalId);
      intervalId = null;
    }
    if (observer) {
      observer.disconnect();
      observer = null;
    }
    document.removeEventListener('click', onDocumentClick, true);
    window.removeEventListener('popstate', onHistoryChange);
    document.removeEventListener('visibilitychange', onVisibilityChange);
    started = false;
  }

  window.__pgEmailMonitorCleanup = cleanup;

  function startObserver() {
    observer = new MutationObserver(() => {
      scheduleScan();
    });
    observer.observe(document.body, { childList: true, subtree: true, attributes: true, characterData: true });
  }

  function scheduleScan() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(checkForEmail, SCAN_DEBOUNCE_MS);
  }

  function checkForEmail() {
    if (document.visibilityState !== 'visible') return;
    const context = collectEmailContext();
    if (!context) return;

    const visibleMessageKey = context.messageKey || '';
    if (visibleMessageKey && visibleMessageKey === lastVisibleMessageKey) return;

    const fingerprint = hashStr(`${context.subject}|${context.body.slice(0, 500)}|${context.links.join(',')}`);
    if (!fingerprint || fingerprint === lastFingerprint || scannedFingerprints.has(fingerprint)) return;
    lastFingerprint = fingerprint;
    lastVisibleMessageKey = visibleMessageKey;
    scannedFingerprints.add(fingerprint);

    if (scannedFingerprints.size > 150) {
      const first = scannedFingerprints.values().next().value;
      scannedFingerprints.delete(first);
    }

    scanEmail(context.subject, context.body, context.links);
  }

  function collectEmailContext() {
    const hostname = location.hostname;
    if (hostname === 'mail.google.com') {
      return collectGmailContext();
    }
    if (hostname.includes('outlook')) {
      return collectOutlookContext();
    }
    return null;
  }

  function collectGmailContext() {
    const subjectEl = firstVisibleElement([
      'h2[data-thread-perm-id]',
      'h2.hP',
      '[role="main"] h2'
    ]);
    const bodies = visibleElements([
      '.a3s.aiL',
      '.ii.gt',
      '[data-message-id] .a3s',
      '[role="listitem"] .a3s'
    ]);
    if (!bodies.length) return null;

    const currentBody = pickCurrentMessageBody(bodies);
    const primaryContext = currentBody ? extractBodyContext(currentBody) : null;
    const fallbackContext = buildCombinedEmailContext(bodies);
    const bodyText = primaryContext?.bodyText || fallbackContext?.bodyText || '';
    const links = primaryContext?.links?.length ? primaryContext.links : (fallbackContext?.links || []);

    if (!bodyText && !links.length) return null;
    return {
      subject: subjectEl ? subjectEl.textContent.trim() : '',
      body: bodyText.slice(0, 12000),
      links,
      messageKey: buildEmailMessageKey(currentBody, subjectEl, bodyText)
    };
  }

  function collectOutlookContext() {
    const subjectEl = firstVisibleElement([
      '[role="heading"][aria-level]',
      '[data-app-section="MailReadCompose"] h1',
      '.XbIp4'
    ]);
    const bodies = visibleElements([
      '[role="document"]',
      'div[aria-label*="Message body"]',
      '.RDRlm',
      '[data-app-section="MailReadCompose"] div[dir="ltr"]'
    ]);
    if (!bodies.length) return null;

    const currentBody = pickCurrentMessageBody(bodies);
    const primaryContext = currentBody ? extractBodyContext(currentBody) : null;
    const fallbackContext = buildCombinedEmailContext(bodies);
    const bodyText = primaryContext?.bodyText || fallbackContext?.bodyText || '';
    const links = primaryContext?.links?.length ? primaryContext.links : (fallbackContext?.links || []);

    if (!bodyText && !links.length) return null;
    return {
      subject: subjectEl ? subjectEl.textContent.trim() : '',
      body: bodyText.slice(0, 12000),
      links,
      messageKey: buildEmailMessageKey(currentBody, subjectEl, bodyText)
    };
  }

  function buildEmailMessageKey(currentBody, subjectEl, bodyText) {
    const messageHost = currentBody || subjectEl;
    if (!messageHost) return '';
    const directId = messageHost.closest?.('[data-message-id]')?.getAttribute('data-message-id')
      || currentBody?.getAttribute?.('data-message-id')
      || location.href;
    const subjectText = (subjectEl?.textContent || '').trim();
    return hashStr(`${directId}|${subjectText}|${String(bodyText || '').slice(0, 300)}`);
  }

  function extractBodyContext(element) {
    if (!element) return null;
    const bodyText = (element.innerText || element.textContent || '').trim();
    const htmlText = element.innerHTML || '';
    const anchorLinks = extractLinksFromAnchors([...element.querySelectorAll('a[href]')]);
    const textLinks = extractPotentialUrlsFromText(`${bodyText}\n${htmlText}`);
    return {
      bodyText,
      links: [...new Set([...anchorLinks, ...textLinks])]
    };
  }

  function buildCombinedEmailContext(bodies) {
    if (!Array.isArray(bodies) || !bodies.length) return null;
    const chunks = [];
    const allLinks = new Set();

    bodies.slice(-6).forEach((body) => {
      const context = extractBodyContext(body);
      if (!context) return;
      if (context.bodyText) chunks.push(context.bodyText);
      context.links.forEach((link) => allLinks.add(link));
    });

    const bodyText = chunks.join('\n\n').trim();
    return {
      bodyText,
      links: [...allLinks]
    };
  }

  function pickCurrentMessageBody(bodies) {
    if (!Array.isArray(bodies) || !bodies.length) return null;
    const sorted = [...bodies].sort((a, b) => {
      const rectA = a.getBoundingClientRect();
      const rectB = b.getBoundingClientRect();
      return rectB.top - rectA.top;
    });
    return sorted[0] || bodies[bodies.length - 1] || null;
  }

  function firstVisibleElement(selectors) {
    for (const selector of selectors) {
      const element = [...document.querySelectorAll(selector)].find(isVisible);
      if (element) return element;
    }
    return null;
  }

  function visibleElements(selectors) {
    const seen = new Set();
    const result = [];
    selectors.forEach((selector) => {
      document.querySelectorAll(selector).forEach((element) => {
        if (!seen.has(element) && isVisible(element) && (element.innerText || element.textContent || '').trim()) {
          seen.add(element);
          result.push(element);
        }
      });
    });
    return result;
  }

  function isVisible(element) {
    if (!element) return false;
    const style = window.getComputedStyle(element);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = element.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }

  function extractLinksFromAnchors(anchorElements) {
    const urls = new Set();
    anchorElements.forEach((anchor) => {
      const normalized = normalizeUrlCandidate(anchor.href || anchor.getAttribute('href') || '');
      if (normalized) urls.add(normalized);
    });
    return [...urls];
  }

  function normalizeUrlCandidate(value) {
    let candidate = String(value || '').trim();
    candidate = candidate.replace(/^[("'`<\[]+/, '').replace(/[)"'`>\].,;:!?]+$/, '');
    if (!candidate) return null;

    try {
      const parsed = new URL(candidate, location.href);
      if (parsed.hostname === 'www.google.com' && parsed.pathname === '/url') {
        candidate = parsed.searchParams.get('q') || parsed.searchParams.get('url') || candidate;
      } else if (parsed.hostname === 'safelinks.protection.outlook.com') {
        candidate = parsed.searchParams.get('url') || candidate;
      } else {
        candidate = parsed.toString();
      }
    } catch (_) {}

    candidate = candidate.replace(/^hxxps:\/\//i, 'https://');
    candidate = candidate.replace(/^hxxp:\/\//i, 'http://');
    candidate = candidate.replace(/\[\.\]|\(\.\)/g, '.');

    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(candidate)) {
      if (/^(?:www\.)?[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9][a-z0-9-]{0,62})+(?:\/\S*)?$/i.test(candidate)) {
        candidate = `https://${candidate}`;
      } else {
        return null;
      }
    }
    return candidate;
  }

  function extractPotentialUrlsFromText(text) {
    const patterns = [
      /\b(?:https?|hxxps?):\/\/[^\s<>"'`{}|\\^\[\]]+/gi,
      /(?<!@)\b(?:www\.)?[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9][a-z0-9-]{0,62})+(?:\/[^\s<>"'`{}|\\^\[\]]*)?/gi,
      /(?<!@)\b[a-z0-9][a-z0-9-]{0,62}(?:\[\.\]|\(\.\)|\.)[a-z0-9][a-z0-9-]{0,62}(?:(?:\[\.\]|\(\.\)|\.)[a-z0-9][a-z0-9-]{0,62})+(?:\/[^\s<>"'`{}|\\^\[\]]*)?/gi
    ];

    const urls = new Set();
    patterns.forEach((pattern) => {
      const matches = String(text || '').match(pattern) || [];
      matches.forEach((match) => {
        const normalized = normalizeUrlCandidate(match);
        if (normalized) urls.add(normalized);
      });
    });
    return [...urls];
  }

  async function scanEmail(subject, body, links) {
    try {
      const result = await chrome.runtime.sendMessage({
        action: 'scanEmail',
        payload: {
          content: body.substring(0, 12000),
          links,
          subject: subject || null,
          source: 'email'
        }
      });

      if (!result || result.error) {
        injectErrorBanner(result?.error || 'CYBERSHIELD email monitoring is temporarily unavailable.');
        return;
      }

      if (result.risk_score >= 25) {
        injectBanner(result);
      } else {
        removeBanner();
      }

      if (Array.isArray(result.scanned_links) && result.scanned_links.length) {
        markSuspiciousLinks(result.scanned_links);
      }
    } catch (err) {
      if (isExtensionContextInvalidated(err)) {
        cleanup();
        return;
      }
      console.error('[CYBERSHIELD] Email scan error:', err);
    }
  }

  function removeBanner() {
    const banner = document.getElementById('pg-email-banner');
    if (banner) banner.remove();
  }

  function injectErrorBanner(message) {
    const old = document.getElementById('pg-email-banner');
    if (old) old.remove();

    const banner = document.createElement('div');
    banner.id = 'pg-email-banner';
    Object.assign(banner.style, {
      position: 'fixed',
      top: '8px',
      right: '8px',
      zIndex: '2147483646',
      background: 'linear-gradient(135deg, #2b1620 0%, #1b1116 100%)',
      color: '#e8eaed',
      padding: '12px 18px',
      borderRadius: '12px',
      maxWidth: '360px',
      boxShadow: '0 8px 32px rgba(0,0,0,0.45)',
      border: '1px solid rgba(239,68,68,0.25)',
      fontFamily: 'system-ui, -apple-system, sans-serif',
      fontSize: '13px',
      lineHeight: '1.4',
      animation: 'pg-slideDown 0.3s ease'
    });

    banner.innerHTML = `
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
        <span style="color:#ef4444;font-size:16px;font-weight:700">CYBERSHIELD Setup Needed</span>
        <span style="margin-left:auto;cursor:pointer;color:#6b7280;font-size:18px" id="pg-banner-close">x</span>
      </div>
      <div style="color:#fca5a5">${escapeHtml(toUserFacingError(message))}</div>
    `;

    document.body.appendChild(banner);
    banner.querySelector('#pg-banner-close').addEventListener('click', () => banner.remove());
    setTimeout(() => { if (banner.parentNode) banner.remove(); }, 15000);
  }

  function injectBanner(result) {
    const old = document.getElementById('pg-email-banner');
    if (old) old.remove();

    const verdict = result.verdict || 'suspicious';
    const colors = {
      safe: '#22c55e',
      suspicious: '#f59e0b',
      phishing: '#ef4444',
      malware: '#ef4444'
    };
    const color = colors[verdict] || '#f59e0b';
    const icons = {
      safe: 'OK',
      suspicious: 'Warn',
      phishing: 'Block',
      malware: 'Block'
    };

    const banner = document.createElement('div');
    banner.id = 'pg-email-banner';
    Object.assign(banner.style, {
      position: 'fixed',
      top: '8px',
      right: '8px',
      zIndex: '2147483646',
      background: 'linear-gradient(135deg, #1e2230 0%, #181b23 100%)',
      color: '#e8eaed',
      padding: '12px 18px',
      borderRadius: '12px',
      maxWidth: '360px',
      boxShadow: '0 8px 32px rgba(0,0,0,0.45)',
      border: `1px solid ${color}33`,
      fontFamily: 'system-ui, -apple-system, sans-serif',
      fontSize: '13px',
      lineHeight: '1.4',
      animation: 'pg-slideDown 0.3s ease'
    });

    const blockDecision = result.block_decision || {};
    banner.innerHTML = `
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
        <span style="color:${color};font-size:16px;font-weight:700">${icons[verdict]} CYBERSHIELD</span>
        <span style="margin-left:auto;cursor:pointer;color:#6b7280;font-size:18px" id="pg-banner-close">x</span>
      </div>
      <div style="color:#9ca3af">
        This email appears <strong style="color:${color}">${escapeHtml(verdict)}</strong>
        with risk score <strong style="color:${color}">${result.risk_score}/100</strong>
      </div>
      <div style="margin-top:6px;color:#6b7280;font-size:11px">${escapeHtml(blockDecision.reason_summary || 'No detailed reason available.')}</div>
    `;

    document.body.appendChild(banner);
    banner.querySelector('#pg-banner-close').addEventListener('click', () => banner.remove());
    setTimeout(() => { if (banner.parentNode) banner.remove(); }, 15000);
  }

  function markSuspiciousLinks(scannedLinks) {
    const risky = scannedLinks.filter((item) => item.risk_score >= 25);
    if (!risky.length) return;

    const riskyMap = new Map(risky.map((item) => [item.url, item]));

    document.querySelectorAll('a[href]').forEach((anchor) => {
      const normalized = normalizeUrlCandidate(anchor.href || anchor.getAttribute('href') || '');
      const match = normalized ? riskyMap.get(normalized) : null;
      if (!match || anchor.querySelector('.pg-link-badge')) return;

      const color = match.risk_score >= 70 ? '#ef4444' : '#f59e0b';
      anchor.dataset.pgRisk = String(match.risk_score);
      anchor.dataset.pgVerdict = match.verdict || 'suspicious';
      anchor.dataset.pgNormalizedUrl = normalized;

      const badge = document.createElement('span');
      badge.className = 'pg-link-badge';
      Object.assign(badge.style, {
        display: 'inline-block',
        background: `${color}22`,
        color,
        borderRadius: '4px',
        padding: '1px 5px',
        fontSize: '10px',
        fontWeight: '700',
        marginLeft: '4px',
        verticalAlign: 'middle',
        border: `1px solid ${color}44`
      });
      badge.textContent = match.risk_score >= 61 ? 'block' : 'warn';
      badge.title = `CYBERSHIELD: ${match.verdict} (${match.risk_score}/100)`;
      anchor.appendChild(badge);
    });
  }

  function injectStyles() {
    if (document.getElementById('pg-email-styles')) return;
    const style = document.createElement('style');
    style.id = 'pg-email-styles';
    style.textContent = `
      @keyframes pg-slideDown { from { transform: translateY(-20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
    `;
    (document.head || document.documentElement).appendChild(style);
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
  }

  function hashStr(str) {
    let hash = 0;
    for (let index = 0; index < str.length; index += 1) {
      hash = ((hash << 5) - hash) + str.charCodeAt(index);
      hash |= 0;
    }
    return String(hash);
  }

  function isExtensionContextInvalidated(err) {
    return /Extension context invalidated/i.test(err?.message || '');
  }

  function toUserFacingError(message) {
    if (/Authentication failed/i.test(message || '')) {
      return 'Email auto-scan is blocked because the extension API key does not match the backend API_SECRET_KEY. Open CYBERSHIELD Options and verify the key.';
    }
    return message || 'Email auto-scan is temporarily unavailable.';
  }

  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'force_extract') {
      const context = collectEmailContext();
      sendResponse({ context });
    }
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
