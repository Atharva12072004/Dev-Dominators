/**
 * PhishGuard AI - WhatsApp Web Monitor Content Script
 */

(() => {
  'use strict';

  try {
    if (typeof window.__pgWhatsappMonitorCleanup === 'function') {
      window.__pgWhatsappMonitorCleanup();
    }
  } catch (_) {}

  const SCAN_DEBOUNCE_MS = 1200;
  const RESCAN_INTERVAL_MS = 3000;
  const scannedFingerprints = new Set();
  const knownMessageKeys = new Set();
  const pendingMessageKeys = new Set();
  const MUTATION_GRACE_MS = 2500;
  const MAX_CONTEXT_MESSAGES = 4;
  let debounceTimer = null;
  let primeTimer = null;
  let intervalId = null;
  let settings = null;
  let observer = null;
  let lastFingerprint = '';
  let lastScannedMessageSignature = '';
  let activeConversationKey = '';
  let ignoreMutationsUntil = 0;
  let conversationPrimed = false;
  let bootstrapConversationScan = false;
  let started = false;

  function onDocumentClick() {
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
    if (!settings || !settings.autoMonitoring || !settings.whatsappMonitoring) return;

    injectStyles();
    primeKnownMessages();
    startObserver();
    document.addEventListener('click', onDocumentClick, true);
    document.addEventListener('visibilitychange', onVisibilityChange);
    intervalId = window.setInterval(() => {
      scheduleScan();
    }, RESCAN_INTERVAL_MS);
    syncConversationState();
    scheduleScan();
  }

  function cleanup() {
    clearTimeout(debounceTimer);
    clearTimeout(primeTimer);
    if (intervalId) {
      clearInterval(intervalId);
      intervalId = null;
    }
    if (observer) {
      observer.disconnect();
      observer = null;
    }
    document.removeEventListener('click', onDocumentClick, true);
    document.removeEventListener('visibilitychange', onVisibilityChange);
    started = false;
  }

  window.__pgWhatsappMonitorCleanup = cleanup;

  function startObserver() {
    observer = new MutationObserver((mutations) => {
      handleMutations(mutations);
      scheduleScan();
    });
    observer.observe(document.body, { childList: true, subtree: true, attributes: true, characterData: true });
  }

  function scheduleScan() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(checkForMessages, SCAN_DEBOUNCE_MS);
  }

  function checkForMessages() {
    if (document.visibilityState !== 'visible') return;
    syncConversationState();
    captureVisiblePendingMessages();
    const context = collectChatContext();
    if (!context) return;

    const fingerprint = hashStr(`${context.sender}|${context.content.slice(0, 500)}|${context.links.join(',')}`);
    if (!fingerprint || fingerprint === lastFingerprint || scannedFingerprints.has(fingerprint)) return;
    lastFingerprint = fingerprint;
    scannedFingerprints.add(fingerprint);

    if (scannedFingerprints.size > 150) {
      const first = scannedFingerprints.values().next().value;
      scannedFingerprints.delete(first);
    }

    scanChat(context.content, context.links, context.sender);
  }

  function handleMutations(mutations) {
    syncConversationState();
    if (Date.now() < ignoreMutationsUntil) return;
    mutations.forEach((mutation) => {
      mutation.addedNodes.forEach((node) => {
        capturePendingFromNode(node);
      });
      capturePendingFromNode(mutation.target);
    });
  }

  function syncConversationState() {
    const nextConversationKey = getConversationKey();
    if (!nextConversationKey) return;
    if (nextConversationKey === activeConversationKey) return;

    activeConversationKey = nextConversationKey;
    knownMessageKeys.clear();
    pendingMessageKeys.clear();
    conversationPrimed = false;
    bootstrapConversationScan = true;
    lastScannedMessageSignature = '';
    ignoreMutationsUntil = Date.now() + MUTATION_GRACE_MS;
    clearTimeout(primeTimer);
    primeTimer = window.setTimeout(() => {
      if (activeConversationKey === nextConversationKey) {
        primeKnownMessages();
        conversationPrimed = true;
      }
    }, MUTATION_GRACE_MS + 150);

    const unreadMessages = collectUnreadIncomingMessages();
    if (unreadMessages.length) {
      unreadMessages.forEach((message) => {
        const key = getMessageKey(message);
        if (key) pendingMessageKeys.add(key);
      });
    } else {
      primeKnownMessages();
      conversationPrimed = true;
    }
  }

  function primeKnownMessages() {
    visibleElements(['[data-testid="msg-container"]', '[data-pre-plain-text]', '.message-in']).forEach((element) => {
      if (!isIncomingMessage(element)) return;
      const key = getMessageKey(element);
      if (key) knownMessageKeys.add(key);
    });
  }

  function collectChatContext(force = false) {
    const sender = getConversationTitle();
    const pendingMessages = collectPendingIncomingMessages(force);
    const shouldUseBootstrapFallback = force || bootstrapConversationScan;
    const messageContainers = pendingMessages.length
      ? pendingMessages
      : (shouldUseBootstrapFallback ? collectRecentIncomingMessages() : []);
    if (!messageContainers.length) return null;

    const messageSignature = buildMessageSignature(messageContainers);
    if (!force && messageSignature && messageSignature === lastScannedMessageSignature) return null;

    const chunks = [];
    const anchorLinks = [];
    messageContainers.forEach((container) => {
      const text = container.innerText || container.textContent || '';
      if (text.trim()) chunks.push(text.trim());
      anchorLinks.push(...extractLinksFromAnchors([...container.querySelectorAll('a[href]')]));
    });

    const content = chunks.join('\n').trim();
    const textLinks = extractPotentialUrlsFromText(content);
    const links = [...new Set([...anchorLinks, ...textLinks])];

    if (!content && !links.length) return null;
    if (!links.length && content.length < 8) return null;

    if (!force) {
      messageContainers.forEach((container) => {
        const key = getMessageKey(container);
        if (key) {
          pendingMessageKeys.delete(key);
          knownMessageKeys.add(key);
        }
      });
      bootstrapConversationScan = false;
      lastScannedMessageSignature = messageSignature;
    }

    return {
      sender,
      content: content.slice(0, 12000),
      links
    };
  }

  function collectPendingIncomingMessages(force = false) {
    const messageMap = new Map();
    visibleElements(['[data-testid="msg-container"]', '[data-pre-plain-text]', '.message-in']).forEach((element) => {
      if (!isIncomingMessage(element)) return;
      const key = getMessageKey(element);
      if (!key) return;
      if (force || pendingMessageKeys.has(key)) {
        messageMap.set(key, element);
      }
    });
    return selectLatestIncomingCluster([...messageMap.values()]);
  }

  function collectRecentIncomingMessages() {
    const orderedMessages = visibleElements(['[data-testid="msg-container"]', '[data-pre-plain-text]', '.message-in', '.message-out'])
      .filter(isMessageContainer)
      .sort(compareMessagePosition);

    const cluster = [];
    for (let index = orderedMessages.length - 1; index >= 0; index -= 1) {
      const element = orderedMessages[index];
      if (!isBottomClusterCandidate(element)) {
        if (cluster.length) break;
        continue;
      }
      if (!isIncomingMessage(element)) {
        if (cluster.length) break;
        continue;
      }
      cluster.unshift(element);
      if (cluster.length >= MAX_CONTEXT_MESSAGES) break;
    }

    return dedupeElements(cluster);
  }

  function captureVisiblePendingMessages() {
    if (!conversationPrimed || Date.now() < ignoreMutationsUntil) return;
    const candidates = visibleElements(['[data-testid="msg-container"]', '[data-pre-plain-text]', '.message-in'])
      .filter((element) => isIncomingMessage(element) && isRecentViewportMessage(element))
      .slice(-4);

    candidates.forEach((element) => {
      const key = getMessageKey(element);
      if (!key || knownMessageKeys.has(key)) return;
      pendingMessageKeys.add(key);
    });
  }

  function collectUnreadIncomingMessages() {
    const separator = findUnreadSeparator();
    if (!separator) return [];

    const messages = [];
    let current = separator.nextElementSibling;
    while (current) {
      collectIncomingMessageElements(current).forEach((element) => {
        if (isIncomingMessage(element)) messages.push(element);
      });
      current = current.nextElementSibling;
    }
    return dedupeElements(messages);
  }

  function findUnreadSeparator() {
    const candidates = [
      '[data-testid="unread-marker"]',
      '[aria-label*="unread" i]',
      '[title*="unread" i]'
    ];
    for (const selector of candidates) {
      const element = [...document.querySelectorAll(selector)].find(isVisible);
      if (element) return element;
    }
    return [...document.querySelectorAll('div, span')].find((element) => {
      if (!isVisible(element)) return false;
      const text = (element.textContent || '').trim().toLowerCase();
      return text === 'unread messages' || text === '1 unread message';
    }) || null;
  }

  function collectIncomingMessageElements(root) {
    const elements = [];
    const base = root instanceof Text ? root.parentElement : root;
    if (!(base instanceof Element)) return elements;
    if (isMessageContainer(base) && isIncomingMessage(base)) {
      elements.push(base);
    }
    const container = base.closest?.('[data-testid="msg-container"], [data-pre-plain-text], .message-in');
    if (container && isIncomingMessage(container)) {
      elements.push(container);
    }
    base.querySelectorAll?.('[data-testid="msg-container"], [data-pre-plain-text], .message-in').forEach((element) => {
      if (isIncomingMessage(element)) elements.push(element);
    });
    return dedupeElements(elements);
  }

  function capturePendingFromNode(node) {
    collectIncomingMessageElements(node).forEach((element) => {
      const key = getMessageKey(element);
      if (!key || knownMessageKeys.has(key)) return;
      pendingMessageKeys.add(key);
    });
  }

  function dedupeElements(elements) {
    const seen = new Set();
    return elements.filter((element) => {
      if (seen.has(element)) return false;
      seen.add(element);
      return true;
    });
  }

  function selectLatestIncomingCluster(elements) {
    const ordered = dedupeElements(elements)
      .filter(isIncomingMessage)
      .sort(compareMessagePosition);

    const cluster = [];
    for (let index = ordered.length - 1; index >= 0; index -= 1) {
      const element = ordered[index];
      if (!isBottomClusterCandidate(element) && cluster.length === 0) continue;
      cluster.unshift(element);
      if (cluster.length >= MAX_CONTEXT_MESSAGES) break;
    }
    return cluster;
  }

  function buildMessageSignature(elements) {
    const keys = elements
      .map((element) => getMessageKey(element))
      .filter(Boolean);
    return keys.join('|');
  }

  function isMessageContainer(element) {
    return element.matches?.('[data-testid="msg-container"], [data-pre-plain-text], .message-in, .message-out');
  }

  function isIncomingMessage(element) {
    if (!element) return false;
    if (element.classList?.contains('message-out')) return false;
    if (element.classList?.contains('message-in')) return true;
    const className = typeof element.className === 'string' ? element.className : '';
    if (className.includes('message-out')) return false;
    if (className.includes('message-in')) return true;
    const dataPrePlainText = element.getAttribute('data-pre-plain-text') || '';
    return dataPrePlainText.includes(']') && !dataPrePlainText.includes('You:');
  }

  function getConversationKey() {
    return getConversationTitle() || location.pathname || 'whatsapp-chat';
  }

  function getMessageKey(element) {
    if (!element) return '';
    const directId = element.getAttribute('data-id')
      || element.getAttribute('data-message-id')
      || element.id;
    if (directId) return `${activeConversationKey || getConversationKey()}::${directId}`;

    const prePlain = element.getAttribute('data-pre-plain-text') || '';
    const text = (element.innerText || element.textContent || '').replace(/\s+/g, ' ').trim();
    if (!text) return '';
    return `${activeConversationKey || getConversationKey()}::${hashStr(`${prePlain}|${text.slice(0, 500)}`)}`;
  }

  function getConversationTitle() {
    const candidates = [
      'header span[title]',
      '[data-testid="conversation-header"] span[title]',
      'header [dir="auto"]',
      '#main header span[dir="auto"]'
    ];
    for (const selector of candidates) {
      const element = [...document.querySelectorAll(selector)].find(isVisible);
      if (element) {
        return (element.getAttribute('title') || element.textContent || '').trim() || null;
      }
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

  function isRecentViewportMessage(element) {
    const rect = element.getBoundingClientRect();
    return rect.bottom >= window.innerHeight * 0.45;
  }

  function isBottomClusterCandidate(element) {
    const rect = element.getBoundingClientRect();
    return rect.bottom >= window.innerHeight * 0.65;
  }

  function compareMessagePosition(left, right) {
    const rectLeft = left.getBoundingClientRect();
    const rectRight = right.getBoundingClientRect();
    return rectLeft.top - rectRight.top;
  }

  function extractLinksFromAnchors(anchorElements) {
    const urls = new Set();
    anchorElements.forEach((anchor) => {
      const normalized = normalizeUrlCandidate(anchor.href || anchor.getAttribute('href') || '');
      if (normalized && !normalized.includes('web.whatsapp.com')) urls.add(normalized);
    });
    return [...urls];
  }

  function normalizeUrlCandidate(value) {
    let candidate = String(value || '').trim();
    candidate = candidate.replace(/^[("'`<\[]+/, '').replace(/[)"'`>\].,;:!?]+$/, '');
    if (!candidate) return null;

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

    try {
      return new URL(candidate, location.href).toString();
    } catch (_) {
      return candidate;
    }
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

  async function scanChat(content, links, sender) {
    try {
      const result = await chrome.runtime.sendMessage({
        action: 'scanChat',
        payload: {
          content: content.substring(0, 12000),
          links,
          sender: sender || null,
          source: 'whatsapp'
        }
      });

      if (!result || result.error) {
        injectErrorBanner(result?.error || 'CYBERSHIELD chat monitoring is temporarily unavailable.');
        return;
      }

      if (result.risk_score >= 25) {
        injectBanner(result, sender);
      } else {
        removeBanner();
      }

      if (Array.isArray(result.scanned_links) && result.scanned_links.length) {
        markSuspiciousLinks(result.scanned_links);
        annotateMessageBubbles(result.scanned_links);
      }
    } catch (err) {
      if (isExtensionContextInvalidated(err)) {
        cleanup();
        return;
      }
      console.error('[CYBERSHIELD] Chat scan error:', err);
    }
  }

  function removeBanner() {
    const banner = document.getElementById('pg-wa-banner');
    if (banner) banner.remove();
  }

  function injectErrorBanner(message) {
    const old = document.getElementById('pg-wa-banner');
    if (old) old.remove();

    const banner = document.createElement('div');
    banner.id = 'pg-wa-banner';
    Object.assign(banner.style, {
      position: 'fixed',
      top: '8px',
      right: '8px',
      zIndex: '2147483646',
      background: 'linear-gradient(135deg, #2b1620 0%, #1b1116 100%)',
      color: '#e8eaed',
      padding: '12px 18px',
      borderRadius: '12px',
      maxWidth: '340px',
      boxShadow: '0 8px 32px rgba(0,0,0,0.45)',
      border: '1px solid rgba(239,68,68,0.25)',
      fontFamily: 'system-ui, -apple-system, sans-serif',
      fontSize: '13px',
      lineHeight: '1.4',
      animation: 'pg-waSlideDown 0.3s ease'
    });

    banner.innerHTML = `
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
        <span style="color:#ef4444;font-size:15px;font-weight:700">CYBERSHIELD Setup Needed</span>
        <span style="margin-left:auto;cursor:pointer;color:#6b7280;font-size:18px" id="pg-wa-close">x</span>
      </div>
      <div style="color:#fca5a5">${escapeHtml(toUserFacingError(message))}</div>
    `;

    document.body.appendChild(banner);
    banner.querySelector('#pg-wa-close').addEventListener('click', () => banner.remove());
    setTimeout(() => { if (banner.parentNode) banner.remove(); }, 12000);
  }

  function injectBanner(result, sender) {
    const old = document.getElementById('pg-wa-banner');
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
    banner.id = 'pg-wa-banner';
    Object.assign(banner.style, {
      position: 'fixed',
      top: '8px',
      right: '8px',
      zIndex: '2147483646',
      background: 'linear-gradient(135deg, #1e2230 0%, #181b23 100%)',
      color: '#e8eaed',
      padding: '12px 18px',
      borderRadius: '12px',
      maxWidth: '340px',
      boxShadow: '0 8px 32px rgba(0,0,0,0.45)',
      border: `1px solid ${color}33`,
      fontFamily: 'system-ui, -apple-system, sans-serif',
      fontSize: '13px',
      lineHeight: '1.4',
      animation: 'pg-waSlideDown 0.3s ease'
    });

    const blockDecision = result.block_decision || {};
    banner.innerHTML = `
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
        <span style="color:${color};font-size:15px;font-weight:700">${icons[verdict]} CYBERSHIELD</span>
        <span style="margin-left:auto;cursor:pointer;color:#6b7280;font-size:18px" id="pg-wa-close">x</span>
      </div>
      <div style="color:#9ca3af">
        ${sender ? `Chat with <strong style="color:#e8eaed">${escapeHtml(sender)}</strong> - ` : ''}
        <strong style="color:${color}">${escapeHtml(verdict)}</strong>
        (risk ${result.risk_score}/100)
      </div>
      <div style="margin-top:4px;color:#6b7280;font-size:11px">${escapeHtml(blockDecision.reason_summary || 'No detailed reason available.')}</div>
    `;

    document.body.appendChild(banner);
    banner.querySelector('#pg-wa-close').addEventListener('click', () => banner.remove());
    setTimeout(() => { if (banner.parentNode) banner.remove(); }, 12000);
  }

  function markSuspiciousLinks(scannedLinks) {
    const riskyMap = new Map(
      scannedLinks
        .filter((item) => item.risk_score >= 25)
        .map((item) => [item.url, item])
    );

    document.querySelectorAll('a[href]').forEach((anchor) => {
      const normalized = normalizeUrlCandidate(anchor.href || anchor.getAttribute('href') || '');
      const match = normalized ? riskyMap.get(normalized) : null;
      if (!match || anchor.querySelector('.pg-wa-badge')) return;

      const color = match.risk_score >= 70 ? '#ef4444' : '#f59e0b';
      anchor.dataset.pgRisk = String(match.risk_score);
      anchor.dataset.pgVerdict = match.verdict || 'suspicious';
      anchor.dataset.pgNormalizedUrl = normalized;

      const badge = document.createElement('span');
      badge.className = 'pg-wa-badge';
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

  function annotateMessageBubbles(scannedLinks) {
    const risky = scannedLinks.filter((item) => item.risk_score >= 25);
    if (!risky.length) return;

    const riskyUrls = risky.map((item) => item.url);
    visibleElements(['[data-testid="msg-container"]', '[data-pre-plain-text]', '.message-in', '.message-out']).forEach((container) => {
      const text = container.innerText || container.textContent || '';
      const match = risky.find((item) => text.includes(item.url) || text.includes(stripProtocol(item.url)));
      if (!match || container.querySelector('.pg-wa-bubble-badge')) return;

      const color = match.risk_score >= 70 ? '#ef4444' : '#f59e0b';
      const badge = document.createElement('div');
      badge.className = 'pg-wa-bubble-badge';
      Object.assign(badge.style, {
        marginTop: '6px',
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        padding: '4px 8px',
        borderRadius: '999px',
        background: `${color}18`,
        color,
        border: `1px solid ${color}33`,
        fontSize: '10px',
        fontWeight: '700'
      });
      badge.textContent = match.risk_score >= 61 ? 'CYBERSHIELD block' : 'CYBERSHIELD warn';
      container.appendChild(badge);
    });
  }

  function stripProtocol(value) {
    return String(value || '').replace(/^https?:\/\//i, '');
  }

  function injectStyles() {
    if (document.getElementById('pg-wa-styles')) return;
    const style = document.createElement('style');
    style.id = 'pg-wa-styles';
    style.textContent = `
      @keyframes pg-waSlideDown { from { transform: translateY(-20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
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
      return 'WhatsApp Web monitoring is blocked because the extension API key does not match the backend API_SECRET_KEY. Open CYBERSHIELD Options and verify the key.';
    }
    return message || 'WhatsApp Web monitoring is temporarily unavailable.';
  }

  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'force_extract') {
      syncConversationState();
      const context = collectChatContext(true); // force true
      sendResponse({ context });
    }
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
