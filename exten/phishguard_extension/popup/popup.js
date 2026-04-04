/**
 * PhishGuard AI - Popup Controller
 */

let popupRefreshTimer = null;
let storageListener = null;

document.addEventListener('DOMContentLoaded', async () => {
  await Theme.init();
  initTabs();
  bindActions();
  bindFileUploads();
  registerLiveSync();
  await syncPopup();
});

window.addEventListener('beforeunload', () => {
  if (popupRefreshTimer) clearInterval(popupRefreshTimer);
  if (storageListener) chrome.storage.onChanged.removeListener(storageListener);
});

async function syncPopup() {
  await Promise.all([
    checkConnection(),
    loadCurrentTab(),
    loadRecentActivity(),
    loadToggles(),
  ]);
}

function registerLiveSync() {
  if (!storageListener) {
    storageListener = async (changes, areaName) => {
      if (areaName === 'session' && changes.currentTabState) {
        await loadCurrentTab();
      }
      if (areaName === 'local' && (changes.recentActivity || changes.scanCache)) {
        await Promise.all([loadRecentActivity(), loadCurrentTab()]);
      }
    };
    chrome.storage.onChanged.addListener(storageListener);
  }

  popupRefreshTimer = setInterval(() => {
    syncPopup().catch(() => {});
  }, 4000);
}

/* ================================================================== */
/*  Connection status                                                  */
/* ================================================================== */

async function checkConnection() {
  const dot = document.getElementById('status-dot');
  const text = document.getElementById('status-text');

  try {
    const resp = await chrome.runtime.sendMessage({ action: 'healthCheck' });
    if (resp && resp.status === 'ok') {
      dot.className = 'status-dot connected';
      text.textContent = 'Connected';
      return;
    }
    throw new Error('Health check failed');
  } catch (_) {
    dot.className = 'status-dot error';
    text.textContent = 'Disconnected';
  }
}

/* ================================================================== */
/*  Current tab                                                        */
/* ================================================================== */

async function loadCurrentTab() {
  const urlEl = document.getElementById('tab-url');
  const verdictEl = document.getElementById('tab-verdict');

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) {
      urlEl.textContent = 'No active tab';
      verdictEl.innerHTML = UI.emptyState('Open a tab to scan', 'Tab');
      return;
    }

    urlEl.textContent = tab.url || 'This tab cannot be scanned';
    urlEl.title = tab.url || '';

    const state = await chrome.runtime.sendMessage({ action: 'getCurrentTabState' });
    if (state && state.result && state.tabId === tab.id) {
      renderTabVerdict(state.result, verdictEl, state.contentType);
      return;
    }

    verdictEl.innerHTML = '<div class="pg-text-muted">No scan result yet</div>';
  } catch (_) {
    urlEl.textContent = 'Unable to read tab';
    verdictEl.innerHTML = '<div class="pg-text-muted">Scan state unavailable</div>';
  }
}

function renderTabVerdict(result, container, contentType = 'url') {
  if (!result) {
    container.innerHTML = '';
    return;
  }

  const action = result.block_decision?.action || 'allow';
  const reason = result.block_decision?.reason_summary || 'No detailed reason available.';

  container.innerHTML = `
    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:4px">
      ${UI.verdictBadge(result.verdict)}
      ${UI.riskBadge(result.risk_score)}
      ${UI.sourceBadge(contentType === 'chat' ? 'whatsapp' : contentType === 'email' ? 'email' : 'browser')}
      ${result.campaign ? UI.campaignBadge(result.campaign) : ''}
    </div>
    <div style="margin-top:8px;font-size:11px;color:var(--pg-text-secondary)">
      Confidence ${UI.formatPct(result.confidence)} · ${UI.formatMs(result.detection_time_ms)} · Action ${UI.escapeHtml(action)}
    </div>
    <div style="margin-top:6px;font-size:11px;color:var(--pg-text-muted)">
      ${UI.escapeHtml(reason)}
    </div>
  `;
}

/* ================================================================== */
/*  Scan current page                                                  */
/* ================================================================== */

async function scanCurrentPage() {
  const btn = document.getElementById('btn-scan-page');
  const verdictEl = document.getElementById('tab-verdict');

  btn.disabled = true;
  btn.innerHTML = `${UI.spinner(14)} Scanning...`;
  verdictEl.innerHTML = '';

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url || (!tab.url.startsWith('http://') && !tab.url.startsWith('https://'))) {
      UI.showToast('Cannot scan this page', 'warning');
      return;
    }

    let result = null;
    let contentType = 'url';

    if (tab.url.startsWith('https://mail.google.com/') || 
        tab.url.startsWith('https://outlook.live.com/') || 
        tab.url.startsWith('https://outlook.office.com/')) {
        try {
            const response = await chrome.tabs.sendMessage(tab.id, { action: 'force_extract' });
            if (response && response.context) {
                const { subject, body, links } = response.context;
                result = await chrome.runtime.sendMessage({
                    action: 'scanEmail',
                    payload: { content: body || '', links: links || [], subject: subject || null, source: 'email' }
                });
                contentType = 'email';
            }
        } catch (e) { console.warn("Email scan override failed:", e); }
    } else if (tab.url.startsWith('https://web.whatsapp.com/')) {
        try {
            const response = await chrome.tabs.sendMessage(tab.id, { action: 'force_extract' });
            if (response && response.context) {
                const { sender, content, links } = response.context;
                result = await chrome.runtime.sendMessage({
                    action: 'scanChat',
                    payload: { content: content || '', links: links || [], sender: sender || null, source: 'whatsapp' }
                });
                contentType = 'chat';
            }
        } catch (e) { console.warn("Whatsapp scan override failed:", e); }
    }

    if (!result) {
        result = await chrome.runtime.sendMessage({
          action: 'scanUrl',
          payload: { url: tab.url, source: 'browser' }
        });
        contentType = 'url';
    }

    if (result && !result.error) {
      renderTabVerdict(result, verdictEl, contentType);
      UI.showToast(`Verdict: ${result.verdict}`, result.verdict === 'safe' ? 'success' : 'warning');
      await loadRecentActivity();
      return;
    }

    UI.showToast(result?.error || 'Scan failed', 'error');
  } catch (err) {
    UI.showToast(`Scan failed: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      Scan This Page
    `;
  }
}

/* ================================================================== */
/*  Analyze tabs                                                       */
/* ================================================================== */

function initTabs() {
  const tabs = document.querySelectorAll('.analyze-tab');
  const panels = document.querySelectorAll('.analyze-panel');

  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      tabs.forEach((item) => item.classList.remove('active'));
      panels.forEach((panel) => panel.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(`panel-${tab.dataset.tab}`).classList.add('active');
      document.getElementById('analyze-result').classList.remove('visible');
    });
  });
}

function initSandboxModeToggle() {
  const buttons = document.querySelectorAll('.sandbox-mode-btn');
  const urlFields = document.getElementById('sandbox-fields-url');
  const fileFields = document.getElementById('sandbox-fields-file');

  buttons.forEach((button) => {
    button.addEventListener('click', () => {
      buttons.forEach((item) => item.classList.remove('active'));
      button.classList.add('active');
      const mode = button.dataset.mode;
      urlFields.classList.toggle('active', mode === 'url');
      fileFields.classList.toggle('active', mode === 'file');
    });
  });
}

/* ================================================================== */
/*  File upload helpers                                                */
/* ================================================================== */

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const base64 = reader.result.split(',')[1];
      resolve(base64);
    };
    reader.onerror = () => reject(new Error('Failed to read file'));
    reader.readAsDataURL(file);
  });
}

async function filesToAttachments(fileInput) {
  const files = Array.from(fileInput.files || []);
  if (files.length === 0) return [];

  const attachments = [];
  for (const file of files) {
    if (file.size > 15 * 1024 * 1024) {
      UI.showToast(`File "${file.name}" exceeds 15MB limit`, 'warning');
      continue;
    }
    const content_base64 = await fileToBase64(file);
    attachments.push({
      filename: file.name,
      content_base64,
      mime_type: file.type || null
    });
  }
  return attachments;
}

function bindFileUploads() {
  // Email attachment file count display
  const emailInput = document.getElementById('file-upload-email');
  if (emailInput) {
    emailInput.addEventListener('change', () => {
      const info = document.getElementById('file-upload-email-info');
      const count = emailInput.files.length;
      info.textContent = count > 0 ? `${count} file${count > 1 ? 's' : ''} selected` : '';
    });
  }

  // Chat attachment file count display
  const chatInput = document.getElementById('file-upload-chat');
  if (chatInput) {
    chatInput.addEventListener('change', () => {
      const info = document.getElementById('file-upload-chat-info');
      const count = chatInput.files.length;
      info.textContent = count > 0 ? `${count} file${count > 1 ? 's' : ''} selected` : '';
    });
  }

  // Attachment tab file input + drop zone
  const attInput = document.getElementById('file-upload-attachment');
  const dropZone = document.getElementById('file-drop-zone');
  const attBtn = document.getElementById('btn-analyze-attachment');
  const attInfo = document.getElementById('attachment-file-info');

  if (dropZone && attInput) {
    dropZone.addEventListener('click', () => attInput.click());

    dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropZone.classList.add('file-drop-active');
    });
    dropZone.addEventListener('dragleave', () => {
      dropZone.classList.remove('file-drop-active');
    });
    dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropZone.classList.remove('file-drop-active');
      if (e.dataTransfer.files.length > 0) {
        attInput.files = e.dataTransfer.files;
        attInput.dispatchEvent(new Event('change'));
      }
    });

    attInput.addEventListener('change', () => {
      const file = attInput.files[0];
      if (file) {
        if (file.size > 15 * 1024 * 1024) {
          UI.showToast('File exceeds 15MB limit', 'warning');
          attInput.value = '';
          attBtn.disabled = true;
          attInfo.innerHTML = '';
          return;
        }
        attBtn.disabled = false;
        attInfo.innerHTML = `
          <div class="file-selected-card">
            <span class="file-selected-name">📎 ${UI.escapeHtml(file.name)}</span>
            <span class="file-selected-size">${UI.formatFileSize(file.size)}</span>
            <button class="file-selected-remove" onclick="clearAttachmentFile()" title="Remove">✕</button>
          </div>`;
      } else {
        attBtn.disabled = true;
        attInfo.innerHTML = '';
      }
    });
  }

  const sandboxInput = document.getElementById('file-upload-sandbox');
  const sandboxZone = document.getElementById('sandbox-drop-zone');
  const sandboxInfo = document.getElementById('sandbox-file-info');

  if (sandboxZone && sandboxInput) {
    sandboxZone.addEventListener('click', () => sandboxInput.click());
    sandboxZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      sandboxZone.classList.add('file-drop-active');
    });
    sandboxZone.addEventListener('dragleave', () => {
      sandboxZone.classList.remove('file-drop-active');
    });
    sandboxZone.addEventListener('drop', (e) => {
      e.preventDefault();
      sandboxZone.classList.remove('file-drop-active');
      if (e.dataTransfer.files.length > 0) {
        sandboxInput.files = e.dataTransfer.files;
        sandboxInput.dispatchEvent(new Event('change'));
      }
    });
    sandboxInput.addEventListener('change', () => {
      const file = sandboxInput.files[0];
      if (!file) {
        sandboxInfo.innerHTML = '';
        return;
      }
      if (file.size > 15 * 1024 * 1024) {
        UI.showToast('File exceeds 15MB limit', 'warning');
        sandboxInput.value = '';
        sandboxInfo.innerHTML = '';
        return;
      }
      sandboxInfo.innerHTML = `
        <div class="file-selected-card">
          <span class="file-selected-name">📎 ${UI.escapeHtml(file.name)}</span>
          <span class="file-selected-size">${UI.formatFileSize(file.size)}</span>
          <button class="file-selected-remove" onclick="clearSandboxFile()" title="Remove">✕</button>
        </div>`;
    });
  }
}

function clearAttachmentFile() {
  const attInput = document.getElementById('file-upload-attachment');
  const attBtn = document.getElementById('btn-analyze-attachment');
  const attInfo = document.getElementById('attachment-file-info');
  if (attInput) attInput.value = '';
  if (attBtn) attBtn.disabled = true;
  if (attInfo) attInfo.innerHTML = '';
}

function clearSandboxFile() {
  const sandboxInput = document.getElementById('file-upload-sandbox');
  const sandboxInfo = document.getElementById('sandbox-file-info');
  if (sandboxInput) sandboxInput.value = '';
  if (sandboxInfo) sandboxInfo.innerHTML = '';
}

/* ================================================================== */
/*  Manual analyze helpers                                             */
/* ================================================================== */

function normalizeUrlCandidate(value) {
  let candidate = String(value || '').trim();
  candidate = candidate.replace(/^[("'`<\[]+/, '').replace(/[)"'`>\].,;:!?]+$/, '');
  candidate = candidate.replace(/^hxxps:\/\//i, 'https://');
  candidate = candidate.replace(/^hxxp:\/\//i, 'http://');
  candidate = candidate.replace(/\[\.\]|\(\.\)/g, '.');

  if (!candidate) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(candidate)) return candidate;
  if (/^(?:www\.)?[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9][a-z0-9-]{0,62})+(?:\/\S*)?$/i.test(candidate)) {
    return `https://${candidate}`;
  }
  return null;
}

function extractPotentialUrlsFromText(text) {
  const patterns = [
    /\b(?:https?|hxxps?):\/\/[^\s<>"'`{}|\\^\[\]]+/gi,
    /(?<!@)\b(?:www\.)?[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9][a-z0-9-]{0,62})+(?:\/[^\s<>"'`{}|\\^\[\]]*)?/gi,
    /(?<!@)\b[a-z0-9][a-z0-9-]{0,62}(?:\[\.\]|\(\.\)|\.)([a-z0-9][a-z0-9-]{0,62})(?:(?:\[\.\]|\(\.\)|\.)([a-z0-9][a-z0-9-]{0,62}))+(?:\/[^\s<>"'`{}|\\^\[\]]*)?/gi,
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

function getSandboxResult(result) {
  return result?.falcon_result || result?.engines?.falcon_sandbox || null;
}

function renderSandboxBehaviorCards(sandbox) {
  if (!sandbox) return '';

  const malicious = sandbox.malicious || /malicious|phishing|malware|suspicious/i.test(String(sandbox.verdict || ''));
  const networkSeen = (Number(sandbox.domains_count || 0) + Number(sandbox.hosts_count || 0)) > 0;
  const droppedFiles = Number(sandbox.extracted_files_count || 0) > 0;
  const multiArtifact = Number(sandbox.related_submissions || 0) > 1;

  const items = [
    {
      label: 'Malicious Behavior',
      value: malicious ? 'Observed' : 'Not Strongly Observed',
      tone: malicious ? 'danger' : 'safe',
      hint: malicious ? 'Sandbox verdict suggests phishing/malware behavior.' : 'No strong malicious behavior was confirmed.'
    },
    {
      label: 'Network Activity',
      value: networkSeen ? `${Number(sandbox.domains_count || 0)} domains / ${Number(sandbox.hosts_count || 0)} hosts` : 'No network activity reported',
      tone: networkSeen ? 'warning' : 'neutral',
      hint: networkSeen ? 'Behavior included external infrastructure contact.' : 'No meaningful external contact was reported.'
    },
    {
      label: 'Dropped Files',
      value: droppedFiles ? `${Number(sandbox.extracted_files_count || 0)} extracted` : 'No extra files',
      tone: droppedFiles ? 'danger' : 'safe',
      hint: droppedFiles ? 'Additional file artifacts were observed.' : 'No dropped or extracted files were reported.'
    },
    {
      label: 'Artifact Spread',
      value: multiArtifact ? `${Number(sandbox.related_submissions || 0)} related submissions` : 'Single artifact',
      tone: multiArtifact ? 'warning' : 'neutral',
      hint: multiArtifact ? 'The root scan produced multiple sandboxed child artifacts.' : 'Only one sandboxed artifact was involved.'
    }
  ];

  return `
    <div class="sandbox-insight-grid">
      ${items.map((item) => `
        <div class="sandbox-insight-card sandbox-${item.tone}">
          <div class="sandbox-insight-label">${UI.escapeHtml(item.label)}</div>
          <div class="sandbox-insight-value">${UI.escapeHtml(item.value)}</div>
          <div class="sandbox-insight-hint">${UI.escapeHtml(item.hint)}</div>
        </div>
      `).join('')}
    </div>
  `;
}

function renderSandboxCompact(result) {
  const sandbox = getSandboxResult(result);
  if (!sandbox) return '';

  const status = String(sandbox.status || (sandbox.enabled ? 'ok' : 'disabled')).toUpperCase();
  const verdict = sandbox.verdict || 'No verdict';
  const threatScore = sandbox.threat_score != null ? `${sandbox.threat_score}/100` : '—';
  const providerNote = sandbox.error
    ? `<div class="sandbox-inline-note">${UI.escapeHtml(sandbox.error)}</div>`
    : '';

  return `
    <div class="sandbox-inline-card">
      <div class="sandbox-inline-header">
        <span class="sandbox-inline-title">Sandbox</span>
        <span class="sandbox-inline-status">${UI.escapeHtml(status)}</span>
      </div>
      <div class="sandbox-inline-meta">
        <span>${UI.escapeHtml(verdict)}</span>
        <span>Threat ${UI.escapeHtml(threatScore)}</span>
        <span>${Number(sandbox.domains_count || 0)} domains</span>
        <span>${Number(sandbox.extracted_files_count || 0)} files</span>
      </div>
      ${renderSandboxBehaviorCards(sandbox)}
      ${providerNote}
    </div>
  `;
}

function renderSandboxCompact(result) {
  const sandbox = getSandboxResult(result);
  if (!sandbox) return '';

  const status = String(sandbox.status || (sandbox.enabled ? 'ok' : 'disabled')).toUpperCase();
  const verdict = sandbox.verdict || 'No verdict';
  const threatScore = sandbox.threat_score != null ? `${sandbox.threat_score}/100` : '—';
  const observedArtifact = (sandbox.redirect_urls || [])[0]
    || (sandbox.domains || [])[0]
    || (sandbox.extracted_files || [])[0]
    || null;
  const providerNote = sandbox.error
    ? `<div class="sandbox-inline-note">${UI.escapeHtml(sandbox.error)}</div>`
    : '';

  return `
    <div class="sandbox-inline-card">
      <div class="sandbox-inline-header">
        <span class="sandbox-inline-title">Sandbox</span>
        <span class="sandbox-inline-status">${UI.escapeHtml(status)}</span>
      </div>
      <div class="sandbox-inline-meta">
        <span>${UI.escapeHtml(verdict)}</span>
        <span>Threat ${UI.escapeHtml(threatScore)}</span>
        <span>${Number(sandbox.domains_count || 0)} domains</span>
        <span>${Number(sandbox.redirect_urls_count || 0)} redirects</span>
        <span>${Number(sandbox.extracted_files_count || 0)} files</span>
      </div>
      ${renderSandboxBehaviorCards(sandbox)}
      ${observedArtifact ? `<div class="sandbox-inline-note">Observed artifact: ${UI.escapeHtml(String(observedArtifact))}</div>` : ''}
      ${providerNote}
    </div>
  `;
}

/* ================================================================== */
/*  Manual analyze                                                     */
/* ================================================================== */

async function analyzeUrl() {
  const input = document.getElementById('input-url').value.trim();
  if (!input) {
    UI.showToast('Enter a URL', 'warning');
    return;
  }

  const urls = Array.from(new Set(
    input
      .split(/[\n\r,]+/)
      .map((value) => normalizeUrlCandidate(value))
      .filter(Boolean)
  ));

  if (!urls.length) {
    UI.showToast('Enter a valid URL or domain', 'warning');
    return;
  }

  const btn = document.getElementById('btn-analyze-url');
  btn.disabled = true;
  btn.textContent = 'Scanning...';

  try {
    if (urls.length === 1) {
      const result = await chrome.runtime.sendMessage({
        action: 'scanUrl',
        payload: { url: urls[0], source: 'manual' }
      });
      showAnalyzeResult(result);
    } else {
      const result = await chrome.runtime.sendMessage({
        action: 'scanBatch',
        payload: { urls, source: 'manual' }
      });
      showBatchResult(result);
    }
    await loadRecentActivity();
  } catch (err) {
    UI.showToast(`Analysis failed: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Analyze';
  }
}

async function analyzeEmail() {
  const content = document.getElementById('input-email-content').value.trim();
  if (!content) {
    UI.showToast('Enter email content', 'warning');
    return;
  }

  const subject = document.getElementById('input-email-subject').value.trim() || null;
  const links = extractPotentialUrlsFromText(content);
  const btn = document.getElementById('btn-analyze-email');
  btn.disabled = true;
  btn.textContent = 'Scanning...';

  try {
    const fileInput = document.getElementById('file-upload-email');
    const attachments = await filesToAttachments(fileInput);

    const result = await chrome.runtime.sendMessage({
      action: 'scanEmail',
      payload: { content, links, attachments, subject, source: 'email' }
    });
    showAnalyzeResult(result);
    await loadRecentActivity();
  } catch (err) {
    UI.showToast(`Analysis failed: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Analyze Email';
  }
}

async function analyzeChat() {
  const content = document.getElementById('input-chat-content').value.trim();
  if (!content) {
    UI.showToast('Enter chat content', 'warning');
    return;
  }

  const sender = document.getElementById('input-chat-sender').value.trim() || null;
  const links = extractPotentialUrlsFromText(content);
  const btn = document.getElementById('btn-analyze-chat');
  btn.disabled = true;
  btn.textContent = 'Scanning...';

  try {
    const fileInput = document.getElementById('file-upload-chat');
    const attachments = await filesToAttachments(fileInput);

    const result = await chrome.runtime.sendMessage({
      action: 'scanChat',
      payload: { content, links, attachments, sender, source: 'whatsapp' }
    });
    showAnalyzeResult(result);
    await loadRecentActivity();
  } catch (err) {
    UI.showToast(`Analysis failed: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Analyze Chat';
  }
}

async function analyzeAttachment() {
  const fileInput = document.getElementById('file-upload-attachment');
  const file = fileInput.files[0];
  if (!file) {
    UI.showToast('Select a file to scan', 'warning');
    return;
  }

  const btn = document.getElementById('btn-analyze-attachment');
  btn.disabled = true;
  btn.textContent = 'Scanning...';
  const resultContainer = document.getElementById('analyze-result');
  resultContainer.innerHTML = `<div class="result-card" style="text-align:center">${UI.spinner(24)}<div style="margin-top:8px;font-size:11px;color:var(--pg-text-muted)">Analyzing ${UI.escapeHtml(file.name)}…</div></div>`;
  resultContainer.classList.add('visible');

  try {
    const content_base64 = await fileToBase64(file);
    const contextLabel = document.getElementById('input-attachment-label').value.trim() || null;

    const result = await API.scanAttachment({
      attachment: {
        filename: file.name,
        content_base64,
        mime_type: file.type || null
      },
      source: 'manual',
      context_label: contextLabel
    });

    showAttachmentResult(result);
    // Track in local activity
    try {
      await Storage.addRecentActivity({
        type: 'attachment',
        url: result.filename || file.name,
        verdict: result.verdict,
        risk_score: result.risk_score,
        source: 'manual'
      });
    } catch (_) {}
    await loadRecentActivity();
  } catch (err) {
    UI.showToast(`Analysis failed: ${err.message}`, 'error');
    resultContainer.innerHTML = `<div class="result-card"><span style="color:var(--pg-danger)">Error: ${UI.escapeHtml(err.message)}</span></div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Analyze File';
  }
}

async function analyzeSandbox() {
  const activeMode = document.querySelector('.sandbox-mode-btn.active')?.dataset.mode || 'url';
  const btn = document.getElementById('btn-run-sandbox');
  const resultContainer = document.getElementById('analyze-result');

  btn.disabled = true;
  btn.textContent = 'Running...';
  resultContainer.innerHTML = `<div class="result-card" style="text-align:center">${UI.spinner(24)}<div style="margin-top:8px;font-size:11px;color:var(--pg-text-muted)">Running behavioral analysis…</div></div>`;
  resultContainer.classList.add('visible');

  try {
    let result;
    if (activeMode === 'url') {
      const rawUrl = document.getElementById('input-sandbox-url').value.trim();
      const url = normalizeUrlCandidate(rawUrl);
      if (!url) {
        UI.showToast('Enter a valid URL or domain', 'warning');
        resultContainer.classList.remove('visible');
        return;
      }
      result = await chrome.runtime.sendMessage({
        action: 'scanUrl',
        payload: { url, source: 'manual', analysis_mode: 'sandbox' }
      });
    } else {
      const fileInput = document.getElementById('file-upload-sandbox');
      const file = fileInput.files[0];
      if (!file) {
        UI.showToast('Select a file for sandbox analysis', 'warning');
        resultContainer.classList.remove('visible');
        return;
      }
      const content_base64 = await fileToBase64(file);
      const contextLabel = document.getElementById('input-sandbox-label').value.trim() || null;
      result = await API.scanAttachment({
        attachment: {
          filename: file.name,
          content_base64,
          mime_type: file.type || null
        },
        source: 'manual',
        context_label: contextLabel
      });
    }

    showSandboxFocusedResult(result);
    await loadRecentActivity();
  } catch (err) {
    UI.showToast(`Sandbox failed: ${err.message}`, 'error');
    resultContainer.innerHTML = `<div class="result-card"><span style="color:var(--pg-danger)">Error: ${UI.escapeHtml(err.message)}</span></div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run Sandbox';
  }
}

function showSandboxFocusedResult(result) {
  const container = document.getElementById('analyze-result');
  if (!result || result.error) {
    container.innerHTML = `<div class="result-card"><span style="color:var(--pg-danger)">Error: ${UI.escapeHtml(result?.error || 'Unknown')}</span></div>`;
    container.classList.add('visible');
    return;
  }

  const sandbox = getSandboxResult(result);
  const reason = result.block_decision?.reason_summary || 'No summary available.';

  container.innerHTML = `
    <div class="result-card">
      <div class="result-header">
        ${UI.scoreGauge(result.risk_score || 0, 48)}
        <div>
          <div>${UI.verdictBadge(result.verdict)}</div>
          <div class="result-meta" style="margin-top:4px">
            <span>Confidence: ${UI.formatPct(result.confidence)}</span>
            <span>${UI.formatMs(result.detection_time_ms)}</span>
          </div>
        </div>
      </div>
      <div style="font-size:11px;color:var(--pg-text-secondary);margin-bottom:8px">${UI.escapeHtml(reason)}</div>
      ${sandbox ? renderSandboxCompact(result) : `<div class="sandbox-inline-note">No sandbox payload was returned for this artifact.</div>`}
      ${UI.renderFlags(result.flags)}
    </div>
  `;
  container.classList.add('visible');
}

function showAttachmentResult(result) {
  const container = document.getElementById('analyze-result');
  if (!result || result.error) {
    container.innerHTML = `<div class="result-card"><span style="color:var(--pg-danger)">Error: ${UI.escapeHtml(result?.error || 'Unknown')}</span></div>`;
    container.classList.add('visible');
    return;
  }

  const extractedCount = (result.extracted_urls || []).length;

  container.innerHTML = `
    <div class="result-card">
      <div class="result-header">
        ${UI.scoreGauge(result.risk_score || 0, 48)}
        <div>
          <div>${UI.verdictBadge(result.verdict)}</div>
          <div class="result-meta" style="margin-top:4px">
            <span>Confidence: ${UI.formatPct(result.confidence)}</span>
            <span>${UI.formatMs(result.detection_time_ms)}</span>
          </div>
        </div>
      </div>
      <div class="att-result-meta">
        <div class="att-meta-row"><span class="att-meta-label">File</span><span>${UI.escapeHtml(result.filename || '—')}</span></div>
        <div class="att-meta-row"><span class="att-meta-label">Detected Type</span><span>${UI.escapeHtml(result.detected_type || result.mime_type || '—')}</span></div>
        <div class="att-meta-row"><span class="att-meta-label">Size</span><span>${UI.formatFileSize(result.file_size)}</span></div>
        <div class="att-meta-row"><span class="att-meta-label">Password Protected</span><span>${result.password_protected ? '🔒 Yes' : 'No'}</span></div>
        <div class="att-meta-row"><span class="att-meta-label">SHA-256</span><span>${UI.truncateHash(result.sha256, 16)}</span></div>
        <div class="att-meta-row"><span class="att-meta-label">Extracted URLs</span><span>${extractedCount}</span></div>
      </div>
      ${result.campaign ? `<div style="margin-top:8px">${UI.campaignBadge(result.campaign)}</div>` : ''}
      ${renderSandboxCompact(result)}
      ${UI.renderFlags(result.flags)}
      ${result.score_breakdown && result.score_breakdown.length > 0 ? `
        <div style="margin-top:10px">
          <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.5px;color:var(--pg-text-muted);margin-bottom:6px">Score Breakdown</div>
          ${UI.renderScoreBreakdown(result.score_breakdown)}
        </div>
      ` : ''}
    </div>
  `;
  container.classList.add('visible');
}

function showAnalyzeResult(result) {
  const container = document.getElementById('analyze-result');
  if (!result || result.error) {
    container.innerHTML = `<div class="result-card"><span style="color:var(--pg-danger)">Error: ${UI.escapeHtml(result?.error || 'Unknown')}</span></div>`;
    container.classList.add('visible');
    return;
  }

  const reason = result.block_decision?.reason_summary || 'No summary available.';

  // Scanned links
  const linksHtml = Array.isArray(result.scanned_links) && result.scanned_links.length
    ? `
      <div style="margin-top:10px">
        <div style="font-size:11px;color:var(--pg-text-secondary);margin-bottom:6px">Scanned links</div>
        ${result.scanned_links.slice(0, 4).map((item) => `
          <div style="display:flex;align-items:center;gap:8px;margin-top:6px">
            ${UI.verdictBadge(item.verdict)}
            <span style="font-size:11px;color:var(--pg-text-muted)">${UI.escapeHtml(UI.truncateUrl(item.url, 48))}</span>
          </div>
        `).join('')}
      </div>
    `
    : '';

  // Scanned attachments
  const attachmentsHtml = Array.isArray(result.scanned_attachments) && result.scanned_attachments.length
    ? `
      <div style="margin-top:10px">
        <div style="font-size:11px;color:var(--pg-text-secondary);margin-bottom:6px">Scanned Attachments</div>
        ${result.scanned_attachments.slice(0, 3).map(att => `
          <div class="compact-att-card">
            <span class="compact-att-name">📎 ${UI.escapeHtml(att.filename || 'file')}</span>
            ${UI.verdictBadge(att.verdict)}
            <span style="font-size:10px;color:var(--pg-text-muted)">${UI.formatFileSize(att.file_size)}</span>
          </div>
        `).join('')}
      </div>
    `
    : '';

  // Campaign badge
  const campaignHtml = result.campaign
    ? `<div style="margin-top:8px">${UI.campaignBadge(result.campaign)}</div>`
    : '';

  // Score breakdown (compact for popup)
  const breakdownHtml = result.score_breakdown && result.score_breakdown.length > 0
    ? `
      <div style="margin-top:10px">
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.5px;color:var(--pg-text-muted);margin-bottom:6px">Score Breakdown</div>
        ${UI.renderScoreBreakdown(result.score_breakdown)}
      </div>
    `
    : '';

  container.innerHTML = `
    <div class="result-card">
      <div class="result-header">
        ${UI.scoreGauge(result.risk_score || 0, 48)}
        <div>
          <div>${UI.verdictBadge(result.verdict)}</div>
          <div class="result-meta" style="margin-top:4px">
            <span>Confidence: ${UI.formatPct(result.confidence)}</span>
            <span>${UI.formatMs(result.detection_time_ms)}</span>
          </div>
        </div>
      </div>
      <div style="font-size:11px;color:var(--pg-text-secondary);margin-bottom:8px">${UI.escapeHtml(reason)}</div>
      ${campaignHtml}
      ${renderSandboxCompact(result)}
      ${UI.renderFlags(result.flags)}
      ${linksHtml}
      ${attachmentsHtml}
      ${breakdownHtml}
    </div>
  `;
  container.classList.add('visible');
}

function showBatchResult(results) {
  const container = document.getElementById('analyze-result');
  if (!Array.isArray(results)) {
    container.innerHTML = '<div class="result-card"><span style="color:var(--pg-danger)">Unexpected response</span></div>';
    container.classList.add('visible');
    return;
  }

  container.innerHTML = results.map((item) => `
    <div class="result-card" style="margin-bottom:6px">
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        ${UI.verdictBadge(item.verdict)}
        ${UI.riskBadge(item.risk_score)}
        ${item.campaign ? UI.campaignBadge(item.campaign) : ''}
      </div>
      <div style="font-size:11px;color:var(--pg-text-muted);margin-top:4px">${UI.escapeHtml(UI.truncateUrl(item.url, 60))}</div>
    </div>
  `).join('');
  container.classList.add('visible');
}

/* ================================================================== */
/*  Recent activity                                                    */
/* ================================================================== */

async function loadRecentActivity() {
  const feed = document.getElementById('recent-feed');

  try {
    const items = await chrome.runtime.sendMessage({ action: 'getRecentActivity' });
    if (!items || items.length === 0) {
      feed.innerHTML = UI.emptyState('No recent scans');
      return;
    }

    const sourceIcons = { browser: 'Web', email: 'Mail', whatsapp: 'Chat', manual: 'Manual', attachment: 'File' };
    feed.innerHTML = items.slice(0, 5).map((item) => {
      const color = UI.verdictColor(item.verdict);
      const bg = UI.verdictBg(item.verdict);
      const icon = UI.verdictIcon(item.verdict);
      const timeAgo = UI.formatTimestamp(item._ts ? new Date(item._ts).toISOString() : null);

      return `
        <div class="feed-item">
          <div class="feed-icon" style="background:${bg};color:${color}">${icon}</div>
          <div class="feed-info">
            <div class="feed-url">${UI.escapeHtml(sourceIcons[item.source] || item.source || 'Scan')} · ${UI.escapeHtml(UI.truncateUrl(item.url, 42))}</div>
            <div class="feed-time">${UI.escapeHtml(item.verdict)} · ${item.risk_score}/100 · ${timeAgo}</div>
          </div>
        </div>
      `;
    }).join('');
  } catch (_) {
    feed.innerHTML = UI.emptyState('Unable to load activity');
  }
}

/* ================================================================== */
/*  Toggles                                                            */
/* ================================================================== */

async function loadToggles() {
  const settings = await Storage.getSettings();
  document.getElementById('toggle-auto').checked = settings.autoMonitoring;
  document.getElementById('toggle-links').checked = settings.linkMonitoring;
  document.getElementById('toggle-email').checked = settings.emailMonitoring;
  document.getElementById('toggle-whatsapp').checked = settings.whatsappMonitoring;
  document.getElementById('toggle-notif').checked = settings.notificationsEnabled;
}

function bindToggle(id, key) {
  document.getElementById(id).addEventListener('change', async (event) => {
    await Storage.saveSettings({ [key]: event.target.checked });
  });
}

/* ================================================================== */
/*  Bind actions                                                       */
/* ================================================================== */

function bindActions() {
  document.getElementById('btn-scan-page').addEventListener('click', scanCurrentPage);
  document.getElementById('btn-analyze-url').addEventListener('click', analyzeUrl);
  document.getElementById('btn-analyze-email').addEventListener('click', analyzeEmail);
  document.getElementById('btn-analyze-chat').addEventListener('click', analyzeChat);
  document.getElementById('btn-analyze-attachment').addEventListener('click', analyzeAttachment);
  document.getElementById('btn-run-sandbox').addEventListener('click', analyzeSandbox);

  document.getElementById('btn-dashboard').addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'openDashboard' });
  });
  document.getElementById('btn-options').addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'openOptions' });
  });

  bindToggle('toggle-auto', 'autoMonitoring');
  bindToggle('toggle-links', 'linkMonitoring');
  bindToggle('toggle-email', 'emailMonitoring');
  bindToggle('toggle-whatsapp', 'whatsappMonitoring');
  bindToggle('toggle-notif', 'notificationsEnabled');
  initSandboxModeToggle();
}
