/**
 * PhishGuard AI — Warning Page Controller
 * Reads threat data from URL parameters (set by service worker).
 * Does NOT call any backend endpoint.
 */

(() => {
  'use strict';

  const params = new URLSearchParams(window.location.search);
  const url = params.get('url') || '';
  const verdict = params.get('verdict') || 'phishing';
  const riskScore = parseInt(params.get('risk_score') || '0', 10);
  const reason = params.get('reason') || '';
  const overrideAllowed = params.get('override') === 'true';
  let flags = [];
  try { flags = JSON.parse(params.get('flags') || '[]'); } catch (_) {}

  /* ---- Determine color scheme ---- */
  const isSuspicious = verdict === 'suspicious';
  const color = isSuspicious ? '#f59e0b' : '#ef4444';
  const colorBg = isSuspicious ? 'rgba(245,158,11,0.12)' : 'rgba(239,68,68,0.12)';

  /* ---- Icons ---- */
  const iconWrap = document.getElementById('warning-icon-wrap');
  if (isSuspicious) iconWrap.classList.add('suspicious');

  /* ---- Title ---- */
  const titleEl = document.getElementById('warning-title');
  const titles = {
    safe: 'Page Flagged',
    suspicious: 'Suspicious Page',
    phishing: 'Phishing Detected',
    malware: 'Malware Detected'
  };
  titleEl.textContent = titles[verdict] || 'Threat Detected';
  if (isSuspicious) titleEl.classList.add('suspicious-title');

  /* ---- Subtitle ---- */
  const subtitles = {
    safe: 'This page has been flagged by CYBERSHIELD',
    suspicious: 'This page shows suspicious characteristics',
    phishing: 'This page has been identified as a phishing attempt',
    malware: 'This page may contain malicious software'
  };
  document.getElementById('warning-subtitle').textContent =
    subtitles[verdict] || 'CYBERSHIELD has blocked this page for your safety';

  /* ---- Verdict badge ---- */
  document.getElementById('warning-verdict').innerHTML = `
    <span class="verdict-badge-lg" style="color:${color};background:${colorBg};border:1px solid ${color}33">
      ${verdict.toUpperCase()}
    </span>
    <span class="risk-score-lg" style="color:${color};background:${colorBg};border:1px solid ${color}22">
      Risk: ${riskScore}/100
    </span>
  `;

  /* ---- URL ---- */
  document.getElementById('warning-url').textContent = url || 'Unknown URL';

  /* ---- Reason ---- */
  if (reason) {
    const reasonWrap = document.getElementById('warning-reason-wrap');
    reasonWrap.style.display = 'block';
    document.getElementById('warning-reason').textContent = reason;
    if (isSuspicious) {
      document.getElementById('warning-reason').style.borderLeftColor = 'rgba(245,158,11,0.4)';
    }
  }

  /* ---- Flags ---- */
  if (flags.length > 0) {
    const flagsEl = document.getElementById('warning-flags');
    flagsEl.style.display = 'block';
    flagsEl.innerHTML = flags.map(f => `
      <div class="warning-flag">
        <div class="warning-flag-dot" style="background:${color}"></div>
        ${escapeHtml(typeof f === 'string' ? f : f.description || f.rule || JSON.stringify(f))}
      </div>
    `).join('');
  }

  /* ---- Go Back ---- */
  document.getElementById('btn-go-back').addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
    }
  });

  /* ---- Proceed Anyway ---- */
  if (overrideAllowed) {
    const proceedBtn = document.getElementById('btn-proceed');
    proceedBtn.style.display = 'block';

    proceedBtn.addEventListener('click', async () => {
      if (!url) return;

      try {
        await chrome.runtime.sendMessage({
          action: 'setProceedOverride',
          payload: { url, duration: 300000 }
        });
      } catch (_) {}

      window.location.href = url;
    });
  }

  /* ---- Util ---- */
  function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = str || '';
    return d.innerHTML;
  }

  /* ---- Page title ---- */
  document.title = `Warning — ${verdict} — CYBERSHIELD`;
})();
