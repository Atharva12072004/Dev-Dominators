/**
 * PhishGuard AI — Reusable UI helpers
 * Shared across popup, dashboard, options, and warning pages.
 */

const UI = (() => {

  /* ------------------------------------------------------------------ */
  /*  Escape HTML                                                        */
  /* ------------------------------------------------------------------ */
  function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  }

  /* ------------------------------------------------------------------ */
  /*  Verdict / Risk colours                                              */
  /* ------------------------------------------------------------------ */
  const VERDICT_COLORS = {
    safe:       '#22c55e',
    suspicious: '#f59e0b',
    phishing:   '#ef4444',
    malware:    '#ef4444'
  };

  const VERDICT_BG = {
    safe:       'rgba(34,197,94,0.12)',
    suspicious: 'rgba(245,158,11,0.12)',
    phishing:   'rgba(239,68,68,0.12)',
    malware:    'rgba(239,68,68,0.12)'
  };

  const VERDICT_ICONS = {
    safe:       '✓',
    suspicious: '⚠',
    phishing:   '✕',
    malware:    '☠'
  };

  const SEVERITY_COLORS = {
    low:    '#6b7280',
    medium: '#f59e0b',
    high:   '#ef4444'
  };

  function verdictColor(verdict) {
    return VERDICT_COLORS[verdict] || '#6b7280';
  }

  function verdictBg(verdict) {
    return VERDICT_BG[verdict] || 'rgba(107,114,128,0.12)';
  }

  function verdictIcon(verdict) {
    return VERDICT_ICONS[verdict] || '?';
  }

  function riskColor(score) {
    if (score >= 70) return '#ef4444';
    if (score >= 40) return '#f59e0b';
    return '#22c55e';
  }

  function riskLabel(score) {
    if (score >= 70) return 'High Risk';
    if (score >= 40) return 'Medium Risk';
    return 'Low Risk';
  }

  function severityColor(sev) {
    return SEVERITY_COLORS[sev] || '#6b7280';
  }

  /* ------------------------------------------------------------------ */
  /*  Badge rendering                                                    */
  /* ------------------------------------------------------------------ */
  function verdictBadge(verdict) {
    const color = verdictColor(verdict);
    const bg = verdictBg(verdict);
    const icon = verdictIcon(verdict);
    return `<span class="pg-badge" style="color:${color};background:${bg};border:1px solid ${color}22">
      <span class="pg-badge-icon">${icon}</span> ${escapeHtml(verdict || 'unknown')}
    </span>`;
  }

  function severityBadge(severity) {
    const color = severityColor(severity);
    return `<span class="pg-badge pg-badge-sm" style="color:${color};background:${color}18;border:1px solid ${color}33">
      ${escapeHtml(severity || 'unknown')}
    </span>`;
  }

  function riskBadge(score) {
    const color = riskColor(score);
    const label = riskLabel(score);
    return `<span class="pg-badge" style="color:${color};background:${color}18;border:1px solid ${color}33">
      ${score} — ${label}
    </span>`;
  }

  function sourceBadge(source) {
    const icons = { browser: '🌐', email: '✉', whatsapp: '💬', manual: '🔍' };
    const icon = icons[source] || '📄';
    return `<span class="pg-badge pg-badge-sm pg-badge-source">${icon} ${escapeHtml(source || 'unknown')}</span>`;
  }

  /* ------------------------------------------------------------------ */
  /*  Score gauge  (SVG ring)                                            */
  /* ------------------------------------------------------------------ */
  function scoreGauge(score, size = 64) {
    const color = riskColor(score);
    const r = (size - 8) / 2;
    const circ = 2 * Math.PI * r;
    const offset = circ - (score / 100) * circ;
    return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" class="pg-gauge">
      <circle cx="${size/2}" cy="${size/2}" r="${r}" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="6"/>
      <circle cx="${size/2}" cy="${size/2}" r="${r}" fill="none" stroke="${color}" stroke-width="6"
        stroke-dasharray="${circ}" stroke-dashoffset="${offset}"
        stroke-linecap="round" transform="rotate(-90 ${size/2} ${size/2})"
        style="transition:stroke-dashoffset .6s ease"/>
      <text x="${size/2}" y="${size/2}" text-anchor="middle" dominant-baseline="central"
        fill="${color}" font-size="${size * 0.28}px" font-weight="700">${score}</text>
    </svg>`;
  }

  /* ------------------------------------------------------------------ */
  /*  Mini bar chart  (SVG)                                              */
  /* ------------------------------------------------------------------ */
  function miniBarChart(data, { width = 320, height = 120, barColor = '#3b82f6' } = {}) {
    if (!data || data.length === 0) return emptyState('No chart data available');
    const max = Math.max(...data.map(d => d.value), 1);
    const gap = 4;
    const barW = Math.max(4, (width - gap * (data.length - 1)) / data.length);
    let svg = `<svg width="${width}" height="${height + 24}" class="pg-chart">`;
    data.forEach((d, i) => {
      const bh = (d.value / max) * height;
      const x = i * (barW + gap);
      const y = height - bh;
      svg += `<rect x="${x}" y="${y}" width="${barW}" height="${bh}" rx="3" fill="${d.color || barColor}" opacity="0.85">
        <title>${escapeHtml(d.label || '')}: ${d.value}</title>
      </rect>`;
      if (data.length <= 14) {
        svg += `<text x="${x + barW/2}" y="${height + 16}" text-anchor="middle" fill="var(--pg-text-muted)" font-size="9">${escapeHtml(d.label || '')}</text>`;
      }
    });
    svg += '</svg>';
    return svg;
  }

  /* ------------------------------------------------------------------ */
  /*  Donut chart  (SVG)                                                 */
  /* ------------------------------------------------------------------ */
  function donutChart(segments, { size = 160, thickness = 22 } = {}) {
    const total = segments.reduce((s, seg) => s + seg.value, 0);
    if (total === 0) return emptyState('No data yet');
    const r = (size - thickness) / 2;
    const circ = 2 * Math.PI * r;
    let acc = 0;
    let svg = `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" class="pg-donut">`;
    svg += `<circle cx="${size/2}" cy="${size/2}" r="${r}" fill="none" stroke="rgba(255,255,255,0.04)" stroke-width="${thickness}"/>`;
    segments.forEach(seg => {
      const pct = seg.value / total;
      const dash = pct * circ;
      const offset = -acc * circ + circ * 0.25;
      svg += `<circle cx="${size/2}" cy="${size/2}" r="${r}" fill="none" stroke="${seg.color}" stroke-width="${thickness}"
        stroke-dasharray="${dash} ${circ - dash}" stroke-dashoffset="${offset}"
        stroke-linecap="butt" style="transition:stroke-dasharray .5s ease">
        <title>${escapeHtml(seg.label)}: ${seg.value}</title>
      </circle>`;
      acc += pct;
    });
    svg += `<text x="${size/2}" y="${size/2}" text-anchor="middle" dominant-baseline="central" fill="var(--pg-text)" font-size="22" font-weight="700">${total}</text>`;
    svg += `<text x="${size/2}" y="${size/2 + 18}" text-anchor="middle" fill="var(--pg-text-muted)" font-size="10">total</text>`;
    svg += '</svg>';
    return svg;
  }

  /* ------------------------------------------------------------------ */
  /*  Empty state                                                        */
  /* ------------------------------------------------------------------ */
  function emptyState(msg, icon = '📭') {
    return `<div class="pg-empty">
      <div class="pg-empty-icon">${icon}</div>
      <div class="pg-empty-msg">${escapeHtml(msg)}</div>
    </div>`;
  }

  /* ------------------------------------------------------------------ */
  /*  Loading spinner                                                    */
  /* ------------------------------------------------------------------ */
  function spinner(size = 32) {
    return `<div class="pg-spinner" style="width:${size}px;height:${size}px"></div>`;
  }

  /* ------------------------------------------------------------------ */
  /*  Timestamp formatting                                               */
  /* ------------------------------------------------------------------ */
  function parseTimestamp(value) {
    if (!value) return null;
    if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
    const raw = String(value).trim();
    if (!raw) return null;
    const normalized = /(?:z|[+-]\d{2}:\d{2})$/i.test(raw) ? raw : `${raw}Z`;
    const parsed = new Date(normalized);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }

  function formatTimestamp(iso) {
    const d = parseTimestamp(iso);
    if (!d) return '—';
    const now = new Date();
    const diff = now - d;
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    if (diff < 604800000) return `${Math.floor(diff / 86400000)}d ago`;
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: d.getFullYear() !== now.getFullYear() ? 'numeric' : undefined });
  }

  function formatDate(iso) {
    const d = parseTimestamp(iso);
    if (!d) return '—';
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  }

  function formatMs(ms) {
    if (ms == null) return '—';
    if (ms < 1000) return `${Math.round(ms)}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
  }

  /* ------------------------------------------------------------------ */
  /*  Truncate URL                                                       */
  /* ------------------------------------------------------------------ */
  function truncateUrl(url, max = 50) {
    if (!url) return '—';
    if (url.length <= max) return url;
    return url.substring(0, max - 3) + '…';
  }

  /* ------------------------------------------------------------------ */
  /*  Percentage display                                                 */
  /* ------------------------------------------------------------------ */
  function formatPct(val) {
    if (val == null) return '—';
    return (val * 100).toFixed(1) + '%';
  }

  function formatPctRaw(val) {
    if (val == null) return '—';
    return val.toFixed(1) + '%';
  }

  /* ------------------------------------------------------------------ */
  /*  Toast notification                                                 */
  /* ------------------------------------------------------------------ */
  function showToast(msg, type = 'info', duration = 3000) {
    let container = document.getElementById('pg-toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'pg-toast-container';
      document.body.appendChild(container);
    }
    const el = document.createElement('div');
    el.className = `pg-toast pg-toast-${type}`;
    el.textContent = msg;
    container.appendChild(el);
    requestAnimationFrame(() => el.classList.add('pg-toast-visible'));
    setTimeout(() => {
      el.classList.remove('pg-toast-visible');
      setTimeout(() => el.remove(), 300);
    }, duration);
  }

  /* ------------------------------------------------------------------ */
  /*  Flag list rendering                                                */
  /* ------------------------------------------------------------------ */
  function renderFlags(flags) {
    if (!flags || flags.length === 0) return '<div class="pg-text-muted">No flags raised</div>';
    return `<div class="pg-flags">${flags.map(f => `
      <div class="pg-flag">
        <span class="pg-flag-sev" style="color:${severityColor(f.severity)}">${escapeHtml(f.severity || '')}</span>
        <span class="pg-flag-rule">${escapeHtml(f.rule || '')}</span>
        <span class="pg-flag-desc">${escapeHtml(f.description || '')}</span>
      </div>
    `).join('')}</div>`;
  }

  /* ------------------------------------------------------------------ */
  /*  File size formatting                                               */
  /* ------------------------------------------------------------------ */
  function formatFileSize(bytes) {
    if (bytes == null || bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const val = bytes / Math.pow(1024, i);
    return `${val < 10 ? val.toFixed(1) : Math.round(val)} ${units[i]}`;
  }

  /* ------------------------------------------------------------------ */
  /*  Hash truncation with copy support                                  */
  /* ------------------------------------------------------------------ */
  function truncateHash(hash, maxLen = 16) {
    if (!hash) return '—';
    if (hash.length <= maxLen) return escapeHtml(hash);
    const id = 'hash-' + Math.random().toString(36).slice(2, 8);
    return `<span class="pg-hash-display" id="${id}">
      <code class="pg-hash-text">${escapeHtml(hash.slice(0, maxLen))}…</code>
      <button class="pg-hash-copy" onclick="navigator.clipboard.writeText('${escapeHtml(hash)}').then(()=>{this.textContent='✓';setTimeout(()=>this.textContent='⧉',1500)})" title="Copy full hash">⧉</button>
    </span>`;
  }

  /* ------------------------------------------------------------------ */
  /*  Copy to clipboard                                                  */
  /* ------------------------------------------------------------------ */
  function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
      showToast('Copied to clipboard', 'success', 1500);
    }).catch(() => {
      showToast('Copy failed', 'error');
    });
  }

  /* ------------------------------------------------------------------ */
  /*  Campaign badge                                                     */
  /* ------------------------------------------------------------------ */
  function campaignBadge(campaign) {
    if (!campaign) return '';
    return `<span class="pg-badge pg-badge-campaign" title="Campaign cluster">
      <span class="pg-badge-icon">🎯</span>
      ${escapeHtml(campaign.key || 'Unknown')}
      <span class="pg-campaign-count">${campaign.size || 0}</span>
    </span>`;
  }

  /* ------------------------------------------------------------------ */
  /*  Malware-aware verdict color                                        */
  /* ------------------------------------------------------------------ */
  function verdictColorFull(verdict) {
    if (verdict === 'malware') return '#b91c1c';
    return verdictColor(verdict);
  }

  /* ------------------------------------------------------------------ */
  /*  Score breakdown rendering                                          */
  /* ------------------------------------------------------------------ */
  function renderScoreBreakdown(breakdown) {
    if (!breakdown || breakdown.length === 0) {
      return emptyState('No score breakdown available', '📊');
    }
    const maxPts = Math.max(...breakdown.map(b => Math.abs(b.points || 0)), 1);
    const sorted = [...breakdown].sort((a, b) => Math.abs(b.points) - Math.abs(a.points));

    return `<div class="pg-breakdown">
      ${sorted.map(item => {
        const pct = Math.min(Math.abs(item.points || 0) / maxPts * 100, 100);
        const sevColor = severityColor(item.severity || 'low');
        return `<div class="pg-breakdown-row">
          <div class="pg-breakdown-header">
            <span class="pg-breakdown-signal">${escapeHtml(item.signal || '')}</span>
            <span class="pg-breakdown-points" style="color:${sevColor}">
              ${item.points > 0 ? '+' : ''}${item.points != null ? item.points.toFixed(1) : '0'} pts
            </span>
          </div>
          <div class="pg-breakdown-bar-track">
            <div class="pg-breakdown-bar-fill" style="width:${pct}%;background:${sevColor};"></div>
          </div>
          <div class="pg-breakdown-desc">${escapeHtml(item.description || '')}</div>
        </div>`;
      }).join('')}
    </div>`;
  }

  /* ------------------------------------------------------------------ */
  /*  Attack chain timeline                                              */
  /* ------------------------------------------------------------------ */
  function renderAttackChain(chain) {
    if (!chain || !chain.steps || chain.steps.length === 0) {
      return emptyState('No attack chain data', '🔗');
    }
    const sorted = [...chain.steps].sort((a, b) => (a.step_order || 0) - (b.step_order || 0));
    return `<div class="pg-attack-chain">
      <div class="pg-chain-summary">
        <span>${escapeHtml(chain.summary || 'Attack Chain')}</span>
        ${verdictBadge(chain.verdict)}
        ${riskBadge(chain.risk_score)}
      </div>
      <div class="pg-chain-timeline">
        ${sorted.map((step, idx) => {
          const vColor = verdictColorFull(step.verdict);
          const isLast = idx === sorted.length - 1;
          const details = step.details || {};
          const noteBits = [];
          if (details.derived_from) noteBits.push(`From ${details.derived_from}`);
          if (details.derived_from_attachment) noteBits.push(`From attachment ${details.derived_from_attachment}`);
          if (details.provider === 'falcon_sandbox') noteBits.push('Falcon observed');
          if (details.artifact_type) noteBits.push(String(details.artifact_type).replace(/_/g, ' '));
          return `<div class="pg-chain-step ${isLast ? 'pg-chain-step-last' : ''}">
            <div class="pg-chain-connector">
              <div class="pg-chain-dot" style="border-color:${vColor};background:${vColor}22"></div>
              ${!isLast ? '<div class="pg-chain-line"></div>' : ''}
            </div>
            <div class="pg-chain-content">
              <div class="pg-chain-step-header">
                <span class="pg-chain-label">${escapeHtml(step.label || step.step_type || '')}</span>
                <span class="pg-chain-relation">${escapeHtml(step.relation || '')}</span>
              </div>
              <div class="pg-chain-step-meta">
                <span class="pg-badge pg-badge-sm" style="color:${vColor};background:${vColor}18;border:1px solid ${vColor}33">${escapeHtml(step.step_type || '')}</span>
                ${step.verdict ? verdictBadge(step.verdict) : ''}
                ${step.risk_score != null ? `<span style="font-size:10px;color:var(--pg-text-muted)">Risk: ${step.risk_score}</span>` : ''}
              </div>
              ${noteBits.length ? `<div class="pg-chain-step-note">${escapeHtml(noteBits.join(' · '))}</div>` : ''}
            </div>
          </div>`;
        }).join('')}
      </div>
    </div>`;
  }

  /* ------------------------------------------------------------------ */
  /*  Campaign insight card                                              */
  /* ------------------------------------------------------------------ */
  function renderCampaign(campaign) {
    if (!campaign) return emptyState('No campaign association', '🎯');
    return `<div class="pg-campaign-card">
      <div class="pg-campaign-header">
        <span class="pg-campaign-icon">🎯</span>
        <span class="pg-campaign-title">Campaign Cluster</span>
      </div>
      <div class="pg-campaign-body">
        <div class="pg-campaign-field">
          <span class="pg-campaign-field-label">Campaign Key</span>
          <span class="pg-campaign-field-value">
            <code>${escapeHtml(campaign.key || '—')}</code>
            <button class="pg-hash-copy" onclick="navigator.clipboard.writeText('${escapeHtml(campaign.key || '')}').then(()=>{this.textContent='✓';setTimeout(()=>this.textContent='⧉',1500)})" title="Copy">⧉</button>
          </span>
        </div>
        <div class="pg-campaign-field">
          <span class="pg-campaign-field-label">Cluster Size</span>
          <span class="pg-campaign-field-value pg-campaign-size">${campaign.size || 0} related scans</span>
        </div>
      </div>
    </div>`;
  }

  /* ------------------------------------------------------------------ */
  /*  Attachment metadata card                                           */
  /* ------------------------------------------------------------------ */
  function renderAttachmentCard(att) {
    if (!att) return '';
    const vColor = verdictColorFull(att.verdict);
    const extractedCount = (att.extracted_urls || []).length;

    let extractedUrlsHtml = '';
    if (att.extracted_url_scans && att.extracted_url_scans.length > 0) {
      extractedUrlsHtml = `
        <div class="pg-att-urls">
          <div class="pg-att-urls-title">Extracted URL Scans</div>
          ${att.extracted_url_scans.slice(0, 5).map(scan => `
            <div class="pg-att-url-row">
              ${verdictBadge(scan.verdict)}
              <span class="pg-att-url-text" title="${escapeHtml(scan.url || '')}">${escapeHtml(truncateUrl(scan.url, 50))}</span>
              <span style="font-size:10px;color:var(--pg-text-muted)">Risk: ${scan.risk_score}</span>
            </div>
          `).join('')}
          ${att.extracted_url_scans.length > 5 ? `<div class="pg-att-url-more">+${att.extracted_url_scans.length - 5} more</div>` : ''}
        </div>`;
    }

    let containedHtml = '';
    if (att.contained_filenames && att.contained_filenames.length > 0) {
      containedHtml = `
        <div class="pg-att-contained">
          <div class="pg-att-urls-title">Contained Files</div>
          <div class="pg-att-file-list">${att.contained_filenames.map(f => `<code class="pg-att-filename">${escapeHtml(f)}</code>`).join('')}</div>
        </div>`;
    }

    return `<div class="pg-attachment-card" style="border-left:3px solid ${vColor}">
      <div class="pg-att-header">
        <div class="pg-att-name">📎 ${escapeHtml(att.filename || 'Unknown file')}</div>
        <div class="pg-att-verdict">${verdictBadge(att.verdict)}</div>
      </div>
      <div class="pg-att-meta-grid">
        <div class="pg-att-meta"><span class="pg-att-meta-label">Type</span><span>${escapeHtml(att.detected_type || att.mime_type || '—')}</span></div>
        <div class="pg-att-meta"><span class="pg-att-meta-label">Extension</span><span>${escapeHtml(att.extension || '—')}</span></div>
        <div class="pg-att-meta"><span class="pg-att-meta-label">Size</span><span>${formatFileSize(att.file_size)}</span></div>
        <div class="pg-att-meta"><span class="pg-att-meta-label">Risk</span><span style="color:${riskColor(att.risk_score)}">${att.risk_score}/100</span></div>
        <div class="pg-att-meta"><span class="pg-att-meta-label">Confidence</span><span>${formatPct(att.confidence)}</span></div>
        <div class="pg-att-meta"><span class="pg-att-meta-label">Password</span><span>${att.password_protected ? '🔒 Yes' : '—'}</span></div>
        <div class="pg-att-meta pg-att-meta-wide"><span class="pg-att-meta-label">SHA-256</span><span>${truncateHash(att.sha256, 20)}</span></div>
        <div class="pg-att-meta"><span class="pg-att-meta-label">Extracted URLs</span><span>${extractedCount}</span></div>
      </div>
      ${att.flags && att.flags.length > 0 ? renderFlags(att.flags) : ''}
      ${containedHtml}
      ${extractedUrlsHtml}
    </div>`;
  }

  /* ------------------------------------------------------------------ */
  /*  Render engine result card                                          */
  /* ------------------------------------------------------------------ */
  function renderEngineCard(name, data) {
    if (!data) return '';
    const label = name.replace(/_result$/, '').replace(/_/g, ' ').toUpperCase();
    let body = '';
    if (typeof data === 'object' && data !== null) {
      body = Object.entries(data).map(([k, v]) => {
        const val = typeof v === 'object' ? JSON.stringify(v) : String(v ?? '—');
        return `<div class="pg-engine-field">
          <span class="pg-engine-field-label">${escapeHtml(k)}</span>
          <span class="pg-engine-field-value">${escapeHtml(val.length > 120 ? val.slice(0, 120) + '…' : val)}</span>
        </div>`;
      }).join('');
    } else {
      body = `<div class="pg-engine-field"><span>${escapeHtml(String(data))}</span></div>`;
    }
    return `<div class="pg-engine-card">
      <div class="pg-engine-title">${label}</div>
      ${body}
    </div>`;
  }

  return {
    escapeHtml,
    verdictColor,
    verdictColorFull,
    verdictBg,
    verdictIcon,
    riskColor,
    riskLabel,
    severityColor,
    verdictBadge,
    severityBadge,
    riskBadge,
    sourceBadge,
    campaignBadge,
    scoreGauge,
    miniBarChart,
    donutChart,
    emptyState,
    spinner,
    formatTimestamp,
    formatDate,
    formatMs,
    formatFileSize,
    truncateUrl,
    truncateHash,
    copyToClipboard,
    formatPct,
    formatPctRaw,
    showToast,
    renderFlags,
    renderScoreBreakdown,
    renderAttackChain,
    renderCampaign,
    renderAttachmentCard,
    renderEngineCard,
    VERDICT_COLORS,
    VERDICT_BG,
    SEVERITY_COLORS
  };
})();

if (typeof globalThis !== 'undefined') globalThis.PhishGuardUI = UI;
