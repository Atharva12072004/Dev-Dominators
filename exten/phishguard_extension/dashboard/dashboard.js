/**
 * PhishGuard AI â€” Dashboard Controller
 */

let currentSection = 'overview';
let historyPage = 1;
const HISTORY_LIMIT = 20;
let historyData = [];
let statsData = null;
let pollTimer = null;
let storageRefreshTimer = null;
const POLL_INTERVAL = 5000;
let pollBackoff = 0;
let expandedRows = new Set();

document.addEventListener('DOMContentLoaded', async () => {
  await Theme.init();
  initNav();
  bindActions();
  bindModalActions();
  bindLiveRefresh();
  await checkConnection();
  await loadOverview();
  await loadHistory();
  startPolling();
});

/* ================================================================== */
/*  Navigation                                                         */
/* ================================================================== */

function initNav() {
  document.querySelectorAll('.sidebar-link').forEach(link => {
    link.addEventListener('click', () => {
      const section = link.dataset.section;
      switchSection(section);
    });
  });
}

function switchSection(name) {
  currentSection = name;
  document.querySelectorAll('.sidebar-link').forEach(l =>
    l.classList.toggle('active', l.dataset.section === name)
  );
  document.querySelectorAll('.dash-section').forEach(s =>
    s.classList.toggle('hidden', s.id !== `section-${name}`)
  );
  document.getElementById('page-title').textContent =
    name === 'overview' ? 'Overview' : 'Scan History';

  // Load fresh data when switching sections
  if (name === 'overview') {
    loadOverview().catch(console.error);
  } else {
    loadHistory().catch(console.error);
  }
}

/* ================================================================== */
/*  Connection                                                         */
/* ================================================================== */

async function checkConnection() {
  const dot = document.getElementById('dash-status-dot');
  const text = document.getElementById('dash-status-text');
  try {
    const resp = await API.health();
    if (resp && resp.status === 'ok') {
      dot.className = 'status-dot connected';
      text.textContent = 'Backend connected';
      pollBackoff = 0;
    } else throw new Error();
  } catch {
    dot.className = 'status-dot error';
    text.textContent = 'Backend unreachable';
    pollBackoff = Math.min(pollBackoff + 1, 5);
  }
}

/* ================================================================== */
/*  Polling                                                            */
/* ================================================================== */

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    await checkConnection();
    // Always refresh both so data stays current
    if (currentSection === 'overview') {
      await loadOverview();
    } else {
      await loadHistory();
    }
    updateTimestamp();
  }, POLL_INTERVAL);
}

function bindLiveRefresh() {
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== 'local' && areaName !== 'session') return;
    if (!changes.recentActivity && !changes.scanCache && !changes.currentTabState) return;

    clearTimeout(storageRefreshTimer);
    storageRefreshTimer = setTimeout(async () => {
      // Refresh both to keep data in sync after scans
      try {
        await loadOverview();
        await loadHistory();
      } catch (_) {}
      updateTimestamp();
    }, 600);
  });
}

function updateTimestamp() {
  document.getElementById('last-updated').textContent =
    `Updated ${new Date().toLocaleTimeString()}`;
}

/* ================================================================== */
/*  Overview â€” Stats                                                   */
/* ================================================================== */

async function loadOverview() {
  try {
    statsData = await API.getStats();
    renderMetrics(statsData);
    renderCategoryChart(statsData.by_category);
    renderDailyChart(statsData.by_day);
    renderPerformance(statsData);
    updateTimestamp();
  } catch (err) {
    console.error('[Dashboard] Stats error:', err);
  }
}

function renderMetrics(stats) {
  const grid = document.getElementById('metric-grid');
  const cards = [
    { label: 'Total Scanned', value: stats.total_scanned ?? 0, accent: '#3b82f6' },
    { label: 'Threats Blocked', value: stats.threats_blocked ?? 0, accent: '#ef4444' },
    { label: 'Safe', value: stats.safe_count ?? 0, accent: '#22c55e' },
    { label: 'Accuracy', value: stats.accuracy != null ? (stats.accuracy * 100).toFixed(1) + '%' : 'â€”', accent: '#8b5cf6', sub: stats.labeled_samples != null ? `${stats.labeled_samples} labeled` : '' },
    { label: 'False Positive Rate', value: stats.false_positive_rate != null ? (stats.false_positive_rate * 100).toFixed(1) + '%' : 'â€”', accent: '#f59e0b' },
    { label: 'Avg Detection', value: stats.avg_detection_speed_ms != null ? Math.round(stats.avg_detection_speed_ms) + 'ms' : 'â€”', accent: '#06b6d4' }
  ];

  grid.innerHTML = cards.map(c => `
    <div class="metric-card" style="--card-accent: ${c.accent}">
      <div class="metric-label">${c.label}</div>
      <div class="metric-value">${c.value}</div>
      ${c.sub ? `<div class="metric-sub">${c.sub}</div>` : ''}
    </div>
  `).join('');
}

function renderCategoryChart(byCategory) {
  const body = document.getElementById('chart-category-body');
  const legend = document.getElementById('chart-category-legend');
  if (!byCategory) {
    body.innerHTML = UI.emptyState('No data yet', 'ðŸ“Š');
    legend.innerHTML = '';
    return;
  }
  const segments = [
    { label: 'Safe', value: byCategory.safe || 0, color: '#22c55e' },
    { label: 'Suspicious', value: byCategory.suspicious || 0, color: '#f59e0b' },
    { label: 'Phishing', value: byCategory.phishing || 0, color: '#ef4444' },
    { label: 'Malware', value: byCategory.malware || 0, color: '#dc2626' }
  ];
  body.innerHTML = UI.donutChart(segments, { size: 160, thickness: 24 });
  legend.innerHTML = segments.map(s =>
    `<div class="legend-item"><div class="legend-dot" style="background:${s.color}"></div>${s.label}: ${s.value}</div>`
  ).join('');
}

function renderDailyChart(byDay) {
  const body = document.getElementById('chart-daily-body');
  if (!byDay || byDay.length === 0) {
    body.innerHTML = UI.emptyState('No daily data yet', 'ðŸ“ˆ');
    return;
  }
  const last14 = byDay.slice(-14);
  const hasActivity = last14.some(d => (d.total || 0) > 0 || (d.blocked || 0) > 0);
  if (!hasActivity) {
    body.innerHTML = UI.emptyState('No scans in the last 14 days');
    return;
  }
  const data = last14.map(d => ({
    label: d.date ? d.date.slice(5) : '',
    value: d.total || 0,
    color: '#3b82f6'
  }));

  const blockedData = last14.map(d => ({
    label: d.date ? d.date.slice(5) : '',
    value: d.blocked || 0,
    color: '#ef4444'
  }));

  const width = Math.max(400, last14.length * 35);
  const height = 120;
  const max = Math.max(...data.map(d => d.value), 1);
  const gap = 6;
  const barW = Math.max(8, (width - gap * (data.length - 1)) / data.length);
  const halfBar = barW / 2;

  let svg = `<svg width="100%" height="${height + 28}" viewBox="0 0 ${width} ${height + 28}" preserveAspectRatio="none" class="pg-chart">`;
  data.forEach((d, i) => {
    const bh = (d.value / max) * height;
    const x = i * (barW + gap);
    const y = height - bh;
    svg += `<rect x="${x}" y="${y}" width="${barW}" height="${bh}" rx="3" fill="${d.color}" opacity="0.3">
      <title>Total: ${d.value}</title></rect>`;
    const blocked = blockedData[i].value;
    const bh2 = (blocked / max) * height;
    svg += `<rect x="${x}" y="${height - bh2}" width="${barW}" height="${bh2}" rx="3" fill="#ef4444" opacity="0.7">
      <title>Blocked: ${blocked}</title></rect>`;
    svg += `<text x="${x + halfBar}" y="${height + 18}" text-anchor="middle" fill="var(--pg-text-muted)" font-size="9">${d.label}</text>`;
  });
  svg += '</svg>';
  body.innerHTML = svg;
}

function renderPerformance(stats) {
  const grid = document.getElementById('perf-grid');
  const items = [
    { label: 'P95 Detection', value: stats.p95_detection_speed_ms != null ? Math.round(stats.p95_detection_speed_ms) + 'ms' : 'â€”' },
    { label: 'Avg Explainability', value: stats.avg_explainability_score != null ? stats.avg_explainability_score.toFixed(2) : 'â€”' },
    { label: 'User Experience', value: stats.user_experience_score != null ? stats.user_experience_score.toFixed(2) : 'â€”' },
    { label: 'Detection Accuracy', value: stats.detection_accuracy != null ? (stats.detection_accuracy * 100).toFixed(1) + '%' : 'â€”' }
  ];
  grid.innerHTML = items.map(i => `
    <div class="perf-card">
      <div class="perf-label">${i.label}</div>
      <div class="perf-value">${i.value}</div>
    </div>
  `).join('');
}

/* ================================================================== */
/*  History                                                            */
/* ================================================================== */

function getFilters() {
  return {
    search: document.getElementById('filter-search').value.trim(),
    risk_level: document.getElementById('filter-risk').value,
    source: document.getElementById('filter-source').value,
    date_from: document.getElementById('filter-date-from').value || undefined,
    date_to: document.getElementById('filter-date-to').value || undefined
  };
}

async function loadHistory() {
  const tbody = document.getElementById('history-tbody');
  const countEl = document.getElementById('history-count');

  try {
    const filters = getFilters();
    const resp = await API.getHistory({
      page: historyPage,
      limit: HISTORY_LIMIT,
      ...filters
    });

    historyData = resp.items || [];
    const total = resp.total || 0;
    countEl.textContent = `${total} records`;

    if (historyData.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9">${UI.emptyState('No history records found', 'ðŸ“‹')}</td></tr>`;
      renderPagination(0, 0);
      return;
    }

    tbody.innerHTML = historyData.map((item, idx) => renderHistoryRow(item, idx)).join('');
    renderPagination(total, resp.page || historyPage);
    bindRowActions();
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="9"><div class="pg-empty"><div class="pg-empty-icon">âš ï¸</div><div class="pg-empty-msg">Failed to load history</div></div></td></tr>`;
  }
}

function renderHistoryRow(item, idx) {
  const isExpanded = expandedRows.has(item.id);
  const sourceIcon = item.content_type === 'attachment' ? 'ðŸ“Ž' : '';
  let row = `
    <tr data-id="${item.id}" class="${isExpanded ? 'row-expanded' : ''}">
      <td>
        <button class="expand-btn ${isExpanded ? 'expanded' : ''}" data-id="${item.id}" data-idx="${idx}">â–¶</button>
      </td>
      <td><div class="url-cell" title="${UI.escapeHtml(item.url_or_content)}">${sourceIcon}${UI.escapeHtml(UI.truncateUrl(item.url_or_content, 50))}</div></td>
      <td><span class="pg-badge pg-badge-sm pg-badge-source">${UI.escapeHtml(item.content_type || '')}</span></td>
      <td>${UI.sourceBadge(item.source)}</td>
      <td>${UI.verdictBadge(item.verdict)}</td>
      <td>${UI.riskBadge(item.risk_score)}</td>
      <td>${UI.formatPct(item.confidence)}</td>
      <td>${UI.formatTimestamp(item.timestamp)}</td>
      <td>
        <div class="row-action-group">
          <button class="action-btn view-btn" data-id="${item.id}" title="View Details">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
          <button class="action-btn delete-btn" data-id="${item.id}" title="Delete">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
          </button>
        </div>
      </td>
    </tr>
  `;

  if (isExpanded) {
    row += renderDetailRow(item);
  }

  return row;
}

function renderDetailRow(item) {
  const detailItems = [
    { label: 'Full URL/Content', value: item.url_or_content || 'â€”' },
    { label: 'Detection Time', value: UI.formatMs(item.detection_time_ms) },
    { label: 'Explainability', value: item.explainability_score != null ? item.explainability_score.toFixed(2) : 'â€”' },
    { label: 'AI Generated Prob.', value: item.ai_generated_probability != null ? (item.ai_generated_probability * 100).toFixed(1) + '%' : 'â€”' },
    { label: 'Recommended Action', value: item.recommended_action || 'â€”' },
    { label: 'Block Recommended', value: item.block_recommended != null ? (item.block_recommended ? 'Yes' : 'No') : 'â€”' },
    { label: 'Scanned At', value: UI.formatDate(item.timestamp) },
    { label: 'IP Address', value: item.ip_address || 'â€”' }
  ];

  const campaignNote = item.campaign_key
    ? `<div style="margin-top:8px"><span class="pg-badge pg-badge-campaign"><span class="pg-badge-icon">ðŸŽ¯</span> ${UI.escapeHtml(item.campaign_key)}</span></div>`
    : '';

  const currentFeedback = item.actual_verdict || '';
  const verdicts = ['safe', 'suspicious', 'phishing', 'malware'];

  return `
    <tr class="row-detail" data-detail="${item.id}">
      <td colspan="9">
        <div class="detail-grid">
          ${detailItems.map(d => `
            <div class="detail-item">
              <div class="detail-label">${d.label}</div>
              <div class="detail-value" style="word-break:break-all">${UI.escapeHtml(String(d.value))}</div>
            </div>
          `).join('')}
        </div>
        ${item.flags && item.flags.length ? UI.renderFlags(item.flags) : ''}
        ${campaignNote}
        <div class="detail-view-more">
          <button class="btn-primary-sm view-detail-btn" data-id="${item.id}">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            View Full Analysis
          </button>
        </div>
        <div class="feedback-row">
          <span class="feedback-label">Analyst Feedback:</span>
          ${verdicts.map(v => `
            <button class="feedback-btn ${currentFeedback === v ? 'selected' : ''}"
                    data-id="${item.id}" data-verdict="${v}">${v}</button>
          `).join('')}
          ${item.feedback_timestamp ? `<span style="font-size:10px;color:var(--pg-text-muted);margin-left:8px">Submitted ${UI.formatTimestamp(item.feedback_timestamp)}</span>` : ''}
        </div>
      </td>
    </tr>
  `;
}

function bindRowActions() {
  // Expand/collapse
  document.querySelectorAll('.expand-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = parseInt(btn.dataset.id);
      if (expandedRows.has(id)) {
        expandedRows.delete(id);
      } else {
        expandedRows.add(id);
      }
      loadHistory();
    });
  });

  // View detail (from table action)
  document.querySelectorAll('.view-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      openDetailModal(parseInt(btn.dataset.id));
    });
  });

  // View detail from expanded row
  document.querySelectorAll('.view-detail-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      openDetailModal(parseInt(btn.dataset.id));
    });
  });

  // Delete
  document.querySelectorAll('.delete-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const id = btn.dataset.id;
      try {
        await API.deleteHistoryItem(id);
        UI.showToast('Record deleted', 'success');
        await loadHistory();
      } catch (err) {
        UI.showToast('Delete failed', 'error');
      }
    });
  });

  // Feedback
  document.querySelectorAll('.feedback-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const id = btn.dataset.id;
      const verdict = btn.dataset.verdict;
      try {
        await API.submitFeedback(id, verdict);
        UI.showToast('Feedback submitted', 'success');
        await loadOverview();
        await loadHistory();
      } catch (err) {
        UI.showToast('Feedback failed', 'error');
      }
    });
  });
}

/* ================================================================== */
/*  Detail Modal / Drawer                                              */
/* ================================================================== */

function bindModalActions() {
  const overlay = document.getElementById('detail-modal-overlay');
  const closeBtn = document.getElementById('detail-modal-close');

  closeBtn.addEventListener('click', closeDetailModal);
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) closeDetailModal();
  });

  // Escape key handler
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && overlay.classList.contains('open')) {
      closeDetailModal();
    }
  });
}

async function openDetailModal(id) {
  const overlay = document.getElementById('detail-modal-overlay');
  const body = document.getElementById('detail-modal-body');
  const title = document.getElementById('detail-modal-title');

  overlay.classList.add('open');
  body.innerHTML = `<div style="text-align:center;padding:60px 20px">${UI.spinner(32)}<div style="margin-top:12px;font-size:12px;color:var(--pg-text-muted)">Loading detailed analysisâ€¦</div></div>`;

  try {
    const detail = await API.getHistoryDetail(id);
    title.textContent = `Scan #${detail.id} â€” ${detail.content_type} Analysis`;
    body.innerHTML = renderDetailModalContent(detail);
  } catch (err) {
    body.innerHTML = `<div style="text-align:center;padding:60px 20px">
      <div style="font-size:28px;opacity:0.5;margin-bottom:8px">âš ï¸</div>
      <div style="color:var(--pg-danger);font-size:13px">Failed to load details</div>
      <div style="color:var(--pg-text-muted);font-size:11px;margin-top:4px">${UI.escapeHtml(err.message)}</div>
    </div>`;
  }
}

function closeDetailModal() {
  document.getElementById('detail-modal-overlay').classList.remove('open');
  document.getElementById('detail-modal-body').innerHTML = '';
}

function renderDetailModalContent(detail) {
  const sections = [];

  // 1. Summary Section
  sections.push(renderDetailSummary(detail));

  // 2. LLM Section
  sections.push(renderDetailLLM(detail));

  // 3. Sandbox Section
  sections.push(renderDetailSandbox(detail));

  // 4. Explainability Section
  sections.push(renderDetailExplainability(detail));

  // 5. Engine Results Section
  sections.push(renderDetailEngines(detail));

  // 6. Attack Chain Section
  sections.push(renderDetailAttackChain(detail));

  // 7. Campaign Section
  sections.push(renderDetailCampaignSection(detail));

  // 8. Attachments Section (if applicable)
  // Note: attachment data from cached scans if available
  sections.push(renderDetailFlags(detail));

  return sections.filter(Boolean).join('');
}

function renderDetailSummary(detail) {
  const action = detail.recommended_action || 'allow';
  const blockRec = detail.block_recommended ? 'Yes' : 'No';

  return `
    <div class="modal-section">
      <div class="modal-section-title">Summary</div>
      <div class="modal-summary-grid">
        <div class="modal-summary-main">
          ${UI.scoreGauge(detail.risk_score || 0, 80)}
          <div class="modal-summary-badges">
            ${UI.verdictBadge(detail.verdict)}
            ${UI.riskBadge(detail.risk_score)}
            <span class="pg-badge pg-badge-sm pg-badge-source">${UI.escapeHtml(detail.content_type || '')}</span>
            ${UI.sourceBadge(detail.source)}
          </div>
        </div>
        <div class="modal-summary-details">
          <div class="modal-detail-row"><span class="modal-detail-label">Confidence</span><span>${UI.formatPct(detail.confidence)}</span></div>
          <div class="modal-detail-row"><span class="modal-detail-label">Detection Time</span><span>${UI.formatMs(detail.detection_time_ms)}</span></div>
          <div class="modal-detail-row"><span class="modal-detail-label">Recommended Action</span><span>${UI.escapeHtml(action)}</span></div>
          <div class="modal-detail-row"><span class="modal-detail-label">Block Recommended</span><span>${blockRec}</span></div>
          <div class="modal-detail-row"><span class="modal-detail-label">Explainability</span><span>${detail.explainability_score != null ? detail.explainability_score.toFixed(2) : 'â€”'}</span></div>
          <div class="modal-detail-row"><span class="modal-detail-label">AI Generated Prob.</span><span>${detail.ai_generated_probability != null ? (detail.ai_generated_probability * 100).toFixed(1) + '%' : 'â€”'}</span></div>
          <div class="modal-detail-row"><span class="modal-detail-label">Scanned At</span><span>${UI.formatDate(detail.timestamp)}</span></div>
          <div class="modal-detail-row"><span class="modal-detail-label">IP Address</span><span>${UI.escapeHtml(detail.ip_address || 'â€”')}</span></div>
          <div class="modal-detail-row modal-detail-row-full"><span class="modal-detail-label">URL / Content</span><span class="modal-detail-content">${UI.escapeHtml(detail.url_or_content || 'â€”')}</span></div>
        </div>
      </div>
    </div>
  `;
}

function renderDetailLLM(detail) {
  const llm = detail.llm_analysis;
  if (!llm) {
    return '';
  }

  const actions = Array.isArray(llm.recommended_actions) ? llm.recommended_actions : [];
  const indicators = Array.isArray(llm.key_indicators) ? llm.key_indicators : [];
  const tactics = Array.isArray(llm.social_engineering_tactics) ? llm.social_engineering_tactics : [];
  const priority = llm.triage_priority ? String(llm.triage_priority).toUpperCase() : 'N/A';
  const status = String(llm.status || (llm.enabled ? 'ok' : 'disabled')).toUpperCase();
  const showContent = llm.enabled !== false && llm.status !== 'disabled' && llm.status !== 'error';

  return `
    <div class="modal-section">
      <div class="modal-section-title">Groq Analyst Layer</div>
      <div class="detail-grid">
        <div class="detail-item">
          <div class="detail-label">Provider</div>
          <div class="detail-value">${UI.escapeHtml(llm.provider || 'groq')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Status</div>
          <div class="detail-value">${UI.escapeHtml(status)}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Model</div>
          <div class="detail-value">${UI.escapeHtml(llm.model || 'â€”')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Phishing Text Score</div>
          <div class="detail-value">${llm.phishing_text_score != null ? `${llm.phishing_text_score}/100` : 'â€”'}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">LLM Confidence</div>
          <div class="detail-value">${UI.formatPct(llm.confidence)}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Triage Priority</div>
          <div class="detail-value">${UI.escapeHtml(priority)}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Cluster Label</div>
          <div class="detail-value">${UI.escapeHtml(llm.cluster_label || 'â€”')}</div>
        </div>
      </div>
      ${llm.error ? `<div class="detail-item" style="margin-top:10px"><div class="detail-label">Error</div><div class="detail-value">${UI.escapeHtml(llm.error)}</div></div>` : ''}
      ${showContent && llm.explanation_summary ? `<div class="detail-item" style="margin-top:10px"><div class="detail-label">Explainability Summary</div><div class="detail-value">${UI.escapeHtml(llm.explanation_summary)}</div></div>` : ''}
      ${showContent && llm.analyst_summary ? `<div class="detail-item" style="margin-top:10px"><div class="detail-label">Analyst Summary</div><div class="detail-value">${UI.escapeHtml(llm.analyst_summary)}</div></div>` : ''}
      ${showContent && llm.cluster_rationale ? `<div class="detail-item" style="margin-top:10px"><div class="detail-label">Clustering Rationale</div><div class="detail-value">${UI.escapeHtml(llm.cluster_rationale)}</div></div>` : ''}
      ${showContent && indicators.length ? `<div class="detail-item" style="margin-top:10px"><div class="detail-label">Key Indicators</div><div class="detail-value">${indicators.map(item => `<div>${UI.escapeHtml(item)}</div>`).join('')}</div></div>` : ''}
      ${showContent && tactics.length ? `<div class="detail-item" style="margin-top:10px"><div class="detail-label">Social Engineering Tactics</div><div class="detail-value">${tactics.map(item => `<div>${UI.escapeHtml(item)}</div>`).join('')}</div></div>` : ''}
      ${showContent && actions.length ? `<div class="detail-item" style="margin-top:10px"><div class="detail-label">Recommended Actions</div><div class="detail-value">${actions.map(item => `<div>${UI.escapeHtml(item)}</div>`).join('')}</div></div>` : ''}
    </div>
  `;
}

function renderDetailExplainability(detail) {
  const breakdown = detail.score_breakdown;
  if (!breakdown || breakdown.length === 0) {
    return `
      <div class="modal-section">
        <div class="modal-section-title">Explainability</div>
        ${UI.emptyState('No score breakdown available for this scan', 'ðŸ“Š')}
      </div>
    `;
  }

  return `
    <div class="modal-section">
      <div class="modal-section-title">
        Explainability
        <span class="modal-section-badge">${breakdown.length} signals</span>
      </div>
      ${UI.renderScoreBreakdown(breakdown)}
    </div>
  `;
}

function renderDetailSandbox(detail) {
  const sandbox = detail.falcon_result;
  if (!sandbox) {
    const message = (detail.content_type === 'email' || detail.content_type === 'chat')
      ? 'No Falcon Sandbox result is stored for this record yet. Run a fresh scan after restarting the backend to populate sandbox data from linked URLs or attachments.'
      : 'No Falcon Sandbox result is available for this scan.';
    return `
      <div class="modal-section">
        <div class="modal-section-title">Sandbox</div>
        ${UI.emptyState(message, 'Sandbox')}
      </div>
    `;
  }

  const tags = Array.isArray(sandbox.tags) ? sandbox.tags : [];
  const status = String(sandbox.status || (sandbox.enabled ? 'ok' : 'disabled')).toUpperCase();
  const completed = sandbox.completed ? 'Yes' : 'No';
  const hasProviderLimit = /already submitted.*last hour/i.test(String(sandbox.error || ''));
  const providerNote = hasProviderLimit
    ? `<div class="detail-item" style="margin-top:10px"><div class="detail-label">Note</div><div class="detail-value">Falcon limits repeated submissions for the same domain. CYBERSHIELD now reuses recent sandbox results when possible, so fresh scans should show fewer duplicate-limit failures after you restart the backend.</div></div>`
    : '';

  return `
    <div class="modal-section">
      <div class="modal-section-title">Sandbox</div>
      <div class="detail-grid">
        <div class="detail-item">
          <div class="detail-label">Provider</div>
          <div class="detail-value">${UI.escapeHtml(sandbox.provider || 'falcon_sandbox')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Status</div>
          <div class="detail-value">${UI.escapeHtml(status)}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Submission Type</div>
          <div class="detail-value">${UI.escapeHtml(sandbox.submission_type || 'â€”')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">State</div>
          <div class="detail-value">${UI.escapeHtml(sandbox.state || 'â€”')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Completed</div>
          <div class="detail-value">${UI.escapeHtml(completed)}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Verdict</div>
          <div class="detail-value">${UI.escapeHtml(sandbox.verdict || 'â€”')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Threat Score</div>
          <div class="detail-value">${sandbox.threat_score != null ? `${sandbox.threat_score}/100` : 'â€”'}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Threat Level</div>
          <div class="detail-value">${UI.escapeHtml(sandbox.threat_level || 'â€”')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Environment</div>
          <div class="detail-value">${sandbox.environment_id != null ? UI.escapeHtml(String(sandbox.environment_id)) : 'â€”'}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Environment Name</div>
          <div class="detail-value">${UI.escapeHtml(sandbox.environment_description || 'â€”')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Related Submissions</div>
          <div class="detail-value">${sandbox.related_submissions != null ? UI.escapeHtml(String(sandbox.related_submissions)) : '0'}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Hosts</div>
          <div class="detail-value">${sandbox.hosts_count != null ? UI.escapeHtml(String(sandbox.hosts_count)) : '0'}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Domains</div>
          <div class="detail-value">${sandbox.domains_count != null ? UI.escapeHtml(String(sandbox.domains_count)) : '0'}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Extracted Files</div>
          <div class="detail-value">${sandbox.extracted_files_count != null ? UI.escapeHtml(String(sandbox.extracted_files_count)) : '0'}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Job ID</div>
          <div class="detail-value" style="word-break:break-all">${UI.escapeHtml(sandbox.job_id || 'â€”')}</div>
        </div>
      </div>
      ${providerNote}
      ${sandbox.error ? `<div class="detail-item" style="margin-top:10px"><div class="detail-label">Error</div><div class="detail-value">${UI.escapeHtml(sandbox.error)}</div></div>` : ''}
      ${tags.length ? `<div class="detail-item" style="margin-top:10px"><div class="detail-label">Tags</div><div class="detail-value">${tags.map(item => `<div>${UI.escapeHtml(String(item))}</div>`).join('')}</div></div>` : ''}
    </div>
  `;
}

function renderSandboxInsightCards(sandbox) {
  const malicious = sandbox.malicious || /malicious|phishing|malware|suspicious/i.test(String(sandbox.verdict || ''));
  const networkSeen = (Number(sandbox.domains_count || 0) + Number(sandbox.hosts_count || 0)) > 0;
  const redirected = Number(sandbox.redirect_urls_count || (Array.isArray(sandbox.redirect_urls) ? sandbox.redirect_urls.length : 0)) > 0;
  const droppedFiles = Number(sandbox.extracted_files_count || 0) > 0;
  const multiArtifact = Number(sandbox.related_submissions || 0) > 1;
  const providerLimited = String(sandbox.status || '').toLowerCase() === 'rate_limited'
    || /already submitted.*last hour/i.test(String(sandbox.error || ''));

  const items = [
    {
      label: 'Malicious Behavior',
      value: malicious ? 'Observed' : 'Not strongly observed',
      tone: malicious ? 'danger' : 'safe',
      description: malicious
        ? 'Falcon suggests phishing, suspicious, or malware-like execution behavior.'
        : 'Falcon did not strongly confirm malicious behavior.'
    },
    {
      label: 'Network Contact',
      value: networkSeen ? `${Number(sandbox.domains_count || 0)} domains / ${Number(sandbox.hosts_count || 0)} hosts` : 'No notable contact',
      tone: networkSeen ? 'warning' : 'neutral',
      description: networkSeen
        ? 'The artifact reached external infrastructure during analysis.'
        : 'No meaningful host or domain activity was reported.'
    },
    {
      label: 'Redirect Chain',
      value: redirected ? `${Number(sandbox.redirect_urls_count || (sandbox.redirect_urls || []).length)} follow-on URL(s)` : 'No redirect path captured',
      tone: redirected ? 'warning' : 'neutral',
      description: redirected
        ? 'Falcon observed downstream URLs after the initial artifact executed.'
        : 'No follow-on URLs were retained from the behavioral report.'
    },
    {
      label: 'Dropped Files',
      value: droppedFiles ? `${Number(sandbox.extracted_files_count || 0)} extracted` : 'No extra files',
      tone: droppedFiles ? 'danger' : 'safe',
      description: droppedFiles
        ? 'Additional file artifacts were extracted or dropped.'
        : 'No dropped or extracted follow-on files were reported.'
    },
    {
      label: 'Artifact Spread',
      value: multiArtifact ? `${Number(sandbox.related_submissions || 0)} related submissions` : 'Single artifact path',
      tone: multiArtifact ? 'warning' : 'neutral',
      description: multiArtifact
        ? 'Multiple child artifacts contributed to this summary.'
        : 'This sandbox view came from a single artifact path.'
    },
    {
      label: 'Provider State',
      value: providerLimited ? 'Duplicate limit hit' : (sandbox.completed ? 'Completed' : 'Pending / partial'),
      tone: providerLimited ? 'warning' : (sandbox.completed ? 'safe' : 'neutral'),
      description: providerLimited
        ? 'Falcon blocked repeated submissions for the same domain in the last hour.'
        : 'Shows whether Falcon returned a completed behavioral report.'
    }
  ];

  return `
    <div class="sandbox-insights-grid">
      ${items.map((item) => `
        <div class="sandbox-insight-card sandbox-${item.tone}">
          <div class="sandbox-insight-label">${UI.escapeHtml(item.label)}</div>
          <div class="sandbox-insight-value">${UI.escapeHtml(item.value)}</div>
          <div class="sandbox-insight-desc">${UI.escapeHtml(item.description)}</div>
        </div>
      `).join('')}
    </div>
  `;
}

function renderSandboxObservedArtifacts(sandbox) {
  const groups = [
    { label: 'Observed Redirect URLs', items: sandbox.redirect_urls, tone: 'warning' },
    { label: 'Contacted Domains', items: sandbox.domains, tone: 'warning' },
    { label: 'Observed Hosts', items: sandbox.hosts, tone: 'neutral' },
    { label: 'Dropped / Extracted Files', items: sandbox.extracted_files, tone: 'danger' }
  ].filter(group => Array.isArray(group.items) && group.items.length);

  if (!groups.length) {
    return '';
  }

  return `
    <div class="sandbox-observed-grid">
      ${groups.map((group) => `
        <div class="sandbox-observed-card sandbox-${group.tone}">
          <div class="sandbox-observed-label">${UI.escapeHtml(group.label)}</div>
          <div class="sandbox-observed-list">
            ${group.items.map((item) => `<div>${UI.escapeHtml(String(item))}</div>`).join('')}
          </div>
        </div>
      `).join('')}
    </div>
  `;
}

function renderDetailSandbox(detail) {
  const sandbox = detail.falcon_result;
  if (!sandbox) {
    const message = (detail.content_type === 'email' || detail.content_type === 'chat')
      ? 'No Falcon Sandbox result is stored for this record yet. Run a fresh scan after restarting the backend to populate sandbox data from linked URLs or attachments.'
      : 'No Falcon Sandbox result is available for this scan.';
    return `
      <div class="modal-section">
        <div class="modal-section-title">Sandbox</div>
        ${UI.emptyState(message, 'Sandbox')}
      </div>
    `;
  }

  const tags = Array.isArray(sandbox.tags) ? sandbox.tags : [];
  const status = String(sandbox.status || (sandbox.enabled ? 'ok' : 'disabled')).toUpperCase();
  const completed = sandbox.completed ? 'Yes' : 'No';
  const hasProviderLimit = /already submitted.*last hour/i.test(String(sandbox.error || ''));
  const providerNote = hasProviderLimit
    ? `<div class="sandbox-note-card">Falcon limits repeated submissions for the same domain. CYBERSHIELD now reuses recent sandbox results when possible, so fresh scans should show fewer duplicate-limit failures after you restart the backend.</div>`
    : '';
  const verdictTone = sandbox.malicious ? 'danger' : (sandbox.completed ? 'safe' : 'neutral');
  const verdictBadge = sandbox.verdict
    ? UI.verdictBadge(
        String(sandbox.verdict).toLowerCase().includes('malware')
          ? 'malware'
          : String(sandbox.verdict).toLowerCase().includes('phish')
            ? 'phishing'
            : String(sandbox.verdict).toLowerCase().includes('suspicious')
              ? 'suspicious'
              : 'safe'
      )
    : '';

  return `
    <div class="modal-section">
      <div class="modal-section-title">Sandbox</div>
      <div class="sandbox-hero sandbox-${verdictTone}">
        <div class="sandbox-hero-header">
          <div class="sandbox-hero-title">Behavioral Sandbox Summary</div>
          <div class="sandbox-hero-status">${UI.escapeHtml(status)}</div>
        </div>
        <div class="sandbox-hero-main">
          ${verdictBadge}
          ${UI.riskBadge(Number(sandbox.threat_score || 0))}
        </div>
        <div class="sandbox-hero-copy">
          ${UI.escapeHtml(sandbox.verdict || 'No explicit Falcon verdict')} Â· ${sandbox.completed ? 'completed behavioral report' : 'partial / limited behavioral report'}
        </div>
      </div>
      ${renderSandboxInsightCards(sandbox)}
      <div class="sandbox-meta-grid">
        <div class="detail-item">
          <div class="detail-label">Provider</div>
          <div class="detail-value">${UI.escapeHtml(sandbox.provider || 'falcon_sandbox')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Submission Type</div>
          <div class="detail-value">${UI.escapeHtml(sandbox.submission_type || 'â€”')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">State</div>
          <div class="detail-value">${UI.escapeHtml(sandbox.state || 'â€”')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Completed</div>
          <div class="detail-value">${UI.escapeHtml(completed)}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Threat Score</div>
          <div class="detail-value">${sandbox.threat_score != null ? `${sandbox.threat_score}/100` : 'â€”'}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Threat Level</div>
          <div class="detail-value">${UI.escapeHtml(sandbox.threat_level || 'â€”')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Environment</div>
          <div class="detail-value">${sandbox.environment_id != null ? UI.escapeHtml(String(sandbox.environment_id)) : 'â€”'}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Environment Name</div>
          <div class="detail-value">${UI.escapeHtml(sandbox.environment_description || 'â€”')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Related Submissions</div>
          <div class="detail-value">${sandbox.related_submissions != null ? UI.escapeHtml(String(sandbox.related_submissions)) : '0'}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Hosts</div>
          <div class="detail-value">${sandbox.hosts_count != null ? UI.escapeHtml(String(sandbox.hosts_count)) : '0'}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Domains</div>
          <div class="detail-value">${sandbox.domains_count != null ? UI.escapeHtml(String(sandbox.domains_count)) : '0'}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Extracted Files</div>
          <div class="detail-value">${sandbox.extracted_files_count != null ? UI.escapeHtml(String(sandbox.extracted_files_count)) : '0'}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Job ID</div>
          <div class="detail-value" style="word-break:break-all">${UI.escapeHtml(sandbox.job_id || 'â€”')}</div>
        </div>
      </div>
      ${providerNote}
      ${sandbox.error ? `<div class="sandbox-note-card sandbox-note-danger"><div class="detail-label">Provider Message</div><div class="detail-value">${UI.escapeHtml(sandbox.error)}</div></div>` : ''}
      ${tags.length ? `<div class="sandbox-tags">${tags.map(item => `<span class="sandbox-tag">${UI.escapeHtml(String(item))}</span>`).join('')}</div>` : ''}
    </div>
  `;
}

function renderDetailSandbox(detail) {
  const sandbox = detail.falcon_result;
  if (!sandbox) {
    const message = (detail.content_type === 'email' || detail.content_type === 'chat')
      ? 'No Falcon Sandbox result is stored for this record yet. Run a fresh scan after restarting the backend to populate sandbox data from linked URLs or attachments.'
      : 'No Falcon Sandbox result is available for this scan.';
    return `
      <div class="modal-section">
        <div class="modal-section-title">Sandbox</div>
        ${UI.emptyState(message, 'Sandbox')}
      </div>
    `;
  }

  const tags = Array.isArray(sandbox.tags) ? sandbox.tags : [];
  const status = String(sandbox.status || (sandbox.enabled ? 'ok' : 'disabled')).toUpperCase();
  const completed = sandbox.completed ? 'Yes' : 'No';
  const hasProviderLimit = /already submitted.*last hour/i.test(String(sandbox.error || ''));
  const providerNote = hasProviderLimit
    ? `<div class="sandbox-note-card">Falcon limits repeated submissions for the same domain. CYBERSHIELD now reuses recent sandbox results when possible, so fresh scans should show fewer duplicate-limit failures after you restart the backend.</div>`
    : '';
  const verdictTone = sandbox.malicious ? 'danger' : (sandbox.completed ? 'safe' : 'neutral');
  const verdictBadge = sandbox.verdict
    ? UI.verdictBadge(
        String(sandbox.verdict).toLowerCase().includes('malware')
          ? 'malware'
          : String(sandbox.verdict).toLowerCase().includes('phish')
            ? 'phishing'
            : String(sandbox.verdict).toLowerCase().includes('suspicious')
              ? 'suspicious'
              : 'safe'
      )
    : '';

  return `
    <div class="modal-section">
      <div class="modal-section-title">Sandbox</div>
      <div class="sandbox-hero sandbox-${verdictTone}">
        <div class="sandbox-hero-header">
          <div class="sandbox-hero-title">Behavioral Sandbox Summary</div>
          <div class="sandbox-hero-status">${UI.escapeHtml(status)}</div>
        </div>
        <div class="sandbox-hero-main">
          ${verdictBadge}
          ${UI.riskBadge(Number(sandbox.threat_score || 0))}
        </div>
        <div class="sandbox-hero-copy">
          ${UI.escapeHtml(sandbox.verdict || 'No explicit Falcon verdict')} Â· ${sandbox.completed ? 'completed behavioral report' : 'partial / limited behavioral report'}
        </div>
      </div>
      ${renderSandboxInsightCards(sandbox)}
      <div class="sandbox-meta-grid">
        <div class="detail-item">
          <div class="detail-label">Provider</div>
          <div class="detail-value">${UI.escapeHtml(sandbox.provider || 'falcon_sandbox')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Submission Type</div>
          <div class="detail-value">${UI.escapeHtml(sandbox.submission_type || 'â€”')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">State</div>
          <div class="detail-value">${UI.escapeHtml(sandbox.state || 'â€”')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Completed</div>
          <div class="detail-value">${UI.escapeHtml(completed)}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Threat Score</div>
          <div class="detail-value">${sandbox.threat_score != null ? `${sandbox.threat_score}/100` : 'â€”'}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Threat Level</div>
          <div class="detail-value">${UI.escapeHtml(sandbox.threat_level || 'â€”')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Redirect URLs</div>
          <div class="detail-value">${sandbox.redirect_urls_count != null ? UI.escapeHtml(String(sandbox.redirect_urls_count)) : '0'}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Environment</div>
          <div class="detail-value">${sandbox.environment_id != null ? UI.escapeHtml(String(sandbox.environment_id)) : 'â€”'}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Environment Name</div>
          <div class="detail-value">${UI.escapeHtml(sandbox.environment_description || 'â€”')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Related Submissions</div>
          <div class="detail-value">${sandbox.related_submissions != null ? UI.escapeHtml(String(sandbox.related_submissions)) : '0'}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Hosts</div>
          <div class="detail-value">${sandbox.hosts_count != null ? UI.escapeHtml(String(sandbox.hosts_count)) : '0'}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Domains</div>
          <div class="detail-value">${sandbox.domains_count != null ? UI.escapeHtml(String(sandbox.domains_count)) : '0'}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Extracted Files</div>
          <div class="detail-value">${sandbox.extracted_files_count != null ? UI.escapeHtml(String(sandbox.extracted_files_count)) : '0'}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Job ID</div>
          <div class="detail-value" style="word-break:break-all">${UI.escapeHtml(sandbox.job_id || 'â€”')}</div>
        </div>
      </div>
      ${renderSandboxObservedArtifacts(sandbox)}
      ${providerNote}
      ${sandbox.error ? `<div class="sandbox-note-card sandbox-note-danger"><div class="detail-label">Provider Message</div><div class="detail-value">${UI.escapeHtml(sandbox.error)}</div></div>` : ''}
      ${tags.length ? `<div class="sandbox-tags">${tags.map(item => `<span class="sandbox-tag">${UI.escapeHtml(String(item))}</span>`).join('')}</div>` : ''}
    </div>
  `;
}

function renderDetailEngines(detail) {
  const engines = [
    { key: 'gsb_result', label: 'Google Safe Browsing' },
    { key: 'yara_result', label: 'YARA Rules' },
    { key: 'heuristics_result', label: 'Local Heuristics' },
    { key: 'vt_result', label: 'VirusTotal' }
  ];

  const hasAny = engines.some(e => detail[e.key] != null);
  if (!hasAny) {
    return `
      <div class="modal-section">
        <div class="modal-section-title">Engine Results</div>
        ${UI.emptyState('No engine data available for this scan', 'ðŸ”§')}
      </div>
    `;
  }

  return `
    <div class="modal-section">
      <div class="modal-section-title">Engine Results</div>
      <div class="modal-engines-grid">
        ${engines.map(e => {
          if (!detail[e.key]) return '';
          return UI.renderEngineCard(e.key, detail[e.key]);
        }).join('')}
      </div>
    </div>
  `;
}

function renderDetailAttackChain(detail) {
  return `
    <div class="modal-section">
      <div class="modal-section-title">Attack Chain</div>
      ${UI.renderAttackChain(detail.attack_chain)}
    </div>
  `;
}

function renderDetailCampaignSection(detail) {
  return `
    <div class="modal-section">
      <div class="modal-section-title">Campaign</div>
      ${UI.renderCampaign(detail.campaign)}
    </div>
  `;
}

function renderDetailFlags(detail) {
  if (!detail.flags || detail.flags.length === 0) return '';

  return `
    <div class="modal-section">
      <div class="modal-section-title">
        Flags
        <span class="modal-section-badge">${detail.flags.length}</span>
      </div>
      ${UI.renderFlags(detail.flags)}
    </div>
  `;
}

/* ================================================================== */
/*  Pagination                                                         */
/* ================================================================== */

function renderPagination(total, currentPage) {
  const container = document.getElementById('pagination');
  const totalPages = Math.ceil(total / HISTORY_LIMIT);
  if (totalPages <= 1) { container.innerHTML = ''; return; }

  let html = `<button class="page-btn" ${currentPage <= 1 ? 'disabled' : ''} data-page="${currentPage - 1}">â† Prev</button>`;

  for (let i = 1; i <= totalPages; i++) {
    if (totalPages > 7 && Math.abs(i - currentPage) > 2 && i !== 1 && i !== totalPages) {
      if (i === currentPage - 3 || i === currentPage + 3) html += `<span style="color:var(--pg-text-muted);padding:0 4px">â€¦</span>`;
      continue;
    }
    html += `<button class="page-btn ${i === currentPage ? 'active' : ''}" data-page="${i}">${i}</button>`;
  }

  html += `<button class="page-btn" ${currentPage >= totalPages ? 'disabled' : ''} data-page="${currentPage + 1}">Next â†’</button>`;
  container.innerHTML = html;

  container.querySelectorAll('.page-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.disabled) return;
      historyPage = parseInt(btn.dataset.page);
      expandedRows.clear();
      loadHistory();
    });
  });
}

/* ================================================================== */
/*  CSV Export (client-side)                                           */
/* ================================================================== */

function exportCSV() {
  if (!historyData.length) {
    UI.showToast('No data to export', 'warning');
    return;
  }

  const headers = ['ID', 'URL/Content', 'Type', 'Source', 'Verdict', 'Risk Score', 'Confidence', 'Detection Time (ms)', 'AI Generated Prob.', 'Recommended Action', 'Campaign Key', 'Timestamp'];
  const rows = historyData.map(item => [
    item.id,
    `"${(item.url_or_content || '').replace(/"/g, '""')}"`,
    item.content_type,
    item.source,
    item.verdict,
    item.risk_score,
    item.confidence,
    item.detection_time_ms,
    item.ai_generated_probability,
    item.recommended_action,
    item.campaign_key || '',
    item.timestamp
  ]);

  const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `cybershield_history_${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
  UI.showToast('CSV exported', 'success');
}

/* ================================================================== */
/*  Clear history confirm                                              */
/* ================================================================== */

function confirmClearHistory() {
  const overlay = document.createElement('div');
  overlay.className = 'confirm-overlay';
  overlay.innerHTML = `
    <div class="confirm-dialog">
      <h3>Clear All History?</h3>
      <p>This will permanently delete all scan history from the backend. This action cannot be undone.</p>
      <div class="confirm-actions">
        <button class="btn-ghost" id="confirm-cancel">Cancel</button>
        <button class="btn-danger-ghost" id="confirm-delete">Delete All</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  overlay.querySelector('#confirm-cancel').addEventListener('click', () => overlay.remove());
  overlay.querySelector('#confirm-delete').addEventListener('click', async () => {
    overlay.remove();
    try {
      await API.clearHistory();
      UI.showToast('History cleared', 'success');
      historyPage = 1;
      expandedRows.clear();
      await loadHistory();
    } catch (err) {
      UI.showToast('Failed to clear history', 'error');
    }
  });
  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
}

/* ================================================================== */
/*  Bind actions                                                       */
/* ================================================================== */

function bindActions() {
  document.getElementById('btn-refresh').addEventListener('click', async () => {
    if (currentSection === 'overview') await loadOverview();
    else await loadHistory();
    await checkConnection();
  });

  document.getElementById('btn-apply-filters').addEventListener('click', () => {
    historyPage = 1;
    expandedRows.clear();
    loadHistory();
  });

  document.getElementById('btn-clear-filters').addEventListener('click', () => {
    document.getElementById('filter-search').value = '';
    document.getElementById('filter-risk').value = '';
    document.getElementById('filter-source').value = '';
    document.getElementById('filter-date-from').value = '';
    document.getElementById('filter-date-to').value = '';
    historyPage = 1;
    expandedRows.clear();
    loadHistory();
  });

  document.getElementById('btn-export-csv').addEventListener('click', exportCSV);
  document.getElementById('btn-clear-history').addEventListener('click', confirmClearHistory);

  document.getElementById('btn-open-options').addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });

  const popupButton = document.getElementById('btn-open-popup');
  if (popupButton) {
    popupButton.addEventListener('click', async () => {
      const popupUrl = chrome.runtime.getURL('popup/popup.html');
      await chrome.tabs.create({ url: popupUrl });
    });
  }

  // Enter key on search
  document.getElementById('filter-search').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      historyPage = 1;
      expandedRows.clear();
      loadHistory();
    }
  });
}
