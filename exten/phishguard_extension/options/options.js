/**
 * PhishGuard AI - Options Controller
 */

document.addEventListener('DOMContentLoaded', async () => {
  await Theme.init();
  await loadSettings();
  await loadWhitelist();
  bindActions();
});

/* ================================================================== */
/*  Load settings                                                      */
/* ================================================================== */

async function loadSettings() {
  const s = await Storage.getSettings();

  document.getElementById('opt-backend-url').value = s.backendUrl || '';
  document.getElementById('opt-api-key').value = s.apiKey || '';
  document.getElementById('opt-auto-monitoring').checked = s.autoMonitoring;
  document.getElementById('opt-link-monitoring').checked = s.linkMonitoring;
  document.getElementById('opt-email-monitoring').checked = s.emailMonitoring;
  document.getElementById('opt-whatsapp-monitoring').checked = s.whatsappMonitoring;
  document.getElementById('opt-notifications').checked = s.notificationsEnabled;
  document.getElementById('opt-warning-threshold').value = s.warningThreshold;
  document.getElementById('threshold-value').textContent = s.warningThreshold;
  document.getElementById('opt-direct-nav').value = s.directNavWarning;
  document.getElementById('opt-proceed-override').checked = s.proceedOverride;
  document.getElementById('opt-retention').value = s.cacheRetentionDays;
  document.getElementById('retention-value').textContent = s.cacheRetentionDays;

  document.querySelectorAll('.theme-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.theme === s.theme);
  });
}

/* ================================================================== */
/*  Save settings                                                      */
/* ================================================================== */

async function saveSettings() {
  const settings = {
    backendUrl: document.getElementById('opt-backend-url').value.trim() || 'http://127.0.0.1:8000',
    apiKey: document.getElementById('opt-api-key').value.trim(),
    autoMonitoring: document.getElementById('opt-auto-monitoring').checked,
    linkMonitoring: document.getElementById('opt-link-monitoring').checked,
    emailMonitoring: document.getElementById('opt-email-monitoring').checked,
    whatsappMonitoring: document.getElementById('opt-whatsapp-monitoring').checked,
    notificationsEnabled: document.getElementById('opt-notifications').checked,
    warningThreshold: parseInt(document.getElementById('opt-warning-threshold').value, 10),
    directNavWarning: document.getElementById('opt-direct-nav').value,
    proceedOverride: document.getElementById('opt-proceed-override').checked,
    cacheRetentionDays: parseInt(document.getElementById('opt-retention').value, 10),
    theme: document.querySelector('.theme-btn.active')?.dataset.theme || 'dark'
  };

  await Storage.saveSettings(settings);
  await loadSettings();
  UI.showToast('Settings saved', 'success');
}

/* ================================================================== */
/*  Test connection                                                    */
/* ================================================================== */

async function testConnection() {
  const btn = document.getElementById('btn-test-connection');
  const result = document.getElementById('connection-result');

  btn.disabled = true;
  btn.textContent = 'Testing...';
  result.textContent = '';
  result.className = 'connection-result';

  const url = document.getElementById('opt-backend-url').value.trim() || 'http://127.0.0.1:8000';
  const key = document.getElementById('opt-api-key').value.trim();
  await Storage.saveSettings({ backendUrl: url, apiKey: key });
  await loadSettings();

  try {
    const health = await API.health();
    await API.getStats();
    if (health && health.status === 'ok') {
      result.textContent = 'Connected successfully and API key accepted';
      result.className = 'connection-result success';
    } else {
      throw new Error('Unexpected response');
    }
  } catch (err) {
    result.textContent = err.message;
    result.className = 'connection-result error';
  } finally {
    btn.disabled = false;
    btn.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
      Test Connection
    `;
  }
}

/* ================================================================== */
/*  Whitelist                                                          */
/* ================================================================== */

async function loadWhitelist() {
  const container = document.getElementById('whitelist-list');

  try {
    const list = await API.getWhitelist();
    if (!list || list.length === 0) {
      container.innerHTML = '<div class="pg-empty"><div class="pg-empty-icon">Shield</div><div class="pg-empty-msg">No whitelisted domains</div></div>';
      return;
    }

    container.innerHTML = list.map((item) => `
      <div class="whitelist-item" data-domain="${UI.escapeHtml(item.domain)}">
        <div>
          <span class="whitelist-domain">${UI.escapeHtml(item.domain)}</span>
          <span class="whitelist-date"> Added ${UI.formatTimestamp(item.added_at)}</span>
        </div>
        <button class="whitelist-remove" data-domain="${UI.escapeHtml(item.domain)}" title="Remove">x</button>
      </div>
    `).join('');

    container.querySelectorAll('.whitelist-remove').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const { domain } = btn.dataset;
        try {
          await API.deleteWhitelistEntry(domain);
          UI.showToast(`${domain} removed`, 'success');
          await loadWhitelist();
        } catch (err) {
          UI.showToast(`Failed to remove: ${err.message}`, 'error');
        }
      });
    });
  } catch (err) {
    container.innerHTML = '<div class="pg-empty"><div class="pg-empty-icon">Alert</div><div class="pg-empty-msg">Could not load whitelist</div></div>';
  }
}

async function addWhitelistDomain() {
  const input = document.getElementById('opt-whitelist-domain');
  const domain = input.value.trim();
  if (!domain) {
    UI.showToast('Enter a domain', 'warning');
    return;
  }

  try {
    await API.createWhitelistEntry(domain);
    input.value = '';
    UI.showToast(`${domain} whitelisted`, 'success');
    await loadWhitelist();
  } catch (err) {
    UI.showToast(`Failed: ${err.message}`, 'error');
  }
}

/* ================================================================== */
/*  Clear cache                                                        */
/* ================================================================== */

async function clearCache() {
  await Storage.clearScanCache();
  await Storage.clearRecentActivity();
  UI.showToast('Local cache cleared', 'success');
}

/* ================================================================== */
/*  Bind actions                                                       */
/* ================================================================== */

function bindActions() {
  document.getElementById('btn-save').addEventListener('click', saveSettings);
  document.getElementById('btn-test-connection').addEventListener('click', testConnection);

  document.getElementById('btn-toggle-key').addEventListener('click', () => {
    const input = document.getElementById('opt-api-key');
    input.type = input.type === 'password' ? 'text' : 'password';
  });

  document.getElementById('opt-warning-threshold').addEventListener('input', (e) => {
    document.getElementById('threshold-value').textContent = e.target.value;
  });
  document.getElementById('opt-retention').addEventListener('input', (e) => {
    document.getElementById('retention-value').textContent = e.target.value;
  });

  document.querySelectorAll('.theme-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.theme-btn').forEach((button) => button.classList.remove('active'));
      btn.classList.add('active');
      Theme.apply(btn.dataset.theme);
    });
  });

  document.getElementById('btn-add-whitelist').addEventListener('click', addWhitelistDomain);
  document.getElementById('opt-whitelist-domain').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') addWhitelistDomain();
  });

  document.getElementById('btn-clear-cache').addEventListener('click', clearCache);
}
