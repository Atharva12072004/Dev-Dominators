/**
 * PhishGuard AI — Theme engine
 * Supports dark / light / system.  Defaults to dark.
 */

const Theme = (() => {

  const DARK = {
    '--pg-bg':            '#0f1117',
    '--pg-bg-secondary':  '#181b23',
    '--pg-bg-card':       '#1e2230',
    '--pg-bg-card-hover': '#252a3a',
    '--pg-bg-input':      '#252a3a',
    '--pg-bg-overlay':    'rgba(0,0,0,0.55)',
    '--pg-border':        'rgba(255,255,255,0.06)',
    '--pg-border-subtle': 'rgba(255,255,255,0.03)',
    '--pg-text':          '#e8eaed',
    '--pg-text-secondary':'#9ca3af',
    '--pg-text-muted':    '#6b7280',
    '--pg-accent':        '#3b82f6',
    '--pg-accent-hover':  '#2563eb',
    '--pg-safe':          '#22c55e',
    '--pg-warning':       '#f59e0b',
    '--pg-danger':        '#ef4444',
    '--pg-neutral':       '#6b7280',
    '--pg-shadow':        '0 4px 24px rgba(0,0,0,0.35)',
    '--pg-shadow-lg':     '0 8px 40px rgba(0,0,0,0.5)',
    '--pg-radius':        '12px',
    '--pg-radius-sm':     '8px',
    '--pg-radius-xs':     '6px',
    '--pg-transition':    '0.2s ease'
  };

  const LIGHT = {
    '--pg-bg':            '#f4f5f7',
    '--pg-bg-secondary':  '#ffffff',
    '--pg-bg-card':       '#ffffff',
    '--pg-bg-card-hover': '#f0f1f3',
    '--pg-bg-input':      '#f0f1f3',
    '--pg-bg-overlay':    'rgba(0,0,0,0.25)',
    '--pg-border':        'rgba(0,0,0,0.08)',
    '--pg-border-subtle': 'rgba(0,0,0,0.04)',
    '--pg-text':          '#1f2937',
    '--pg-text-secondary':'#6b7280',
    '--pg-text-muted':    '#9ca3af',
    '--pg-accent':        '#3b82f6',
    '--pg-accent-hover':  '#2563eb',
    '--pg-safe':          '#16a34a',
    '--pg-warning':       '#d97706',
    '--pg-danger':        '#dc2626',
    '--pg-neutral':       '#6b7280',
    '--pg-shadow':        '0 4px 24px rgba(0,0,0,0.08)',
    '--pg-shadow-lg':     '0 8px 40px rgba(0,0,0,0.12)',
    '--pg-radius':        '12px',
    '--pg-radius-sm':     '8px',
    '--pg-radius-xs':     '6px',
    '--pg-transition':    '0.2s ease'
  };

  function _applyVars(vars) {
    const root = document.documentElement;
    for (const [k, v] of Object.entries(vars)) {
      root.style.setProperty(k, v);
    }
  }

  function _prefersDark() {
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  }

  function apply(theme) {
    let effective = theme;
    if (theme === 'system') effective = _prefersDark() ? 'dark' : 'light';
    _applyVars(effective === 'light' ? LIGHT : DARK);
    document.documentElement.setAttribute('data-theme', effective);
  }

  async function init() {
    const { theme = 'dark' } = await chrome.storage.sync.get('theme');
    apply(theme);

    // listen for system changes
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', async () => {
      const { theme: t = 'dark' } = await chrome.storage.sync.get('theme');
      if (t === 'system') apply('system');
    });

    // listen for storage changes from options page
    chrome.storage.onChanged.addListener((changes) => {
      if (changes.theme) apply(changes.theme.newValue || 'dark');
    });
  }

  return { init, apply, DARK, LIGHT };
})();

if (typeof globalThis !== 'undefined') globalThis.PhishGuardTheme = Theme;
