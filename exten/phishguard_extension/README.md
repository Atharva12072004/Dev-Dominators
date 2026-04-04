# CYBERSHIELD — Browser Extension

> AI-powered real-time phishing detection for browser links, Gmail, Outlook Web, and WhatsApp Web.

## Overview

CYBERSHIELD is a Manifest V3 Chrome/Edge browser extension that integrates with a FastAPI backend to provide real-time phishing and malware detection. It monitors browser navigation, email services, and messaging platforms to protect users from malicious content.

## Installation

### Load as Unpacked Extension

1. Open Chrome or Edge and navigate to `chrome://extensions/` (or `edge://extensions/`)
2. Enable **Developer mode** (toggle in the top-right corner)
3. Click **Load unpacked**
4. Select the `phishguard_extension` directory
5. The extension icon will appear in your browser toolbar

### Configure Backend

1. On first install, the **Settings** page will open automatically
2. Enter your **Backend URL** (e.g., `http://127.0.0.1:8000`)
3. Enter your **API Key** (if the backend requires one via `X-API-Key` header)
4. Click **Test Connection** to verify
5. Click **Save Settings**

## Features

### 🔗 Browser Link Monitoring
- Intercepts clicked links on all web pages
- Scans URLs in real-time via the backend before navigation
- Shows a floating shield indicator on pages
- Displays inline warning modals for suspicious links
- Redirects to a warning interstitial page for blocked threats
- Supports temporary "proceed anyway" overrides (5-minute window)

### ✉️ Email Monitoring
- **Supported platforms:** Gmail, Outlook Web (outlook.live.com, outlook.office.com)
- Automatically detects when an email is opened
- Extracts subject, body text, and embedded links
- Unwraps Google redirect URLs and Outlook Safe Links
- Scans via `/api/v1/scan/email`
- Injects inline risk badges next to suspicious links
- Shows a compact warning banner for risky emails
- Deduplicates scans using content fingerprints

### 💬 WhatsApp Web Monitoring
- **Supported platform:** WhatsApp Web (web.whatsapp.com)
- Observes conversation changes and new messages
- Extracts URLs from message text and link previews
- Scans via `/api/v1/scan/chat`
- Injects small risk badges near suspicious URLs
- Shows a compact warning banner for risky conversations
- Deduplicates scans using content fingerprints

### 📊 Dashboard
- Full-page security dashboard accessible from the popup
- Metric cards: total scanned, threats blocked, safe count, accuracy, false positive rate, detection speed
- Donut chart of scan distribution by category
- Daily activity bar chart (last 14 days)
- Performance metrics: P95 detection, explainability, user experience score
- Full scan history table with filtering, search, and pagination
- Expandable rows with detailed scan information
- Analyst feedback buttons for each history record
- Client-side CSV export (no backend export endpoint exists)
- Automatic polling every 15 seconds with retry/backoff

### ⚙️ Settings
- Backend URL and API key configuration
- Connection health test
- Monitoring toggles (auto, browser links, email, WhatsApp)
- Notification settings
- Warning threshold (risk score slider)
- Direct navigation warning behavior (warn/block/allow)
- Proceed-once override toggle
- Domain whitelist management
- Theme selection (dark/light/system)
- Local cache retention settings
- Clear local cache

### 🛡️ Warning Page
- Premium interstitial page shown when threats are blocked
- Displays verdict, risk score, reason, and flags
- "Go Back to Safety" button
- "Proceed Anyway" button (when override is allowed by backend)
- Proceed sets a 5-minute temporary override

## Architecture

```
phishguard_extension/
├── manifest.json               # MV3 manifest
├── background/
│   └── service_worker.js       # Background service worker
├── shared/
│   ├── api.js                  # Backend API helpers
│   ├── storage.js              # chrome.storage wrappers
│   ├── ui.js                   # Reusable UI components
│   └── theme.js                # Theme engine
├── content_scripts/
│   ├── interceptor.js          # Link click interception
│   ├── email_monitor.js        # Gmail/Outlook monitor
│   └── whatsapp_monitor.js     # WhatsApp Web monitor
├── popup/
│   ├── popup.html
│   ├── popup.js
│   └── popup.css
├── dashboard/
│   ├── dashboard.html
│   ├── dashboard.js
│   └── dashboard.css
├── options/
│   ├── options.html
│   ├── options.js
│   └── options.css
├── warning/
│   ├── warning.html
│   ├── warning.js
│   └── warning.css
├── assets/
│   ├── logo.svg
│   ├── icon16.png
│   ├── icon32.png
│   ├── icon48.png
│   └── icon128.png
└── README.md
```

## Important Limitations

### 🖥️ Native Desktop Apps Are NOT Monitored
This extension only monitors **web content inside the browser**:
- Gmail and Outlook **Web** (not desktop Outlook)
- WhatsApp **Web** (not the WhatsApp desktop app or mobile app)
- Links clicked **within browser pages**

Desktop applications, native email clients, and mobile apps are outside the browser extension's scope.

### 📋 History Detail Availability
- The backend `/api/v1/history` endpoint returns summary data only
- There is **no** separate history detail endpoint (no `GET /api/v1/history/{id}`)
- Full engine details are only available from the **extension's local cache** for recently scanned items
- If cached data is unavailable, the dashboard shows: *"Detailed engine data unavailable for this record."*

### 🔄 Polling Behavior
- The dashboard polls the backend every **15 seconds** for updated stats and history
- If the backend is unreachable, polling continues with exponential backoff
- The connection status indicator in the dashboard and popup reflects the current state

### ⚠️ Warning Override Behavior
- When the backend returns `override_allowed: true`, users can click "Proceed Anyway"
- This sets a **5-minute temporary override** for that specific URL
- After 5 minutes, the URL will be scanned again on next visit
- Overrides are stored in extension local storage and cleaned up periodically

### 🚫 MV3 Blocking Limitations
- Manifest V3 does **not** support synchronous `webRequest.onBeforeRequest` blocking
- Link interception works via click event handlers, which covers most user-initiated navigation
- Direct URL bar navigation or JavaScript-initiated navigation **cannot** be pre-blocked in all cases
- The extension relies on the backend's `block_decision` response to determine post-scan action

### 📤 CSV Export
- There is **no backend export endpoint**
- CSV export is generated **client-side** from the currently loaded/filtered history data
- Only the visible page of results is exported

### 🗂️ Data Retention
- The "Cache Retention" setting in options applies only to the **extension's local cache**
- Backend data retention is managed by the backend server independently
- The extension cleans up expired local data every hour via `chrome.alarms`

## Backend API

The extension communicates with a FastAPI backend. See the backend documentation for API details.

**Required endpoints:**
- `GET /health` — Connection status check
- `POST /api/v1/scan/url` — Scan single URL
- `POST /api/v1/scan/email` — Scan email content
- `POST /api/v1/scan/chat` — Scan chat content
- `POST /api/v1/scan/batch` — Scan multiple URLs
- `GET /api/v1/history` — Scan history with filters
- `DELETE /api/v1/history/{id}` — Delete history record
- `DELETE /api/v1/history/all` — Clear all history
- `POST /api/v1/history/{id}/feedback` — Submit analyst feedback
- `GET /api/v1/stats` — Dashboard statistics
- `GET /api/v1/whitelist` — List whitelisted domains
- `POST /api/v1/whitelist` — Add domain to whitelist
- `DELETE /api/v1/whitelist/{domain}` — Remove from whitelist

## Permissions

| Permission | Reason |
|---|---|
| `storage` | Settings, cache, overrides |
| `tabs` | Current tab URL and navigation |
| `activeTab` | Scan current page |
| `webNavigation` | Track page loads |
| `notifications` | Threat alerts |
| `scripting` | Content script injection |
| `alarms` | Periodic cache cleanup |
| `<all_urls>` | Link interception on all sites |

## License

This project is provided as-is for security research and educational purposes.
