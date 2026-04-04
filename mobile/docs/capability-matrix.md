# CyberShield AI Capability Matrix

This matrix is the source of truth for what CyberShield AI can realistically do by platform.

## Legend

- `Fully feasible on Android`
- `Partially feasible on Android`
- `Fallback only`
- `Limited on iOS`
- `Not feasible on iOS`

## Source Coverage

| Capability | Android | iOS | Notes |
|---|---|---|---|
| Manual scan for URL/text/email/SMS content | Fully feasible on Android | Fully feasible on iOS | Pure React Native + backend + local heuristics |
| Offline local heuristic scan | Fully feasible on Android | Fully feasible on iOS | JS/native local scanning supported on both |
| Local logs, blocked state, ignored state | Fully feasible on Android | Fully feasible on iOS | SQLite/AsyncStorage-backed |
| Gmail OAuth login and sync via Gmail API | Fully feasible on Android | Fully feasible on iOS | Near-real-time polling or server-triggered sync, not mailbox interception |
| Gmail near-real-time sync via backend + push/watch | Fully feasible on Android | Fully feasible on iOS | Best implemented with backend Gmail watch + app sync |
| SMS real-time ingestion | Fully feasible on Android | Not feasible on iOS | Android BroadcastReceiver / SMS permissions; iOS does not allow arbitrary SMS reading |
| Notification text monitoring from selected apps | Fully feasible on Android | Not feasible on iOS | Android NotificationListenerService only |
| WhatsApp/social notification protection | Fully feasible on Android | Not feasible on iOS | Done through notification listener, not private app APIs |
| Accessibility-based link detection inside other apps | Partially feasible on Android | Not feasible on iOS | Powerful but sensitive; requires careful UX and policy review |
| Full browser URL interception system-wide | Partially feasible on Android | Not feasible on iOS | Cannot universally intercept every URL open; app can warn on supported flows |
| Scan before opening links inside CyberShield AI | Fully feasible on Android | Fully feasible on iOS | App controls its own open flow |
| Scan shared links via Android share target / deep links | Fully feasible on Android | Partially feasible on iOS | Strong Android path; iOS share extension requires native extension work outside plain Expo managed flow |
| Full-screen warning overlay above other apps | Partially feasible on Android | Not feasible on iOS | Android overlay requires special permission and policy-sensitive use |
| Foreground warning activity from monitored event | Fully feasible on Android | Limited on iOS | Android can launch warning UI from native service pathways more practically |
| Blocking dangerous opens outside the app | Partially feasible on Android | Not feasible on iOS | Best effort only; true universal blocking is OS-limited |
| Selected-app protection routing | Fully feasible on Android | Fallback only | Android can match package names from notifications |
| Browser security check before external launch from app | Fully feasible on Android | Fully feasible on iOS | App-owned navigation only |
| Chrome URL capture before every open | Partially feasible on Android | Not feasible on iOS | No general-purpose guaranteed interception of Chrome navigation |

## Product Implications

### Android

Android is the primary real-time protection platform. CyberShield AI can support:

- real-time SMS ingestion
- real-time notification ingestion from selected apps
- Gmail sync with backend support
- app-aware logs and warning flows
- best-effort browser and link guarding
- optional advanced native services such as accessibility helpers and overlays

### iOS

iOS should not pretend to offer system-wide monitoring it cannot legally or technically provide. The product should focus on:

- manual scans
- Gmail OAuth + sync-based email protection
- browser checks inside app-controlled flows
- local logs/history
- blocked/ignored state for content originating inside CyberShield AI

## Engineering Rule

Any feature that depends on:

- reading SMS inbox contents in real time
- reading other apps' notifications
- intercepting arbitrary app links system-wide
- overlaying a blocking window over other apps

must be implemented as Android-specific functionality and clearly labeled as unavailable or reduced on iOS.

