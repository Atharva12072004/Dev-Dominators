# CyberShield AI Mobile Architecture

## Target Stack

- React Native with Expo
- Expo Router
- Expo development build, not Expo Go, for advanced native integrations
- Android-first native extensions
- iOS graceful fallback architecture

## Top-Level Structure

```text
mobile/
  app/
  api/
  components/
  docs/
  features/
  hooks/
  native/
  repositories/
  services/
  storage/
  utils/
```

## Layer Responsibilities

### `app/`

Route entrypoints and navigation shells only.

### `features/`

Feature modules such as:

- protection pipeline
- gmail connect
- browser guard
- logs
- settings

### `components/`

Shared UI primitives and reusable widgets.

### `services/`

Runtime orchestration and platform services:

- threat pipeline coordinator
- capability detection
- background sync coordination

### `native/`

Bridges and descriptors for native Android and iOS-specific functionality.

### `repositories/`

Data access abstraction for:

- backend API
- local persistence
- settings
- logs

### `storage/`

SQLite schema and storage-level primitives.

### `api/`

HTTP client and backend request/response contracts.

### `hooks/`

App-facing React hooks over repositories/services.

### `utils/`

Theme, config, helpers, offline heuristics, formatting.

## Real-Time Protection Architecture

```text
Native source / Gmail sync
  -> normalized event
  -> offline scan
  -> backend enrichment
  -> local persistence
  -> warning decision
  -> block / ignore action
  -> UI sync
```

## Android-Only Boundaries

- notification monitoring
- SMS ingestion
- accessibility helper
- foreground warning activity
- possible overlay manager

## iOS Boundaries

- no universal monitoring of SMS or third-party notifications
- Gmail sync and manual scans remain supported
- browser checks are limited to app-owned flows

