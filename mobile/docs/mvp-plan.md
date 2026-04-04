# Android-First MVP Plan

## MVP Scope

### Phase 1

- manual scan
- offline heuristics
- backend unified scan integration
- SQLite protection logs
- blocked / ignored state
- browser security flow inside app-owned opens
- settings and source toggles

### Phase 2

- Gmail OAuth
- Gmail sync endpoint integration
- Android notification listener ingestion
- selected-app protection
- warning full-screen activity

### Phase 3

- Android SMS real-time ingestion
- optional accessibility helper for advanced link detection
- background sync jobs
- stronger blocked-content reopening protections

### Phase 4

- advanced reputation providers
- domain intelligence caching
- native overlay experiments if policy-safe

## MVP Recommendation

Build Phase 1 and Phase 2 before trying accessibility or overlay-based controls. Those advanced native features add review, trust, and lifecycle complexity.

