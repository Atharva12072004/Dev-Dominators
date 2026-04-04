# Protection Feature Module

This feature owns the end-to-end threat pipeline:

1. ingest source event
2. normalize event
3. run offline scan
4. enrich with backend scan
5. persist protection event
6. trigger warning flow
7. record block / ignore actions

Future implementation should split this module into:

- `ingestion/`
- `scanning/`
- `warning/`
- `logs/`
- `settings/`

