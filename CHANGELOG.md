# Changelog

All notable changes to MCP Shield are documented here.

## [0.1.0-alpha] — 2026-09-10

First public alpha release.

### Highlights
- Transparent MCP proxy with YAML policy engine (deterministic allow/deny)
- Secret redaction (AWS/GCP/GitHub/Slack/OpenAI-style tokens, PEM, etc.)
- Prompt-injection detection (regex + heuristics; optional embeddings/LLM)
- Capability graph / cross-call exfiltration chain blocking
- Human-in-the-loop approval queue (file-based + optional webhook)
- Tamper-evident hash-chained JSONL audit log
- Optional self-hosted multi-tenant cloud dashboard + event shipper

### Security fixes included in this tag
- Block RFC1918 `172.16.0.0/12` in URL `block_internal` checks
- Wire CLI `--fail-closed` to force deny-by-default
- Fix monthly event-limit off-by-one
- Fix shipper re-spool on duplicate `accepted` counts
- Multi-proxy cloud dedupe via `proxy_id`
- Capability-graph errors fail closed
- Approval poller ignores invalid decisions instead of early-exit
- SMTP implicit TLS (port 465), `/forgot` rate limit
- Disable unpaid self-serve plan upgrades by default
- Postgres boot: do not create `proxy_id` index before migration

### Known limitations
See [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md).
