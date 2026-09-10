# Known limitations (alpha)

MCP Shield is useful today as a **local/self-hosted MCP security proxy**.
These gaps are intentional honesty for early adopters — not a full product roadmap.

## Proxy

| Limitation | Notes |
|---|---|
| Tool poisoning / rug-pull detection | Documented as **planned**. `tools/list` injection scanning helps, but tool-definition hashing/freeze is not done yet. |
| Policy action `redact` | Secrets are redacted by the SecretRedactor; policy `redact` is treated as allow-after-redact, not a separate transform. |
| Stdio MCP only | The proxy speaks JSON-RPC over stdio. HTTP/SSE MCP transports are out of scope for 0.1. |
| Single downstream server per process | One wrapped MCP server command per `mcp-shield` process. |

## Cloud dashboard (optional)

| Limitation | Notes |
|---|---|
| No billing / payments | Self-serve upgrades require `MCP_SHIELD_ALLOW_SELF_UPGRADE=1` (demo only). |
| SSO / OIDC | Stubbed (`/sso/login` → 501). Password auth only. |
| Plan feature flags | Event/month limits are enforced. Proxy count, MCP-server count, SSO, compliance gates are mostly UI/docs for now. |
| Retention | `Plan.data_retention_days` is not fully wired; use `MCP_SHIELD_RETENTION_DAYS` / ops jobs. |
| In-memory rate limits | Per-process. Multi-worker deployments need an external limiter for hard guarantees. |

## Detection

| Limitation | Notes |
|---|---|
| Heuristic/regex detectors | Strong on common patterns; not a substitute for model-aware defenses on every payload. |
| Optional ML layers | Need `pip install mcp-shield[detector]` and extra config; off by default. |

## Ops

| Limitation | Notes |
|---|---|
| Alpha stability | Schema migrations and cloud deploys are improving; pin a release tag in production. |
| Default policy | Ships `defaults.action: allow`. Use `--fail-closed` or edit the YAML for production. |
