# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| `0.1.x` (alpha) | ✅ best-effort |
| older / untagged | ❌ |

MCP Shield is currently an **alpha**. Treat it as a security control that reduces risk — not as a complete guarantee.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security bugs.

Email: open a private report via GitHub **Security Advisories** on this repository
(Preferred: *Security* → *Report a vulnerability*), or contact the maintainers
listed on the GitHub profile.

Include:
- affected component (proxy / policy / detector / cloud)
- steps to reproduce
- impact (bypass, info leak, privilege escalation, DoS)
- suggested fix if you have one

We aim to acknowledge reports within a few days.

## What is intentionally public

- Default bootstrap credentials `admin@mcp-shield.local` / `admin` for a **fresh**
  self-hosted cloud dashboard (forced password change on first login).
- AWS/GitHub/Slack **documentation example** strings in unit/smoke tests
  (e.g. `AKIAIOSFODNN7EXAMPLE`). These are not live credentials.

## Hardening checklist (operators)

1. Prefer `--fail-closed` (or `defaults.action: deny`) in production.
2. Keep `--detect-injection` and `--track-chains` on for agent workloads.
3. Never commit `.env`, API keys, or audit logs with real data.
4. If you run the cloud dashboard publicly: change the bootstrap admin password,
   set a strong session secret, use Postgres + HTTPS, and keep
   `MCP_SHIELD_ALLOW_SELF_UPGRADE` unset unless you really want demo upgrades.
5. Rotate any API key (`mcp_live_…`) that may have leaked.
