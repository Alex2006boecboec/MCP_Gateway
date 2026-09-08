# MCP Shield — Architecture

## Overview

MCP Shield is a **man-in-the-middle proxy** for the Model Context Protocol. It sits between an AI agent (the MCP client) and one or more MCP servers, applying a security pipeline to every tool call.

## Deployment (stdio transport)

```
┌──────────┐   stdin   ┌──────────────┐   stdin   ┌────────────┐
│ AI Agent │ ───────► │  MCP Shield  │ ───────► │ MCP Server  │
│          │ ◄─────── │   (proxy)   │ ◄─────── │ (subprocess)│
└──────────┘  stdout  └──────────────┘  stdout  └────────────┘
```

The agent launches MCP Shield as if it were the MCP server (we accept the same stdio JSON-RPC). MCP Shield in turn spawns the real MCP server as a subprocess and forwards traffic through, applying the security pipeline on every `tools/list` and `tools/call`.

## Request pipeline

```
tools/call request from agent
  │
  ▼
[1] Secret Redactor — mask secrets in arguments
  │   (so they don't reach the server in the clear, and don't end up in logs)
  ▼
[2] Policy Engine — deterministic allow/deny (YAML rules)
  │   (no LLM in the decision path — prompt injection cannot bypass it)
  ▼
[3] Injection Detector — scan arguments for prompt injection  (Phase 2)
  │
  ▼
[4] Capability Graph — taint tracking, cross-server chain detection  (Phase 3)
  │
  ▼
[5] Approval Flow — hold high-risk calls for human approval  (Phase 4)
  │
  ▼
forward to MCP server
  │
  ▼
response from MCP server
  │
  ▼
[3] Injection Detector — scan response for prompt injection  (Phase 2)
  │
  ▼
[1] Secret Redactor — mask secrets in response
  │
  ▼
[6] Audit Logger — hash-chained JSONL entry
  │
  ▼
return to agent
```

## Components

### `mcp_shield/protocol.py` — JSON-RPC 2.0 framing
- Newline-delimited JSON-RPC 2.0 over stdio
- `Message` dataclass with convenience accessors
- `read_message` / `write_message` with strict size limits (4 MiB)
- Helpers: `is_tools_list`, `is_tools_call`, `make_error_response`
- Error codes: `ERR_POLICY_DENIED`, `ERR_INJECTION_DETECTED`, `ERR_VALIDATION_FAILED`, etc.

### `mcp_shield/policy.py` — deterministic policy engine
- YAML policy format: `servers`, `rules`, `defaults`
- Per-server trust levels (low/medium/high)
- Per-tool config: allow/deny/validate (url/path/command)
- Global rules: tool_regex + arg_regex → action (allow/deny/redact/approve)
- `block_internal` special-case for SSRF protection
- Path traversal, shell metacharacter, internal IP validators
- **Deterministic** — no LLM in the decision path (fail-closed mode available)

### `mcp_shield/redactor.py` — secret redaction
- Curated regex patterns for AWS, GCP, GitHub, Slack, OpenAI, Anthropic, Google API keys, PEM private keys, Bearer tokens, connection-string passwords
- Bidirectional: redacts arguments (in) and responses (out)
- Recursive dict/list traversal
- Mask keeps first 4 / last 2 chars visible for debuggability
- Records every redaction so the audit log can show what was masked

### `mcp_shield/audit.py` — tamper-evident audit log
- Append-only JSONL, one decision per line
- Hash-chained: each entry contains SHA-256 of the previous entry
- `verify()` walks the chain and detects tampering
- Resumes the chain on restart (reads the last hash)
- File permissions set to 0600 on POSIX (best-effort on Windows)
- Secrets never written to the log (redaction runs before audit)

### `mcp_shield/proxy.py` — the main loop
- Spawns the MCP server as a subprocess
- Pumps messages between agent stdin/stdout and server stdin/stdout
- Runs the request pipeline on every `tools/call`
- Runs the response pipeline on every response
- Writes an audit entry for every decision
- Phase 1: sequential pump (one request → one response). Phase 2 will add async for concurrent notifications.

### `mcp_shield/cli.py` — command-line entry point
- `mcp-shield --policy X --audit Y -- <server command>`
- `--fail-closed` for production (deny by default)
- `--no-redact` to disable redaction (NOT recommended)
- Logs go to stderr (stdout is the MCP channel — must stay clean)

## Design principles

1. **Deterministic policy, no LLM in the decision path.** Prompt injection cannot bypass the policy engine. LLMs are only used in the optional Layer 4 of the injection detector, never for the final allow/deny.
2. **Fail-closed by default in production.** When no rule matches and `defaults.action: deny`, the call is blocked. This is the safe default.
3. **Secrets never reach logs.** Redaction runs before audit logging, so even the audit log doesn't contain secrets.
4. **Tamper-evident, not tamper-proof.** We rely on filesystem permissions for integrity. The hash chain detects tampering after the fact.
5. **Transparent to agent and server.** Neither side knows the proxy is there. We forward bytes unchanged (except when we modify them on purpose).
6. **Minimal dependencies.** Phase 1 only needs `pyyaml` and `jsonschema`. The injection detector (Phase 2) adds `sentence-transformers` and `scikit-learn`.

## Threat model

**In scope:**
- Prompt injection via tool descriptions and tool responses
- Command injection via unsafe argument handling in MCP servers
- SSRF via fetch-like tools
- Path traversal via filesystem-like tools
- Secret leakage into agent context
- Cross-server exfiltration chains (Phase 3)
- Unauthorized high-risk actions (Phase 4 approval flow)

**Out of scope (for now):**
- Authentication of the MCP server itself (use mTLS / OAuth separately)
- Sandboxing the MCP server (use Docker / nsjail separately)
- Network-level attacks (use a firewall separately)
- Defending against a malicious agent (we assume the agent is the victim, not the attacker)

## Future phases

- **Phase 2:** Injection detector — regex → heuristics → embeddings → optional LLM judge. Applied to tool descriptions (on connect) and tool responses (on every call).
- **Phase 3:** Capability graph — extract capabilities from tool descriptions, track data flow across calls in a session, detect dangerous chains (read→send, file→http). This is the killer-feature: we see attacks no single-server scanner can see.
- **Phase 4:** Approval flow — Slack/Teams webhook for high-risk calls (rm, exec, external POST, large data transfer). Fail-closed on timeout.
- **Phase 5:** Cloud dashboard — multi-tenant, RBAC, SSO, compliance reports (SOC2, ISO27001, 152-ФЗ). Commercial tier.
