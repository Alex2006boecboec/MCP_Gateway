# MCP Shield

**Security gateway for the Model Context Protocol.** Intercepts AI agent tool calls, enforces policy, detects prompt injection, redacts secrets, tracks cross-server data-flow chains, holds high-risk calls for human approval, and writes a tamper-evident audit log.

> ⚠️ **Status: Phase 4 (alpha)** — policy engine, secret redaction, audit logging, transparent proxy, multi-layer injection detection, capability-graph chain detection, and human-in-the-loop approval flow are implemented. Cloud dashboard is planned.

---

## Why

The Model Context Protocol (MCP) lets AI agents (Claude, Cursor, LangChain agents) call external tools — filesystem, databases, shell, HTTP, APIs. The protocol has **no security layer**: agents can call any tool with any arguments, MCP servers can be malicious (tool poisoning), and tool responses go straight into the agent's context (prompt injection).

MCP Shield is a proxy that sits between the agent and MCP servers, applying a security pipeline to every tool call.

### Attacks MCP Shield prevents

| Attack | Real-world example | How we block it |
|---|---|---|
| Tool poisoning | [microsoft/autogen#7427](https://github.com/microsoft/autogen/issues/7427) — RCE via unsigned tool definitions | Scan tool descriptions on connect, freeze hash (rug-pull detection) *(planned)* |
| Prompt injection via response | [anthropics/claude-code#58138](https://github.com/anthropics/claude-code/issues/58138) | Multi-layer detector on every tool response ✅ |
| Command injection | [railwayapp/railway-mcp-server#19](https://github.com/railwayapp/railway-mcp-server/issues/19) | Argument validators (path / URL / command allowlists) ✅ |
| Cross-server exfiltration | ChainCaps (arXiv), MCP-Lattice | Capability graph + taint tracking ✅ |
| SSRF | [modelcontextprotocol/servers#4497](https://github.com/modelcontextprotocol/servers/pull/4497) (still open!) | URL validator blocks internal/metadata IPs ✅ |
| Secret leakage | — | Secret redactor masks AWS/GCP/GitHub/Slack/OpenAI keys ✅ |

---

## Quickstart

### Install

```bash
pip install mcp-shield
```

### Wrap an MCP server

Point your MCP client at `mcp-shield` instead of the real server. Everything after `--` is the real server command:

```bash
mcp-shield \
  --policy policies/default.yaml \
  --audit audit.jsonl \
  --detect-injection \
  --track-chains \
  --require-approval \
  --approval-dir approvals \
  --approval-timeout 120 \
  -- \
  npx -y @modelcontextprotocol/server-filesystem /home/me
```

`--detect-injection` enables prompt injection detection (regex + heuristics, deterministic, no extra deps). `--track-chains` enables the capability graph, which tracks data flow across tool calls and blocks dangerous cross-server chains (e.g. read a secret file then send its contents to an external URL). `--require-approval` holds high-risk tool calls for human approval via a file-based queue (with optional Slack/Teams webhook). Optional ML layers (embeddings + LLM judge) need `pip install mcp-shield[detector]` and are configured via a policy/SDK.

### Claude Desktop config

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-shield",
      "args": [
        "--policy", "C:/Users/me/policies/default.yaml",
        "--audit", "C:/Users/me/.mcp-shield/audit.jsonl",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "C:/Users/me"
      ]
    }
  }
}
```

### Verify the audit log

```bash
# Every line is one decision. The hash chain makes the log tamper-evident.
tail -f audit.jsonl | jq .

# Verify integrity:
python -c "from mcp_shield.audit import AuditLogger; print(AuditLogger('audit.jsonl').verify())"
```

---

## Policy format

```yaml
defaults:
  action: allow          # or "deny" for fail-closed mode

servers:
  filesystem:
    trust: high
    tools:
      read_file: {allow: true}
      write_file: {deny: true, reason: "writes blocked"}
  fetch:
    trust: low
    tools:
      fetch_url: {validate: url, block_internal: true}

rules:
  - name: block-ssrf-metadata
    when: {tool_regex: ".*fetch.*"}
    check: {arg_regex: "169\\.254\\.169\\.254"}
    action: deny
    reason: "SSRF to cloud metadata endpoint blocked"
```

See [`policies/default.yaml`](policies/default.yaml) for a secure-by-default policy.

---

## Architecture

```
AI Agent → [MCP SECURITY GATEWAY] → MCP Servers

Gateway pipeline (every tools/call):
  1. Secret Redactor   — mask secrets in args (before logging/forwarding)
  2. Policy Engine     — deterministic allow/deny (YAML rules, fail-closed)
  3. Injection Detector — scan args & responses for prompt injection ✅
  4. Capability Graph  — taint tracking, cross-server chain detection ✅
  5. Approval Flow     — human-in-the-loop for high-risk calls (planned)
  6. Audit Logger      — hash-chained JSONL, tamper-evident
```

**Design principle:** the policy engine is **deterministic** — no LLM is ever consulted for a policy decision. Prompt injection cannot bypass it. LLMs are only used in the optional Layer 4 of the injection detector, never for the final allow/deny.

### Injection detection (Phase 2)

4 layers, 2 mandatory + 2 optional. The final block/allow is a deterministic threshold over a numeric score.

| Layer | Type | Deps | Default |
|---|---|---|---|
| 0. Regex | mandatory, deterministic | stdlib | on |
| 1. Heuristics | mandatory, deterministic | stdlib | on |
| 2. Embeddings | optional, semantic | sentence-transformers | off |
| 3. LLM judge | optional, advisory | httpx + API key | off |

Layer 0–1 catch 90%+ of injections instantly (microseconds, no ML). Layer 2–3 only run on the ambiguous "suspicious" band (score 0.5–0.9). A confirmed Layer 0 hit blocks immediately without loading any model. See [`docs/phase2_plan.md`](docs/phase2_plan.md) for the full design.

### Capability graph (Phase 3)

The capability graph is what no single-call scanner can see: **cross-server data-flow chains**. It tracks what each tool can do (its *capabilities*) and what sensitive data it read (*taints*), then blocks when a later call sends that data somewhere dangerous.

- **Capabilities**: each tool is tagged with read/write/send/exec capabilities, inferred from its description (with a static registry for well-known MCP servers).
- **Taints**: when a read call returns a secret (detected via the redactor's in-memory matches, sensitive file paths, or env-var lines), a *taint* is created — a fingerprint of the secret value (sha256, truncated). **The secret itself is never stored.**
- **Chains**: when a later call is a dangerous sink (network send, exec) and its arguments contain a value whose fingerprint matches an active taint, a dangerous chain is detected and blocked.

| Chain rule | Source | Sink | Severity |
|---|---|---|---|
| secret-exfiltration | read:secret | network:send | block |
| env-exfiltration | read:env | network:send | block |
| secret-to-exec | read:secret | exec:command | block |
| env-to-exec | read:env | exec:command | block |
| db-to-exfiltration | read:database | network:send | block |
| secret-to-write | read:secret | write:filesystem | review |
| file-to-exec | read:filesystem | exec:command | review |
| network-to-exec | read:network | exec:command | review |

Memory is bounded (LRU eviction + TTL expiry) and the graph resets on each new agent session. See [`docs/phase3_plan.md`](docs/phase3_plan.md) for the full design.

### Approval flow (Phase 4)

Some calls are too dangerous to auto-allow but too useful to auto-deny: `rm -rf`, `exec` with untrusted args, external POST, a "review"-severity chain. Phase 4 **holds** these calls and asks a human to approve or deny them. On timeout → fail-closed (deny).

- **Triggers**: a policy rule with `action: approve`, a risk rule in the policy's `approval` section (tool_regex + arg_regex), or a graph "review" chain (optional).
- **File-based queue** (zero deps): the proxy writes `approvals/pending/<id>.json` (args already redacted); a human or Slack bot writes `approvals/responses/<id>.json` with `{"decision": "approve"|"deny", "by": "..."}`.
- **Optional webhook**: `--approval-webhook` posts a notification to a Slack/Teams incoming webhook (best-effort; the file queue is the source of truth).
- **Fail-closed**: timeout → `ERR_APPROVAL_TIMEOUT`; deny → `ERR_APPROVAL_DENIED`; policy `approve` with approval disabled → DENY (loud misconfig signal).

```yaml
approval:
  require_for_review_chains: true
  risk_rules:
    - name: high-risk-exec
      tool_regex: ".*exec|.*run|.*shell"
      reason: "exec-like tool requires approval"
    - name: destructive-file
      tool_regex: ".*delete|.*remove|.*rm"
      arg_regex: "rm|delete|remove"
      reason: "destructive file operation requires approval"
```

See [`docs/phase4_plan.md`](docs/phase4_plan.md) for the full design.

See [`docs/architecture.md`](docs/architecture.md) for the full design.

---

## Roadmap

| Phase | Status | Scope |
|---|---|---|
| 1. Foundation | ✅ | Proxy, policy engine, secret redaction, audit log, CLI |
| 2. Injection detection | ✅ | Regex + heuristics (deterministic); optional embeddings + LLM judge |
| 3. Capability graph | ✅ | Cross-server taint tracking, chain detection (killer-feature) |
| 4. Approval flow | ✅ | Slack/Teams webhook for high-risk calls, file-based queue, fail-closed |
| 5. Cloud dashboard | 🔜 | Multi-tenant, RBAC, SSO, compliance reports (commercial tier) |

---

## Contributing

PRs welcome. See [`docs/architecture.md`](docs/architecture.md) for the design and run `pytest` for tests.

## License

MIT
