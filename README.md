# MCP Shield

**Security gateway for the Model Context Protocol.** Intercepts AI agent tool calls, enforces policy, detects prompt injection, redacts secrets, and writes a tamper-evident audit log.

> ⚠️ **Status: Phase 1 (alpha)** — policy engine, secret redaction, audit logging, transparent proxy. Injection detection and capability graph are stubbed for later phases.

---

## Why

The Model Context Protocol (MCP) lets AI agents (Claude, Cursor, LangChain agents) call external tools — filesystem, databases, shell, HTTP, APIs. The protocol has **no security layer**: agents can call any tool with any arguments, MCP servers can be malicious (tool poisoning), and tool responses go straight into the agent's context (prompt injection).

MCP Shield is a proxy that sits between the agent and MCP servers, applying a security pipeline to every tool call.

### Attacks MCP Shield prevents

| Attack | Real-world example | How we block it |
|---|---|---|
| Tool poisoning | [microsoft/autogen#7427](https://github.com/microsoft/autogen/issues/7427) — RCE via unsigned tool definitions | Scan tool descriptions on connect, freeze hash (rug-pull detection) *(planned)* |
| Prompt injection via response | [anthropics/claude-code#58138](https://github.com/anthropics/claude-code/issues/58138) | Multi-layer detector on every tool response *(planned)* |
| Command injection | [railwayapp/railway-mcp-server#19](https://github.com/railwayapp/railway-mcp-server/issues/19) | Argument validators (path / URL / command allowlists) ✅ |
| Cross-server exfiltration | ChainCaps (arXiv), MCP-Lattice | Capability graph + taint tracking *(planned)* |
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
  -- \
  npx -y @modelcontextprotocol/server-filesystem /home/me
```

`--detect-injection` enables prompt injection detection (regex + heuristics, deterministic, no extra deps). Optional ML layers (embeddings + LLM judge) need `pip install mcp-shield[detector]` and are configured via a policy/SDK.

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
  3. Injection Detector — scan args & responses for prompt injection (planned)
  4. Capability Graph  — taint tracking, cross-server chain detection (planned)
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

See [`docs/architecture.md`](docs/architecture.md) for the full design.

---

## Roadmap

| Phase | Status | Scope |
|---|---|---|
| 1. Foundation | ✅ | Proxy, policy engine, secret redaction, audit log, CLI |
| 2. Injection detection | ✅ | Regex + heuristics (deterministic); optional embeddings + LLM judge |
| 3. Capability graph | 🔜 | Cross-server taint tracking, chain detection (killer-feature) |
| 4. Approval flow | 🔜 | Slack/Teams webhook for high-risk calls |
| 5. Cloud dashboard | 🔜 | Multi-tenant, RBAC, SSO, compliance reports (commercial tier) |

---

## Contributing

PRs welcome. See [`docs/architecture.md`](docs/architecture.md) for the design and run `pytest` for tests.

## License

MIT
