# MCP Shield

**Open-source security gateway for the Model Context Protocol (MCP).**

Sit it in front of any MCP server. It intercepts tool calls, enforces a deterministic YAML policy, redacts secrets, detects prompt injection, blocks cross-tool exfiltration chains, can hold high-risk calls for human approval, and writes a tamper-evident audit log.

> ⚠️ **Status: `v0.1.0-alpha` (free / MIT)** — ready for early adopters and self-hosted use. Not a turnkey commercial SaaS. See [Known limitations](docs/KNOWN_LIMITATIONS.md).

```bash
pip install mcp-shield
mcp-shield --policy policies/default.yaml --detect-injection --track-chains --fail-closed \
  -- -- npx -y @modelcontextprotocol/server-filesystem ~/docs
```

---

## Why

MCP lets AI agents (Claude, Cursor, LangChain, …) call external tools — filesystem, databases, shell, HTTP. The protocol has **no security layer**: agents can call any tool with any arguments, MCP servers can be malicious, and tool responses go straight into the model context.

### What MCP Shield blocks

| Attack | How we block it |
|---|---|
| Prompt injection via tool responses | Multi-layer detector (regex + heuristics; optional ML) ✅ |
| Command / arg injection | Path / URL / command validators ✅ |
| SSRF (metadata & RFC1918) | URL validator with `block_internal` ✅ |
| Cross-server exfiltration | Capability graph + taint tracking ✅ |
| Secret leakage into logs/context | Secret redactor (AWS/GCP/GitHub/Slack/OpenAI/PEM/…) ✅ |
| High-risk tools without a human | Approval queue (file-based + optional webhook) ✅ |
| No audit trail | Hash-chained JSONL audit log ✅ |
| Tool poisoning / rug-pull | Description scanning helps; full hash-freeze *(planned)* |

---

## Quickstart

### 1. Install

```bash
pip install mcp-shield
```

### 2. Wrap an MCP server

Point your MCP client at `mcp-shield` instead of the real server. Everything after `--` is the real server command:

```bash
mcp-shield \
  --policy policies/default.yaml \
  --audit audit.jsonl \
  --detect-injection \
  --track-chains \
  --fail-closed \
  -- \
  npx -y @modelcontextprotocol/server-filesystem /home/me
```

| Flag | Purpose |
|---|---|
| `--detect-injection` | Regex + heuristics (no extra deps) |
| `--track-chains` | Cross-call taint / exfil chain blocking |
| `--fail-closed` | Deny when no rule matches (recommended) |
| `--require-approval` | Hold high-risk calls for a human |
| `--cloud-url` / `--cloud-key` | Optional: ship events to a self-hosted dashboard |

Optional ML layers: `pip install mcp-shield[detector]`.

### 3. Claude Desktop / Cursor-style config

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-shield",
      "args": [
        "--policy", "/absolute/path/to/policies/default.yaml",
        "--audit", "/absolute/path/to/audit.jsonl",
        "--detect-injection",
        "--track-chains",
        "--fail-closed",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/absolute/path/to/allowed/dir"
      ]
    }
  }
}
```

### 4. Verify the audit log

```bash
tail -f audit.jsonl | jq .
python -c "from mcp_shield.audit import AuditLogger; print(AuditLogger('audit.jsonl').verify())"
```

---

## Policy format

```yaml
defaults:
  action: allow          # or "deny" / use --fail-closed

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

See [`policies/default.yaml`](policies/default.yaml) for a secure-by-default starter policy.

**Design principle:** the policy engine is **deterministic** — no LLM is consulted for allow/deny. Prompt injection cannot talk the gateway into changing policy. Optional LLMs only advise inside the injection detector.

---

## Architecture

```
AI Agent → [MCP SHIELD] → MCP Server(s)

Every tools/call:
  1. Secret Redactor
  2. Policy Engine
  3. Injection Detector
  4. Capability Graph (taint / chains)
  5. Approval Flow (optional)
  6. Audit Logger (hash chain)
  7. Cloud Shipper (optional)
```

Details: [`docs/architecture.md`](docs/architecture.md) · phases 2–5 under [`docs/`](docs/).

---

## Optional: self-hosted cloud dashboard

Central multi-tenant UI for audit events, RBAC, and compliance report exports.
This is **optional** — the proxy works fully offline.

```bash
pip install "mcp-shield[cloud]"
mcp-shield-cloud   # → http://127.0.0.1:8000
# First boot prints a one-time admin password to stderr/logs — change it immediately.
```

Then point a proxy with `--cloud-url` and `--cloud-key`.

---

## Roadmap

| Phase | Status | Scope |
|---|---|---|
| 1. Foundation | ✅ | Proxy, policy, redaction, audit, CLI |
| 2. Injection detection | ✅ | Regex + heuristics; optional embeddings/LLM |
| 3. Capability graph | ✅ | Cross-call taint / chain detection |
| 4. Approval flow | ✅ | File queue + webhook, fail-closed |
| 5. Cloud dashboard | ✅ alpha | Multi-tenant UI, RBAC, reports (SSO stubbed) |
| 6. Tool freeze / rug-pull | 🔜 | Hash tool definitions on connect |

---

## Security

- Report vulnerabilities privately — see [`SECURITY.md`](SECURITY.md)
- Operator caveats — see [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md)
- Changelog — [`CHANGELOG.md`](CHANGELOG.md)

## Contributing

PRs welcome. See [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md). Run `pytest`.

## License

MIT
