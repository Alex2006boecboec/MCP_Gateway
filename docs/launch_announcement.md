# Launch notes (public alpha)

Use this when announcing MCP Shield on GitHub / HN / socials.

## One-liner

**Open-source security proxy for MCP** — block SSRF, secret leaks, prompt injection, and cross-tool exfiltration before they reach your agent.

## Positioning

- Lead with the **local proxy** (`pip install` + wrap any MCP server).
- Cloud dashboard = optional self-hosted extras, not the pitch.
- Status: **alpha**, MIT, free to use.

## Show HN draft

**Title:** Show HN: MCP Shield – open-source security gateway for Model Context Protocol

**Body:**

```text
MCP lets AI agents call tools (filesystem, fetch, shell, DBs) with basically no
security layer. That means SSRF to cloud metadata, secret leakage into context,
prompt injection via tool responses, and cross-server exfil chains.

MCP Shield is a transparent proxy you put in front of an MCP server:

  pip install mcp-shield
  mcp-shield --policy policies/default.yaml --detect-injection --track-chains \
    --fail-closed -- -- npx -y @modelcontextprotocol/server-filesystem ~/docs

It enforces a deterministic YAML policy (no LLM in the allow/deny path),
redacts secrets, scores prompt injection, tracks taint across tool calls, and
writes a hash-chained audit log. Optional human approval for high-risk tools.
Optional self-hosted dashboard if you want central visibility.

Alpha / MIT. Feedback and nasty bypass reports welcome.

Repo: https://github.com/Alex2006boecboec/MCP_Gateway
```

## GitHub topics (set on the repo)

`mcp` `model-context-protocol` `ai-security` `prompt-injection` `llm` `cybersecurity` `proxy` `agents` `secret-scanning`

## Checklist before posting

- [ ] README opens with proxy quickstart (no cloud required)
- [ ] `SECURITY.md` + Known limitations linked
- [ ] Tag `v0.1.0-alpha` published
- [ ] Repo is public
- [ ] No `.env` / real keys in the tree (see pre-launch secret scan)
