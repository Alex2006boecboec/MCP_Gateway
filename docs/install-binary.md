# Installing MCP Shield (no-code / standalone binary)

You don't need Python. Download the prebuilt binary for your OS from the
[Releases page](https://github.com/Alex2006boecboec/MCP_Gateway/releases)
and run it.

## 1. Download

| OS | File |
| --- | --- |
| macOS (Apple Silicon) | `mcp-shield-macos-arm64` |
| macOS (Intel) | `mcp-shield-macos-x64` |
| Linux | `mcp-shield-linux-x64` |
| Windows | `mcp-shield-windows-x64.exe` |

## 2. Make it executable (macOS / Linux only)

```sh
chmod +x mcp-shield-macos-arm64
```

On macOS the first launch may warn the binary is "from an unidentified
developer". Open **System Settings → Privacy & Security** and click
**Open Anyway**, or run once with:

```sh
xattr -d com.apple.quarantine mcp-shield-macos-arm64
```

## 3. Verify it runs

```sh
./mcp-shield-macos-arm64 --help
```

## 4. Point your AI agent at it

MCP Shield wraps your real MCP server. Tell your agent to launch MCP Shield
instead of the server, and put the server's original command after `--`.

### Claude Desktop

Edit `claude_desktop_config.json` (Claude Desktop → Settings → Developer →
Edit Config):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/absolute/path/to/mcp-shield-macos-arm64",
      "args": [
        "--", "npx", "-y", "@modelcontextprotocol/server-filesystem",
        "/Users/you/Documents"
      ]
    }
  }
}
```

### Cursor / other MCP clients

Use the same shape: `command` = path to the binary, `args` = `["--", <real server command...>]`.

## 5. Defaults (zero-config)

If you don't pass `--policy` or `--audit`, MCP Shield uses:

- **Policy:** a bundled secure-by-default policy that blocks SSRF to
  internal/metadata IPs, path traversal, shell metacharacters, and access
  to credential files.
- **Audit log:** `~/.mcp-shield/audit.jsonl` (auto-created, hash-chained,
  tamper-evident).

So the minimum working invocation is just:

```sh
./mcp-shield-macos-arm64 -- npx -y @modelcontextprotocol/server-filesystem ~/Documents
```

## 6. Optional: ship audit events to your cloud dashboard

If you run the MCP Shield cloud dashboard (separate deploy), pass its URL
and an API key to forward every audit event there:

```sh
./mcp-shield-macos-arm64 \
  --cloud-url https://your-dashboard.example.com \
  --cloud-key mcp_live_xxxxxxxx \
  -- npx -y @modelcontextprotocol/server-filesystem ~/Documents
```

## 7. Optional hardening flags

| Flag | Effect |
| --- | --- |
| `--fail-closed` | Deny any call no rule explicitly allows (recommended for production). |
| `--detect-injection` | Enable prompt-injection detection on tool responses/descriptions. |
| `--track-chains` | Track data flow across calls; block exfiltration chains (read secret → send externally). |
| `--require-approval` | Hold high-risk calls for human approval (file queue + optional webhook). |

## Troubleshooting

- **`Permission denied`** — run `chmod +x` on the binary (macOS/Linux).
- **macOS "unidentified developer"** — see step 2.
- **`No MCP server command provided`** — you forgot the `--` before the server command.
- **Proxy starts but agent can't connect** — make sure `command` is the
  absolute path to the binary in your agent config.
