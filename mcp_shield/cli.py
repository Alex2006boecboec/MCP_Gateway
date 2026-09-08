"""Command-line entry point: `mcp-shield` launches the gateway.

Usage:

    mcp-shield --policy policy.yaml --audit audit.jsonl -- <mcp server command>

The `--` separates mcp-shield's own arguments from the command that
launches the real MCP server. Everything after `--` is the server
command, exactly as the agent would have launched it.

Example (Claude Desktop config):

    {
      "mcpServers": {
        "filesystem": {
          "command": "mcp-shield",
          "args": [
            "--policy", "C:/Users/alexa/policies/filesystem.yaml",
            "--audit", "C:/Users/alexa/.mcp-shield/audit.jsonl",
            "--",
            "npx", "-y", "@modelcontextprotocol/server-filesystem", "C:/Users/alexa"
          ]
        }
      }
    }
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from mcp_shield.proxy import Proxy, ProxyConfig


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-shield",
        description="Security gateway for MCP (Model Context Protocol). "
        "Wraps an MCP server, intercepts tool calls, enforces policy, "
        "redacts secrets, and writes a tamper-evident audit log.",
    )
    parser.add_argument("--policy", required=True, help="Path to the YAML policy file")
    parser.add_argument("--audit", default="audit.jsonl", help="Path to the audit log JSONL file")
    parser.add_argument("--fail-closed", action="store_true", default=False,
                        help="Deny by default when no rule matches (recommended for production)")
    parser.add_argument("--no-redact", action="store_true", default=False,
                        help="Disable secret redaction (NOT recommended)")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    # Everything after `--` is the MCP server command.
    parser.add_argument("server_command", nargs=argparse.REMAINDER,
                        help="Command to launch the MCP server (use `--` first)")

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,  # never write logs to stdout — that's the MCP channel
    )

    # Strip a leading `--` if argparse left it in.
    cmd = list(args.server_command)
    while cmd and cmd[0] == "--":
        cmd.pop(0)
    if not cmd:
        parser.error("No MCP server command provided. Use `--` followed by the server command.")

    config = ProxyConfig(
        policy_path=Path(args.policy),
        audit_path=Path(args.audit),
        server_command=cmd,
        fail_closed=args.fail_closed,
        redact_secrets=not args.no_redact,
    )
    proxy = Proxy(config)
    return proxy.run()


if __name__ == "__main__":
    sys.exit(main())
