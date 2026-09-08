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
from typing import Any

import yaml

from mcp_shield.approval import ApprovalConfig, RiskRule
from mcp_shield.detector import DetectorConfig
from mcp_shield.graph import GraphConfig
from mcp_shield.proxy import Proxy, ProxyConfig
from mcp_shield.shipper import CloudShipper, CloudShipperConfig


def _load_approval_from_policy(policy_path: Path) -> dict[str, Any] | None:
    """Read the `approval:` section from the policy YAML, if present.

    Returns None if the policy has no `approval` section. Does NOT raise on
    a missing file (the proxy will raise a clearer error later).
    """
    try:
        data = yaml.safe_load(Path(policy_path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    if not isinstance(data, dict):
        return None
    return data.get("approval")


def _build_approval_config(
    *,
    enabled: bool,
    policy_path: Path,
    approval_dir: str | None,
    timeout: float | None,
    webhook: str | None,
) -> ApprovalConfig | None:
    """Build an ApprovalConfig from CLI flags + the policy `approval` section.

    Returns None if approval is not enabled and the policy has no approval
    section. CLI flags override policy values.
    """
    policy_section = _load_approval_from_policy(policy_path) or {}
    if not enabled and not policy_section:
        return None

    cfg = ApprovalConfig(enabled=True)
    # Base dir overrides (CLI --approval-dir).
    if approval_dir:
        cfg.pending_dir = str(Path(approval_dir) / "pending")
        cfg.response_dir = str(Path(approval_dir) / "responses")
        cfg.resolved_dir = str(Path(approval_dir) / "resolved")
    # Timeout override (CLI --approval-timeout).
    if timeout is not None:
        cfg.timeout_seconds = timeout
    # Webhook override (CLI --approval-webhook).
    if webhook is not None:
        cfg.webhook_url = webhook
    # From policy section.
    if "require_for_review_chains" in policy_section:
        cfg.require_for_review_chains = bool(policy_section["require_for_review_chains"])
    if "timeout_seconds" in policy_section:
        cfg.timeout_seconds = float(policy_section["timeout_seconds"])
    if "webhook_url" in policy_section and webhook is None:
        cfg.webhook_url = policy_section["webhook_url"]
    # Risk rules from policy.
    for rraw in policy_section.get("risk_rules") or []:
        if not isinstance(rraw, dict):
            continue
        cfg.risk_rules.append(RiskRule(
            name=str(rraw.get("name", "rule")),
            tool_regex=str(rraw.get("tool_regex", ".*")),
            arg_regex=rraw.get("arg_regex"),
            reason=str(rraw.get("reason", "")),
        ))
    return cfg


def _build_shipper(cloud_url: str | None, cloud_key: str | None) -> CloudShipper | None:
    """Build a CloudShipper from CLI flags. Returns None if cloud shipping is disabled."""
    if not cloud_url and not cloud_key:
        return None
    if not cloud_url or not cloud_key:
        raise SystemExit("error: --cloud-url and --cloud-key must both be set (or both omitted)")
    return CloudShipper(CloudShipperConfig(
        enabled=True,
        url=cloud_url,
        api_key=cloud_key,
    ))


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
    parser.add_argument("--detect-injection", action="store_true", default=False,
                        help="Enable prompt injection detection (regex + heuristics). "
                        "Optional ML layers require the [detector] pip extra.")
    parser.add_argument("--track-chains", action="store_true", default=False,
                        help="Enable the capability graph: track data flow across tool "
                        "calls and block dangerous cross-server chains (e.g. read a "
                        "secret then send it externally).")
    parser.add_argument("--require-approval", action="store_true", default=False,
                        help="Enable the approval flow: hold high-risk tool calls for "
                        "human approval (file-based queue + optional Slack/Teams webhook). "
                        "Risk rules are read from the policy's `approval` section.")
    parser.add_argument("--approval-dir", default=None,
                        help="Base directory for the approval queue (pending/, responses/, "
                        "resolved/ subdirs). Default: ./approvals")
    parser.add_argument("--approval-timeout", type=float, default=None,
                        help="Seconds to wait for a human decision before timing out "
                        "(fail-closed). Default: 120")
    parser.add_argument("--approval-webhook", default=None,
                        help="Slack/Teams incoming webhook URL for approval notifications. "
                        "Optional; the file queue works without it.")
    parser.add_argument("--cloud-url", default=None,
                        help="Phase 5: URL of the MCP Shield cloud dashboard "
                        "(e.g. https://shield.example.com). Enables shipping audit "
                        "events to the cloud. Requires --cloud-key.")
    parser.add_argument("--cloud-key", default=None,
                        help="Phase 5: API key for the cloud dashboard. Get it from "
                        "the dashboard's API Keys page.")
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
        detector_config=DetectorConfig() if args.detect_injection else None,
        graph_config=GraphConfig() if args.track_chains else None,
        approval_config=_build_approval_config(
            enabled=args.require_approval,
            policy_path=Path(args.policy),
            approval_dir=args.approval_dir,
            timeout=args.approval_timeout,
            webhook=args.approval_webhook,
        ),
        shipper=_build_shipper(args.cloud_url, args.cloud_key),
    )
    proxy = Proxy(config)
    return proxy.run()


if __name__ == "__main__":
    sys.exit(main())
