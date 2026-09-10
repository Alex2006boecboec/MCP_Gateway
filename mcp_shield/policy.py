"""Declarative policy engine — the deterministic core of the gateway.

The policy is a YAML document with three top-level sections:

    servers:        # per-server trust level and per-tool overrides
      filesystem:
        trust: high
        tools:
          read_file: { allow: true }
          write_file: { allow: false, reason: "writes not permitted in this env" }
      fetch:
        trust: low
        tools:
          fetch_url: { validate: url, block_internal: true }

    rules:           # global rules applied to every call
      - name: block-shell-metacharacters
        when: { tool_regex: ".*exec|.*run|.*shell" }
        check: { arg_regex: "[;&|`$\\\\]" }
        action: deny
        reason: "shell metacharacters in exec-like tool args"
      - name: block-internal-urls
        when: { tool_regex: ".*fetch|.*http" }
        check: { arg_regex: "(169\\.254\\.|127\\.|10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)" }
        action: deny
        reason: "SSRF to internal/metadata IP blocked"

    defaults:       # default action when no rule matches
      action: allow  # or deny (fail-closed mode)

The engine is deterministic — no LLM is ever consulted for a policy
decision. This is deliberate: prompt injection cannot bypass it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


class PolicyError(ValueError):
    """Raised when a policy file is malformed."""


@dataclass
class Decision:
    """Outcome of evaluating the policy for a single tool call."""
    action: str            # "allow" | "deny" | "redact" | "approve"
    reason: str = ""        # human-readable explanation
    rule_name: str = ""    # which rule fired (for the audit log)
    redactions: list[tuple[str, str]] = field(default_factory=list)  # (path, replacement)


@dataclass
class Rule:
    name: str
    tool_regex: re.Pattern
    arg_regex: Optional[re.Pattern]
    action: str            # "allow" | "deny" | "redact" | "approve"
    reason: str
    block_internal: bool = False   # special-case for URL validation


@dataclass
class ToolConfig:
    allow: Optional[bool] = None
    deny: Optional[bool] = None
    validate: Optional[str] = None   # "url" | "path" | "command"
    block_internal: Optional[bool] = None
    reason: str = ""


@dataclass
class ServerConfig:
    trust: str = "medium"   # "low" | "medium" | "high"
    tools: dict[str, ToolConfig] = field(default_factory=dict)


@dataclass
class Policy:
    servers: dict[str, ServerConfig] = field(default_factory=dict)
    rules: list[Rule] = field(default_factory=list)
    default_action: str = "allow"

    def for_server(self, name: str) -> ServerConfig:
        return self.servers.get(name, ServerConfig())


def load_policy(path: str | Path) -> Policy:
    """Load and validate a YAML policy file."""
    p = Path(path)
    if not p.exists():
        raise PolicyError(f"Policy file not found: {p}")
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"YAML parse error: {exc}") from exc
    if data is None:
        return Policy()
    if not isinstance(data, dict):
        raise PolicyError("Top-level YAML must be a mapping")
    return _build_policy(data)


def _build_policy(data: dict[str, Any]) -> Policy:
    servers: dict[str, ServerConfig] = {}
    for sname, sraw in (data.get("servers") or {}).items():
        if not isinstance(sraw, dict):
            raise PolicyError(f"server '{sname}' must be a mapping")
        sc = ServerConfig(trust=str(sraw.get("trust", "medium")))
        for tname, traw in (sraw.get("tools") or {}).items():
            if not isinstance(traw, dict):
                raise PolicyError(f"server '{sname}' tool '{tname}' must be a mapping")
            tc = ToolConfig(
                allow=traw.get("allow"),
                deny=traw.get("deny"),
                validate=traw.get("validate"),
                block_internal=traw.get("block_internal"),
                reason=str(traw.get("reason", "")),
            )
            sc.tools[tname] = tc
        servers[sname] = sc

    rules: list[Rule] = []
    for i, rraw in enumerate(data.get("rules") or []):
        if not isinstance(rraw, dict):
            raise PolicyError(f"rule #{i} must be a mapping")
        when = rraw.get("when") or {}
        check = rraw.get("check") or {}
        try:
            tool_re = re.compile(when.get("tool_regex", ".*"))
        except re.error as exc:
            raise PolicyError(f"rule #{i} bad tool_regex: {exc}") from exc
        try:
            arg_re = re.compile(check["arg_regex"]) if "arg_regex" in check else None
        except re.error as exc:
            raise PolicyError(f"rule #{i} bad arg_regex: {exc}") from exc
        rules.append(
            Rule(
                name=str(rraw.get("name", f"rule-{i}")),
                tool_regex=tool_re,
                arg_regex=arg_re,
                action=str(rraw.get("action", "deny")),
                reason=str(rraw.get("reason", "")),
                block_internal=bool(check.get("block_internal", False)),
            )
        )

    defaults = data.get("defaults") or {}
    if not isinstance(defaults, dict):
        raise PolicyError(f"'defaults' must be a mapping, got {type(defaults).__name__}")
    default_action = str(defaults.get("action", "allow"))
    if default_action not in {"allow", "deny"}:
        raise PolicyError(f"defaults.action must be 'allow' or 'deny', got {default_action!r}")

    return Policy(servers=servers, rules=rules, default_action=default_action)


class PolicyEngine:
    """Evaluate a policy against a tool call. Stateless w.r.t. the policy."""

    def __init__(self, policy: Policy):
        self.policy = policy

    def evaluate(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any],
    ) -> Decision:
        # 1. Per-server / per-tool config first (most specific).
        sc = self.policy.for_server(server)
        tc = sc.tools.get(tool)
        if tc is not None:
            if tc.deny is True:
                return Decision("deny", tc.reason or f"tool {tool} denied on server {server}", "server-config")
            if tc.allow is True:
                # Still run global rules — allow is not a bypass.
                pass
            if tc.validate:
                v = self._validate(tc.validate, arguments, tc.block_internal)
                if v is not None:
                    v.rule_name = f"server.{server}.tools.{tool}.validate"
                    return v

        # 2. Global rules.
        for rule in self.policy.rules:
            if not rule.tool_regex.match(tool):
                continue
            if rule.arg_regex is None:
                return Decision(rule.action, rule.reason, rule.name)
            # Search all argument values for the regex.
            for key, value in arguments.items():
                sval = str(value)
                if rule.arg_regex.search(sval):
                    return Decision(rule.action, rule.reason, rule.name)
                if rule.block_internal and self._looks_internal(sval):
                    return Decision("deny", f"internal target blocked by {rule.name}", rule.name)

        # 3. Default.
        return Decision(self.policy.default_action, "no rule matched (default)", "default")

    @staticmethod
    def _validate(kind: str, args: dict[str, Any], block_internal: Optional[bool]) -> Optional[Decision]:
        if kind == "url":
            for key, value in args.items():
                sval = str(value)
                if block_internal and PolicyEngine._looks_internal(sval):
                    return Decision("deny", f"internal URL blocked in arg '{key}'", "url-validator")
        elif kind == "path":
            for key, value in args.items():
                sval = str(value)
                if ".." in sval or sval.startswith("~") or sval.startswith("/etc") or sval.startswith("\\"):
                    return Decision("deny", f"path traversal blocked in arg '{key}'", "path-validator")
        elif kind == "command":
            for key, value in args.items():
                sval = str(value)
                if re.search(r"[;&|`$]", sval):
                    return Decision("deny", f"shell metacharacters blocked in arg '{key}'", "command-validator")
        return None

    @staticmethod
    def _looks_internal(value: str) -> bool:
        """Return True if value looks like an internal/metadata URL or host.

        Covers loopback, RFC1918 (10/8, 172.16/12, 192.168/16), link-local,
        localhost, and cloud metadata endpoints.
        """
        import ipaddress
        from urllib.parse import urlparse

        v = value.strip().lower()
        # Cloud metadata endpoints (host or anywhere in string).
        if "169.254.169.254" in v or "metadata.google.internal" in v:
            return True

        # Extract host from URL if present; otherwise treat whole string as host.
        host = v
        if "://" in v:
            try:
                parsed = urlparse(v if "://" in v else f"http://{v}")
                host = (parsed.hostname or "").lower()
            except Exception:
                host = v
        else:
            # Bare host:port or path-ish — take before first '/' or ':'.
            host = v.split("/")[0].split(":")[0]

        if not host:
            return False
        if host == "localhost" or host.endswith(".localhost"):
            return True
        if host.endswith(".local") or host.endswith(".internal"):
            return True

        # Strip brackets from IPv6 literals.
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]

        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            # Not an IP — check dotted prefixes for partial/unparsed hosts.
            if host.startswith(("10.", "127.", "192.168.", "169.254.")):
                return True
            # 172.16.0.0/12 → 172.16–172.31
            if host.startswith("172."):
                parts = host.split(".")
                if len(parts) >= 2 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
                    return True
            return False

        return bool(
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        )
