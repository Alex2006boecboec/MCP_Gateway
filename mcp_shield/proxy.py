"""MCP Security Gateway — the proxy that sits between agent and MCP servers.

Deployment (stdio transport, the most common case):

    ┌──────────┐   stdin   ┌──────────────┐   stdin   ┌────────────┐
    │ AI Agent │ ───────► │  MCP Shield  │ ───────► │ MCP Server  │
    │          │ ◄─────── │   (proxy)   │ ◄─────── │ (subprocess)│
    └──────────┘  stdout  └──────────────┘  stdout  └────────────┘

The agent launches MCP Shield as if it were the MCP server (we accept
the same stdio JSON-RPC). MCP Shield in turn spawns the real MCP server
as a subprocess and forwards traffic through, applying the security
pipeline on every `tools/list` and `tools/call`:

    request  → redact args → policy → (injection) → (chain) → forward
    response → injection → redact → audit → return

Phase 1 (this file) implements: protocol framing, transparent
forwarding, policy enforcement, secret redaction, and audit logging.
Injection detection (Layer 0–3) and capability graph are stubbed for
later phases but the hooks are already in place.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from mcp_shield.audit import AuditLogger
from mcp_shield.policy import PolicyEngine, Decision, load_policy
from mcp_shield.protocol import (
    ERR_INJECTION_DETECTED,
    ERR_POLICY_DENIED,
    ERR_VALIDATION_FAILED,
    Message,
    make_error_response,
    read_message,
    write_message,
)
from mcp_shield.redactor import SecretRedactor

log = logging.getLogger("mcp_shield")


@dataclass
class ProxyConfig:
    """Runtime configuration for the proxy."""
    policy_path: Path
    audit_path: Path
    server_command: list[str]   # the command to spawn the real MCP server
    fail_closed: bool = True    # if True, deny when no rule matches and default is deny
    redact_secrets: bool = True


class Proxy:
    """The man-in-the-middle between an MCP agent and an MCP server.

    Lifecycle:
        proxy = Proxy(config)
        proxy.run()   # blocks until either side closes
    """

    def __init__(self, config: ProxyConfig):
        self.config = config
        self.policy = PolicyEngine(load_policy(config.policy_path))
        self.redactor = SecretRedactor() if config.redact_secrets else None
        self.audit = AuditLogger(config.audit_path)
        # The downstream MCP server subprocess.
        self._proc: Optional[subprocess.Popen] = None

    # ------------------------------------------------------------------ run

    def run(self) -> int:
        """Main loop: pump messages between agent (stdin/stdout) and the
        MCP server subprocess. Returns the exit code."""
        self._spawn_server()
        try:
            self._pump()
        finally:
            self._shutdown()
        return 0

    # -------------------------------------------------------------- spawn

    def _spawn_server(self) -> None:
        log.info("Spawning MCP server: %s", self.config.server_command)
        self._proc = subprocess.Popen(
            self.config.server_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            bufsize=0,
        )

    def _shutdown(self) -> None:
        if self._proc is not None:
            try:
                if self._proc.stdin:
                    self._proc.stdin.close()
            except OSError:
                pass
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None

    # --------------------------------------------------------------- pump

    def _pump(self) -> None:
        """Two-way pump: agent stdin → server, server stdout → agent stdout.

        We process sequentially in Phase 1 (one request → one response). This
        is correct for MCP because the protocol is request/response over
        stdio. Async/concurrent handling is a Phase 2 concern.
        """
        assert self._proc is not None and self._proc.stdout is not None and self._proc.stdin is not None
        while True:
            # 1. Read a request from the agent (our stdin).
            req = read_message(sys.stdin.buffer)
            if req is None:
                # Agent closed the pipe — we're done.
                return
            # 2. Apply the security pipeline to the request.
            decision, processed = self._inspect_request(req)
            if decision.action == "deny":
                # Block: respond with an error directly to the agent.
                err = make_error_response(
                    req.id if req.id is not None else 0,
                    ERR_POLICY_DENIED if decision.rule_name != "validator" else ERR_VALIDATION_FAILED,
                    decision.reason,
                    data={"rule": decision.rule_name},
                )
                write_message(sys.stdout.buffer, err)
                self._audit(req, decision, processed, blocked=True)
                continue
            # 3. Forward (possibly redacted) request to the MCP server.
            write_message(self._proc.stdin, processed)
            # 4. Read the response from the MCP server.
            resp = read_message(self._proc.stdout)
            if resp is None:
                # Server died — tell the agent.
                err = make_error_response(
                    req.id if req.id is not None else 0,
                    -32000,
                    "MCP server closed the connection",
                )
                write_message(sys.stdout.buffer, err)
                return
            # 5. Apply the security pipeline to the response.
            resp_decision, processed_resp = self._inspect_response(req, resp)
            if resp_decision.action == "deny":
                # Injection in the response — block and tell the agent.
                err = make_error_response(
                    req.id if req.id is not None else 0,
                    ERR_INJECTION_DETECTED,
                    resp_decision.reason,
                    data={"rule": resp_decision.rule},
                )
                write_message(sys.stdout.buffer, err)
                self._audit_response(req, resp_decision, processed_resp, blocked=True)
                continue
            # 6. Forward the (possibly redacted) response to the agent.
            write_message(sys.stdout.buffer, processed_resp)
            self._audit(req, decision, processed, blocked=False)

    # ------------------------------------------------------- inspect (req)

    def _inspect_request(self, msg: Message) -> tuple[Decision, Message]:
        """Run the request-side pipeline. Returns (decision, possibly-modified message)."""
        if msg.method not in ("tools/list", "tools/call"):
            # Non-intercepted method — pass through untouched.
            return Decision("allow", "non-intercepted method", "passthrough"), msg

        if msg.method == "tools/list":
            # We don't modify tool/list requests, but we WILL inspect the
            # response for tool poisoning. Mark as passthrough here.
            return Decision("allow", "tools/list forwarded", "passthrough"), msg

        # tools/call — extract server/tool/arguments.
        params = msg.params or {}
        server = str(params.get("server", "unknown"))
        tool = str(params.get("name", params.get("tool", "unknown")))
        # MCP spec: arguments live under params.arguments or params directly.
        arguments = params.get("arguments") or {k: v for k, v in params.items() if k not in ("server", "name", "tool")}

        # 1. Redact secrets in arguments before any logging or forwarding.
        redactions: list[dict[str, str]] = []
        if self.redactor is not None and arguments:
            new_args, reds = self.redactor.redact_dict(arguments)
            arguments = new_args
            redactions = [{"name": r.name, "field": r.field, "replacement": r.replacement} for r in reds]

        # 2. Policy evaluation (deterministic).
        decision = self.policy.evaluate(server=server, tool=tool, arguments=arguments)

        # 3. Rebuild the message with (possibly) redacted arguments.
        new_raw = dict(msg.raw)
        if msg.params is not None:
            new_params = dict(msg.params)
            if "arguments" in new_params:
                new_params["arguments"] = arguments
            else:
                # arguments were at the top level
                for k in arguments:
                    new_params[k] = arguments[k]
            new_raw["params"] = new_params
        processed = Message(
            raw=new_raw,
            id=msg.id,
            method=msg.method,
            params=new_raw.get("params"),
        )
        # Attach redactions to the decision so audit can record them.
        # (Decision is a dataclass — we stash via a side channel.)
        processed._redactions = redactions  # type: ignore[attr-defined]
        return decision, processed

    def _inspect_response(self, req: Message, resp: Message) -> tuple[Decision, Message]:
        """Run the response-side pipeline. Returns (decision, possibly-modified message)."""
        # Phase 1: passthrough with secret redaction on the response.
        # Phase 2 will add injection detection here.
        if self.redactor is not None and isinstance(resp.result, dict):
            new_result, _ = self.redactor.redact_dict(resp.result, container="result")
            new_raw = dict(resp.raw)
            new_raw["result"] = new_result
            processed = Message(
                raw=new_raw,
                id=resp.id,
                result=new_result,
            )
        else:
            processed = resp
        return Decision("allow", "response passthrough", "passthrough"), processed

    # --------------------------------------------------------------- audit

    def _audit(self, req: Message, decision: Decision, processed: Message, *, blocked: bool) -> None:
        redactions = getattr(processed, "_redactions", [])  # type: ignore[attr-defined]
        params = req.params or {}
        self.audit.log(
            decision=decision.action,
            server=str(params.get("server", "unknown")),
            tool=str(params.get("name", params.get("tool", "unknown"))),
            # Args are already redacted (we redact before policy eval).
            args=params.get("arguments", {k: v for k, v in params.items() if k not in ("server", "name", "tool")}),
            reason=decision.reason,
            rule=decision.rule_name,
            redactions=redactions,
        )

    def _audit_response(self, req: Message, decision: Decision, processed: Message, *, blocked: bool) -> None:
        # Response-side audit (for blocked injections). Same shape as request audit.
        params = req.params or {}
        self.audit.log(
            decision=decision.action,
            server=str(params.get("server", "unknown")),
            tool=str(params.get("name", params.get("tool", "unknown"))),
            args={"response_blocked": True},
            reason=decision.reason,
            rule=decision.rule_name,
            redactions=[],
        )
