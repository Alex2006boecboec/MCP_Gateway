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
from mcp_shield.approval import ApprovalConfig, ApprovalEngine, matches_risk_rule
from mcp_shield.detector import Detector, DetectorConfig
from mcp_shield.graph import CapabilityGraph, GraphConfig
from mcp_shield.policy import PolicyEngine, Decision, load_policy
from mcp_shield.protocol import (
    ERR_APPROVAL_DENIED,
    ERR_APPROVAL_TIMEOUT,
    ERR_CHAIN_BLOCKED,
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
    detector_config: Optional[DetectorConfig] = None  # None = detector disabled
    graph_config: Optional[GraphConfig] = None       # None = graph disabled
    approval_config: Optional[ApprovalConfig] = None  # None = approval disabled


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
        self.detector = Detector(config.detector_config) if config.detector_config else None
        self.graph = CapabilityGraph(config.graph_config) if config.graph_config else None
        self.approval = ApprovalEngine(config.approval_config) if config.approval_config else None
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
                # Map the rule_name to the right JSON-RPC error code.
                if decision.rule_name == "validator":
                    code = ERR_VALIDATION_FAILED
                elif decision.rule_name == "injection-detector":
                    code = ERR_INJECTION_DETECTED
                elif decision.rule_name == "capability-graph":
                    code = ERR_CHAIN_BLOCKED
                elif decision.rule_name == "approval":
                    code = ERR_APPROVAL_DENIED if "timeout" not in decision.reason else ERR_APPROVAL_TIMEOUT
                else:
                    code = ERR_POLICY_DENIED
                err = make_error_response(
                    req.id if req.id is not None else 0,
                    code,
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
                    data={"rule": resp_decision.rule_name},
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
        # New agent session -> reset the capability graph.
        if msg.method == "initialize" and self.graph is not None:
            self.graph.reset()

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
        processed._redaction_objs = reds if (self.redactor is not None and arguments) else []  # type: ignore[attr-defined]

        # 2b. Capability graph: check if this call is a dangerous sink whose
        # args match an active taint (cross-call exfiltration chain). Runs
        # AFTER policy (policy has first say). Only if policy allowed.
        chain = None
        if decision.action != "deny" and self.graph is not None:
            try:
                g_decision, chain = self.graph.check_sink(
                    msg.id if msg.id is not None else 0, tool, arguments,
                    request_redactions=processed._redaction_objs,  # type: ignore[attr-defined]
                )
                if g_decision.action == "deny":
                    decision = g_decision
                    processed._chain = _chain_to_dict(chain) if chain else None  # type: ignore[attr-defined]
            except Exception as exc:
                log.warning("graph check_sink error: %s", exc)

        # 2c. Approval flow: hold high-risk calls for human approval. Runs
        # LAST on the request side (after policy + graph). Only consulted
        # when: policy said "approve", OR a graph review chain + require flag,
        # OR a risk rule matched. Fail-closed: policy "approve" with approval
        # disabled -> DENY (loud misconfig signal).
        if decision.action != "deny" and self.approval is not None:
            try:
                approval_decision = self._maybe_require_approval(
                    msg, server, tool, arguments, decision, chain, processed,
                )
                if approval_decision is not None:
                    decision = approval_decision
            except Exception as exc:
                # Fail-closed: if approval errors, deny (never forward a call
                # that needed approval but whose approval errored).
                log.warning("approval error: %s", exc)
                decision = Decision("deny", f"approval error: {exc}", "approval")

        elif decision.action == "approve" and self.approval is None:
            # Policy said "approve" but no approval engine configured ->
            # fail-closed (loud misconfig signal).
            decision = Decision(
                "deny",
                "policy requires approval but no approval engine is configured",
                "approval",
            )

        return decision, processed

    def _inspect_response(self, req: Message, resp: Message) -> tuple[Decision, Message]:
        """Run the response-side pipeline. Returns (decision, possibly-modified message)."""
        # 1. Secret redaction on the response.
        resp_red_objs: list = []
        if self.redactor is not None and isinstance(resp.result, dict):
            new_result, resp_red_objs = self.redactor.redact_dict(resp.result, container="result")
            new_raw = dict(resp.raw)
            new_raw["result"] = new_result
            processed = Message(
                raw=new_raw,
                id=resp.id,
                result=new_result,
            )
        else:
            processed = resp

        # 2. Injection detection (Phase 2).
        if self.detector is not None and isinstance(processed.result, dict):
            req_args = self._extract_args(req)
            is_tool_list = req.method == "tools/list"
            context = {"request_args": req_args, "is_tool_description": is_tool_list}
            for text in _extract_text(processed.result):
                try:
                    result = self.detector.scan(text, context=context)
                except Exception as exc:
                    log.warning("detector error: %s", exc)
                    continue
                if result.verdict == "blocked":
                    reason = f"injection detected (score={result.score:.2f})"
                    if result.signals:
                        reason += f": {result.signals[0].name}"
                    # Stash detection detail on the processed message for audit.
                    processed._detection = {  # type: ignore[attr-defined]
                        "score": result.score,
                        "verdict": result.verdict,
                        "signals": [
                            {"layer": s.layer, "name": s.name, "score": s.score}
                            for s in result.signals
                        ],
                    }
                    return Decision("deny", reason, "injection-detector"), processed
                # Suspicious or clean: record detection detail for audit but allow.
                processed._detection = {  # type: ignore[attr-defined]
                    "score": result.score,
                    "verdict": result.verdict,
                    "signals": [
                        {"layer": s.layer, "name": s.name, "score": s.score}
                        for s in result.signals
                    ],
                }

        # 3. Capability graph (Phase 3).
        if self.graph is not None and isinstance(processed.result, dict):
            try:
                if req.method == "tools/list":
                    # Register each tool's capabilities from its description.
                    tools = processed.result.get("tools", []) if isinstance(processed.result, dict) else []
                    for t in tools:
                        if isinstance(t, dict):
                            self.graph.register_tool(
                                str(t.get("name", "")),
                                str(t.get("description", "")),
                            )
                elif req.method == "tools/call":
                    # Record this call as a potential sensitive source.
                    req_args = self._extract_args(req)
                    resp_text = " ".join(_extract_text(processed.result))
                    self.graph.record_source(
                        req.id if req.id is not None else 0,
                        str((req.params or {}).get("name", (req.params or {}).get("tool", "unknown"))),
                        req_args,
                        response_redactions=resp_red_objs,
                        response_text=resp_text,
                    )
            except Exception as exc:
                log.warning("graph response hook error: %s", exc)

        return Decision("allow", "response passthrough", "passthrough"), processed

    # ----------------------------------------------------------- approval

    def _maybe_require_approval(
        self,
        msg: Message,
        server: str,
        tool: str,
        args: dict,
        decision: Decision,
        chain,
        processed: Message,
    ) -> Optional[Decision]:
        """Decide whether this call needs human approval and, if so, run the
        approval engine. Returns a Decision if approval denied/errored (caller
        uses it), or None if approved (caller falls through to forward)."""
        need = False
        trigger = ""
        rule_name = ""
        reason = ""

        if decision.action == "approve":
            need, trigger, rule_name = True, "policy", decision.rule_name
            reason = decision.reason or "policy requires approval"
        elif (chain is not None and self.approval is not None
              and self.approval.config.require_for_review_chains):
            need, trigger, rule_name = True, "review-chain", chain.rule_name
            reason = f"review chain: {chain.rule_name}"
        else:
            rule = self.approval.matches_risk_rule(tool, args)
            if rule is not None:
                need, trigger, rule_name = True, "risk-rule", rule.name
                reason = rule.reason

        if not need:
            return None

        call_id = msg.id if msg.id is not None else 0
        outcome, response = self.approval.evaluate(
            call_id=call_id, server=server, tool=tool, args=args,
            reason=reason, trigger=trigger, rule_name=rule_name,
        )
        processed._approval = _approval_to_dict(  # type: ignore[attr-defined]
            request_id=None, trigger=trigger, rule_name=rule_name,
            outcome=outcome, response=response,
        )
        if outcome == "approve":
            return None  # fall through -> forward
        if outcome == "timeout":
            return Decision("deny", f"approval timeout: {reason}", "approval")
        return Decision("deny", f"approval denied: {reason}", "approval")

    # --------------------------------------------------------------- audit

    def _audit(self, req: Message, decision: Decision, processed: Message, *, blocked: bool) -> None:
        redactions = getattr(processed, "_redactions", [])  # type: ignore[attr-defined]
        detection = getattr(processed, "_detection", None)  # type: ignore[attr-defined]
        chain = getattr(processed, "_chain", None)  # type: ignore[attr-defined]
        approval = getattr(processed, "_approval", None)  # type: ignore[attr-defined]
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
            detection=detection,
            chain=chain,
            approval=approval,
        )

    def _audit_response(self, req: Message, decision: Decision, processed: Message, *, blocked: bool) -> None:
        # Response-side audit (for blocked injections). Same shape as request audit.
        params = req.params or {}
        detection = getattr(processed, "_detection", None)  # type: ignore[attr-defined]
        self.audit.log(
            decision=decision.action,
            server=str(params.get("server", "unknown")),
            tool=str(params.get("name", params.get("tool", "unknown"))),
            args={"response_blocked": True},
            reason=decision.reason,
            rule=decision.rule_name,
            redactions=[],
            detection=detection,
        )

    # ------------------------------------------------------------- helpers

    @staticmethod
    def _extract_args(req: Message) -> dict:
        """Extract the arguments dict from a tools/call request (for detector context)."""
        params = req.params or {}
        return params.get("arguments") or {
            k: v for k, v in params.items() if k not in ("server", "name", "tool")
        }


def _extract_text(result: dict) -> list[str]:
    """Extract text fields from an MCP tool result for injection scanning.

    MCP tool results have shape {"content": [{"type":"text","text":"..."}, ...]}.
    tools/list results have shape {"tools": [{"name":..., "description":...}, ...]}.
    We scan every "text" and "description" string we can find.
    """
    texts: list[str] = []
    content = result.get("content") or result.get("tools") or []
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict):
                if "text" in item and isinstance(item["text"], str):
                    texts.append(item["text"])
                if "description" in item and isinstance(item["description"], str):
                    texts.append(item["description"])
    return texts


def _chain_to_dict(chain) -> dict:
    """Serialize a graph Chain to a dict for the audit log."""
    if chain is None:
        return None
    return {
        "source_call_id": chain.source_call_id,
        "source_tool": chain.source_tool,
        "sink_call_id": chain.sink_call_id,
        "sink_tool": chain.sink_tool,
        "label": chain.label,
        "sink_capability": chain.sink_capability,
        "rule_name": chain.rule_name,
    }


def _approval_to_dict(*, request_id, trigger, rule_name, outcome, response) -> dict:
    """Serialize an approval outcome to a dict for the audit log."""
    return {
        "trigger": trigger,
        "rule_name": rule_name,
        "outcome": outcome,            # "approve" | "deny" | "timeout"
        "by": response.by if response else "",
        "comment": response.comment if response else "",
    }
