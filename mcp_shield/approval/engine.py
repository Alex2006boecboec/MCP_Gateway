"""ApprovalEngine - the orchestrator for the approval flow (Phase 4).

Creates an ApprovalRequest, persists it to the pending queue, optionally
notifies a webhook, then blocks until a human decision arrives (or timeout).
Called by the proxy when a high-risk call is detected.

Lifecycle:
    engine = ApprovalEngine(config)
    outcome, response = engine.evaluate(call_id=..., ...)
    # outcome: "approve" | "deny" | "timeout"

File layout:
    pending_dir/<id>.json    - the request (args already redacted)
    response_dir/<id>.json   - the human's decision (written by human/bot)
    resolved_dir/<id>.json   - the request + decision (moved here after)
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from mcp_shield.approval.notifier import notify
from mcp_shield.approval.responder import wait_for_response
from mcp_shield.approval.rules import compile_risk_rules, CompiledRiskRule
from mcp_shield.approval.types import (
    ApprovalConfig, ApprovalRequest, ApprovalResponse,
)

log = logging.getLogger("mcp_shield.approval")


class ApprovalEngine:
    """Orchestrates approval requests. One per proxy session."""

    def __init__(self, config: ApprovalConfig):
        self.config = config
        # Clamp poll interval so we poll at least ~10x within the timeout.
        # Avoids missing a response that arrives just after a single poll.
        if config.poll_interval_seconds * 10 > config.timeout_seconds:
            config.poll_interval_seconds = max(config.timeout_seconds / 10, 0.05)
        # Compile risk rules at init (fail-fast on bad regex).
        self._compiled_rules: list[CompiledRiskRule] = compile_risk_rules(config.risk_rules)
        self._ensure_dirs()

    # ------------------------------------------------------------- public

    def request(
        self,
        *,
        call_id: int | str,
        server: str,
        tool: str,
        args: dict[str, Any],
        reason: str,
        trigger: str,
        rule_name: str,
    ) -> ApprovalRequest:
        """Create + persist + notify. Returns the request (not the decision)."""
        now = time.time()
        req = ApprovalRequest(
            request_id=uuid.uuid4().hex,
            call_id=call_id,
            server=server,
            tool=tool,
            args=self._truncate_args(args),
            reason=reason,
            trigger=trigger,
            rule_name=rule_name,
            created_at=now,
            expires_at=now + self.config.timeout_seconds,
        )
        self._write_pending(req)
        # Best-effort notification; never raises.
        if self.config.webhook_url:
            try:
                notify(self.config.webhook_url, req, self.config.webhook_timeout_seconds)
            except Exception as exc:
                log.warning("approval notify error: %s", exc)
        return req

    def await_decision(self, request: ApprovalRequest) -> tuple[str, Optional[ApprovalResponse]]:
        """Block until a decision arrives or timeout. Returns
        ('approve'|'deny'|'timeout', response_or_None)."""
        response = wait_for_response(
            request,
            response_dir=self.config.response_dir,
            poll_interval=self.config.poll_interval_seconds,
            timeout=self.config.timeout_seconds,
        )
        if response is None:
            return "timeout", None
        return response.decision, response

    def evaluate(
        self,
        *,
        call_id: int | str,
        server: str,
        tool: str,
        args: dict[str, Any],
        reason: str,
        trigger: str,
        rule_name: str,
    ) -> tuple[str, Optional[ApprovalResponse]]:
        """Convenience: request + await_decision in one call. This is what
        the proxy calls. Returns ('approve'|'deny'|'timeout', response)."""
        req = self.request(
            call_id=call_id, server=server, tool=tool, args=args,
            reason=reason, trigger=trigger, rule_name=rule_name,
        )
        outcome, response = self.await_decision(req)
        self._mark_resolved(req, outcome, response)
        return outcome, response

    # ----------------------------------------------------------- internals

    def _ensure_dirs(self) -> None:
        """Create pending/response/resolved dirs. Fail-fast at init."""
        for d in (self.config.pending_dir, self.config.response_dir, self.config.resolved_dir):
            Path(d).mkdir(parents=True, exist_ok=True)

    def matches_risk_rule(self, tool: str, args: dict) -> Optional[CompiledRiskRule]:
        """Return the first matching risk rule for this call, or None."""
        from mcp_shield.approval.rules import matches_risk_rule as _match
        return _match(tool, args, self._compiled_rules)

    def _write_pending(self, request: ApprovalRequest) -> None:
        """Write the request to pending/<id>.json. Args are already redacted."""
        path = Path(self.config.pending_dir) / f"{request.request_id}.json"
        data = {
            "request_id": request.request_id,
            "call_id": request.call_id,
            "server": request.server,
            "tool": request.tool,
            "args": request.args,
            "reason": request.reason,
            "trigger": request.trigger,
            "rule_name": request.rule_name,
            "created_at": request.created_at,
            "expires_at": request.expires_at,
        }
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def _mark_resolved(
        self, request: ApprovalRequest, outcome: str, response: Optional[ApprovalResponse],
    ) -> None:
        """Move pending/<id>.json to resolved/<id>.json with the decision appended."""
        pending_path = Path(self.config.pending_dir) / f"{request.request_id}.json"
        resolved_path = Path(self.config.resolved_dir) / f"{request.request_id}.json"
        try:
            data = {}
            if pending_path.exists():
                data = json.loads(pending_path.read_text(encoding="utf-8"))
            data["outcome"] = outcome
            if response is not None:
                data["decision"] = response.decision
                data["decided_by"] = response.by
                data["comment"] = response.comment
                data["decided_at"] = response.decided_at
            else:
                data["decision"] = None
                data["decided_by"] = None
                data["comment"] = None
                data["decided_at"] = time.time()
            resolved_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            # Remove from pending now that it's resolved.
            if pending_path.exists():
                pending_path.unlink()
        except Exception as exc:
            log.warning("approval: failed to mark resolved for %s: %s", request.request_id, exc)

    def _truncate_args(self, args: dict[str, Any]) -> dict[str, Any]:
        """Truncate large arg values so the pending file stays small.

        Caps each value at max_arg_bytes and the whole dict at max_args_bytes
        (of JSON). Adds a "[truncated]" marker when a value is cut.
        """
        max_v = self.config.max_arg_bytes
        out: dict[str, Any] = {}
        total = 0
        for key, value in args.items():
            sval = str(value)
            if len(sval) > max_v:
                sval = sval[:max_v] + "[truncated]"
                value = sval
            out[key] = value
            total += len(json.dumps(value, ensure_ascii=False))
            if total > self.config.max_args_bytes:
                out[key] = "[args-truncated]"
                break
        return out
