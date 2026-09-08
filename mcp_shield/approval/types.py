"""Data structures for the approval flow (Phase 4).

Kept in a separate module so every approval submodule can import these
types without circular imports (rules/notifier/responder import types;
engine imports them all).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ApprovalRequest:
    """A request to a human to approve or deny a high-risk tool call.

    The args are ALREADY redacted (redaction runs before approval in the
    proxy pipeline), so no secrets are written to the pending file.
    """
    request_id: str            # uuid4 hex
    call_id: int | str         # the JSON-RPC id of the tools/call
    server: str
    tool: str
    args: dict[str, Any]       # already redacted (no secrets)
    reason: str                # why approval is required
    trigger: str               # "policy" | "risk-rule" | "review-chain"
    rule_name: str             # which rule triggered
    created_at: float          # time.time()
    expires_at: float          # created_at + timeout_seconds


@dataclass
class ApprovalResponse:
    """A human's decision on an ApprovalRequest."""
    request_id: str
    decision: str             # "approve" | "deny"
    by: str                   # who approved/denied (for the audit log)
    comment: str = ""
    decided_at: float = 0.0


@dataclass
class RiskRule:
    """A declarative rule marking a tool call as high-risk (requires approval).

    tool_regex and arg_regex are stored as strings and compiled to
    re.Pattern at ApprovalEngine init time (fail-fast on bad regex).
    """
    name: str
    tool_regex: str           # compiled to re.Pattern at load time
    arg_regex: Optional[str] = None     # optional; compiled if present
    reason: str = ""


@dataclass
class ApprovalConfig:
    """Configuration for the ApprovalEngine. All fields have safe defaults."""
    enabled: bool = True
    # File-based queue directories (the responder polls responses/).
    pending_dir: str = "approvals/pending"
    response_dir: str = "approvals/responses"
    # Where resolved (decided/expired) requests are moved for the audit trail.
    resolved_dir: str = "approvals/resolved"
    # How long to wait for a human before timing out (fail-closed).
    timeout_seconds: float = 120.0
    # Poll interval for the response file.
    poll_interval_seconds: float = 1.0
    # Optional webhook notification (Slack/Teams incoming webhook URL).
    # None = no notification (file-based only).
    webhook_url: Optional[str] = None
    webhook_timeout_seconds: float = 5.0
    # Route graph "review" chains to approval (off by default).
    require_for_review_chains: bool = False
    # Declarative high-risk rules (the primary trigger).
    risk_rules: list[RiskRule] = field(default_factory=list)
    # Max size of an arg value written to the pending file (bytes of JSON).
    max_arg_bytes: int = 10_000
    # Max total size of the args dict written to the pending file.
    max_args_bytes: int = 50_000
