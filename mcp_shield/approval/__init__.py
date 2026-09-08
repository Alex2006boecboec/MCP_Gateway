"""MCP Shield approval flow - human-in-the-loop for high-risk calls (Phase 4).

Holds high-risk tool calls for human approval. File-based queue (no
external deps); optional Slack/Teams webhook notification. Fail-closed
on timeout.

Public API:
    from mcp_shield.approval import ApprovalEngine, ApprovalConfig, RiskRule
"""

from mcp_shield.approval.engine import ApprovalEngine
from mcp_shield.approval.rules import ApprovalError, matches_risk_rule
from mcp_shield.approval.types import (
    ApprovalConfig, ApprovalRequest, ApprovalResponse, RiskRule,
)

__all__ = [
    "ApprovalEngine",
    "ApprovalConfig",
    "ApprovalRequest",
    "ApprovalResponse",
    "RiskRule",
    "ApprovalError",
    "matches_risk_rule",
]
