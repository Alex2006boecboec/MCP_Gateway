"""MCP Shield capability graph — cross-server taint tracking (Phase 3).

Tracks data flow across tool calls in a session to detect dangerous
chains that no single-call scanner can see (e.g. read a secret then send
it externally).

Public API:
    from mcp_shield.graph import CapabilityGraph, GraphConfig, Taint, Chain
"""

from mcp_shield.graph.graph import CapabilityGraph
from mcp_shield.graph.types import Chain, ChainRule, GraphConfig, Taint

__all__ = [
    "CapabilityGraph",
    "GraphConfig",
    "Taint",
    "Chain",
    "ChainRule",
]
