"""Data structures for the capability graph (Phase 3).

Kept in a separate module so every graph submodule can import these
types without creating circular imports (capabilities/sources/rules
import types; graph imports them all).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Taint:
    """In-memory record that sensitive data was read at a specific call.

    The secret value itself is NEVER stored — only a fingerprint
    (sha256, truncated). The fingerprint lets us match the same value
    later in a sink's arguments without persisting the secret.
    """
    taint_id: str            # uuid4 hex
    source_call_id: int | str
    source_tool: str
    label: str               # "secret:ssh_key", "env:API_KEY", "file:~/.ssh", ...
    fingerprint: str         # sha256(value)[:size] (in memory only)
    created_at: float        # time.time()
    source_capabilities: list[str] = field(default_factory=list)  # caps of the source tool


@dataclass
class Chain:
    """A detected dangerous chain: source -> sink with data flow."""
    source_call_id: int | str
    source_tool: str
    sink_call_id: int | str
    sink_tool: str
    label: str               # the taint label that matched
    sink_capability: str    # e.g. "network:send"
    rule_name: str           # which chain rule fired


@dataclass
class ChainRule:
    """A rule defining a dangerous (source_capability, sink_capability) pair."""
    name: str
    source_capability: str   # e.g. "read:secret"
    sink_capability: str     # e.g. "network:send"
    severity: str            # "block" | "review"


@dataclass
class GraphConfig:
    """Configuration for the CapabilityGraph. All fields have safe defaults."""
    enabled: bool = True
    max_taints: int = 1000            # LRU eviction above this
    taint_ttl_seconds: float = 1800.0  # 30 min
    fingerprint_size: int = 16        # chars of sha256 hex
    max_arg_scan_chars: int = 50_000  # don't fingerprint huge args
    # Override/extend the built-in capability registry
    extra_capabilities: Optional[dict[str, list[str]]] = None
    # Override/extend the built-in chain rules
    extra_rules: Optional[list[ChainRule]] = None
