"""Dangerous chain rules (Phase 3).

A chain rule defines a dangerous (source_capability, sink_capability) pair.
When a sink call's arguments contain a value matching an active taint whose
source capability matches the rule's source, the chain fires.

severity:
  "block"  -> deny the sink call (ERR_CHAIN_BLOCKED)
  "review" -> log but allow (future: route to approval flow)

"block" is for clear exfiltration (secret/env -> external send/exec).
"review" is for weaker signals (file -> exec) where the data flow is
plausible but not clearly malicious.
"""

from __future__ import annotations

from typing import Optional

from mcp_shield.graph.types import ChainRule

# Built-in dangerous chains. Order matters: the first matching rule wins.
DANGEROUS_CHAINS: list[ChainRule] = [
    ChainRule("secret-exfiltration", "read:secret", "network:send", "block"),
    ChainRule("env-exfiltration", "read:env", "network:send", "block"),
    ChainRule("secret-to-exec", "read:secret", "exec:command", "block"),
    ChainRule("env-to-exec", "read:env", "exec:command", "block"),
    ChainRule("db-to-exfiltration", "read:database", "network:send", "block"),
    ChainRule("secret-to-write", "read:secret", "write:filesystem", "review"),
    ChainRule("file-to-exec", "read:filesystem", "exec:command", "review"),
    ChainRule("network-to-exec", "read:network", "exec:command", "review"),
]


def is_dangerous_chain(
    source_caps: list[str],
    sink_caps: list[str],
    rules: Optional[list[ChainRule]] = None,
) -> Optional[ChainRule]:
    """Return the first matching rule (source cap in source_caps,
    sink cap in sink_caps), or None.

    A rule matches if its source_capability is in source_caps AND its
    sink_capability is in sink_caps. The first matching rule (in order)
    wins so that more specific / severe rules can be placed earlier.
    """
    rule_list = rules if rules is not None else DANGEROUS_CHAINS
    for rule in rule_list:
        if rule.source_capability in source_caps and rule.sink_capability in sink_caps:
            return rule
    return None
