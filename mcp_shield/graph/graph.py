"""CapabilityGraph — the stateful combiner (Phase 3).

Tracks tool capabilities and taints across a session. Detects dangerous
chains: a sensitive source (read of a secret) followed by a dangerous
sink (send/exec) whose arguments contain a value matching an active taint.

Lifecycle (one Proxy instance = one graph = one session):
  - register_tool(name, description)  on tools/list response
  - check_sink(call_id, tool, args, request_redactions)  on tools/call REQUEST
      -> returns (Decision, Chain | None). If a chain is detected and the
         rule severity is "block", the decision is "deny".
  - record_source(call_id, tool, args, response_redactions, response_text)
      on tools/call RESPONSE. If the call was a sensitive source, creates
      taints from the response (redactions + env scan).
  - reset()  on a new initialize (new session)

Memory is bounded: max_taints (LRU eviction) + taint_ttl_seconds (expiry).

NOT thread-safe. The proxy is sequential (Phase 1-3), so one graph per
proxy instance is correct.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Optional

from mcp_shield.graph.capabilities import (
    SINK_CAPABILITIES, SOURCE_CAPABILITIES, get_capabilities,
)
from mcp_shield.graph.rules import DANGEROUS_CHAINS, is_dangerous_chain
from mcp_shield.graph.sources import (
    SOURCE_CAPS, extract_sensitive_values_from_response,
    fingerprint, fingerprint_arg_values, fingerprint_redactions,
    is_sensitive_source,
)
from mcp_shield.graph.types import Chain, ChainRule, GraphConfig, Taint
from mcp_shield.policy import Decision

log = logging.getLogger("mcp_shield.graph")


class CapabilityGraph:
    """Stateful taint tracker + chain detector. One per proxy session."""

    def __init__(self, config: GraphConfig):
        self.config = config
        # tool name -> capabilities
        self._tool_caps: dict[str, list[str]] = {}
        # fingerprint -> Taint (dedup by fingerprint)
        self._taints: dict[str, Taint] = {}
        # fingerprints in insertion order (for LRU eviction)
        self._taint_order: list[str] = []
        # detected chains (for audit/debug)
        self._chains: list[Chain] = []
        # merged chain rules (built-in + extra)
        self._rules: list[ChainRule] = list(DANGEROUS_CHAINS)
        if config.extra_rules:
            self._rules = list(config.extra_rules) + self._rules  # user rules first
        # merged capability registry (built-in + extra)
        self._registry: dict[str, list[str]] = {}
        if config.extra_capabilities:
            self._registry.update(config.extra_capabilities)

    # ------------------------------------------------------------- public

    def register_tool(self, name: str, description: str = "") -> None:
        """Register a tool's capabilities (called on tools/list)."""
        if not self.config.enabled:
            return
        caps = get_capabilities(name, description, registry=self._registry or None)
        self._tool_caps[name] = caps

    def reset(self) -> None:
        """Clear all state (new session)."""
        self._tool_caps.clear()
        self._taints.clear()
        self._taint_order.clear()
        self._chains.clear()

    def check_sink(
        self,
        call_id: int | str,
        tool: str,
        args: dict,
        request_redactions: list | None = None,
    ) -> tuple[Decision, Optional[Chain]]:
        """Called on a tools/call REQUEST. Returns (decision, chain).

        If this call is a dangerous sink and its args (or request redactions)
        contain a value matching an active taint, returns a deny decision
        (for "block" rules) with the chain. Otherwise returns (allow, None).
        """
        if not self.config.enabled:
            return Decision("allow", "graph disabled", "graph"), None

        caps = self._tool_caps.get(tool) or get_capabilities(tool, registry=self._registry or None)
        sink_caps = [c for c in caps if c in SINK_CAPABILITIES]
        if not sink_caps:
            return Decision("allow", "not a sink", "graph"), None

        # Collect fingerprints from the sink's args + request redactions.
        arg_fps = fingerprint_arg_values(
            args, max_scan_chars=self.config.max_arg_scan_chars, fp_size=self.config.fingerprint_size,
        )
        if request_redactions:
            arg_fps |= fingerprint_redactions(request_redactions, fp_size=self.config.fingerprint_size)

        if not arg_fps:
            return Decision("allow", "no args to match", "graph"), None

        # Expire old taints before checking.
        self._evict_expired()

        # Check each active taint against the arg fingerprints.
        for fp, taint in self._taints.items():
            if fp not in arg_fps:
                continue
            # Match by the taint's label category (what was read), not the
            # tool's capability — a read:filesystem tool can read a secret.
            source_caps = self._source_caps_for_label(taint.label)
            rule = is_dangerous_chain(source_caps, sink_caps, rules=self._rules)
            if rule is None:
                continue
            chain = Chain(
                source_call_id=taint.source_call_id,
                source_tool=taint.source_tool,
                sink_call_id=call_id,
                sink_tool=tool,
                label=taint.label,
                sink_capability=rule.sink_capability,
                rule_name=rule.name,
            )
            self._chains.append(chain)
            if rule.severity == "block":
                return Decision(
                    "deny",
                    f"dangerous chain detected: {rule.name} ({taint.source_tool} -> {tool}, label={taint.label})",
                    "capability-graph",
                ), chain
            # review severity: log but allow
            log.info("chain review: %s (%s -> %s)", rule.name, taint.source_tool, tool)
            return Decision("allow", f"chain review: {rule.name}", "capability-graph"), chain

        return Decision("allow", "no chain matched", "graph"), None

    def record_source(
        self,
        call_id: int | str,
        tool: str,
        args: dict,
        response_redactions: list | None = None,
        response_text: str = "",
    ) -> list[Taint]:
        """Called on a tools/call RESPONSE. If this call was a sensitive
        source, create taints from the response. Returns the taints created.
        """
        if not self.config.enabled:
            return []

        caps = self._tool_caps.get(tool) or get_capabilities(tool, registry=self._registry or None)
        is_sensitive, path_label = is_sensitive_source(tool, args, caps)
        sensitive_values = extract_sensitive_values_from_response(
            response_redactions or [], response_text,
        )

        if not is_sensitive and not sensitive_values:
            return []

        # If the path was sensitive but no secret content was found in the
        # response, we still taint based on the path label (the file itself
        # is sensitive even if we didn't recognize its content format).
        created: list[Taint] = []
        if is_sensitive and not sensitive_values:
            # Create a taint with the path label and a placeholder fingerprint
            # derived from the path (so a later send of the same path is caught).
            for value in _iter_string_values(args):
                if _is_sensitive_path(value):
                    fp = fingerprint(value, self.config.fingerprint_size)
                    t = self._add_taint(call_id, tool, path_label, fp, source_caps=caps)
                    if t:
                        created.append(t)
                    break

        # Create taints for each sensitive value found in the response.
        for label, value in sensitive_values:
            fp = fingerprint(value, self.config.fingerprint_size)
            t = self._add_taint(call_id, tool, label, fp, source_caps=caps)
            if t:
                created.append(t)

        if created:
            self._evict_expired()
        return created

    # ----------------------------------------------------------- internals

    def _source_caps_for_label(self, label: str) -> list[str]:
        """Map a taint label to its source capability category.

        The label tells us WHAT was read (a secret, an env var, a file).
        The tool's capability tells us HOW — but a read:filesystem tool can
        read a secret file, so we match rules by the LABEL category, not the
        tool capability. This is why read_file ~/.aws/credentials -> send
        matches secret-exfiltration (read:secret source), not a benign
        filesystem rule.
        """
        if label.startswith("secret:"):
            return ["read:secret"]
        if label.startswith("env:"):
            return ["read:env"]
        if label.startswith("file:"):
            return ["read:filesystem"]
        # Unknown label prefix -> allow any source to match (conservative).
        return list(SOURCE_CAPS)

    def _add_taint(
        self, call_id, tool: str, label: str, fp: str, source_caps: list[str] | None = None,
    ) -> Optional[Taint]:
        """Add a taint, dedup by fingerprint. Returns the taint or None if dup."""
        if fp in self._taints:
            # Refresh LRU position.
            self._taint_order.remove(fp)
            self._taint_order.append(fp)
            return None
        taint = Taint(
            taint_id=uuid.uuid4().hex,
            source_call_id=call_id,
            source_tool=tool,
            label=label,
            fingerprint=fp,
            created_at=time.time(),
            source_capabilities=source_caps or [],
        )
        self._taints[fp] = taint
        self._taint_order.append(fp)
        return taint

    def _evict_expired(self) -> None:
        """Remove taints past their TTL and enforce max_taints (LRU)."""
        now = time.time()
        ttl = self.config.taint_ttl_seconds
        # TTL expiry.
        expired = [fp for fp, t in self._taints.items() if now - t.created_at > ttl]
        for fp in expired:
            self._taints.pop(fp, None)
            if fp in self._taint_order:
                self._taint_order.remove(fp)
        # LRU eviction.
        while len(self._taints) > self.config.max_taints and self._taint_order:
            oldest = self._taint_order.pop(0)
            self._taints.pop(oldest, None)

    # ------------------------------------------------------------- accessors

    @property
    def taint_count(self) -> int:
        return len(self._taints)

    @property
    def chains(self) -> list[Chain]:
        return list(self._chains)


# Module-level helpers (kept here to avoid importing from sources twice).

def _iter_string_values(args: dict):
    from mcp_shield.graph.sources import _iter_string_values as _iv
    yield from _iv(args)


def _is_sensitive_path(value: str) -> bool:
    from mcp_shield.graph.sources import SENSITIVE_PATH_PATTERNS
    return any(pat.search(value) for pat, _ in SENSITIVE_PATH_PATTERNS)
