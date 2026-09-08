"""Risk rule matching for the approval flow (Phase 4).

A risk rule marks a tool call as high-risk (requires human approval).
Matching is separate from the policy engine's allow/deny rules: a call
can be allowed by policy AND require approval by a risk rule.

RiskRule stores regexes as strings; compile_risk_rules() validates and
compiles them at ApprovalEngine init time (fail-fast on bad regex, not
at call time).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from mcp_shield.approval.types import RiskRule


class ApprovalError(ValueError):
    """Raised when approval configuration is malformed (e.g. bad regex)."""


@dataclass
class CompiledRiskRule:
    """A RiskRule with its regexes pre-compiled."""
    name: str
    tool_re: re.Pattern
    arg_re: re.Pattern | None
    reason: str


def compile_risk_rules(rules: list[RiskRule]) -> list[CompiledRiskRule]:
    """Compile all risk rules' regexes. Raises ApprovalError on a bad regex.

    Called at ApprovalEngine init (fail-fast). Never called at call time.
    """
    compiled: list[CompiledRiskRule] = []
    for i, rule in enumerate(rules):
        try:
            tool_re = re.compile(rule.tool_regex)
        except re.error as exc:
            raise ApprovalError(
                f"risk rule #{i} '{rule.name}': bad tool_regex {rule.tool_regex!r}: {exc}"
            ) from exc
        arg_re = None
        if rule.arg_regex is not None:
            try:
                arg_re = re.compile(rule.arg_regex)
            except re.error as exc:
                raise ApprovalError(
                    f"risk rule #{i} '{rule.name}': bad arg_regex {rule.arg_regex!r}: {exc}"
                ) from exc
        compiled.append(CompiledRiskRule(name=rule.name, tool_re=tool_re, arg_re=arg_re, reason=rule.reason))
    return compiled


def matches_risk_rule(
    tool: str,
    args: dict[str, Any],
    rules: list[CompiledRiskRule],
) -> CompiledRiskRule | None:
    """Return the first matching risk rule, or None.

    A rule matches if its tool_regex matches the tool name AND (if arg_regex
    is set) the arg_regex matches some argument value. The first matching
    rule wins (order matters: put more specific rules earlier).
    """
    for rule in rules:
        if not rule.tool_re.match(tool):
            continue
        if rule.arg_re is None:
            return rule
        # Search all argument values for the regex.
        for value in args.values():
            if rule.arg_re.search(str(value)):
                return rule
    return None
