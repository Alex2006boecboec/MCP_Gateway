"""Tests for risk rule matching + regex compilation."""
import pytest

from mcp_shield.approval.rules import (
    compile_risk_rules, matches_risk_rule, ApprovalError,
)
from mcp_shield.approval.types import RiskRule


def test_matches_exec():
    rules = compile_risk_rules([RiskRule("exec", ".*exec.*", reason="exec needs approval")])
    m = matches_risk_rule("exec", {"cmd": "ls"}, rules)
    assert m is not None
    assert m.name == "exec"


def test_matches_with_arg():
    rules = compile_risk_rules([RiskRule("destructive", ".*exec.*", arg_regex="rm", reason="rm needs approval")])
    m = matches_risk_rule("exec", {"cmd": "rm -rf /"}, rules)
    assert m is not None
    assert m.name == "destructive"


def test_no_match_tool():
    rules = compile_risk_rules([RiskRule("exec", ".*exec.*", reason="x")])
    assert matches_risk_rule("read_file", {"path": "/tmp"}, rules) is None


def test_no_match_arg():
    rules = compile_risk_rules([RiskRule("destructive", ".*exec.*", arg_regex="rm", reason="x")])
    # tool matches but arg doesn't -> no match
    assert matches_risk_rule("exec", {"cmd": "ls -la"}, rules) is None


def test_first_rule_wins():
    rules = compile_risk_rules([
        RiskRule("first", ".*exec.*", reason="first"),
        RiskRule("second", ".*exec.*", reason="second"),
    ])
    m = matches_risk_rule("exec", {}, rules)
    assert m.name == "first"


def test_bad_tool_regex():
    with pytest.raises(ApprovalError):
        compile_risk_rules([RiskRule("bad", "(", reason="x")])


def test_bad_arg_regex():
    with pytest.raises(ApprovalError):
        compile_risk_rules([RiskRule("bad", ".*", arg_regex="(", reason="x")])


def test_empty_rules():
    assert matches_risk_rule("exec", {"cmd": "ls"}, []) is None


def test_arg_regex_searches_all_values():
    rules = compile_risk_rules([RiskRule("x", ".*", arg_regex="secret", reason="x")])
    # secret is in the second arg value
    m = matches_risk_rule("any_tool", {"a": "benign", "b": "send-this-secret-now"}, rules)
    assert m is not None


def test_arg_regex_no_args():
    rules = compile_risk_rules([RiskRule("x", ".*exec.*", arg_regex="rm", reason="x")])
    # tool matches, arg_regex set, but no args -> no match
    assert matches_risk_rule("exec", {}, rules) is None


def test_compiled_rule_has_reason():
    rules = compile_risk_rules([RiskRule("x", ".*", reason="my reason")])
    assert rules[0].reason == "my reason"
