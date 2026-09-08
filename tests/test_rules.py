"""Tests for dangerous chain rules."""
from mcp_shield.graph.rules import is_dangerous_chain, DANGEROUS_CHAINS
from mcp_shield.graph.types import ChainRule


def test_secret_exfiltration_block():
    r = is_dangerous_chain(["read:secret"], ["network:send"])
    assert r is not None
    assert r.name == "secret-exfiltration"
    assert r.severity == "block"


def test_env_exfiltration_block():
    r = is_dangerous_chain(["read:env"], ["network:send"])
    assert r is not None
    assert r.name == "env-exfiltration"
    assert r.severity == "block"


def test_secret_to_exec_block():
    r = is_dangerous_chain(["read:secret"], ["exec:command"])
    assert r is not None
    assert r.severity == "block"


def test_env_to_exec_block():
    r = is_dangerous_chain(["read:env"], ["exec:command"])
    assert r is not None
    assert r.severity == "block"


def test_db_to_exfiltration_block():
    r = is_dangerous_chain(["read:database"], ["network:send"])
    assert r is not None
    assert r.severity == "block"


def test_file_to_exec_review():
    r = is_dangerous_chain(["read:filesystem"], ["exec:command"])
    assert r is not None
    assert r.severity == "review"


def test_secret_to_write_review():
    r = is_dangerous_chain(["read:secret"], ["write:filesystem"])
    assert r is not None
    assert r.severity == "review"


def test_network_to_exec_review():
    r = is_dangerous_chain(["read:network"], ["exec:command"])
    assert r is not None
    assert r.severity == "review"


def test_benign_chain_no_match():
    # read:filesystem -> write:filesystem is not in the rules (data tampering
    # is plausible but not clearly malicious; left to policy).
    r = is_dangerous_chain(["read:filesystem"], ["write:filesystem"])
    assert r is None


def test_no_source_cap_no_match():
    assert is_dangerous_chain([], ["network:send"]) is None


def test_no_sink_cap_no_match():
    assert is_dangerous_chain(["read:secret"], []) is None


def test_first_matching_rule_wins():
    # If two rules could match, the earlier one wins.
    custom = [
        ChainRule("custom-first", "read:secret", "network:send", "block"),
        ChainRule("custom-second", "read:secret", "network:send", "review"),
    ]
    r = is_dangerous_chain(["read:secret"], ["network:send"], rules=custom)
    assert r.name == "custom-first"


def test_multiple_sink_caps():
    # A tool with multiple sink caps; any matching sink cap fires.
    r = is_dangerous_chain(["read:secret"], ["read:network", "network:send"])
    assert r is not None
    assert r.name == "secret-exfiltration"


def test_all_rules_have_valid_severity():
    for r in DANGEROUS_CHAINS:
        assert r.severity in ("block", "review")
        assert r.source_capability and r.sink_capability
