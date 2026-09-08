"""Tests for the policy engine — YAML loading and rule evaluation."""
import textwrap

import pytest

from mcp_shield.policy import PolicyEngine, PolicyError, load_policy


def _write_policy(tmp_path, content):
    p = tmp_path / "policy.yaml"
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


def test_load_empty_policy(tmp_path):
    p = _write_policy(tmp_path, "")
    policy = load_policy(p)
    assert policy.default_action == "allow"
    assert policy.servers == {}
    assert policy.rules == []


def test_load_full_policy(tmp_path):
    p = _write_policy(tmp_path, """
        defaults:
          action: deny
        servers:
          filesystem:
            trust: high
            tools:
              read_file: {allow: true}
              write_file: {allow: false, reason: "writes blocked"}
          fetch:
            trust: low
            tools:
              fetch_url: {validate: url, block_internal: true}
        rules:
          - name: block-ssrf
            when: {tool_regex: '.*fetch.*'}
            check: {arg_regex: '169\.254\.169\.254'}
            action: deny
            reason: "metadata IP blocked"
    """)
    policy = load_policy(p)
    assert policy.default_action == "deny"
    assert "filesystem" in policy.servers
    assert policy.servers["filesystem"].trust == "high"
    assert policy.servers["filesystem"].tools["read_file"].allow is True
    assert policy.servers["filesystem"].tools["write_file"].allow is False
    assert len(policy.rules) == 1
    assert policy.rules[0].name == "block-ssrf"


def test_bad_defaults_raises(tmp_path):
    p = _write_policy(tmp_path, "defaults: [1,2,3]")
    with pytest.raises(PolicyError):
        load_policy(p)


def test_bad_default_action_raises(tmp_path):
    p = _write_policy(tmp_path, "defaults:\n  action: maybe")
    with pytest.raises(PolicyError):
        load_policy(p)


def test_missing_file_raises(tmp_path):
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "nonexistent.yaml")


# --- Engine evaluation ---------------------------------------------------

def _engine(tmp_path, content):
    return PolicyEngine(load_policy(_write_policy(tmp_path, content)))


def test_allow_by_default(tmp_path):
    engine = _engine(tmp_path, "defaults:\n  action: allow")
    d = engine.evaluate(server="x", tool="y", arguments={})
    assert d.action == "allow"


def test_deny_by_default(tmp_path):
    engine = _engine(tmp_path, "defaults:\n  action: deny")
    d = engine.evaluate(server="x", tool="y", arguments={})
    assert d.action == "deny"


def test_tool_deny_in_server_config(tmp_path):
    engine = _engine(tmp_path, """
        servers:
          fs:
            tools:
              write_file: {deny: true, reason: "no writes"}
    """)
    d = engine.evaluate(server="fs", tool="write_file", arguments={})
    assert d.action == "deny"
    assert "no writes" in d.reason


def test_ssrf_rule_blocks_metadata_ip(tmp_path):
    engine = _engine(tmp_path, """
        rules:
          - name: block-ssrf
            when: {tool_regex: '.*fetch.*'}
            check: {arg_regex: '169\.254\.169\.254'}
            action: deny
            reason: "metadata IP blocked"
    """)
    d = engine.evaluate(server="fetch", tool="fetch_url", arguments={"url": "http://169.254.169.254/latest/meta-data/"})
    assert d.action == "deny"
    assert d.rule_name == "block-ssrf"


def test_ssrf_rule_allows_safe_url(tmp_path):
    engine = _engine(tmp_path, """
        rules:
          - name: block-ssrf
            when: {tool_regex: '.*fetch.*'}
            check: {arg_regex: '169\.254\.169\.254'}
            action: deny
            reason: "metadata IP blocked"
    """)
    d = engine.evaluate(server="fetch", tool="fetch_url", arguments={"url": "https://example.com"})
    assert d.action == "allow"


def test_url_validator_blocks_internal(tmp_path):
    engine = _engine(tmp_path, """
        servers:
          fetch:
            tools:
              fetch_url: {validate: url, block_internal: true}
    """)
    d = engine.evaluate(server="fetch", tool="fetch_url", arguments={"url": "http://10.0.0.1/"})
    assert d.action == "deny"
    assert "internal" in d.reason.lower()


def test_path_validator_blocks_traversal(tmp_path):
    engine = _engine(tmp_path, """
        servers:
          fs:
            tools:
              read_file: {validate: path}
    """)
    d = engine.evaluate(server="fs", tool="read_file", arguments={"path": "../../../etc/passwd"})
    assert d.action == "deny"
    assert "traversal" in d.reason.lower()


def test_command_validator_blocks_metacharacters(tmp_path):
    engine = _engine(tmp_path, """
        servers:
          shell:
            tools:
              exec: {validate: command}
    """)
    d = engine.evaluate(server="shell", tool="exec", arguments={"cmd": "ls; rm -rf /"})
    assert d.action == "deny"
    assert "metacharacter" in d.reason.lower()
