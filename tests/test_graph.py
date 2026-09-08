"""Tests for the CapabilityGraph."""
import time
from types import SimpleNamespace

from mcp_shield.graph.graph import CapabilityGraph
from mcp_shield.graph.types import GraphConfig


def _graph(**kw):
    return CapabilityGraph(GraphConfig(**kw))


def test_register_then_check_not_a_sink():
    g = _graph()
    g.register_tool("read_file")
    dec, chain = g.check_sink(1, "read_file", {})
    assert dec.action == "allow"
    assert chain is None


def test_register_sink_no_taint_allows():
    g = _graph()
    g.register_tool("fetch_url")  # read:network, not a send sink
    dec, chain = g.check_sink(1, "fetch_url", {"url": "http://x"})
    assert dec.action == "allow"


def test_taint_then_block_chain():
    g = _graph()
    g.register_tool("read_file")
    g.register_tool("http_request")  # has network:send
    # Simulate a sensitive read: response contained an AWS key.
    secret = "AKIAIOSFODNN7EXAMPLE"
    red = SimpleNamespace(original=secret, name="aws_access_key_id")
    created = g.record_source(1, "read_file", {"path": "~/.aws/credentials"}, [red], "")
    assert len(created) >= 1
    # Now the agent tries to send the same secret externally.
    dec, chain = g.check_sink(2, "http_request", {"body": secret})
    assert dec.action == "deny"
    assert chain is not None
    assert chain.rule_name == "secret-exfiltration"
    assert chain.source_tool == "read_file"
    assert chain.sink_tool == "http_request"


def test_taint_via_request_redactions_blocks():
    g = _graph()
    g.register_tool("read_file")
    g.register_tool("post_url")  # network:send
    secret = "AKIAIOSFODNN7EXAMPLE"
    # Source: read returned the secret (redacted in response).
    g.record_source(1, "read_file", {"path": "~/.aws/credentials"},
                    [SimpleNamespace(original=secret, name="aws_access_key_id")], "")
    # Sink: the agent put the secret in the send's args; the redactor masked it.
    req_red = [SimpleNamespace(original=secret, name="aws_access_key_id")]
    dec, chain = g.check_sink(2, "post_url", {"body": "[REDACTED]"}, request_redactions=req_red)
    assert dec.action == "deny"
    assert chain is not None


def test_taint_dedup():
    g = _graph()
    g.register_tool("read_file")
    secret = "AKIAIOSFODNN7EXAMPLE"
    red = SimpleNamespace(original=secret, name="aws_access_key_id")
    t1 = g.record_source(1, "read_file", {"path": "~/.aws/credentials"}, [red], "")
    t2 = g.record_source(2, "read_file", {"path": "~/.aws/credentials"}, [red], "")
    # Same secret -> dedup -> only one new taint.
    assert len(t1) >= 1
    assert t2 == []
    assert g.taint_count == 1


def test_no_taint_no_block():
    g = _graph()
    g.register_tool("post_url")
    dec, chain = g.check_sink(1, "post_url", {"body": "benign-data"})
    assert dec.action == "allow"
    assert chain is None


def test_reset_clears():
    g = _graph()
    g.register_tool("read_file")
    g.record_source(1, "read_file", {"path": "~/.ssh/id_rsa"},
                    [SimpleNamespace(original="some-secret-value-123", name="x")], "")
    assert g.taint_count >= 1
    g.reset()
    assert g.taint_count == 0
    g.register_tool("post_url")
    dec, _ = g.check_sink(2, "post_url", {"body": "some-secret-value-123"})
    assert dec.action == "allow"


def test_unknown_tool_failopen():
    g = _graph()
    # Tool never registered -> no capabilities -> allow (fail-open).
    dec, chain = g.check_sink(1, "mystery_tool", {"x": "y"})
    assert dec.action == "allow"
    assert chain is None


def test_large_arg_no_crash():
    g = _graph()
    g.register_tool("post_url")
    big = "x" * 200_000
    dec, chain = g.check_sink(1, "post_url", {"body": big})
    assert dec.action == "allow"  # no taint -> allow, no crash


def test_graph_disabled_noop():
    g = _graph(enabled=False)
    g.register_tool("read_file")
    # All methods are no-ops when disabled.
    assert g.record_source(1, "read_file", {}, [], "") == []
    dec, chain = g.check_sink(2, "post_url", {"body": "x"})
    assert dec.action == "allow"


def test_max_taints_eviction():
    g = _graph(max_taints=3)
    g.register_tool("read_file")
    for i in range(5):
        red = SimpleNamespace(original=f"secret-value-{i}-pad", name="x")
        g.record_source(i, "read_file", {"path": f"~/.aws/credentials"}, [red], "")
    assert g.taint_count <= 3


def test_taint_ttl_expiry():
    g = _graph(taint_ttl_seconds=0.01)
    g.register_tool("read_file")
    g.register_tool("post_url")
    secret = "short-secret-12345"
    red = SimpleNamespace(original=secret, name="x")
    g.record_source(1, "read_file", {"path": "~/.aws/credentials"}, [red], "")
    assert g.taint_count >= 1
    time.sleep(0.05)  # past TTL
    # check_sink evicts expired taints -> no match -> allow.
    dec, chain = g.check_sink(2, "post_url", {"body": secret})
    assert dec.action == "allow"


def test_env_taint_blocks_to_exec():
    g = _graph()
    g.register_tool("get_env")  # read:env
    g.register_tool("exec")     # exec:command
    # Source: env var with secret-ish name.
    g.record_source(1, "get_env", {}, [], "API_KEY=sk-secret-value-123456\n")
    # Sink: exec with the env value as an arg.
    dec, chain = g.check_sink(2, "exec", {"cmd": "sk-secret-value-123456"})
    assert dec.action == "deny"
    assert chain.rule_name == "env-to-exec"


def test_review_severity_allows_but_logs():
    # A secret SSH key read then passed to exec is secret-to-exec (block),
    # NOT file-to-exec (review) — the label is secret:ssh_key.
    g = _graph()
    g.register_tool("read_file")  # read:filesystem
    g.register_tool("exec")       # exec:command
    g.record_source(1, "read_file", {"path": "~/.ssh/id_rsa"},
                    [SimpleNamespace(original="some-secret-content-here", name="x")], "")
    dec, chain = g.check_sink(2, "exec", {"cmd": "some-secret-content-here"})
    assert dec.action == "deny"
    assert chain is not None
    assert chain.rule_name == "secret-to-exec"


def test_benign_file_to_exec_no_chain():
    # A benign file read (no secret) -> exec: no taint -> no chain.
    g = _graph()
    g.register_tool("read_file")
    g.register_tool("exec")
    g.record_source(1, "read_file", {"path": "/tmp/script.sh"}, [], "echo hello")
    dec, chain = g.check_sink(2, "exec", {"cmd": "echo hello"})
    assert dec.action == "allow"
    assert chain is None


def test_benign_read_then_send_no_false_positive():
    g = _graph()
    g.register_tool("read_file")
    g.register_tool("post_url")
    # Benign read (no secret in response).
    g.record_source(1, "read_file", {"path": "/tmp/report.txt"}, [], "Here is the report.")
    # Benign send of report content (not a tainted secret).
    dec, chain = g.check_sink(2, "post_url", {"body": "Here is the report."})
    assert dec.action == "allow"
    assert chain is None


def test_chains_recorded():
    g = _graph()
    g.register_tool("read_file")
    g.register_tool("http_request")
    secret = "AKIAIOSFODNN7EXAMPLE"
    g.record_source(1, "read_file", {"path": "~/.aws/credentials"},
                    [SimpleNamespace(original=secret, name="aws_access_key_id")], "")
    g.check_sink(2, "http_request", {"body": secret})
    assert len(g.chains) == 1
