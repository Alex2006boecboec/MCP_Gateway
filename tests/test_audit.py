"""Tests for the audit logger — hash chaining and tamper detection."""
import json

from mcp_shield.audit import AuditLogger


def test_first_entry_has_zero_prev_hash(tmp_path):
    audit = AuditLogger(tmp_path / "audit.jsonl")
    entry = audit.log(decision="allow", server="fs", tool="read_file", args={"path": "/tmp/x"}, reason="ok", rule="default")
    assert entry.prev_hash == "0" * 64
    assert entry.this_hash != "0" * 64
    assert entry.this_hash == entry.compute_hash()


def test_second_entry_chains_to_first(tmp_path):
    audit = AuditLogger(tmp_path / "audit.jsonl")
    e1 = audit.log(decision="allow", server="fs", tool="read", args={}, reason="ok", rule="default")
    e2 = audit.log(decision="deny", server="fs", tool="write", args={}, reason="blocked", rule="rule-1")
    assert e2.prev_hash == e1.this_hash
    assert e2.this_hash == e2.compute_hash()


def test_log_is_appended_jsonl(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLogger(path)
    audit.log(decision="allow", server="fs", tool="read_file", args={"path": "/tmp"}, reason="ok", rule="default")
    audit.log(decision="deny", server="fs", tool="write_file", args={"path": "/etc"}, reason="blocked", rule="rule-1")
    lines = path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2
    j1 = json.loads(lines[0])
    j2 = json.loads(lines[1])
    assert j1["seq"] == 1
    assert j2["seq"] == 2
    assert j2["prev_hash"] == j1["this_hash"]


def test_verify_intact_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLogger(path)
    audit.log(decision="allow", server="fs", tool="read", args={}, reason="ok", rule="default")
    audit.log(decision="deny", server="fs", tool="write", args={}, reason="no", rule="rule-1")
    audit2 = AuditLogger(path)  # resume
    assert audit2.verify() is True


def test_verify_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLogger(path)
    audit.log(decision="allow", server="fs", tool="read", args={"path": "/tmp"}, reason="ok", rule="default")
    audit.log(decision="deny", server="fs", tool="write", args={"path": "/etc"}, reason="no", rule="rule-1")
    # Tamper: change the reason of the first entry.
    lines = path.read_text(encoding="utf-8").strip().split("\n")
    j1 = json.loads(lines[0])
    j1["reason"] = "TAMPERED"
    lines[0] = json.dumps(j1, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    audit2 = AuditLogger(path)
    assert audit2.verify() is False


def test_resume_continues_seq(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLogger(path)
    audit.log(decision="allow", server="fs", tool="read", args={}, reason="ok", rule="default")
    audit.log(decision="deny", server="fs", tool="write", args={}, reason="no", rule="rule-1")
    audit2 = AuditLogger(path)  # resume from existing log
    e3 = audit2.log(decision="allow", server="fs", tool="read", args={}, reason="ok2", rule="default")
    assert e3.seq == 3
    lines = path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 3


def test_redactions_recorded(tmp_path):
    audit = AuditLogger(tmp_path / "audit.jsonl")
    audit.log(
        decision="redact",
        server="fs",
        tool="read_file",
        args={"path": "/tmp/x"},
        reason="secret in args",
        rule="redactor",
        redactions=[{"name": "openai_api_key", "field": "args.token", "replacement": "sk-…[REDACTED]…"}],
    )
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip().split("\n")
    j = json.loads(lines[0])
    assert j["redactions"][0]["name"] == "openai_api_key"
    # The original secret must NEVER appear in the log.
    assert "sk-ant-" not in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
