"""Tests for the ApprovalEngine."""
import json
import time
from pathlib import Path

import pytest

from mcp_shield.approval.engine import ApprovalEngine
from mcp_shield.approval.types import ApprovalConfig, RiskRule


def _config(tmp_path):
    return ApprovalConfig(
        pending_dir=str(tmp_path / "pending"),
        response_dir=str(tmp_path / "responses"),
        resolved_dir=str(tmp_path / "resolved"),
        timeout_seconds=1.0,
        poll_interval_seconds=0.05,
    )


def test_approve_flow(tmp_path):
    """Create engine; write an approve response file; evaluate -> ('approve', resp)."""
    cfg = _config(tmp_path)
    eng = ApprovalEngine(cfg)
    # Pre-write the response file (poll will find it on first check).
    # But we need the request_id first... so use request() then write, then await.
    req = eng.request(
        call_id=1, server="fs", tool="exec", args={"cmd": "ls"},
        reason="high risk", trigger="risk-rule", rule_name="exec-rule",
    )
    resp_path = Path(cfg.response_dir) / f"{req.request_id}.json"
    resp_path.write_text(json.dumps({"decision": "approve", "by": "alice"}), encoding="utf-8")
    outcome, response = eng.await_decision(req)
    eng._mark_resolved(req, outcome, response)
    assert outcome == "approve"
    assert response is not None
    assert response.by == "alice"


def test_deny_flow(tmp_path):
    cfg = _config(tmp_path)
    eng = ApprovalEngine(cfg)
    req = eng.request(
        call_id=1, server="fs", tool="exec", args={"cmd": "ls"},
        reason="high risk", trigger="risk-rule", rule_name="exec-rule",
    )
    (Path(cfg.response_dir) / f"{req.request_id}.json").write_text(
        json.dumps({"decision": "deny", "by": "bob", "comment": "too risky"}), encoding="utf-8"
    )
    outcome, response = eng.await_decision(req)
    eng._mark_resolved(req, outcome, response)
    assert outcome == "deny"
    assert response.comment == "too risky"


def test_timeout_flow(tmp_path):
    """No response file, short timeout -> ('timeout', None)."""
    cfg = ApprovalConfig(
        pending_dir=str(tmp_path / "pending"),
        response_dir=str(tmp_path / "responses"),
        resolved_dir=str(tmp_path / "resolved"),
        timeout_seconds=0.1,
        poll_interval_seconds=0.02,
    )
    eng = ApprovalEngine(cfg)
    outcome, response = eng.evaluate(
        call_id=1, server="fs", tool="exec", args={"cmd": "ls"},
        reason="high risk", trigger="risk-rule", rule_name="exec-rule",
    )
    assert outcome == "timeout"
    assert response is None


def test_pending_file_written(tmp_path):
    cfg = _config(tmp_path)
    eng = ApprovalEngine(cfg)
    req = eng.request(
        call_id=1, server="fs", tool="exec", args={"cmd": "ls"},
        reason="high risk", trigger="risk-rule", rule_name="exec-rule",
    )
    pending = Path(cfg.pending_dir) / f"{req.request_id}.json"
    assert pending.exists()
    data = json.loads(pending.read_text(encoding="utf-8"))
    assert data["tool"] == "exec"
    assert data["reason"] == "high risk"
    assert data["trigger"] == "risk-rule"


def test_resolved_file_written(tmp_path):
    cfg = _config(tmp_path)
    eng = ApprovalEngine(cfg)
    req = eng.request(
        call_id=1, server="fs", tool="exec", args={"cmd": "ls"},
        reason="high risk", trigger="risk-rule", rule_name="exec-rule",
    )
    (Path(cfg.response_dir) / f"{req.request_id}.json").write_text(
        json.dumps({"decision": "approve", "by": "alice"}), encoding="utf-8"
    )
    outcome, response = eng.await_decision(req)
    eng._mark_resolved(req, outcome, response)
    resolved = Path(cfg.resolved_dir) / f"{req.request_id}.json"
    assert resolved.exists()
    data = json.loads(resolved.read_text(encoding="utf-8"))
    assert data["outcome"] == "approve"
    assert data["decided_by"] == "alice"
    # Pending file should be removed.
    pending = Path(cfg.pending_dir) / f"{req.request_id}.json"
    assert not pending.exists()


def test_dirs_created(tmp_path):
    """Missing dirs are created on init."""
    pending = tmp_path / "pending"
    responses = tmp_path / "responses"
    resolved = tmp_path / "resolved"
    cfg = ApprovalConfig(
        pending_dir=str(pending), response_dir=str(responses), resolved_dir=str(resolved),
    )
    assert not pending.exists()
    ApprovalEngine(cfg)
    assert pending.exists()
    assert responses.exists()
    assert resolved.exists()


def test_secrets_redacted_in_pending(tmp_path):
    """The engine receives ALREADY-redacted args (proxy redacts first).
    Verify the pending file has the redacted form, not a raw secret."""
    cfg = _config(tmp_path)
    eng = ApprovalEngine(cfg)
    # Simulate already-redacted args (what the proxy passes).
    redacted_args = {"key": "[REDACTED:aws_access_key_id]"}
    req = eng.request(
        call_id=1, server="fs", tool="exec", args=redacted_args,
        reason="high risk", trigger="risk-rule", rule_name="exec-rule",
    )
    pending = Path(cfg.pending_dir) / f"{req.request_id}.json"
    text = pending.read_text(encoding="utf-8")
    assert "[REDACTED:" in text
    assert "AKIA" not in text  # no raw secret


def test_large_args_truncated(tmp_path):
    """A very large arg value is truncated in the pending file."""
    cfg = ApprovalConfig(
        pending_dir=str(tmp_path / "pending"),
        response_dir=str(tmp_path / "responses"),
        resolved_dir=str(tmp_path / "resolved"),
        timeout_seconds=0.1,
        max_arg_bytes=100,
        max_args_bytes=200,
    )
    eng = ApprovalEngine(cfg)
    big = "x" * 100_000
    req = eng.request(
        call_id=1, server="fs", tool="exec", args={"data": big},
        reason="high risk", trigger="risk-rule", rule_name="exec-rule",
    )
    pending = Path(cfg.pending_dir) / f"{req.request_id}.json"
    data = json.loads(pending.read_text(encoding="utf-8"))
    assert "[truncated]" in data["args"]["data"]
    assert len(data["args"]["data"]) < 100_000


def test_risk_rules_compiled_at_init(tmp_path):
    """Risk rules are compiled at init; bad regex fails fast."""
    cfg = _config(tmp_path)
    cfg.risk_rules = [RiskRule("bad", "(", reason="x")]
    with pytest.raises(Exception):
        ApprovalEngine(cfg)


def test_evaluate_convenience(tmp_path):
    """evaluate() does request + await + mark_resolved in one call."""
    cfg = _config(tmp_path)
    eng = ApprovalEngine(cfg)
    # Pre-create a response writer thread.
    import threading
    def write_resp():
        time.sleep(0.05)
        # We don't know the id yet; poll the pending dir for the file.
        pending_dir = Path(cfg.pending_dir)
        for _ in range(20):
            files = list(pending_dir.glob("*.json"))
            if files:
                rid = files[0].stem
                (Path(cfg.response_dir) / f"{rid}.json").write_text(
                    json.dumps({"decision": "approve", "by": "alice"}), encoding="utf-8"
                )
                return
            time.sleep(0.02)
    t = threading.Thread(target=write_resp)
    t.start()
    outcome, response = eng.evaluate(
        call_id=1, server="fs", tool="exec", args={"cmd": "ls"},
        reason="high risk", trigger="risk-rule", rule_name="exec-rule",
    )
    t.join()
    assert outcome == "approve"
    assert response is not None
