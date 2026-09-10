"""Tests for the file-based approval responder."""
import json
import time
from pathlib import Path

from mcp_shield.approval.responder import wait_for_response, _parse_response
from mcp_shield.approval.types import ApprovalRequest, ApprovalResponse


def _req(expires_in=1.0):
    now = time.time()
    return ApprovalRequest(
        request_id="abc123",
        call_id=1,
        server="fs",
        tool="exec",
        args={"cmd": "ls"},
        reason="high risk",
        trigger="risk-rule",
        rule_name="exec-rule",
        created_at=now,
        expires_at=now + expires_in,
    )


def test_response_arrives(tmp_path):
    """Write a response file after a short delay -> parsed response."""
    resp_dir = tmp_path / "responses"
    resp_dir.mkdir()
    req = _req(expires_in=2.0)
    # Write the response file immediately (poll will find it on first check).
    (resp_dir / "abc123.json").write_text(
        json.dumps({"decision": "approve", "by": "alice", "comment": "ok"}), encoding="utf-8"
    )
    resp = wait_for_response(req, str(resp_dir), poll_interval=0.05, timeout=2.0)
    assert resp is not None
    assert resp.decision == "approve"
    assert resp.by == "alice"
    assert resp.comment == "ok"


def test_deny_response(tmp_path):
    resp_dir = tmp_path / "responses"
    resp_dir.mkdir()
    req = _req(expires_in=2.0)
    (resp_dir / "abc123.json").write_text(
        json.dumps({"decision": "deny", "by": "bob"}), encoding="utf-8"
    )
    resp = wait_for_response(req, str(resp_dir), poll_interval=0.05, timeout=2.0)
    assert resp is not None
    assert resp.decision == "deny"
    assert resp.by == "bob"


def test_timeout_no_file(tmp_path):
    """No response file, short timeout -> None."""
    resp_dir = tmp_path / "responses"
    resp_dir.mkdir()
    req = _req(expires_in=0.05)
    resp = wait_for_response(req, str(resp_dir), poll_interval=0.02, timeout=0.1)
    assert resp is None


def test_malformed_file_ignored_then_timeout(tmp_path):
    """A malformed response file is ignored; poller keeps waiting, then times out."""
    resp_dir = tmp_path / "responses"
    resp_dir.mkdir()
    req = _req(expires_in=0.2)
    (resp_dir / "abc123.json").write_text("not valid json{{{", encoding="utf-8")
    resp = wait_for_response(req, str(resp_dir), poll_interval=0.05, timeout=0.3)
    assert resp is None


def test_malformed_then_fixed(tmp_path):
    """A malformed file is ignored; if it's fixed in time, the response is parsed."""
    resp_dir = tmp_path / "responses"
    resp_dir.mkdir()
    req = _req(expires_in=1.0)
    (resp_dir / "abc123.json").write_text("bad", encoding="utf-8")
    # Fix it after a short delay in a thread.
    import threading
    def fix():
        time.sleep(0.1)
        (resp_dir / "abc123.json").write_text(
            json.dumps({"decision": "approve", "by": "alice"}), encoding="utf-8"
        )
    t = threading.Thread(target=fix)
    t.start()
    resp = wait_for_response(req, str(resp_dir), poll_interval=0.05, timeout=2.0)
    t.join()
    assert resp is not None
    assert resp.decision == "approve"


def test_malformed_decision_ignored_then_timeout(tmp_path):
    """Valid JSON with an unknown decision is ignored; poller keeps waiting."""
    resp_dir = tmp_path / "responses"
    resp_dir.mkdir()
    req = _req(expires_in=0.35)
    (resp_dir / "abc123.json").write_text(
        json.dumps({"decision": "maybe", "by": "alice"}), encoding="utf-8"
    )
    t0 = time.time()
    resp = wait_for_response(req, str(resp_dir), poll_interval=0.05, timeout=0.4)
    elapsed = time.time() - t0
    assert resp is None
    assert elapsed >= 0.25


def test_parse_response_deny():
    r = _parse_response("id1", {"decision": "deny", "by": "bob"})
    assert r is not None
    assert r.decision == "deny"


def test_parse_response_bad_decision():
    assert _parse_response("id1", {"decision": "maybe"}) is None


def test_parse_response_not_dict():
    assert _parse_response("id1", "not a dict") is None


def test_parse_response_missing_decision():
    assert _parse_response("id1", {"by": "alice"}) is None


def test_expired_request_returns_none_immediately(tmp_path):
    """If expires_at is in the past, return None without polling."""
    resp_dir = tmp_path / "responses"
    resp_dir.mkdir()
    req = _req(expires_in=-1.0)  # already expired
    resp = wait_for_response(req, str(resp_dir), poll_interval=0.05, timeout=0.5)
    assert resp is None
