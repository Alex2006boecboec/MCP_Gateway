"""Tests for the cloud database layer (SQLite)."""
import json
import time

import pytest

from mcp_shield.cloud.db import Database
from mcp_shield.cloud.models import Event


@pytest.fixture
def db(tmp_path):
    d = Database(tmp_path / "test.db")
    yield d
    d.close()


def test_init_db_creates_tables(db):
    # If we can insert and query, the tables exist.
    org = db.create_org("Acme")
    assert org.id
    assert org.name == "Acme"


def test_create_and_get_org(db):
    org = db.create_org("Acme")
    fetched = db.get_org(org.id)
    assert fetched is not None
    assert fetched.name == "Acme"


def test_get_org_missing(db):
    assert db.get_org("nonexistent") is None


def test_create_and_get_user(db):
    org = db.create_org("Acme")
    u = db.create_user(org.id, "admin@acme.com", "hash123", "admin")
    assert u.email == "admin@acme.com"
    assert u.role == "admin"
    fetched = db.get_user_by_email("admin@acme.com")
    assert fetched is not None
    assert fetched.role == "admin"
    assert fetched.password_hash == "hash123"


def test_get_user_missing(db):
    assert db.get_user_by_email("nobody@nowhere.com") is None


def test_list_users_scoped_by_org(db):
    org_a = db.create_org("A")
    org_b = db.create_org("B")
    db.create_user(org_a.id, "a1@a.com", "h", "admin")
    db.create_user(org_a.id, "a2@a.com", "h", "viewer")
    db.create_user(org_b.id, "b1@b.com", "h", "admin")
    users_a = db.list_users(org_a.id)
    users_b = db.list_users(org_b.id)
    assert len(users_a) == 2
    assert len(users_b) == 1
    # Org A cannot see org B users.
    assert all(u.org_id == org_a.id for u in users_a)


def test_create_and_validate_api_key(db):
    org = db.create_org("Acme")
    key = db.create_api_key(org.id, "prod")
    assert key.key.startswith("mcp_live_")
    validated = db.validate_api_key(key.key)
    assert validated is not None
    assert validated.org_id == org.id


def test_validate_revoked_key(db):
    org = db.create_org("Acme")
    key = db.create_api_key(org.id, "prod")
    assert db.validate_api_key(key.key) is not None
    db.revoke_api_key(key.key)
    assert db.validate_api_key(key.key) is None


def test_validate_unknown_key(db):
    assert db.validate_api_key("mcp_live_nonexistent") is None


def test_list_api_keys_scoped(db):
    org_a = db.create_org("A")
    org_b = db.create_org("B")
    db.create_api_key(org_a.id, "k1")
    db.create_api_key(org_b.id, "k2")
    keys_a = db.list_api_keys(org_a.id)
    assert len(keys_a) == 1
    assert keys_a[0].label == "k1"


def test_insert_event(db):
    org = db.create_org("Acme")
    entry = {"seq": 1, "ts": "2026-01-01T00:00:00Z", "decision": "deny",
             "server": "fs", "tool": "exec", "args": {"cmd": "ls"},
             "reason": "blocked", "rule": "exec-rule"}
    inserted = db.insert_event(org.id, entry)
    assert inserted is True
    events = db.query_events(org.id)
    assert len(events) == 1
    assert events[0].decision == "deny"
    assert events[0].tool == "exec"
    assert events[0].args == {"cmd": "ls"}


def test_insert_event_idempotent(db):
    """Same (org, seq) twice -> one row."""
    org = db.create_org("Acme")
    entry = {"seq": 1, "ts": "2026-01-01T00:00:00Z", "decision": "deny",
             "server": "fs", "tool": "exec", "args": {}, "reason": "x", "rule": "r"}
    assert db.insert_event(org.id, entry) is True
    assert db.insert_event(org.id, entry) is False  # duplicate
    events = db.query_events(org.id)
    assert len(events) == 1


def test_query_events_cross_org_isolation(db):
    """Org A cannot see org B events."""
    org_a = db.create_org("A")
    org_b = db.create_org("B")
    db.insert_event(org_a.id, {"seq": 1, "ts": "t1", "decision": "deny", "server": "s", "tool": "t", "args": {}, "reason": "x", "rule": "r"})
    db.insert_event(org_b.id, {"seq": 1, "ts": "t1", "decision": "allow", "server": "s", "tool": "t", "args": {}, "reason": "x", "rule": "r"})
    events_a = db.query_events(org_a.id)
    events_b = db.query_events(org_b.id)
    assert len(events_a) == 1
    assert len(events_b) == 1
    assert events_a[0].org_id == org_a.id
    assert events_b[0].org_id == org_b.id


def test_query_events_filter_decision(db):
    org = db.create_org("Acme")
    db.insert_event(org.id, {"seq": 1, "ts": "t1", "decision": "deny", "server": "s", "tool": "t", "args": {}, "reason": "x", "rule": "r"})
    db.insert_event(org.id, {"seq": 2, "ts": "t2", "decision": "allow", "server": "s", "tool": "t", "args": {}, "reason": "x", "rule": "r"})
    denies = db.query_events(org.id, decision="deny")
    assert len(denies) == 1
    assert denies[0].decision == "deny"


def test_query_events_pagination(db):
    org = db.create_org("Acme")
    for i in range(60):
        db.insert_event(org.id, {"seq": i, "ts": "t", "decision": "allow", "server": "s", "tool": "t", "args": {}, "reason": "x", "rule": "r"})
    page1 = db.query_events(org.id, limit=50, offset=0)
    page2 = db.query_events(org.id, limit=50, offset=50)
    assert len(page1) == 50
    assert len(page2) == 10


def test_count_events(db):
    org = db.create_org("Acme")
    db.insert_event(org.id, {"seq": 1, "ts": "t", "decision": "deny", "server": "s", "tool": "t", "args": {}, "reason": "x", "rule": "r"})
    db.insert_event(org.id, {"seq": 2, "ts": "t", "decision": "allow", "server": "s", "tool": "t", "args": {}, "reason": "x", "rule": "r"})
    assert db.count_events(org.id) == 2
    assert db.count_events(org.id, decision="deny") == 1


def test_get_event(db):
    org = db.create_org("Acme")
    db.insert_event(org.id, {"seq": 1, "ts": "t", "decision": "deny", "server": "s", "tool": "exec", "args": {"cmd": "ls"}, "reason": "x", "rule": "r"})
    events = db.query_events(org.id)
    eid = events[0].id
    ev = db.get_event(org.id, eid)
    assert ev is not None
    assert ev.tool == "exec"
    # Cross-org: org B can't see org A's event.
    org_b = db.create_org("B")
    assert db.get_event(org_b.id, eid) is None


def test_summary(db):
    org = db.create_org("Acme")
    db.insert_event(org.id, {"seq": 1, "ts": "t", "decision": "deny", "server": "s", "tool": "t", "args": {}, "reason": "x", "rule": "r"})
    db.insert_event(org.id, {"seq": 2, "ts": "t", "decision": "allow", "server": "s", "tool": "t", "args": {}, "reason": "x", "rule": "r"})
    db.insert_event(org.id, {"seq": 3, "ts": "t", "decision": "deny", "server": "s", "tool": "t", "args": {}, "reason": "x", "rule": "r"})
    s = db.summary(org.id)
    assert s["total"] == 3
    assert s["deny"] == 2
    assert s["allow"] == 1


def test_summary_includes_all_decisions(db):
    """total must count approve/redact, not only allow+deny."""
    org = db.create_org("Acme")
    db.insert_event(org.id, {"seq": 1, "ts": "t", "decision": "deny", "server": "s", "tool": "t", "args": {}, "reason": "x", "rule": "r"})
    db.insert_event(org.id, {"seq": 2, "ts": "t", "decision": "allow", "server": "s", "tool": "t", "args": {}, "reason": "x", "rule": "r"})
    db.insert_event(org.id, {"seq": 3, "ts": "t", "decision": "approve", "server": "s", "tool": "t", "args": {}, "reason": "x", "rule": "r"})
    db.insert_event(org.id, {"seq": 4, "ts": "t", "decision": "redact", "server": "s", "tool": "t", "args": {}, "reason": "x", "rule": "r"})
    s = db.summary(org.id)
    assert s["total"] == 4
    assert s["deny"] == 1
    assert s["allow"] == 1
    assert s["approve"] == 1
    assert s["redact"] == 1


def test_multi_proxy_same_seq_accepted(db):
    """Two proxies under one org may both use seq=1."""
    org = db.create_org("Acme")
    assert db.insert_event(org.id, {"seq": 1, "proxy_id": "proxy-a", "ts": "t", "decision": "allow", "server": "s", "tool": "t", "args": {}, "reason": "x", "rule": "r"})
    assert db.insert_event(org.id, {"seq": 1, "proxy_id": "proxy-b", "ts": "t", "decision": "deny", "server": "s", "tool": "t", "args": {}, "reason": "x", "rule": "r"})
    assert db.count_events(org.id) == 2
    # Same proxy + seq is still a duplicate.
    assert not db.insert_event(org.id, {"seq": 1, "proxy_id": "proxy-a", "ts": "t", "decision": "allow", "server": "s", "tool": "t", "args": {}, "reason": "x", "rule": "r"})


def test_event_with_detection_chain_approval(db):
    """An event with Phase 2-4 fields round-trips through the DB."""
    org = db.create_org("Acme")
    entry = {
        "seq": 1, "ts": "2026-01-01T00:00:00Z", "decision": "deny",
        "server": "fs", "tool": "exec", "args": {"cmd": "[REDACTED]"},
        "reason": "chain blocked", "rule": "capability-graph",
        "detection": {"score": 0.9, "verdict": "blocked"},
        "chain": {"source_tool": "read_file", "sink_tool": "exec", "rule_name": "secret-to-exec"},
        "approval": {"outcome": "deny", "by": "alice"},
    }
    db.insert_event(org.id, entry)
    ev = db.query_events(org.id)[0]
    assert ev.detection == {"score": 0.9, "verdict": "blocked"}
    assert ev.chain["rule_name"] == "secret-to-exec"
    assert ev.approval["outcome"] == "deny"


def test_secrets_redacted_in_db(db):
    """A raw secret must NOT appear in the DB; only [REDACTED:] markers."""
    org = db.create_org("Acme")
    db.insert_event(org.id, {
        "seq": 1, "ts": "t", "decision": "allow", "server": "s", "tool": "t",
        "args": {"key": "[REDACTED:aws_access_key_id]"}, "reason": "x", "rule": "r",
    })
    ev = db.get_event(org.id, 1) or db.query_events(org.id)[0]
    assert "[REDACTED:" in ev.args["key"]
    assert "AKIA" not in ev.args["key"]
