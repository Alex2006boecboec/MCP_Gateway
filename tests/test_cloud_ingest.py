"""Tests for the ingest API (POST /api/ingest)."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_shield.cloud.api_ingest import router
from mcp_shield.cloud.db import Database


@pytest.fixture
def client(tmp_path):
    db = Database(tmp_path / "test.db")
    org = db.create_org("Acme")
    key = db.create_api_key(org.id, "prod")
    app = FastAPI()
    app.include_router(router)
    app.state.db = db
    client = TestClient(app)
    yield client, db, org, key
    db.close()


def _entry(seq=1, decision="deny"):
    return {
        "seq": seq, "ts": "2026-01-01T00:00:00Z", "decision": decision,
        "server": "fs", "tool": "exec", "args": {"cmd": "ls"},
        "reason": "blocked", "rule": "exec-rule",
    }


def test_ingest_success(client):
    c, db, org, key = client
    resp = c.post("/api/ingest", json={"entries": [_entry()]},
                   headers={"Authorization": f"Bearer {key.key}"})
    assert resp.status_code == 200
    assert resp.json()["accepted"] == 1


def test_ingest_bad_key(client):
    c, db, org, key = client
    resp = c.post("/api/ingest", json={"entries": [_entry()]},
                   headers={"Authorization": "Bearer mcp_live_badkey"})
    assert resp.status_code == 401


def test_ingest_revoked_key(client):
    c, db, org, key = client
    db.revoke_api_key(key.key)
    resp = c.post("/api/ingest", json={"entries": [_entry()]},
                   headers={"Authorization": f"Bearer {key.key}"})
    assert resp.status_code == 401


def test_ingest_no_auth(client):
    c, db, org, key = client
    resp = c.post("/api/ingest", json={"entries": [_entry()]})
    assert resp.status_code == 401


def test_ingest_idempotent(client):
    """Same seq twice -> one accepted on second call."""
    c, db, org, key = client
    resp1 = c.post("/api/ingest", json={"entries": [_entry(seq=1)]},
                    headers={"Authorization": f"Bearer {key.key}"})
    resp2 = c.post("/api/ingest", json={"entries": [_entry(seq=1)]},
                    headers={"Authorization": f"Bearer {key.key}"})
    assert resp1.json()["accepted"] == 1
    assert resp2.json()["accepted"] == 0  # duplicate


def test_ingest_large_batch_rejected(client):
    c, db, org, key = client
    entries = [_entry(seq=i) for i in range(101)]
    resp = c.post("/api/ingest", json={"entries": entries},
                   headers={"Authorization": f"Bearer {key.key}"})
    assert resp.status_code == 413


def test_ingest_bad_body(client):
    c, db, org, key = client
    resp = c.post("/api/ingest", json={"not_entries": []},
                   headers={"Authorization": f"Bearer {key.key}"})
    assert resp.status_code == 400


def test_ingest_secrets_redacted(client):
    """An event with [REDACTED:] is stored as-is (no raw secret)."""
    c, db, org, key = client
    entry = _entry()
    entry["args"] = {"key": "[REDACTED:aws_access_key_id]"}
    resp = c.post("/api/ingest", json={"entries": [entry]},
                   headers={"Authorization": f"Bearer {key.key}"})
    assert resp.status_code == 200
    events = db.query_events(org.id)
    assert "[REDACTED:" in events[0].args["key"]
    assert "AKIA" not in events[0].args["key"]


def test_ingest_cross_org_isolation(client):
    """Org A's key cannot write to org B."""
    c, db, org_a, key_a = client
    org_b = db.create_org("B")
    # Ingest with org A's key -> stored under org A.
    c.post("/api/ingest", json={"entries": [_entry(seq=1)]},
            headers={"Authorization": f"Bearer {key_a.key}"})
    # Org B sees zero events.
    assert db.count_events(org_b.id) == 0
    assert db.count_events(org_a.id) == 1


def test_ingest_multiple_entries(client):
    c, db, org, key = client
    entries = [_entry(seq=i) for i in range(5)]
    resp = c.post("/api/ingest", json={"entries": entries},
                   headers={"Authorization": f"Bearer {key.key}"})
    assert resp.status_code == 200
    assert resp.json()["accepted"] == 5
    assert db.count_events(org.id) == 5
