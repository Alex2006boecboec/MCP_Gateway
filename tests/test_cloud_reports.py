"""Tests for compliance report generators."""
import pytest

from mcp_shield.cloud.db import Database
from mcp_shield.cloud.reports import generate_report, report_to_csv, FRAMEWORKS


@pytest.fixture
def db_with_events(tmp_path):
    db = Database(tmp_path / "test.db")
    org = db.create_org("Acme")
    # Insert a mix of events.
    db.insert_event(org.id, {"seq": 1, "ts": "2026-01-01T00:00:00Z", "decision": "allow",
                             "server": "fs", "tool": "read_file", "args": {}, "reason": "x", "rule": "r"})
    db.insert_event(org.id, {"seq": 2, "ts": "2026-01-02T00:00:00Z", "decision": "deny",
                             "server": "fs", "tool": "exec", "args": {}, "reason": "blocked", "rule": "exec-rule"})
    db.insert_event(org.id, {"seq": 3, "ts": "2026-01-03T00:00:00Z", "decision": "deny",
                             "server": "fetch", "tool": "fetch_url", "args": {}, "reason": "injection",
                             "rule": "injection-detector",
                             "detection": {"score": 0.95, "verdict": "blocked"}})
    db.insert_event(org.id, {"seq": 4, "ts": "2026-01-04T00:00:00Z", "decision": "deny",
                             "server": "fs", "tool": "exec", "args": {}, "reason": "chain",
                             "rule": "capability-graph",
                             "chain": {"source_tool": "read_file", "sink_tool": "exec", "sink_capability": "exec:command"}})
    db.insert_event(org.id, {"seq": 5, "ts": "2026-01-05T00:00:00Z", "decision": "deny",
                             "server": "fetch", "tool": "http_request", "args": {}, "reason": "approval",
                             "rule": "approval",
                             "approval": {"outcome": "deny", "by": "alice"}})
    yield db, org
    db.close()


def test_soc2_summary(db_with_events):
    db, org = db_with_events
    r = generate_report(db, org.id, "soc2")
    assert r["framework"] == "soc2"
    assert r["title"] == "SOC2 Security Report"
    cards = {c["label"]: c["value"] for c in r["summary_cards"]}
    assert cards["Total calls"] == 5
    assert cards["Denied"] == 4
    assert cards["Injections blocked"] == 1
    assert cards["Chains blocked"] == 1
    assert cards["Approvals"] == 1


def test_iso27001_summary(db_with_events):
    db, org = db_with_events
    r = generate_report(db, org.id, "iso27001")
    assert r["framework"] == "iso27001"
    # At least one control has a count.
    controls_row = r["rows"][0]
    assert controls_row["category"] == "Annex A controls"
    assert any(count > 0 for _, count in controls_row["items"])


def test_152fz_summary(db_with_events):
    db, org = db_with_events
    r = generate_report(db, org.id, "152fz")
    assert r["framework"] == "152fz"
    cards = {c["label"]: c["value"] for c in r["summary_cards"]}
    assert cards["PII exfiltration chains"] == 0  # no network:send chains in test data
    assert cards["Approvals"] == 1


def test_csv_output(db_with_events):
    db, org = db_with_events
    r = generate_report(db, org.id, "soc2")
    csv = report_to_csv(r)
    assert "SOC2 Security Report" in csv
    assert "Total calls,5" in csv
    assert "Denied,4" in csv


def test_empty_period(tmp_path):
    """No events -> zero counts (not error)."""
    db = Database(tmp_path / "test.db")
    org = db.create_org("Acme")
    r = generate_report(db, org.id, "soc2")
    cards = {c["label"]: c["value"] for c in r["summary_cards"]}
    assert cards["Total calls"] == 0
    db.close()


def test_unknown_framework(db_with_events):
    db, org = db_with_events
    with pytest.raises(ValueError):
        generate_report(db, org.id, "unknown")


def test_date_range_filter(db_with_events):
    db, org = db_with_events
    r = generate_report(db, org.id, "soc2", start="2026-01-02T00:00:00Z", end="2026-01-03T23:59:59Z")
    cards = {c["label"]: c["value"] for c in r["summary_cards"]}
    # Only events on Jan 2 and Jan 3 (seq 2 and 3).
    assert cards["Total calls"] == 2


def test_all_frameworks_recognized():
    assert "soc2" in FRAMEWORKS
    assert "iso27001" in FRAMEWORKS
    assert "152fz" in FRAMEWORKS
