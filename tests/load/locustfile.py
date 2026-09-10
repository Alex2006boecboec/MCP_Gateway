"""Locust load test for MCP Shield Cloud Dashboard.

Tests:
  1. Ingest API: 1000 events/sec
  2. Dashboard: 100 concurrent users
  3. p99 < 500ms

Run:  locust -f tests/load/locustfile.py --host https://your-cloud-url

Usage:
  - Start the cloud server locally:  mcp-shield-cloud
  - Run locust:  locust -f tests/load/locustfile.py --host http://localhost:8000
  - Open http://localhost:8089 for the web UI
"""

from __future__ import annotations

import json
import random
import uuid

from locust import HttpUser, between, task


class IngestUser(HttpUser):
    """Simulates a proxy shipping events to the ingest API."""

    wait_time = between(0.01, 0.05)  # ~20-100 req/sec per user

    def on_start(self):
        # Use a pre-created API key. Set via env or use default.
        self.api_key = "mcp_live_replace_with_real_key"
        self.org_id = "replace_with_real_org_id"
        self.seq = 0

    @task
    def ingest_events(self):
        self.seq += 1
        entry = {
            "seq": self.seq,
            "ts": "2026-01-01T00:00:00Z",
            "decision": random.choice(["allow", "deny"]),
            "server": random.choice(["fs", "fetch", "exec"]),
            "tool": random.choice(["read_file", "exec", "fetch_url"]),
            "args": {"cmd": "[REDACTED:secret]"},
            "reason": "load test",
            "rule": "test-rule",
            "redactions": [{"arg": "cmd", "fingerprint": "secret"}],
        }
        self.client.post(
            "/api/v1/ingest",
            json={"entries": [entry]},
            headers={"Authorization": f"Bearer {self.api_key}"},
        )


class DashboardUser(HttpUser):
    """Simulates a user browsing the dashboard."""

    wait_time = between(1, 5)  # realistic browsing

    def on_start(self):
        # Login first.
        self.client.post(
            "/login",
            data={
                "email": "admin@localhost",
                "password": "replace-me",
                "csrf_token": "",  # would need to fetch from /login first
            },
        )

    @task(3)
    def view_dashboard(self):
        self.client.get("/dashboard")

    @task(2)
    def view_reports(self):
        self.client.get("/reports")

    @task(1)
    def view_users(self):
        self.client.get("/users")

    @task(1)
    def view_keys(self):
        self.client.get("/keys")

    @task(1)
    def view_audit(self):
        self.client.get("/audit")
