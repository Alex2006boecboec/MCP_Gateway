"""Tests for Stage 7: TLS verification, local spool, graceful shutdown."""

from __future__ import annotations

import json
import os
import tempfile
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

import pytest

from mcp_shield.shipper import CloudShipper, CloudShipperConfig


class _CloudMockHandler(BaseHTTPRequestHandler):
    received_batches = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        data = json.loads(body)
        entries = data.get("entries", [])
        _CloudMockHandler.received_batches.append(entries)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"accepted": len(entries)}).encode())

    def log_message(self, *args):
        pass


@pytest.fixture
def cloud_server():
    _CloudMockHandler.received_batches = []
    server = HTTPServer(("127.0.0.1", 0), _CloudMockHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def _entry(seq=1):
    return {"seq": seq, "ts": "2026-01-01T00:00:00Z", "decision": "deny",
            "server": "fs", "tool": "exec", "args": {}, "reason": "x", "rule": "r"}


# ----------------------------------------------------------- TLS verification


class TestTLSVerification:
    def test_http_rejected_by_default(self, cloud_server):
        """http:// URLs are rejected by default (TLS required)."""
        cfg = CloudShipperConfig(enabled=True, url=cloud_server, api_key="key")
        s = CloudShipper(cfg)
        assert not s.is_enabled()  # disabled by TLS validation

    def test_http_allowed_with_flag(self, cloud_server):
        """http:// URLs allowed when allow_http=True."""
        cfg = CloudShipperConfig(enabled=True, url=cloud_server, api_key="key",
                                  allow_http=True)
        s = CloudShipper(cfg)
        assert s.is_enabled()

    def test_http_allowed_with_env(self, cloud_server, monkeypatch):
        """http:// URLs allowed when MCP_SHIELD_ALLOW_HTTP_CLOUD=1."""
        monkeypatch.setenv("MCP_SHIELD_ALLOW_HTTP_CLOUD", "1")
        cfg = CloudShipperConfig(enabled=True, url=cloud_server, api_key="key")
        s = CloudShipper(cfg)
        assert s.is_enabled()


# ----------------------------------------------------------- Local spool


class TestLocalSpool:
    def test_spool_on_failure(self, tmp_path):
        """Events are spooled to disk when cloud is unreachable."""
        cfg = CloudShipperConfig(
            enabled=True,
            url="http://127.0.0.1:1",  # unreachable
            api_key="key",
            max_retries=1,
            timeout=1,
            allow_http=True,
            spool_dir=str(tmp_path),
        )
        s = CloudShipper(cfg)
        s.ship(_entry(1))
        s.ship(_entry(2))
        s.flush()
        # Check spool files exist.
        spool_dir = tmp_path / "spool"
        spool_files = list(spool_dir.glob("pending_*.jsonl"))
        assert len(spool_files) >= 1
        # Check content.
        all_events = []
        for f in spool_files:
            for line in f.read_text().strip().split("\n"):
                if line:
                    all_events.append(json.loads(line))
        assert len(all_events) >= 2

    def test_spool_retry_succeeds(self, tmp_path, cloud_server):
        """Spooled events are retried and sent when cloud becomes available."""
        cfg = CloudShipperConfig(
            enabled=True,
            url="http://127.0.0.1:1",  # initially unreachable
            api_key="key",
            max_retries=1,
            timeout=1,
            allow_http=True,
            spool_dir=str(tmp_path),
        )
        s = CloudShipper(cfg)
        s.ship(_entry(1))
        s.flush()
        # Spool file exists.
        spool_dir = tmp_path / "spool"
        assert len(list(spool_dir.glob("pending_*.jsonl"))) >= 1
        # Now point to the working server and retry.
        s.config.url = cloud_server
        s._retry_spooled()
        # Spool files should be deleted after successful send.
        assert len(list(spool_dir.glob("pending_*.jsonl"))) == 0
        assert len(_CloudMockHandler.received_batches) >= 1

    def test_no_spool_dir_events_lost(self):
        """Without spool_dir, unsent events are lost (logged)."""
        cfg = CloudShipperConfig(
            enabled=True,
            url="http://127.0.0.1:1",
            api_key="key",
            max_retries=1,
            timeout=1,
            allow_http=True,
        )
        s = CloudShipper(cfg)
        s.ship(_entry(1))
        sent = s.flush()
        assert sent == 0  # no crash, events lost


# ----------------------------------------------------------- Graceful shutdown


class TestGracefulShutdown:
    def test_shutdown_flushes(self, cloud_server):
        """shutdown() flushes remaining events."""
        cfg = CloudShipperConfig(
            enabled=True, url=cloud_server, api_key="key",
            batch_size=100, flush_interval=999, allow_http=True,
        )
        s = CloudShipper(cfg)
        s.ship(_entry(1))
        s.ship(_entry(2))
        s.shutdown()
        assert len(_CloudMockHandler.received_batches) >= 1
