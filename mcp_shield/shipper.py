"""CloudShipper - sends audit events from the proxy to the cloud dashboard.

Lives in the proxy package (not cloud/) because it runs on the proxy side.
Uses stdlib urllib only (no new mandatory deps). Best-effort: never
raises, never blocks the proxy. If the cloud is unreachable, events are
spooled to disk and retried.

Design:
  - Batches events in memory, flushes every `flush_interval` or when
    `batch_size` is reached.
  - Retries with exponential backoff (max 3 attempts).
  - On failure, events are spooled to disk (spool/pending_*.jsonl).
  - Background thread retries spooled events.
  - TLS verification: rejects http:// by default (env MCP_SHIELD_ALLOW_HTTP_CLOUD=1
    to allow for dev). Custom CA cert via ca_cert_path.
  - Idempotent: the cloud DB dedupes on (org_id, seq).
  - Thread-safe (a lock guards the buffer).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
import ssl
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("mcp_shield.shipper")

# Spool limits.
_SPOOL_MAX_BYTES = 100 * 1024 * 1024  # 100MB
_SPOOL_DIR_NAME = "spool"


class CloudShipperConfig:
    """Configuration for the cloud shipper."""

    def __init__(
        self,
        *,
        enabled: bool = False,
        url: str = "",
        api_key: str = "",
        org_id: str = "",
        batch_size: int = 20,
        flush_interval: float = 5.0,
        timeout: float = 5.0,
        max_retries: int = 3,
        ca_cert_path: str = "",
        allow_http: bool = False,
        spool_dir: str = "",
    ):
        self.enabled = enabled
        self.url = url.rstrip("/") if url else ""
        self.api_key = api_key
        self.org_id = org_id
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.timeout = timeout
        self.max_retries = max_retries
        self.ca_cert_path = ca_cert_path
        self.allow_http = allow_http or os.environ.get("MCP_SHIELD_ALLOW_HTTP_CLOUD", "") == "1"
        self.spool_dir = spool_dir


class CloudShipper:
    """Batches and ships audit events to the cloud dashboard."""

    def __init__(self, config: CloudShipperConfig):
        self.config = config
        self._buffer: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._last_flush = time.time()
        self._spool_dir: Optional[Path] = None
        self._spool_thread: Optional[threading.Thread] = None
        self._shutdown = False

        # Validate TLS.
        self._validate_tls()

        # Setup spool directory.
        if config.spool_dir:
            self._spool_dir = Path(config.spool_dir) / _SPOOL_DIR_NAME
            self._spool_dir.mkdir(parents=True, exist_ok=True)
            self._start_spool_thread()

    def _validate_tls(self) -> None:
        """Validate that the cloud URL uses HTTPS (unless allow_http)."""
        if not self.config.url:
            return
        if self.config.url.startswith("http://") and not self.config.allow_http:
            logger.error(
                "shipper: cloud URL uses http:// (insecure). "
                "Set MCP_SHIELD_ALLOW_HTTP_CLOUD=1 to allow for dev."
            )
            # Disable shipping — don't silently send over plaintext.
            self.config.enabled = False

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create an SSL context for TLS verification."""
        if self.config.ca_cert_path:
            ctx = ssl.create_default_context(cafile=self.config.ca_cert_path)
        else:
            ctx = ssl.create_default_context()
        return ctx

    def is_enabled(self) -> bool:
        return self.config.enabled and bool(self.config.url) and bool(self.config.api_key)

    def ship(self, entry: dict[str, Any]) -> None:
        """Add an audit entry to the buffer. Flushes if batch is full."""
        if not self.is_enabled():
            return
        with self._lock:
            self._buffer.append(entry)
            should_flush = (
                len(self._buffer) >= self.config.batch_size
                or (time.time() - self._last_flush) >= self.config.flush_interval
            )
        if should_flush:
            self.flush()

    def flush(self) -> int:
        """Send all buffered events to the cloud. Returns number sent.
        Never raises — logs warnings on failure."""
        if not self.is_enabled():
            return 0
        with self._lock:
            batch = self._buffer[:]
            self._buffer.clear()
            self._last_flush = time.time()
        if not batch:
            return 0
        sent = self._send_batch(batch)
        if sent < len(batch):
            # Spool unsent events to disk.
            unsent = batch[sent:]
            self._spool_events(unsent)
            logger.warning("shipper: sent %d/%d events, spooled %d", sent, len(batch), len(unsent))
        return sent

    def _send_batch(self, batch: list[dict[str, Any]]) -> int:
        """Send a batch to the cloud. Returns number of events confirmed sent."""
        url = f"{self.config.url}/api/v1/ingest"
        body = json.dumps({"entries": batch}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.api_key}",
        }
        ssl_ctx = None
        if url.startswith("https://"):
            ssl_ctx = self._create_ssl_context()

        for attempt in range(1, self.config.max_retries + 1):
            try:
                req = urllib.request.Request(url, data=body, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=self.config.timeout, context=ssl_ctx) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        return data.get("accepted", len(batch))
                    logger.warning("shipper: HTTP %d from cloud", resp.status)
                    return 0
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    logger.error("shipper: auth error (%d), not retrying", e.code)
                    return 0
                if e.code == 429:
                    logger.warning("shipper: rate limited, will retry")
                else:
                    logger.warning("shipper: HTTP %d on attempt %d", e.code, attempt)
            except (urllib.error.URLError, OSError, TimeoutError) as e:
                logger.warning("shipper: network error on attempt %d: %s", attempt, e)
            if attempt < self.config.max_retries:
                time.sleep(0.5 * (2 ** (attempt - 1)))
        logger.error("shipper: failed after %d attempts, spooling %d events", self.config.max_retries, len(batch))
        return 0

    # ----------------------------------------------------------- spool

    def _spool_events(self, events: list[dict[str, Any]]) -> None:
        """Write unsent events to spool directory for later retry."""
        if self._spool_dir is None:
            # No spool dir configured — events are lost.
            logger.error("shipper: no spool dir, %d events lost", len(events))
            return
        # Check spool size limit.
        try:
            spool_size = sum(f.stat().st_size for f in self._spool_dir.glob("pending_*.jsonl"))
        except OSError:
            spool_size = 0
        if spool_size >= _SPOOL_MAX_BYTES:
            logger.error("shipper: spool full (%d bytes), %d events lost", spool_size, len(events))
            return
        # Write to a timestamped file.
        filename = self._spool_dir / f"pending_{int(time.time() * 1000)}.jsonl"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                for event in events:
                    f.write(json.dumps(event, ensure_ascii=False) + "\n")
            logger.info("shipper: spooled %d events to %s", len(events), filename.name)
        except OSError as e:
            logger.error("shipper: failed to spool: %s", e)

    def _start_spool_thread(self) -> None:
        """Start a background thread that retries spooled events."""
        if self._spool_thread is not None:
            return

        def _retry_loop():
            while not self._shutdown:
                try:
                    self._retry_spooled()
                except Exception as e:
                    logger.error("shipper: spool retry error: %s", e)
                time.sleep(30)  # retry every 30 seconds

        self._spool_thread = threading.Thread(target=_retry_loop, daemon=True, name="shipper-spool")
        self._spool_thread.start()

    def _retry_spooled(self) -> None:
        """Read spooled events and try to send them."""
        if self._spool_dir is None or not self.is_enabled():
            return
        for spool_file in sorted(self._spool_dir.glob("pending_*.jsonl")):
            try:
                events = []
                with open(spool_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            events.append(json.loads(line))
                if not events:
                    spool_file.unlink()
                    continue
                sent = self._send_batch(events)
                if sent >= len(events):
                    spool_file.unlink()
                    logger.info("shipper: spool %s sent and deleted (%d events)", spool_file.name, sent)
                else:
                    logger.warning("shipper: spool %s partial send (%d/%d)", spool_file.name, sent, len(events))
            except Exception as e:
                logger.error("shipper: error reading spool %s: %s", spool_file, e)
                break  # don't process more files this cycle

    def shutdown(self) -> None:
        """Graceful shutdown: flush remaining events, spool unsent."""
        self._shutdown = True
        self.flush()
        logger.info("shipper: shutdown complete")
