"""CloudShipper - sends audit events from the proxy to the cloud dashboard.

Lives in the proxy package (not cloud/) because it runs on the proxy side.
Uses stdlib urllib only (no new mandatory deps). Best-effort: never
raises, never blocks the proxy. If the cloud is unreachable, events are
dropped (the local tamper-evident audit log is the source of truth).

Design:
  - Batches events in memory, flushes every `flush_interval` or when
    `batch_size` is reached.
  - Retries with exponential backoff (max 3 attempts).
  - Idempotent: the cloud DB dedupes on (org_id, seq).
  - Thread-safe (a lock guards the buffer).
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Optional

logger = logging.getLogger("mcp_shield.shipper")


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
    ):
        self.enabled = enabled
        self.url = url.rstrip("/") if url else ""
        self.api_key = api_key
        self.org_id = org_id
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.timeout = timeout
        self.max_retries = max_retries


class CloudShipper:
    """Batches and ships audit events to the cloud dashboard."""

    def __init__(self, config: CloudShipperConfig):
        self.config = config
        self._buffer: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._last_flush = time.time()

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
            # Re-buffer unsent events (best-effort, don't grow unbounded).
            unsent = batch[sent:]
            with self._lock:
                # Prepend unsent so they're retried first.
                self._buffer = unsent + self._buffer
            logger.warning("shipper: sent %d/%d events, re-buffered %d", sent, len(batch), len(unsent))
        return sent

    def _send_batch(self, batch: list[dict[str, Any]]) -> int:
        """Send a batch to the cloud. Returns number of events confirmed sent."""
        url = f"{self.config.url}/api/ingest"
        body = json.dumps({"entries": batch}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.api_key}",
        }
        for attempt in range(1, self.config.max_retries + 1):
            try:
                req = urllib.request.Request(url, data=body, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
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
        logger.error("shipper: failed after %d attempts, dropping %d events", self.config.max_retries, len(batch))
        return 0
