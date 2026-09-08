"""Tamper-evident audit log — every proxy decision is recorded.

The audit log is a JSONL file where each line is one decision. To make
the log tamper-evident (not tamper-proof — we rely on filesystem
permissions for that), each entry contains the SHA-256 of the previous
entry. Deleting or modifying an entry breaks the chain.

Entry shape:
    {
      "seq": 1,
      "ts": "2026-09-09T00:00:00Z",
      "decision": "deny",
      "server": "fetch",
      "tool": "fetch_url",
      "args": {"url": "http://169.254.169.254/..."},   # already redacted
      "reason": "internal URL blocked in arg 'url'",
      "rule": "url-validator",
      "prev_hash": "0000...0000",                    # all zeros for the first entry
      "this_hash": "a3f1...c2b9"                     # sha256(prev_hash || canonical(entry))
    }

Secrets are NEVER written to the log — the redactor runs before audit.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional


ZERO_HASH = "0" * 64


@dataclass
class AuditEntry:
    seq: int
    ts: str
    decision: str            # "allow" | "deny" | "redact" | "approve"
    server: str
    tool: str
    args: dict[str, Any]    # already redacted
    reason: str
    rule: str
    redactions: list[dict[str, str]] = field(default_factory=list)
    detection: Optional[dict[str, Any]] = None   # Phase 2: detector signals
    chain: Optional[dict[str, Any]] = None       # Phase 3: detected chain
    prev_hash: str = ZERO_HASH
    this_hash: str = ""

    def canonical_bytes(self) -> bytes:
        """Stable serialization for hashing — fields excluded from the hash
        are `this_hash` (it IS the hash) and `prev_hash` (chained separately)."""
        d = asdict(self)
        d.pop("this_hash", None)
        # Keep prev_hash IN the hash input so the chain is unbreakable.
        return json.dumps(d, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def compute_hash(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


class AuditLogger:
    """Append-only JSONL audit log with hash chaining."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._seq = 0
        self._prev_hash = ZERO_HASH
        # If the log exists, resume the chain from the last entry.
        self._resume()

    def _resume(self) -> None:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self._seq = int(entry.get("seq", self._seq))
                self._prev_hash = entry.get("this_hash", ZERO_HASH)

    def log(
        self,
        *,
        decision: str,
        server: str,
        tool: str,
        args: dict[str, Any],
        reason: str,
        rule: str,
        redactions: list[dict[str, str]] | None = None,
        detection: Optional[dict[str, Any]] = None,
        chain: Optional[dict[str, Any]] = None,
    ) -> AuditEntry:
        entry = AuditEntry(
            seq=self._seq + 1,
            ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            decision=decision,
            server=server,
            tool=tool,
            args=args,
            reason=reason,
            rule=rule,
            redactions=redactions or [],
            detection=detection,
            chain=chain,
            prev_hash=self._prev_hash,
        )
        entry.this_hash = entry.compute_hash()
        self._append(entry)
        self._seq = entry.seq
        self._prev_hash = entry.this_hash
        return entry

    def _append(self, entry: AuditEntry) -> None:
        # Ensure parent dir exists; do not leak the file to other users.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(asdict(entry), ensure_ascii=False, separators=(",", ":"))
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass  # best effort on Windows

    def verify(self) -> bool:
        """Verify the hash chain of the existing log. Returns True if intact."""
        if not self.path.exists():
            return True
        prev = ZERO_HASH
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False
                this_hash = entry.pop("this_hash", None)
                # Reconstruct entry to recompute the hash.
                tmp = AuditEntry(**entry)
                if tmp.compute_hash() != this_hash:
                    return False
                if tmp.prev_hash != prev:
                    return False
                prev = this_hash
        return True
