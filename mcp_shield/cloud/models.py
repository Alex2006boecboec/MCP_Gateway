"""Data models for the cloud dashboard (Phase 5).

Pure dataclasses — no DB or framework deps. Imported by db.py, api_ingest.py,
reports.py, dashboard.py. Kept separate to avoid circular imports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Org:
    """A tenant (organization). One per customer."""
    id: str
    name: str
    created_at: float
    plan: str = "free"  # "free" | "pro" | "business" | "enterprise"


@dataclass
class User:
    """A dashboard login user. Belongs to an org. Has a role."""
    id: str
    org_id: str
    email: str
    role: str        # "admin" | "analyst" | "viewer"
    created_at: float
    password_hash: Optional[str] = None   # None for SSO-only users
    token_version: int = 0               # increment to invalidate sessions
    must_change_password: bool = False    # force password change on next login
    deleted: bool = False                # soft delete


@dataclass
class ApiKey:
    """A machine credential for the proxy shipper. Identifies the org."""
    key: str
    org_id: str
    label: str
    created_at: float
    revoked: bool = False
    scopes: list[str] = field(default_factory=lambda: ["ingest"])  # ["ingest"] | ["read"] | both
    allowed_ips: list[str] = field(default_factory=list)  # empty = no restriction


@dataclass
class Event:
    """An audit event shipped from a proxy. Mirrors the JSONL AuditEntry."""
    id: int
    org_id: str
    seq: int
    ts: str
    decision: str
    server: str
    tool: str
    args: dict[str, Any]
    reason: str
    rule: str
    redactions: list[dict[str, Any]] = field(default_factory=list)
    detection: Optional[dict[str, Any]] = None
    chain: Optional[dict[str, Any]] = None
    approval: Optional[dict[str, Any]] = None
    received_at: float = 0.0
