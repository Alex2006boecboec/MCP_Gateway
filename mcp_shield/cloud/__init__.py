"""MCP Shield Cloud Dashboard (Phase 5).

Multi-tenant SaaS dashboard with RBAC, SSO-ready auth, compliance reports,
and a proxy-to-cloud audit event shipper.

Public API:
  - create_app()  - build the FastAPI app (for tests / embedding)
  - Database      - SQLite store
  - SessionManager - signed session cookies
  - generate_report() - compliance report generator
"""

from mcp_shield.cloud.auth import SessionManager, hash_password, verify_password
from mcp_shield.cloud.db import SqliteStorage
from mcp_shield.cloud.models import ApiKey, Event, Org, User
from mcp_shield.cloud.passwords import is_strong_password, validate_password
from mcp_shield.cloud.rbac import can, is_valid_role
from mcp_shield.cloud.reports import FRAMEWORKS, generate_report, report_to_csv
from mcp_shield.cloud.storage import Storage
from mcp_shield.cloud.storage_factory import create_storage

# Lazy imports for create_app/main — importing server here breaks
# `python -m mcp_shield.cloud.server` (RuntimeWarning: module already in sys.modules).


def create_app(*args, **kwargs):
    from mcp_shield.cloud.server import create_app as _create_app
    return _create_app(*args, **kwargs)


def main(*args, **kwargs):
    from mcp_shield.cloud.server import main as _main
    return _main(*args, **kwargs)


__all__ = [
    "create_app",
    "create_storage",
    "main",
    "SqliteStorage",
    "Storage",
    "SessionManager",
    "hash_password",
    "verify_password",
    "can",
    "is_valid_role",
    "generate_report",
    "report_to_csv",
    "FRAMEWORKS",
    "validate_password",
    "is_strong_password",
    "Org",
    "User",
    "ApiKey",
    "Event",
]
