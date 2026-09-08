"""MCP Shield — security gateway for the Model Context Protocol.

Intercepts AI agent tool calls, enforces policy, detects prompt injection,
redacts secrets, and writes a tamper-evident audit log.

Public API:
    from mcp_shield import Proxy, Policy, AuditLogger, SecretRedactor
"""

from mcp_shield.proxy import Proxy
from mcp_shield.policy import Policy, PolicyEngine, load_policy
from mcp_shield.redactor import SecretRedactor
from mcp_shield.audit import AuditLogger, AuditEntry

__version__ = "0.1.0"
__all__ = [
    "Proxy",
    "Policy",
    "PolicyEngine",
    "load_policy",
    "SecretRedactor",
    "AuditLogger",
    "AuditEntry",
]
