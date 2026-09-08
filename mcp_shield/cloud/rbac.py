"""Role-Based Access Control for the cloud dashboard (Phase 5).

Three roles per org: admin, analyst, viewer. Unknown roles are denied by
default (fail-closed). Enforced in every dashboard route via a dependency.
"""

from __future__ import annotations

# All recognized actions.
ACTIONS = {
    "view_events",
    "manage_users",
    "manage_keys",
    "view_reports",
    "manage_org",
}

# role -> set of allowed actions.
_PERMISSIONS: dict[str, set[str]] = {
    "admin": {
        "view_events", "manage_users", "manage_keys",
        "view_reports", "manage_org",
    },
    "analyst": {
        "view_events", "view_reports",
    },
    "viewer": {
        "view_events",
    },
}


def can(role: str, action: str) -> bool:
    """Return True if `role` may perform `action`.

    Unknown roles are denied by default (fail-closed). Unknown actions are
    also denied (typo protection).
    """
    if action not in ACTIONS:
        return False
    return action in _PERMISSIONS.get(role, set())


def is_valid_role(role: str) -> bool:
    """Return True if `role` is a recognized role."""
    return role in _PERMISSIONS
