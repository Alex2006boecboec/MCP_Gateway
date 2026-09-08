"""Tests for RBAC."""
from mcp_shield.cloud.rbac import can, is_valid_role, ACTIONS


def test_admin_can_all():
    for action in ACTIONS:
        assert can("admin", action), f"admin should allow {action}"


def test_analyst_can_view_not_manage():
    assert can("analyst", "view_events")
    assert can("analyst", "view_reports")
    assert not can("analyst", "manage_users")
    assert not can("analyst", "manage_keys")
    assert not can("analyst", "manage_org")


def test_viewer_only_view_events():
    assert can("viewer", "view_events")
    assert not can("viewer", "view_reports")
    assert not can("viewer", "manage_users")
    assert not can("viewer", "manage_keys")
    assert not can("viewer", "manage_org")


def test_unknown_role_denied():
    """Unknown role -> all actions denied (fail-closed)."""
    assert not can("superuser", "view_events")
    assert not can("superuser", "manage_org")


def test_unknown_action_denied():
    """Unknown action -> denied (typo protection)."""
    assert not can("admin", "delete_everything")
    assert not can("admin", "")


def test_is_valid_role():
    assert is_valid_role("admin")
    assert is_valid_role("analyst")
    assert is_valid_role("viewer")
    assert not is_valid_role("superuser")
    assert not is_valid_role("")
