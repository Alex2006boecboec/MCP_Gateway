"""Tests for subscription plan limits and helpers."""
from mcp_shield.cloud.plans import can_upgrade_to, check_event_limit, get_plan


def test_check_event_limit_allows_exact_max():
    """Projected total == max must be allowed (not off-by-one)."""
    max_events = get_plan("free").max_events_per_month
    assert check_event_limit("free", max_events)[0] is True
    assert check_event_limit("free", max_events + 1)[0] is False


def test_check_event_limit_unlimited_enterprise():
    assert check_event_limit("enterprise", 10_000_000)[0] is True


def test_can_upgrade_to():
    assert can_upgrade_to("free", "pro")
    assert can_upgrade_to("pro", "business")
    assert not can_upgrade_to("business", "pro")
    assert not can_upgrade_to("free", "free")
