"""Subscription plan definitions and limit enforcement.

Plans:
  free       — 1 proxy, 1 MCP server, 1000 events/month, SQLite, no SSO
  pro        — 5 proxies, 10 MCP servers, 50K events/month, Postgres, approval flow
  business   — 25 proxies, 500K events/month, SSO, RBAC, compliance reports
  enterprise — unlimited, on-prem, custom rules, SLA

Limits are enforced in:
  - API ingest (events/month)
  - Dashboard (proxy count, MCP server count — future)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Plan:
    """Subscription tier with resource limits."""
    name: str
    display_name: str
    price_monthly: int  # USD cents (0 = free)
    max_events_per_month: int  # -1 = unlimited
    max_proxies: int  # -1 = unlimited
    max_mcp_servers: int  # -1 = unlimited
    has_postgres: bool
    has_sso: bool
    has_approval_flow: bool
    has_compliance_reports: bool
    has_ip_allowlist: bool
    has_custom_rules: bool
    data_retention_days: int  # -1 = configurable


PLANS: dict[str, Plan] = {
    "free": Plan(
        name="free",
        display_name="Free",
        price_monthly=0,
        max_events_per_month=1000,
        max_proxies=1,
        max_mcp_servers=1,
        has_postgres=False,
        has_sso=False,
        has_approval_flow=False,
        has_compliance_reports=False,
        has_ip_allowlist=False,
        has_custom_rules=False,
        data_retention_days=30,
    ),
    "pro": Plan(
        name="pro",
        display_name="Pro",
        price_monthly=2900,  # $29/mo
        max_events_per_month=50_000,
        max_proxies=5,
        max_mcp_servers=10,
        has_postgres=True,
        has_sso=False,
        has_approval_flow=True,
        has_compliance_reports=False,
        has_ip_allowlist=False,
        has_custom_rules=False,
        data_retention_days=90,
    ),
    "business": Plan(
        name="business",
        display_name="Business",
        price_monthly=9900,  # $99/mo
        max_events_per_month=500_000,
        max_proxies=25,
        max_mcp_servers=50,
        has_postgres=True,
        has_sso=True,
        has_approval_flow=True,
        has_compliance_reports=True,
        has_ip_allowlist=True,
        has_custom_rules=False,
        data_retention_days=365,
    ),
    "enterprise": Plan(
        name="enterprise",
        display_name="Enterprise",
        price_monthly=0,  # custom pricing
        max_events_per_month=-1,  # unlimited
        max_proxies=-1,
        max_mcp_servers=-1,
        has_postgres=True,
        has_sso=True,
        has_approval_flow=True,
        has_compliance_reports=True,
        has_ip_allowlist=True,
        has_custom_rules=True,
        data_retention_days=-1,
    ),
}

PLAN_NAMES = list(PLANS.keys())


def get_plan(name: str) -> Plan:
    """Get a Plan by name. Defaults to free if unknown."""
    return PLANS.get(name, PLANS["free"])


def can_upgrade_to(current: str, target: str) -> bool:
    """Check if it's valid to upgrade from current to target plan."""
    order = ["free", "pro", "business", "enterprise"]
    try:
        return order.index(target) > order.index(current)
    except ValueError:
        return False


def check_event_limit(plan_name: str, current_count: int) -> tuple[bool, str]:
    """Check if an org can accept events given a projected monthly total.

    `current_count` is the projected total AFTER the new batch would be
    inserted (i.e. existing + len(batch)). Allowed when projected <= max.

    Returns (allowed, reason). If allowed is False, reason explains why.
    """
    plan = get_plan(plan_name)
    if plan.max_events_per_month == -1:
        return True, "unlimited"
    if current_count > plan.max_events_per_month:
        return False, f"monthly event limit reached ({plan.max_events_per_month} events/month on {plan.display_name} plan)"
    return True, ""
