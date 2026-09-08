"""Slack/Teams webhook notifier for the approval flow (Phase 4).

Sends a human-readable notification when an approval request is created.
Best-effort: if the webhook is unreachable, the request is still queued
locally (the file queue is the source of truth). Never raises.

Uses urllib.request (stdlib) so no new dependencies. Both Slack and
Teams incoming webhooks accept a JSON body with a `text` field.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from mcp_shield.approval.types import ApprovalRequest

log = logging.getLogger("mcp_shield.approval")


def notify(webhook_url: Optional[str], request: ApprovalRequest, timeout: float) -> bool:
    """POST a notification to a Slack/Teams incoming webhook.

    Returns True on HTTP 2xx, False on any failure (network error, non-2xx,
    or webhook_url is None). Never raises - notification is best-effort.
    """
    if not webhook_url:
        return False
    try:
        import urllib.request
        import urllib.error

        text = _format_message(request)
        payload = json.dumps({"text": text}).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except urllib.error.URLError as exc:
        log.warning("approval notify: webhook unreachable: %s", exc)
        return False
    except Exception as exc:
        log.warning("approval notify: unexpected error: %s", exc)
        return False


def _format_message(request: ApprovalRequest) -> str:
    """Build a human-readable Slack/Teams message for an approval request."""
    from datetime import datetime, timezone

    expires = datetime.fromtimestamp(request.expires_at, tz=timezone.utc).strftime("%H:%M:%S UTC")
    lines = [
        "Approval required for a tool call",
        f"  Tool: {request.tool} (server: {request.server})",
        f"  Reason: {request.reason}",
        f"  Trigger: {request.trigger} ({request.rule_name})",
        f"  Request ID: {request.request_id}",
        f"  Expires: {expires}",
        "",
        f"To approve, write approvals/responses/{request.request_id}.json:",
        '  {"decision": "approve", "by": "<your-name>"}',
        'To deny, write the same file with: {"decision": "deny", "by": "<your-name>"}',
    ]
    return "\n".join(lines)
