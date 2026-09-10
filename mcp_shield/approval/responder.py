"""File-based response poller for the approval flow (Phase 4).

Polls a response directory for a decision file written by a human (or a
Slack bot). The file is `responses/<request_id>.json` with shape:
    {"decision": "approve" | "deny", "by": "<user>", "comment": "..."}

Never raises: a malformed file is ignored (log warning, keep polling) so
the human can fix it. Returns None on timeout.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Optional

from mcp_shield.approval.types import ApprovalRequest, ApprovalResponse

log = logging.getLogger("mcp_shield.approval")


def wait_for_response(
    request: ApprovalRequest,
    response_dir: str,
    poll_interval: float,
    timeout: float,
) -> Optional[ApprovalResponse]:
    """Poll response_dir for <request_id>.json until it appears or the
    request expires (request.expires_at). Returns the parsed
    ApprovalResponse, or None on timeout.

    Never raises: a malformed response file is ignored (the human can
    re-write it). A negative/zero remaining time returns None immediately
    (no spin).
    """
    resp_path = Path(response_dir) / f"{request.request_id}.json"
    deadline = request.expires_at
    # Guard against clock skew: don't poll longer than `timeout` from now.
    hard_deadline = min(deadline, time.time() + timeout)

    while time.time() < hard_deadline:
        if resp_path.exists():
            try:
                data = json.loads(resp_path.read_text(encoding="utf-8"))
                parsed = _parse_response(request.request_id, data)
                if parsed is None:
                    log.warning(
                        "approval: invalid decision in %s (ignoring; human can fix)",
                        resp_path,
                    )
                    time.sleep(max(poll_interval, 0.5))
                    continue
                return parsed
            except (json.JSONDecodeError, OSError) as exc:
                log.warning(
                    "approval: malformed response file %s: %s (ignoring; human can fix)",
                    resp_path, exc,
                )
                # Don't re-read the same bad file every iteration forever;
                # but we can't delete it (the human may be editing it).
                # Sleep a bit longer before re-checking.
                time.sleep(max(poll_interval, 0.5))
                continue
        time.sleep(poll_interval)
    return None


def _parse_response(request_id: str, data: dict) -> Optional[ApprovalResponse]:
    """Parse a response dict into an ApprovalResponse. Returns None if the
    shape is wrong (caller treats as malformed)."""
    if not isinstance(data, dict):
        return None
    decision = str(data.get("decision", "")).lower()
    if decision not in ("approve", "deny"):
        return None
    return ApprovalResponse(
        request_id=request_id,
        decision=decision,
        by=str(data.get("by", "")),
        comment=str(data.get("comment", "")),
        decided_at=float(data.get("decided_at", time.time())),
    )
