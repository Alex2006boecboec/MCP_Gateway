"""Compliance report generators for the cloud dashboard (Phase 5).

Generates summaries over a date range for a given framework. Output as a
dict (rendered as HTML by the dashboard, or as CSV by /download).

Frameworks:
  - SOC2 (security): event counts, top blocked tools/servers, policy violations.
  - ISO27001 (information security): events mapped to Annex A controls.
  - 152-ФЗ (Russian personal data law): PII exfiltration chains, approvals.
"""

from __future__ import annotations

from typing import Any

from mcp_shield.cloud.db import Database

FRAMEWORKS = ("soc2", "iso27001", "152fz")


def generate_report(
    db: Database,
    org_id: str,
    framework: str,
    start: str | None = None,
    end: str | None = None,
) -> dict[str, Any]:
    """Generate a compliance report for an org over a date range.

    Returns a dict with: title, framework, period, summary_cards, rows.
    The dashboard renders it as HTML; /download renders it as CSV.
    """
    if framework not in FRAMEWORKS:
        raise ValueError(f"unknown framework: {framework}")

    events = db.query_events(org_id, start=start, end=end, limit=10000)
    summary = db.summary(org_id, start=start, end=end)

    if framework == "soc2":
        return _soc2(events, summary, start, end)
    if framework == "iso27001":
        return _iso27001(events, summary, start, end)
    if framework == "152fz":
        return _fz152(events, summary, start, end)
    return {}


def _soc2(events, summary, start, end):
    """SOC2 security report."""
    # Count by rule type.
    injections = sum(1 for e in events if e.detection and e.detection.get("verdict") == "blocked")
    chains = sum(1 for e in events if e.chain)
    approvals = sum(1 for e in events if e.approval)
    # Top blocked tools.
    blocked = [e for e in events if e.decision == "deny"]
    tool_counts: dict[str, int] = {}
    for e in blocked:
        tool_counts[e.tool] = tool_counts.get(e.tool, 0) + 1
    top_tools = sorted(tool_counts.items(), key=lambda x: -x[1])[:10]
    # Top blocked servers.
    server_counts: dict[str, int] = {}
    for e in blocked:
        server_counts[e.server] = server_counts.get(e.server, 0) + 1
    top_servers = sorted(server_counts.items(), key=lambda x: -x[1])[:10]
    return {
        "title": "SOC2 Security Report",
        "framework": "soc2",
        "period": {"start": start or "all", "end": end or "now"},
        "summary_cards": [
            {"label": "Total calls", "value": summary["total"]},
            {"label": "Allowed", "value": summary["allow"]},
            {"label": "Denied", "value": summary["deny"]},
            {"label": "Injections blocked", "value": injections},
            {"label": "Chains blocked", "value": chains},
            {"label": "Approvals", "value": approvals},
        ],
        "rows": [
            {"category": "Top blocked tools", "items": top_tools},
            {"category": "Top blocked servers", "items": top_servers},
        ],
    }


def _iso27001(events, summary, start, end):
    """ISO27001 report: events mapped to Annex A controls."""
    controls = {
        "A.8.1 (Access Control)": 0,
        "A.8.2 (Information Classification)": 0,
        "A.12.6 (Technical Vulnerabilities)": 0,
        "A.13.1 (Network Security)": 0,
    }
    for e in events:
        if e.redactions:
            controls["A.8.2 (Information Classification)"] += 1
        if e.detection and e.detection.get("verdict") == "blocked":
            controls["A.12.6 (Technical Vulnerabilities)"] += 1
        if e.decision == "deny" and e.rule in ("server-config", "default", "url-validator", "path-validator"):
            controls["A.8.1 (Access Control)"] += 1
        if e.chain or (e.decision == "deny" and "network" in (e.reason or "")):
            controls["A.13.1 (Network Security)"] += 1
    return {
        "title": "ISO27001 Information Security Report",
        "framework": "iso27001",
        "period": {"start": start or "all", "end": end or "now"},
        "summary_cards": [
            {"label": "Total events", "value": summary["total"]},
            {"label": "Denied", "value": summary["deny"]},
        ],
        "rows": [
            {"category": "Annex A controls", "items": list(controls.items())},
        ],
    }


def _fz152(events, summary, start, end):
    """152-ФЗ (Russian personal data law) report."""
    # PII exfiltration: chains with read:database or read:env to network:send.
    pii_chains = 0
    for e in events:
        if e.chain and "send" in (e.chain.get("sink_capability") or ""):
            pii_chains += 1
    # Approval audit: who approved/denied what.
    approval_rows = []
    for e in events:
        if e.approval:
            approval_rows.append({
                "ts": e.ts,
                "tool": e.tool,
                "outcome": e.approval.get("outcome", ""),
                "by": e.approval.get("by", ""),
            })
    return {
        "title": "152-ФЗ Personal Data Report",
        "framework": "152fz",
        "period": {"start": start or "all", "end": end or "now"},
        "summary_cards": [
            {"label": "Total events", "value": summary["total"]},
            {"label": "PII exfiltration chains", "value": pii_chains},
            {"label": "Approvals", "value": len(approval_rows)},
        ],
        "rows": [
            {"category": "Approval audit", "items": [(r["ts"], r["tool"], r["outcome"], r["by"]) for r in approval_rows]},
        ],
    }


def report_to_csv(report: dict[str, Any]) -> str:
    """Render a report dict as CSV text."""
    lines = [report["title"]]
    lines.append(f"Period: {report['period']['start']} to {report['period']['end']}")
    lines.append("")
    lines.append("Summary")
    lines.append("Metric,Value")
    for card in report["summary_cards"]:
        lines.append(f"{card['label']},{card['value']}")
    lines.append("")
    for section in report["rows"]:
        lines.append(section["category"])
        for item in section["items"]:
            if isinstance(item, tuple) and len(item) == 2:
                lines.append(f"{item[0]},{item[1]}")
            else:
                lines.append(str(item))
        lines.append("")
    return "\n".join(lines)
