# Phase 4 — Human-in-the-Loop Approval Flow: Detailed Plan

> Spec I implement against. Every function signature, file format, config
> field, and test case is concrete. Goal: implement once, green on first
> run, no conflicts with Phase 1-3, no bugs.

## 1. Goal — human-in-the-loop for high-risk calls

Some tool calls are too dangerous to auto-allow but too useful to
auto-deny: `rm -rf`, `exec` with untrusted args, an external POST with
large data, a "review"-severity chain from Phase 3. Phase 4 **holds**
these calls and asks a human to approve or deny them. On timeout →
fail-closed (deny). On deny → block. On approve → forward.

This closes the gap between Phase 1 (auto-allow/deny) and Phase 3
(review = log only). "review" chains and "approve" policy rules now
route to a human instead of silently passing.

## 2. What Phase 4 does NOT do (conflict avoidance)

- Does NOT replace or weaken Phase 1 policy. Policy still runs first.
  A policy `deny` is returned immediately; approval is only consulted
  when policy says `approve` (a NEW action) or when the graph returns a
  `review` chain AND approval is enabled.
- Does NOT replace Phase 2 injection detection. Injection still blocks
  hard; approval is for calls that are risky-but-ambiguous, not injections.
- Does NOT replace Phase 3 graph. Graph "block" chains still block
  immediately. Only graph "review" chains route to approval (optional,
  off by default).
- Does NOT block the MCP server subprocess. The proxy holds the REQUEST
  to the server while waiting (the server is not contacted until a human
  approves). This is safe — the agent is waiting for the response anyway.
- Is OPTIONAL. `approval_config=None` disables it; proxy behaves exactly
  like Phase 1-3. Default off (safer rollout; approval needs a human).
- Does NOT add mandatory dependencies. The notifier uses `urllib`
  (stdlib). The responder is file-based (stdlib). Slack/Teams HTTP
  webhook is a thin optional layer.

## 3. Core concepts

### 3.1 Approval trigger

A call requires approval when ANY of:
  a. Policy `Decision.action == "approve"` (policy rule with
     `action: approve` — already supported in the YAML format and the
     `Decision` dataclass).
  b. Capability graph returns a "review"-severity chain AND
     `ApprovalConfig.require_for_review_chains is True` (off by default;
     review chains normally just log).
  c. A risk rule in `ApprovalConfig.risk_rules` matches (tool_regex +
     optional arg_regex). This is the primary, declarative way to mark
     high-risk tools (e.g. `exec`, `rm`, external POST).

### 3.2 Approval request

When a trigger fires, the proxy creates an `ApprovalRequest` (a JSON
document) with: request_id, call details (server, tool, args — already
redacted), reason, created_at, expires_at. It writes this to a
**pending queue** (a directory of JSON files) and optionally POSTs a
notification to a webhook (Slack/Teams).

### 3.3 Approval response

A human (or a separate bot) writes a response JSON file to a **response
directory**: `responses/<request_id>.json` with `{"decision": "approve"
| "deny", "by": "<user>", "comment": "..."}`. The proxy polls this
directory until a response arrives or the timeout expires.

This file-based design is:
  - Dependency-free (stdlib only).
  - Fully testable (tests write response files directly).
  - Easy to wrap with a Slack bot (the bot reads pending/*.json and
    writes responses/*.json). The bot is out of scope for Phase 4; we
    provide the contract it implements.

### 3.4 Timeout

If no response arrives within `ApprovalConfig.timeout_seconds`, the call
is denied with `ERR_APPROVAL_TIMEOUT` (fail-closed). The pending request
file is marked expired.

## 4. Data structures (approval/types.py)

```python
@dataclass
class ApprovalRequest:
    request_id: str            # uuid4 hex
    call_id: int | str         # the JSON-RPC id of the tools/call
    server: str
    tool: str
    args: dict[str, Any]       # already redacted (no secrets)
    reason: str                # why approval is required
    trigger: str               # "policy" | "risk-rule" | "review-chain"
    rule_name: str             # which rule triggered
    created_at: float          # time.time()
    expires_at: float          # created_at + timeout_seconds

@dataclass
class ApprovalResponse:
    request_id: str
    decision: str             # "approve" | "deny"
    by: str                   # who approved/denied (for the audit log)
    comment: str = ""
    decided_at: float = 0.0

@dataclass
class RiskRule:
    name: str
    tool_regex: str           # compiled to re.Pattern at load time
    arg_regex: str | None     # optional; compiled if present
    reason: str

@dataclass
class ApprovalConfig:
    enabled: bool = True
    # File-based queue directories (the responder polls responses/).
    pending_dir: str = "approvals/pending"
    response_dir: str = "approvals/responses"
    # How long to wait for a human before timing out (fail-closed).
    timeout_seconds: float = 120.0
    # Poll interval for the response file.
    poll_interval_seconds: float = 1.0
    # Optional webhook notification (Slack/Teams incoming webhook URL).
    # None = no notification (file-based only).
    webhook_url: str | None = None
    webhook_timeout_seconds: float = 5.0
    # Route graph "review" chains to approval (off by default).
    require_for_review_chains: bool = False
    # Declarative high-risk rules (the primary trigger).
    risk_rules: list[RiskRule] = field(default_factory=list)
```
