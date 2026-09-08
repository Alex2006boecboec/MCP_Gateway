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

## 5. The notifier (approval/notifier.py)

Sends a notification when a request is created. Optional and best-effort:
if the webhook is unreachable, the request is still queued locally.

```python
def notify(webhook_url: str, request: ApprovalRequest, timeout: float) -> bool:
    """POST a human-readable notification to a Slack/Teams incoming webhook.
    Returns True on HTTP 200, False on any failure. Never raises -
    notification is best-effort; the file queue is the source of truth."""
```

Uses `urllib.request` (stdlib). Payload is a Slack-compatible JSON:
`{"text": "Approval required for <tool> on <server>: <reason>..."}`.
Teams accepts the same shape (a JSON body with a `text` field). A single
function covers both.

## 6. The responder (approval/responder.py)

Polls the response directory for a decision file.

```python
def wait_for_response(
    request: ApprovalRequest,
    response_dir: str,
    poll_interval: float,
    timeout: float,
) -> ApprovalResponse | None:
    """Poll response_dir for <request_id>.json until it appears or the
    timeout (request.expires_at) is reached. Returns the parsed
    ApprovalResponse, or None on timeout. Never raises - a malformed
    response file is ignored (the human can re-write it)."""
```

Poll loop:
```
while time.time() < request.expires_at:
    path = response_dir / f"{request.request_id}.json"
    if path.exists():
        try: return parse(path)
        except: ignore (log warning; let human fix the file)
    time.sleep(poll_interval)
return None  # timeout
```

## 7. The engine (approval/engine.py)

Orchestrates: create request -> write to pending -> notify -> wait ->
return decision. Called by the proxy.

```python
class ApprovalEngine:
    def __init__(self, config: ApprovalConfig):
        self.config = config
        self._ensure_dirs()

    def request(self, *, call_id, server, tool, args, reason, trigger, rule_name) -> ApprovalRequest:
        """Create + persist + notify. Returns the request (not the decision)."""

    def await_decision(self, request: ApprovalRequest) -> tuple[str, ApprovalResponse | None]:
        """Block until a decision arrives or timeout. Returns
        ('approve'|'deny'|'timeout', response_or_None)."""

    def evaluate(self, *, call_id, server, tool, args, reason, trigger, rule_name) -> tuple[str, ApprovalResponse | None]:
        """Convenience: request + await_decision in one call. Returns
        ('approve'|'deny'|'timeout', response). This is what the proxy calls."""

    def _ensure_dirs(self): ...
    def _write_pending(self, request): ...
    def _mark_resolved(self, request, response): ...   # move pending -> resolved
```

### 7.1 evaluate algorithm

```
1. request = ApprovalRequest(...)
2. _write_pending(request)            # pending/<id>.json
3. notify(webhook_url, request, ...)   # best-effort; ignore failure
4. decision, response = await_decision(request)
5. _mark_resolved(request, response)   # pending/<id>.json -> resolved/<id>.json
6. return (decision, response)
```

`await_decision` returns:
  - `("approve", response)` - human approved
  - `("deny", response)` - human denied
  - `("timeout", None)` - no response in time

## 8. Risk rule matching (approval/rules.py)

```python
def matches_risk_rule(tool: str, args: dict, rules: list[RiskRule]) -> RiskRule | None:
    """Return the first matching risk rule (tool_regex matches tool name,
    and if arg_regex is set, it matches some arg value), or None."""
```

This mirrors the policy engine's rule matching but is separate (approval
rules are a different concern from allow/deny policy). A call can be
allowed by policy AND require approval by a risk rule.

## 9. Integration into proxy.py (NO conflict with Phase 1-3)

### 9.1 ProxyConfig

Add:
```python
approval_config: Optional[ApprovalConfig] = None  # None = approval disabled
```

### 9.2 Proxy.__init__

```python
self.approval = ApprovalEngine(config.approval_config) if config.approval_config else None
```

### 9.3 Pipeline order (the critical non-conflict design)

Request side (`_inspect_request`), AFTER redaction, AFTER policy, AFTER
graph:
```
redact args -> policy -> graph.check_sink -> [approval] -> forward
```

Approval runs LAST on the request side. Only consulted when:
  - policy.action == "approve" (policy routed to approval), OR
  - graph returned a review chain AND approval.require_for_review_chains, OR
  - a risk rule matches AND approval is enabled.

If approval returns "deny" or "timeout" -> return deny (do NOT forward).
If "approve" -> forward (fall through to the normal forward path).

**Important**: approval does NOT modify the message. It only decides
whether to forward. The redacted args are forwarded as-is.

### 9.4 When approval is triggered

```python
# After policy + graph, if not already denied:
need_approval = False
trigger = ""
rule_name = ""
reason = ""

if decision.action == "approve":          # policy routed here
    need_approval, trigger, rule_name = True, "policy", decision.rule_name
    reason = decision.reason or "policy requires approval"
elif (self.approval is not None and chain is not None
      and self.approval.config.require_for_review_chains):
    need_approval, trigger, rule_name = True, "review-chain", chain.rule_name
    reason = f"review chain: {chain.rule_name}"
elif self.approval is not None:
    rule = matches_risk_rule(tool, arguments, self.approval.config.risk_rules)
    if rule is not None:
        need_approval, trigger, rule_name = True, "risk-rule", rule.name
        reason = rule.reason

if need_approval and self.approval is not None:
    outcome, response = self.approval.evaluate(
        call_id=msg.id, server=server, tool=tool, args=arguments,
        reason=reason, trigger=trigger, rule_name=rule_name,
    )
    if outcome != "approve":
        decision = Decision("deny", f"approval {outcome}: {reason}", "approval")
        processed._approval = _approval_to_dict(...)  # for audit
    # else: fall through - forward the (redacted) request
```

### 9.5 New error codes

Already defined in protocol.py:
  - `ERR_APPROVAL_TIMEOUT = -32005`
  - `ERR_APPROVAL_DENIED = -32006`

Use them in the error response when approval denies/times out. The pump
already maps `decision.rule_name` to error codes; add a branch:
`ERR_APPROVAL_TIMEOUT if outcome == "timeout" else ERR_APPROVAL_DENIED`.

### 9.6 Audit enrichment

Add `approval` field to audit entries:
```python
approval = {
    "request_id": req.request_id,
    "trigger": trigger,
    "rule_name": rule_name,
    "outcome": outcome,            # "approve" | "deny" | "timeout"
    "by": response.by if response else "",
    "comment": response.comment if response else "",
    "waited_seconds": ...,
}
```
Pass to `audit.log(..., approval=approval)`. Add the field to `AuditEntry`
and `AuditLogger.log()` (same pattern as the Phase 3 `chain` field).

### 9.7 The pump: blocking is safe

Approval blocks in `_inspect_request` (before forwarding). The MCP
server subprocess has NOT been contacted yet for this call, so nothing
on the server side is held open. The agent is blocked waiting for the
response anyway. The only cost is one goroutine-free thread of the
proxy. Document: long timeouts (minutes) are acceptable; the agent UI
shows a spinner.

### 9.8 Response side: no change

Approval is request-side only. The response pipeline (`_inspect_response`)
is unchanged: redact -> detect -> graph.record_source -> audit. Approval
does not re-run on the response.

## 10. Edge cases & bug-prevention (the critical list)

1. **Approval disabled (config=None)**
   -> Proxy behaves EXACTLY like Phase 1-3. All existing tests pass
   unchanged. Verify with the full suite after integration.

2. **Policy says "approve" but approval is disabled**
   -> Treat "approve" as "allow" (fail-open for the approval step, since
   no human is configured). Log a warning. Document this clearly: if you
   use `action: approve` in policy, you MUST enable approval or the call
   auto-passes. Safer alternative: treat as "deny" (fail-closed). Decision:
   **fail-closed** - if policy says "approve" and approval is disabled,
   DENY with a clear reason ("approval required but no approval engine
   configured"). This is safer and surfaces misconfiguration loudly.

3. **Timeout (no human responds)**
   -> Deny with ERR_APPROVAL_TIMEOUT. Fail-closed. Move the pending file
   to resolved/ with outcome "timeout".

4. **Malformed response file**
   -> Ignore it (log warning), keep polling. The human can fix the file.
   Never crash on a bad JSON.

5. **Duplicate response file (human writes twice)**
   -> First read wins. The second write is ignored (the request is already
   resolved). The resolved/ file has the first response.

6. **Pending dir does not exist / not writable**
   -> _ensure_dirs creates it on engine init. If creation fails, raise
   ApprovalError at startup (fail-fast, not at call time).

7. **Webhook unreachable**
   -> notify() returns False, logs warning, does NOT raise. The request
   is still in pending/ for a local human to see. Approval proceeds
   (waiting for the file response).

8. **Approval must not crash the proxy**
   -> The proxy wraps the approval call in try/except. On any unexpected
   error: deny with ERR_APPROVAL_DENIED (fail-closed) and log. Never
   forward a call that needed approval but whose approval errored.

9. **Secrets in the approval request file**
   -> The args are ALREADY redacted (redaction runs before approval in
   the pipeline). The pending/<id>.json contains only redacted args.
   Verify in tests: a secret in original args is [REDACTED:...] in the
   pending file.

10. **Large args in the pending file**
    -> The pending file is JSON. Cap the args dump at a reasonable size
    (e.g. 10KB per arg, 50KB total) with a "[truncated]" marker. Avoid
    writing a 50MB file on every approval.

11. **Concurrent requests needing approval**
    -> Each gets a unique request_id (uuid4). The pending dir holds
    multiple files. The proxy is sequential (Phase 1-4), so only one
    approval is awaited at a time. Document: concurrent approvals need
    async pump (future phase).

12. **Clock skew / negative timeout**
    -> expires_at = created_at + timeout. If time.time() > expires_at
    at first check, return timeout immediately (no poll). Never spin.

13. **Response file for a different request_id**
    -> Ignored (we only look for <our_id>.json). Stale response files
    for old requests are left in place (a cleanup task can GC them;
    out of scope for Phase 4).

14. **Risk rule with bad regex**
    -> Validated at config load (ApprovalEngine.__init__ compiles all
    risk_rules' regexes). Raise ApprovalError at startup, not at call time.

15. **Review chain routing**
    -> Only when require_for_review_chains=True. The graph returns a
    Chain with a "review" rule. We pass the chain to approval. The graph
    itself does NOT block (it returns "allow" for review). Approval is
    the one that blocks.

16. **Circular dependency**
    -> approval imports NOTHING from protocol/proxy. It's pure
    (request, response_dir) -> (decision, response). The proxy calls it.
    types.py is imported by approval modules only.

17. **Approval + graph block chain**
    -> Graph block chains deny BEFORE approval is consulted. So a
    "block" chain never reaches approval. Only "review" chains do (and
    only if require_for_review_chains). Order: policy -> graph -> approval.

## 11. Test plan (concrete cases)

### 11.1 test_approval_types.py

| Case | Input | Expected |
|---|---|---|
| request_instantiation | ApprovalRequest fields | dataclass builds, expires_at = created_at + timeout |
| response_instantiation | ApprovalResponse fields | dataclass builds |
| risk_rule_instantation | RiskRule fields | dataclass builds |
| config_defaults | ApprovalConfig() | enabled=True, timeout=120, webhook=None |

### 11.2 test_approval_rules.py

| Case | Input | Expected |
|---|---|---|
| matches_exec | tool="exec", rule tool_regex=".*exec.*" | match |
| matches_with_arg | tool="exec", args={cmd:"rm -rf"}, arg_regex="rm" | match |
| no_match_tool | tool="read_file", rule tool_regex=".*exec.*" | None |
| no_match_arg | tool="exec", args={cmd:"ls"}, arg_regex="rm" | None |
| first_rule_wins | two matching rules | first one returned |
| bad_regex | rule with "(" | ApprovalError at compile |

### 11.3 test_approval_notifier.py

| Case | Input | Expected |
|---|---|---|
| notify_success | mock 200 response | returns True |
| notify_failure | mock 500 response | returns False (no raise) |
| notify_unreachable | bad URL | returns False (no raise) |
| notify_no_url | webhook_url=None | returns False (skipped) |

### 11.4 test_approval_responder.py

| Case | Input | Expected |
|---|---|---|
| response_arrives | write response file after 0.1s | parsed ApprovalResponse |
| timeout | no response file, timeout=0.05 | returns None |
| malformed_file | write bad JSON | ignored, keeps polling, then timeout |
| deny_response | decision="deny" | returns with decision="deny" |

### 11.5 test_approval_engine.py

| Case | Steps | Expected |
|---|---|---|
| approve_flow | create engine; write response file; evaluate | ("approve", response) |
| deny_flow | write deny response | ("deny", response) |
| timeout_flow | no response, short timeout | ("timeout", None) |
| pending_file_written | after request() | pending/<id>.json exists with redacted args |
| resolved_file_written | after evaluate | resolved/<id>.json exists with response |
| dirs_created | missing dirs | created on init |
| secrets_redacted_in_pending | args with secret | pending file has [REDACTED:...] not the secret |
| large_args_truncated | 100KB arg | pending file truncated with marker |

### 11.6 test_proxy_approval.py (integration)

| Case | Steps | Expected |
|---|---|---|
| policy_approve_routed | policy action="approve"; write response | forwarded (allow) |
| policy_approve_disabled | policy action="approve", approval=None | DENY (fail-closed, misconfig) |
| risk_rule_triggers | risk rule matches exec; write response | forwarded after approval |
| risk_rule_timeout | risk rule matches; no response, short timeout | ERR_APPROVAL_TIMEOUT |
| review_chain_routed | graph review chain + require_for_review_chains | approval triggered |
| review_chain_not_routed | graph review chain + require_for_review_chains=False | allowed (no approval) |
| approval_disabled_noop | approval_config=None | proxy behaves like Phase 1-3 |
| audit_has_approval_field | after an approval | audit entry has approval dict |

### 11.7 smoke_approval.py (end-to-end)

Fake MCP server + a background thread that writes the response file:
- Case 1: high-risk exec call -> approval -> human approves -> forwarded.
- Case 2: high-risk exec call -> approval -> human denies -> ERR_APPROVAL_DENIED.
- Case 3: high-risk exec call -> approval -> timeout -> ERR_APPROVAL_TIMEOUT.
- Case 4: benign call (no risk rule) -> no approval -> forwarded immediately.

## 12. Implementation order (bug-free sequence)

Each step is independently testable and green before the next. No forward
references. Phase 1-3 tests stay green throughout.

1. `approval/types.py` - dataclasses (ApprovalRequest, ApprovalResponse,
   RiskRule, ApprovalConfig). Test: import works, dataclasses instantiate.
   GREEN.

2. `approval/rules.py` - matches_risk_rule + regex compilation validation.
   Test: test_approval_rules.py. GREEN.

3. `approval/notifier.py` - notify() using urllib, best-effort.
   Test: test_approval_notifier.py (mock urllib). GREEN.

4. `approval/responder.py` - wait_for_response poll loop.
   Test: test_approval_responder.py (tmp_path). GREEN.

5. `approval/engine.py` - ApprovalEngine (request, await_decision,
   evaluate, _ensure_dirs, _write_pending, _mark_resolved).
   Test: test_approval_engine.py (tmp_path). GREEN.

6. `approval/__init__.py` - public API exports.

7. Integrate into `proxy.py`:
   - ProxyConfig.approval_config
   - Proxy.__init__ self.approval
   - _inspect_request: approval trigger logic after policy + graph
   - pump: map approval deny/timeout to error codes
   - audit: approval field
   Test: full Phase 1-3 suite still green (approval disabled by default);
   test_proxy_approval.py green (approval enabled); smoke_approval.py green.

8. `audit.py` - add `approval` field to AuditEntry + AuditLogger.log().

9. CLI: `--require-approval` flag (enables ApprovalConfig with defaults) +
   `--approval-dir` (overrides pending/response dirs) +
   `--approval-timeout` (overrides timeout) +
   `--approval-webhook` (sets webhook URL) +
   policy YAML `risk_rules` section loader (or a separate approval.yaml).
   README + pyproject (no new mandatory deps).

10. Commit, push.

## 13. Dependencies

- **Zero new mandatory dependencies.** Phase 4 uses only stdlib (json,
  os, time, uuid, re, dataclasses, urllib.request, pathlib). The Slack/
  Teams webhook uses urllib (no requests/httpx needed). This keeps the
  package lightweight and avoids any install/compatibility risk.

## 14. Success criteria for Phase 4

- All Phase 1-3 tests pass unchanged (196 passed, 1 skipped) - no regression.
- New tests: 40+ across types/rules/notifier/responder/engine/proxy, all green.
- smoke_approval.py: 4 scenarios (approve, deny, timeout, benign) all pass.
- Approval disabled (config=None) -> proxy behaves exactly like Phase 1-3.
- Policy `action: approve` with approval disabled -> DENY (fail-closed, loud).
- Approval timeout -> ERR_APPROVAL_TIMEOUT (fail-closed).
- Approval deny -> ERR_APPROVAL_DENIED.
- Approval approve -> call forwarded (redacted args, unchanged).
- Pending request file contains REDACTED args (no secrets on disk).
- Approval never crashes the proxy (try/except on all hooks).
- Audit log includes approval field when approval was consulted.
- No new mandatory dependencies.

## 15. File structure

```
mcp_shield/
  approval/
    __init__.py        # public API: ApprovalEngine, ApprovalConfig, ...
    types.py           # ApprovalRequest, ApprovalResponse, RiskRule, ApprovalConfig
    rules.py           # matches_risk_rule + regex validation
    notifier.py        # notify() - Slack/Teams webhook (urllib, best-effort)
    responder.py       # wait_for_response() - file-based poll loop
    engine.py          # ApprovalEngine (the orchestrator)
```

Changes to existing files:
- `proxy.py` - ProxyConfig.approval_config, self.approval, _inspect_request
  approval trigger, pump error-code mapping, audit approval field.
- `audit.py` - new `approval` field on AuditEntry + AuditLogger.log().
- `cli.py` - new flags: --require-approval, --approval-dir,
  --approval-timeout, --approval-webhook.
- `README.md` - Phase 4 section + roadmap update.
- `pyproject.toml` - no new deps; document approval as built-in.

## 16. CLI design (concrete)

```
mcp-shield \
  --policy policies/default.yaml \
  --audit audit.jsonl \
  --detect-injection \
  --track-chains \
  --require-approval \
  --approval-dir approvals \
  --approval-timeout 120 \
  --approval-webhook https://hooks.slack.com/services/... \
  -- \
  npx -y @modelcontextprotocol/server-filesystem /home/me
```

- `--require-approval`: enable the approval engine (ApprovalConfig with
  defaults). Off by default.
- `--approval-dir DIR`: base dir for pending/ and responses/ subdirs.
  Default: ./approvals
- `--approval-timeout SECONDS`: human response timeout. Default: 120.
- `--approval-webhook URL`: Slack/Teams incoming webhook. Optional.

Risk rules come from the policy YAML (a new top-level `approval` section)
so they live with the rest of the security policy:

```yaml
approval:
  require_for_review_chains: true
  risk_rules:
    - name: high-risk-exec
      tool_regex: ".*exec|.*run|.*shell"
      reason: "exec-like tool requires approval"
    - name: destructive-file
      tool_regex: ".*delete|.*remove|.*rm"
      arg_regex: "rm|delete|remove"
      reason: "destructive file operation requires approval"
    - name: external-post
      tool_regex: ".*post|.*send|.*upload"
      reason: "external data send requires approval"
```

The CLI `--require-approval` flag + policy `approval` section together
configure the engine. If `--require-approval` is set but the policy has
no `approval` section, the engine runs with defaults (no risk rules;
only policy `action: approve` and review chains trigger it).
