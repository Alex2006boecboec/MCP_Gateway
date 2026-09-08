"""Smoke test: proxy with approval flow holds high-risk calls for human approval.

Scenarios:
  1. High-risk exec call -> human approves -> forwarded (success).
  2. High-risk exec call -> human denies -> ERR_APPROVAL_DENIED.
  3. High-risk exec call -> timeout -> ERR_APPROVAL_TIMEOUT.
  4. Benign call (no risk rule) -> no approval -> forwarded immediately.

Run: python tests/smoke_approval.py
"""
import json
import subprocess
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent
PY = str(ROOT / ".venv" / "Scripts" / "python.exe")

# Fake MCP server: echoes the tool name back.
FAKE_SERVER = r'''
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    msg = json.loads(line)
    if msg.get("method") == "initialize":
        sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":msg["id"],"result":{"protocolVersion":"1","capabilities":{},"serverInfo":{"name":"f","version":"0"}}}) + "\n"); sys.stdout.flush()
    elif msg.get("method") == "tools/list":
        tools = [
            {"name": "read_file", "description": "read a file", "inputSchema": {"type": "object"}},
            {"name": "exec", "description": "execute a shell command", "inputSchema": {"type": "object"}},
        ]
        sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":msg["id"],"result":{"tools":tools}}) + "\n"); sys.stdout.flush()
    elif msg.get("method") == "tools/call":
        params = msg.get("params", {})
        name = params.get("name", "")
        result = {"content": [{"type": "text", "text": f"executed {name}"}]}
        sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":msg["id"],"result":result}) + "\n"); sys.stdout.flush()
'''

# Policy with an approval section that marks exec as high-risk.
POLICY_YAML = """\
defaults:
  action: allow
approval:
  risk_rules:
    - name: high-risk-exec
      tool_regex: ".*exec.*"
      reason: "exec-like tool requires approval"
"""


def _write_response_when_ready(approval_dir, decision, by="tester", delay=0.2):
    """Poll the pending dir; when a request appears, write its response."""
    pending = Path(approval_dir) / "pending"
    responses = Path(approval_dir) / "responses"
    pending.mkdir(parents=True, exist_ok=True)
    responses.mkdir(parents=True, exist_ok=True)
    time.sleep(delay)
    for _ in range(50):
        files = list(pending.glob("*.json"))
        if files:
            rid = files[0].stem
            (responses / f"{rid}.json").write_text(
                json.dumps({"decision": decision, "by": by}), encoding="utf-8"
            )
            return rid
        time.sleep(0.05)
    return None


def run_case(name, tool, expect_code, approval_dir, responder_action):
    """responder_action: 'approve' | 'deny' | None (timeout)"""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        srv = td / "s.py"
        srv.write_text(FAKE_SERVER, encoding="utf-8")
        pol = td / "p.yaml"
        pol.write_text(POLICY_YAML, encoding="utf-8")
        audit = td / "a.jsonl"

        # Start the responder thread (writes the response file when a request appears).
        if responder_action is not None:
            t = threading.Thread(
                target=_write_response_when_ready,
                args=(approval_dir, responder_action),
            )
            t.start()
        else:
            t = None

        proc = subprocess.Popen(
            [PY, "-m", "mcp_shield.cli", "--policy", str(pol), "--audit", str(audit),
             "--require-approval", "--approval-dir", str(approval_dir),
             "--approval-timeout", "1.0",
             "--", PY, str(srv)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
        )
        try:
            # initialize
            proc.stdin.write((json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n").encode())
            proc.stdin.flush()
            init = proc.stdout.readline().decode().strip()
            assert "result" in init, f"init failed: {init}"

            # tools/list
            proc.stdin.write((json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n").encode())
            proc.stdin.flush()
            tl = proc.stdout.readline().decode().strip()
            assert "tools" in tl, f"tools/list failed: {tl}"

            # tools/call
            req = {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                   "params": {"name": tool, "arguments": {"cmd": "ls"}}}
            proc.stdin.write((json.dumps(req) + "\n").encode())
            proc.stdin.flush()
            time.sleep(0.3)
            resp_line = proc.stdout.readline().decode().strip()
            resp = json.loads(resp_line)

            if expect_code is None:
                # Expect success (result).
                assert "result" in resp, f"{name}: expected success, got: {resp}"
                print(f"  [OK] {name}: allowed -> {resp['result'].get('content', [{}])[0].get('text', '')}")
            else:
                assert "error" in resp, f"{name}: expected error {expect_code}, got: {resp}"
                assert resp["error"]["code"] == expect_code, f"{name}: wrong code: {resp}"
                print(f"  [OK] {name}: blocked ({resp['error']['code']}) -> {resp['error']['message']}")

            # Verify audit log.
            lines = audit.read_text(encoding="utf-8").strip().split("\n")
            assert len(lines) >= 1, "no audit entry"
            print(f"  [OK] {name}: audit has {len(lines)} entries")
        finally:
            proc.stdin.close()
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            if t is not None:
                t.join(timeout=2)


if __name__ == "__main__":
    print("Smoke test: approval flow in proxy")
    print("=" * 60)
    all_ok = True

    # Use a temp dir for the approval queue that persists across cases.
    approval_base = tempfile.mkdtemp(prefix="approval_smoke_")

    try:
        # Case 1: high-risk exec -> human approves -> forwarded.
        run_case("approve-exec", "exec", None, approval_base, responder_action="approve")

        # Case 2: high-risk exec -> human denies -> ERR_APPROVAL_DENIED (-32006).
        run_case("deny-exec", "exec", -32006, approval_base, responder_action="deny")

        # Case 3: high-risk exec -> timeout -> ERR_APPROVAL_TIMEOUT (-32005).
        run_case("timeout-exec", "exec", -32005, approval_base, responder_action=None)

        # Case 4: benign read_file (no risk rule) -> no approval -> forwarded.
        run_case("benign-read", "read_file", None, approval_base, responder_action=None)
    finally:
        import shutil
        shutil.rmtree(approval_base, ignore_errors=True)

    print("=" * 60)
    print("All approval smoke tests passed.")
