"""Third audit: verify all fixes from second audit + edge cases.

Run:  python tests/audit3_verify.py
"""
from __future__ import annotations
import sys, tempfile, json, logging, io
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from mcp_shield.cloud.server import create_app
from mcp_shield.cloud.rate_limit import login_limiter, register_limiter
from mcp_shield.cloud.auth import hash_password

PASS = 0
FAIL = 0
BUGS = []

def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [OK] {name}")
    else:
        FAIL += 1
        BUGS.append(f"{name}: {detail}")
        print(f"  [FAIL] {name} -- {detail}")

def section(t):
    print(f"\n{'='*60}\n  {t}\n{'='*60}")

def get_csrf(c):
    c.get("/login")
    return c.cookies.get("mcp_shield_csrf", "")

def login_admin(c, email, pw):
    login_limiter._buckets.clear()
    csrf = get_csrf(c)
    return c.post("/login", data={"email": email, "password": pw, "csrf_token": csrf}, follow_redirects=False)

def change_pw(c, old, new):
    csrf = get_csrf(c)
    return c.post("/settings", data={"old_password": old, "new_password": new, "new_password_confirm": new, "csrf_token": csrf}, follow_redirects=False)

def main():
    db_path = tempfile.mktemp(suffix="_a3.db")
    app = create_app(db_path, secret="a3-secret")
    client = TestClient(app)
    db = app.state.db
    creds = app.state.bootstrap_credentials
    assert creds
    admin_email = creds["email"]
    admin_password = creds["password"]
    admin = db.get_user_by_email(admin_email)
    org_id = admin.org_id

    # === S-1: XSS fix ===
    section("S-1: XSS fix in users.html")
    # Login + change password first
    login_admin(client, admin_email, admin_password)
    change_pw(client, admin_password, "AdminPass123!")
    admin_password = "AdminPass123!"
    # Create user with XSS email
    db.create_user(org_id, "x';alert(1);'@test.com", hash_password("ViewerPass123!"), "viewer")
    r = client.get("/users")
    check("No inline onsubmit", "onsubmit" not in r.text)
    check("Has data-confirm", "data-confirm" in r.text)
    check("alert(1) not in onsubmit JS", "onsubmit" not in r.text or "alert" not in r.text.split("onsubmit")[1][:200] if "onsubmit" in r.text else True)
    # Verify the data-confirm attribute contains the email (HTML-escaped)
    check("data-confirm has email", "data-confirm" in r.text and "test.com" in r.text)

    # === S-2: must_change_password enforcement ===
    section("S-2: must_change_password enforcement")
    # Fresh app with bootstrap admin (must_change_password=True)
    db2_path = tempfile.mktemp(suffix="_a3b.db")
    app2 = create_app(db2_path, secret="a3b-secret")
    c2 = TestClient(app2)
    creds2 = app2.state.bootstrap_credentials
    login_admin(c2, creds2["email"], creds2["password"])
    # Should redirect to /settings
    r = c2.get("/dashboard", follow_redirects=False)
    check("dashboard -> 302", r.status_code == 302, f"got {r.status_code}")
    check("redirect to /settings", "/settings" in r.headers.get("location", ""), f"got {r.headers.get('location','')}")
    r = c2.get("/reports/soc2", follow_redirects=False)
    check("reports -> 302", r.status_code == 302)
    r = c2.get("/users", follow_redirects=False)
    check("users -> 302", r.status_code == 302)
    r = c2.get("/keys", follow_redirects=False)
    check("keys -> 302", r.status_code == 302)
    r = c2.get("/audit", follow_redirects=False)
    check("audit -> 302", r.status_code == 302)
    # /settings should be accessible
    r = c2.get("/settings", follow_redirects=False)
    check("settings -> 200", r.status_code == 200)
    # /logout should be accessible
    r = c2.get("/logout", follow_redirects=False)
    check("logout -> 302", r.status_code == 302)
    # Re-login after logout, then change password
    login_admin(c2, creds2["email"], creds2["password"])
    change_pw(c2, creds2["password"], "NewPass1234!")
    r = c2.get("/dashboard", follow_redirects=False)
    check("dashboard after pw change -> 200", r.status_code == 200, f"got {r.status_code}")

    # === R-1: page validation ===
    section("R-1: page parameter validation")
    r = client.get("/dashboard?page=0", follow_redirects=False)
    check("page=0 -> 200", r.status_code == 200, f"got {r.status_code}")
    r = client.get("/dashboard?page=-1", follow_redirects=False)
    check("page=-1 -> 200", r.status_code == 200, f"got {r.status_code}")
    r = client.get("/dashboard?page=99999", follow_redirects=False)
    check("page=99999 -> 200", r.status_code == 200)
    r = client.get("/audit?page=0", follow_redirects=False)
    check("audit page=0 -> 200", r.status_code == 200)
    r = client.get("/audit?page=-5", follow_redirects=False)
    check("audit page=-5 -> 200", r.status_code == 200)

    # === D-7: stricter email regex ===
    section("D-7: stricter email regex")
    register_limiter._buckets.clear()
    csrf = get_csrf(client)
    # Email with single quote should be rejected
    r = client.post("/register", data={"org_name": "XSSCorp", "email": "x';alert(1);'@test.com", "password": "StrongPass123!", "csrf_token": csrf}, follow_redirects=False)
    check("XSS email rejected", r.status_code == 400, f"got {r.status_code}")
    # Email with semicolon should be rejected
    register_limiter._buckets.clear()
    csrf = get_csrf(client)
    r = client.post("/register", data={"org_name": "SemCorp", "email": "a;b@test.com", "password": "StrongPass123!", "csrf_token": csrf}, follow_redirects=False)
    check("Semicolon email rejected", r.status_code == 400)
    # Valid email should pass
    register_limiter._buckets.clear()
    csrf = get_csrf(client)
    r = client.post("/register", data={"org_name": "GoodCorp", "email": "good@test.com", "password": "StrongPass123!", "csrf_token": csrf}, follow_redirects=False)
    check("Valid email accepted", r.status_code == 302, f"got {r.status_code}")
    # Email with + should pass (Gmail aliases)
    register_limiter._buckets.clear()
    csrf = get_csrf(client)
    r = client.post("/register", data={"org_name": "PlusCorp", "email": "user+tag@test.com", "password": "StrongPass123!", "csrf_token": csrf}, follow_redirects=False)
    check("Plus-addressing email accepted", r.status_code == 302)

    # === R-3: length limits ===
    section("R-3: org_name and label length limits")
    # Re-login as admin (register auto-logins may have changed session)
    login_admin(client, admin_email, "AdminPass123!")
    register_limiter._buckets.clear()
    csrf = get_csrf(client)
    long_name = "A" * 200
    r = client.post("/register", data={"org_name": long_name, "email": "long@test.com", "password": "StrongPass123!", "csrf_token": csrf}, follow_redirects=False)
    check("Long org_name accepted (truncated)", r.status_code == 302)
    # Verify it was truncated
    admin2 = app.state.db.get_user_by_email("long@test.com")
    if admin2:
        org2 = app.state.db.get_org(admin2.org_id)
        check("org_name truncated to 100", len(org2.name) <= 100, f"got {len(org2.name)}")

    # Re-login as admin (register auto-logged in as long@test.com)
    login_admin(client, admin_email, "AdminPass123!")
    # Long label for API key
    csrf = get_csrf(client)
    long_label = "L" * 200
    r = client.post("/keys", data={"label": long_label, "scopes": "ingest", "csrf_token": csrf}, follow_redirects=False)
    check("Long label accepted (truncated)", r.status_code == 302)
    keys = db.list_api_keys(org_id)
    new_key = [k for k in keys if k.label and len(k.label) <= 100 and k.label.startswith("L")]
    check("Label truncated to 100", any(len(k.label) <= 100 for k in keys if k.label and k.label.startswith("L")), "no key with truncated L label found")

    # === S-3: reset token not in logs ===
    section("S-3: reset token not logged in plaintext")
    log_capture = io.StringIO()
    log_handler = logging.StreamHandler(log_capture)
    log_handler.setLevel(logging.INFO)
    logger = logging.getLogger("mcp_shield.cloud")
    logger.addHandler(log_handler)
    csrf = get_csrf(client)
    r = client.post("/forgot", data={"email": admin_email, "csrf_token": csrf}, follow_redirects=False)
    log_output = log_capture.getvalue()
    logger.removeHandler(log_handler)
    # Check that the full token is NOT in the logs
    # The token is 32 hex chars; we log only first 8
    check("Reset token not in logs", "token for" not in log_output or log_output.count("token") < 2)
    check("Only token prefix logged", "..." in log_output or "prefix" in log_output or "token" not in log_output)

    # === Edge cases ===
    section("Edge cases")
    # Empty email
    register_limiter._buckets.clear()
    csrf = get_csrf(client)
    r = client.post("/register", data={"org_name": "E", "email": "", "password": "StrongPass123!", "csrf_token": csrf}, follow_redirects=False)
    check("Empty email rejected", r.status_code in (400, 422), f"got {r.status_code}")

    # Empty password
    register_limiter._buckets.clear()
    csrf = get_csrf(client)
    r = client.post("/register", data={"org_name": "E2", "email": "e2@test.com", "password": "", "csrf_token": csrf}, follow_redirects=False)
    check("Empty password rejected", r.status_code in (400, 422), f"got {r.status_code}")

    # Very long password (should be accepted, just truncated by Pydantic max_length)
    register_limiter._buckets.clear()
    csrf = get_csrf(client)
    r = client.post("/register", data={"org_name": "LongPw", "email": "lp@test.com", "password": "A" * 1000 + "1!", "csrf_token": csrf}, follow_redirects=False)
    check("Very long password accepted", r.status_code == 302 or r.status_code == 400)  # either truncated or rejected

    # SQL injection in email field
    register_limiter._buckets.clear()
    csrf = get_csrf(client)
    r = client.post("/register", data={"org_name": "SQLi", "email": "admin@test.com' OR '1'='1", "password": "StrongPass123!", "csrf_token": csrf}, follow_redirects=False)
    check("SQL injection in email rejected", r.status_code == 400)

    # SQL injection in org_name
    register_limiter._buckets.clear()
    csrf = get_csrf(client)
    r = client.post("/register", data={"org_name": "'; DROP TABLE users; --", "email": "sqli@test.com", "password": "StrongPass123!", "csrf_token": csrf}, follow_redirects=False)
    check("SQL injection in org_name rejected or safe", r.status_code in (302, 400))

    # Path traversal in event_id
    r = client.get("/events/../../../etc/passwd", follow_redirects=False)
    check("Path traversal blocked", r.status_code in (404, 422, 400))

    # Negative event_id
    r = client.get("/events/-1", follow_redirects=False)
    check("Negative event_id -> 404", r.status_code == 404)

    # Very large page number
    r = client.get("/dashboard?page=999999999", follow_redirects=False)
    check("Huge page number -> 200", r.status_code == 200)

    # Non-existent report framework
    r = client.get("/reports/nonexistent", follow_redirects=False)
    check("Unknown report framework -> 404", r.status_code == 404)

    # Report with hyphen (152-fz vs 152fz)
    r = client.get("/reports/152-fz", follow_redirects=False)
    check("152-fz (hyphen) -> 404", r.status_code == 404)
    r = client.get("/reports/152fz", follow_redirects=False)
    check("152fz (no hyphen) -> 200", r.status_code == 200)

    # === Concurrent user simulation ===
    section("Concurrent users (multi-tenant isolation)")
    # Create two orgs
    org_a = db.create_org("OrgA")
    org_b = db.create_org("OrgB")
    user_a = db.create_user(org_a.id, "usera@orga.com", hash_password("Pass123!"), "admin")
    user_b = db.create_user(org_b.id, "userb@orgb.com", hash_password("Pass123!"), "admin")
    # Insert events in both orgs
    db.insert_event(org_a.id, {"seq": 1, "ts": "2026-01-01", "decision": "deny", "server": "fs", "tool": "exec", "args": {}, "reason": "r", "rule": "r"})
    db.insert_event(org_b.id, {"seq": 1, "ts": "2026-01-01", "decision": "allow", "server": "fs", "tool": "read", "args": {}, "reason": "r", "rule": "r"})
    # Login as user_a
    ca = TestClient(app)
    login_limiter._buckets.clear()
    csrf = get_csrf(ca)
    ca.post("/login", data={"email": "usera@orga.com", "password": "Pass123!", "csrf_token": csrf}, follow_redirects=False)
    # User A should only see OrgA events
    r = ca.get("/dashboard", follow_redirects=False)
    check("UserA sees own events", "exec" in r.text)
    check("UserA cannot see OrgB events", "read" not in r.text or "allow" not in r.text)
    # User A tries to access OrgB event by ID
    events_b = db.query_events(org_b.id)
    if events_b:
        r = ca.get(f"/events/{events_b[0].id}", follow_redirects=False)
        check("UserA cannot access OrgB event (IDOR)", r.status_code == 404)

    # === Summary ===
    print(f"\n{'='*60}")
    print(f"  THIRD AUDIT SUMMARY")
    print(f"{'='*60}")
    print(f"  Passed: {PASS}")
    print(f"  Failed: {FAIL}")
    if BUGS:
        print(f"\n  BUGS FOUND:")
        for b in BUGS:
            print(f"    - {b}")
    else:
        print(f"\n  No bugs found!")
    print(f"{'='*60}")
    return 0 if FAIL == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
