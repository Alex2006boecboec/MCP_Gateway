"""Comprehensive audit — simulates ALL user flows to find bugs.

Run:  python tests/audit_simulation.py
"""
from __future__ import annotations
import json, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from mcp_shield.cloud.server import create_app
from mcp_shield.cloud.rate_limit import login_limiter, register_limiter

PASS = 0
FAIL = 0
BUGS: list[str] = []

def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [OK] {name}")
    else:
        FAIL += 1
        BUGS.append(f"{name}: {detail}")
        print(f"  [FAIL] {name} -- {detail}")

def section(title):
    print(f"\n{'='*60}\n  {title}\n{'='*60}")

def get_csrf(c):
    c.get("/login")
    return c.cookies.get("mcp_shield_csrf", "")

def do_login(c, email, pw, csrf=None):
    if csrf is None:
        csrf = get_csrf(c)
    return c.post("/login", data={"email": email, "password": pw, "csrf_token": csrf}, follow_redirects=False)

def main():
    db_path = tempfile.mktemp(suffix="_audit.db")
    app = create_app(db_path, secret="audit-secret")
    client = TestClient(app)
    db = app.state.db
    admin = db.get_user_by_email("admin@mcp-shield.local")
    org_id = admin.org_id
    admin_email = "admin@mcp-shield.local"

    # Run all test sections
    test_registration(client, db, org_id)
    test_login(client, admin_email)
    test_dashboard(client, db, org_id)
    test_reports(client)
    test_users(client, db, org_id, admin_email)
    test_api_keys(client, db, org_id)
    test_audit(client)
    test_settings(client, admin_email)
    test_password_reset(client, db, admin_email)
    test_ingest_api(client, db, org_id)
    test_gdpr(client)
    test_health(client)
    test_security_headers(client)
    test_viewer_permissions(client, db, org_id)

    # Summary
    print(f"\n{'='*60}")
    print(f"  AUDIT SUMMARY")
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


def test_registration(client, db, org_id):
    section("1. REGISTRATION")
    register_limiter._buckets.clear()
    csrf = get_csrf(client)
    r = client.post("/register", data={
        "org_name": "AuditCorp", "email": "ceo@auditcorp.com",
        "password": "StrongPass123!", "csrf_token": csrf,
    }, follow_redirects=False)
    check("1a. Valid registration -> 302", r.status_code == 302, f"got {r.status_code}")

    register_limiter._buckets.clear()
    csrf = get_csrf(client)
    r = client.post("/register", data={
        "org_name": "Dup", "email": "ceo@auditcorp.com",
        "password": "StrongPass123!", "csrf_token": csrf,
    }, follow_redirects=False)
    check("1b. Duplicate email -> 400", r.status_code == 400)

    register_limiter._buckets.clear()
    csrf = get_csrf(client)
    r = client.post("/register", data={
        "org_name": "Weak", "email": "w@w.com",
        "password": "short", "csrf_token": csrf,
    }, follow_redirects=False)
    check("1c. Short password -> 400", r.status_code == 400)

    register_limiter._buckets.clear()
    csrf = get_csrf(client)
    r = client.post("/register", data={
        "org_name": "NoUpper", "email": "n@n.com",
        "password": "alllowercase123", "csrf_token": csrf,
    }, follow_redirects=False)
    check("1d. No uppercase -> 400", r.status_code == 400)

    register_limiter._buckets.clear()
    client.get("/login")
    r = client.post("/register", data={
        "org_name": "NoCSRF", "email": "n@n.com", "password": "StrongPass123!",
    }, follow_redirects=False)
    check("1e. No CSRF -> 403", r.status_code == 403)


def test_login(client, admin_email):
    section("2. LOGIN")
    login_limiter._buckets.clear()
    csrf = get_csrf(client)
    r = do_login(client, admin_email, "admin", csrf)
    check("2a. Valid login -> 302", r.status_code == 302)

    login_limiter._buckets.clear()
    csrf = get_csrf(client)
    r = do_login(client, admin_email, "wrong", csrf)
    check("2b. Wrong password -> 401", r.status_code == 401)

    login_limiter._buckets.clear()
    csrf = get_csrf(client)
    r = do_login(client, "nobody@nowhere.com", "x", csrf)
    check("2c. Unknown email -> 401", r.status_code == 401)

    login_limiter._buckets.clear()
    client.get("/login")
    r = client.post("/login", data={"email": admin_email, "password": "admin"}, follow_redirects=False)
    check("2d. No CSRF -> 403", r.status_code == 403)

    # Rate limit lockout
    login_limiter._buckets.clear()
    csrf = get_csrf(client)
    for i in range(5):
        client.post("/login", data={"email": "rl@test.com", "password": "wrong", "csrf_token": csrf}, follow_redirects=False)
    r = client.post("/login", data={"email": "rl@test.com", "password": "wrong", "csrf_token": csrf}, follow_redirects=False)
    check("2e. Rate limit -> 429", r.status_code == 429)


def test_dashboard(client, db, org_id):
    section("3. DASHBOARD")
    login_limiter._buckets.clear()
    csrf = get_csrf(client)
    do_login(client, "admin@mcp-shield.local", "admin", csrf)

    # Bootstrap admin has must_change_password=True — dashboard should redirect.
    r = client.get("/dashboard", follow_redirects=False)
    check("3a. Dashboard with must_change -> 302", r.status_code == 302, f"got {r.status_code}")

    # Change password to clear must_change_password.
    csrf = get_csrf(client)
    client.post("/settings", data={
        "old_password": "admin", "new_password": "AdminPass123!",
        "new_password_confirm": "AdminPass123!", "csrf_token": csrf,
    }, follow_redirects=False)

    # Now dashboard should be accessible.
    r = client.get("/dashboard", follow_redirects=False)
    check("3a2. Dashboard after password change -> 200", r.status_code == 200, f"got {r.status_code}")

    client2 = TestClient(app := client.app)
    r = client2.get("/dashboard", follow_redirects=False)
    check("3b. No login -> 403", r.status_code == 403)

    r = client.get("/dashboard?decision=deny", follow_redirects=False)
    check("3c. Filter -> 200", r.status_code == 200)

    # IDOR test
    org2 = db.create_org("Other")
    db.insert_event(org2.id, {"seq": 1, "ts": "2026-01-01", "decision": "deny",
                               "server": "fs", "tool": "x", "args": {}, "reason": "r", "rule": "r"})
    other_events = db.query_events(org2.id)
    if other_events:
        r = client.get(f"/events/{other_events[0].id}", follow_redirects=False)
        check("3e. Cross-org IDOR -> 404", r.status_code == 404, f"got {r.status_code} -- SECURITY BUG!")


def test_reports(client):
    section("4. REPORTS")
    check("4a. Reports page", client.get("/reports").status_code == 200)
    check("4b. SOC2", client.get("/reports/soc2").status_code == 200)
    check("4c. ISO27001", client.get("/reports/iso27001").status_code == 200)
    check("4d. 152fz", client.get("/reports/152fz").status_code == 200)
    r = client.get("/reports/soc2/download")
    check("4e. CSV download", r.status_code == 200 and "text/csv" in r.headers.get("content-type", ""))


def test_users(client, db, org_id, admin_email):
    section("5. USERS")
    check("5a. Users page", client.get("/users").status_code == 200)

    csrf = get_csrf(client)
    r = client.post("/users", data={"email": "viewer@test.com", "password": "ViewerPass123!",
        "role": "viewer", "csrf_token": csrf}, follow_redirects=False)
    check("5b. Create viewer -> 302", r.status_code == 302)

    csrf = get_csrf(client)
    r = client.post("/users", data={"email": "analyst@test.com", "password": "AnalystPass123!",
        "role": "analyst", "csrf_token": csrf}, follow_redirects=False)
    check("5c. Create analyst -> 302", r.status_code == 302)

    csrf = get_csrf(client)
    r = client.post("/users", data={"email": "viewer@test.com", "password": "X",
        "role": "viewer", "csrf_token": csrf}, follow_redirects=False)
    check("5d. Duplicate email -> 400", r.status_code == 400)

    viewer = db.get_user_by_email("viewer@test.com")
    csrf = get_csrf(client)
    r = client.post(f"/users/{viewer.id}/delete", data={"csrf_token": csrf}, follow_redirects=False)
    check("5e. Delete viewer -> 302", r.status_code == 302)
    check("5e. Soft-deleted", db.get_user(viewer.id).deleted)

    admin = db.get_user_by_email(admin_email)
    csrf = get_csrf(client)
    r = client.post(f"/users/{admin.id}/delete", data={"csrf_token": csrf}, follow_redirects=False)
    check("5f. Self-delete -> 400", r.status_code == 400)

    analyst = db.get_user_by_email("analyst@test.com")
    csrf = get_csrf(client)
    r = client.post(f"/users/{analyst.id}/role", data={"role": "admin", "csrf_token": csrf}, follow_redirects=False)
    check("5h. Role change -> 302", r.status_code == 302)
    check("5h. Role = admin", db.get_user(analyst.id).role == "admin")

    csrf = get_csrf(client)
    r = client.post(f"/users/{admin.id}/role", data={"role": "viewer", "csrf_token": csrf}, follow_redirects=False)
    check("5i. Self role change -> 400", r.status_code == 400)


def test_api_keys(client, db, org_id):
    section("6. API KEYS")
    check("6a. Keys page", client.get("/keys").status_code == 200)

    csrf = get_csrf(client)
    r = client.post("/keys", data={"label": "test-ingest", "scopes": "ingest", "csrf_token": csrf}, follow_redirects=False)
    check("6b. Create ingest key -> 302", r.status_code == 302)

    csrf = get_csrf(client)
    r = client.post("/keys", data={"label": "test-read", "scopes": "read", "csrf_token": csrf}, follow_redirects=False)
    check("6c. Create read key -> 302", r.status_code == 302)

    keys = db.list_api_keys(org_id)
    ingest_key = next((k for k in keys if k.label == "test-ingest"), None)
    read_key = next((k for k in keys if k.label == "test-read"), None)
    check("6d. Ingest key has scope", ingest_key and "ingest" in ingest_key.scopes)
    check("6e. Read key has scope", read_key and "read" in read_key.scopes)

    if ingest_key:
        csrf = get_csrf(client)
        r = client.post(f"/keys/{ingest_key.key}/revoke", data={"csrf_token": csrf}, follow_redirects=False)
        check("6f. Revoke key -> 302", r.status_code == 302)


def test_audit(client):
    section("7. AUDIT LOG")
    r = client.get("/audit", follow_redirects=False)
    check("7a. Audit page (admin) -> 200", r.status_code == 200)


def test_settings(client, admin_email):
    section("8. SETTINGS (password change)")
    check("8a. Settings page", client.get("/settings").status_code == 200)

    csrf = get_csrf(client)
    r = client.post("/settings", data={"old_password": "wrong", "new_password": "NewPass123!",
        "new_password_confirm": "NewPass123!", "csrf_token": csrf}, follow_redirects=False)
    check("8b. Wrong old -> 400", r.status_code == 400)

    csrf = get_csrf(client)
    r = client.post("/settings", data={"old_password": "admin", "new_password": "NewPass123!",
        "new_password_confirm": "Different!", "csrf_token": csrf}, follow_redirects=False)
    check("8c. Mismatch -> 400", r.status_code == 400)

    csrf = get_csrf(client)
    r = client.post("/settings", data={"old_password": "admin", "new_password": "weak",
        "new_password_confirm": "weak", "csrf_token": csrf}, follow_redirects=False)
    check("8d. Weak new -> 400", r.status_code == 400)


def test_password_reset(client, db, admin_email):
    section("9. PASSWORD RESET")
    check("9a. Forgot page", client.get("/forgot").status_code == 200)
    csrf = get_csrf(client)
    r = client.post("/forgot", data={"email": admin_email, "csrf_token": csrf}, follow_redirects=False)
    check("9b. Forgot submit -> 200", r.status_code == 200)

    admin = db.get_user_by_email(admin_email)
    if admin:
        token = db.create_password_reset(admin.id, ttl=3600)
        check("9c. Reset page (valid)", client.get(f"/reset?token={token}").status_code == 200)
        csrf = get_csrf(client)
        r = client.post("/reset", data={"token": token, "new_password": "BrandNewPass123!",
            "new_password_confirm": "BrandNewPass123!", "csrf_token": csrf}, follow_redirects=False)
        check("9d. Reset -> 302", r.status_code == 302)
        check("9e. Token used", db.get_password_reset(token) is None)

        exp_token = db.create_password_reset(admin.id, ttl=-1)
        csrf = get_csrf(client)
        r = client.post("/reset", data={"token": exp_token, "new_password": "BrandNewPass123!",
            "new_password_confirm": "BrandNewPass123!", "csrf_token": csrf}, follow_redirects=False)
        check("9f. Expired token -> 400", r.status_code == 400)


def test_ingest_api(client, db, org_id):
    section("10. INGEST API")
    entry = {"seq": 999, "ts": "2026-01-01", "decision": "deny", "server": "fs",
             "tool": "exec", "args": {}, "reason": "r", "rule": "r"}
    keys = db.list_api_keys(org_id)
    ingest_key = next((k for k in keys if "ingest" in k.scopes and not k.revoked), None)
    read_key = next((k for k in keys if k.scopes == ["read"] and not k.revoked), None)

    if ingest_key:
        r = client.post("/api/v1/ingest", json={"entries": [entry]},
            headers={"Authorization": f"Bearer {ingest_key.key}"})
        check("10a. Valid ingest -> 200", r.status_code == 200)

    r = client.post("/api/v1/ingest", json={"entries": [entry]},
        headers={"Authorization": "Bearer invalid_key"})
    check("10b. Invalid key -> 401", r.status_code == 401)

    r = client.post("/api/v1/ingest", json={"entries": [entry]})
    check("10c. No auth -> 401", r.status_code == 401)

    if read_key:
        r = client.post("/api/v1/ingest", json={"entries": [entry]},
            headers={"Authorization": f"Bearer {read_key.key}"})
        check("10d. Wrong scope -> 403", r.status_code == 403)

    if ingest_key:
        r = client.post("/api/v1/ingest", json={"not_entries": []},
            headers={"Authorization": f"Bearer {ingest_key.key}"})
        check("10e. Bad body -> 422", r.status_code == 422)

        big = [{"seq": i, "ts": "2026-01-01", "decision": "deny", "server": "fs",
                "tool": "x", "args": {}, "reason": "r", "rule": "r"} for i in range(101)]
        r = client.post("/api/v1/ingest", json={"entries": big},
            headers={"Authorization": f"Bearer {ingest_key.key}"})
        check("10f. Large batch -> 413", r.status_code == 413)


def test_gdpr(client):
    section("11. GDPR")
    # Re-login (session may be invalidated by password reset in section 9).
    login_limiter._buckets.clear()
    csrf = get_csrf(client)
    do_login(client, "admin@mcp-shield.local", "BrandNewPass123!", csrf)
    r = client.get("/org/export", follow_redirects=False)
    check("11a. Export -> 200", r.status_code == 200, f"got {r.status_code}")
    check("11b. Export is JSON", "application/json" in r.headers.get("content-type", ""))
    data = json.loads(r.content)
    check("11c. Export has org", data.get("org") is not None)
    check("11d. Export has users", len(data.get("users", [])) > 0)

    csrf = get_csrf(client)
    r = client.post("/org/delete", data={"confirm": "yes", "csrf_token": csrf}, follow_redirects=False)
    check("11e. Delete without DELETE -> 400", r.status_code == 400)


def test_health(client):
    section("12. HEALTH")
    r = client.get("/health")
    check("12a. Health -> 200", r.status_code == 200)
    check("12b. Health has status", "status" in r.json())


def test_security_headers(client):
    section("13. SECURITY HEADERS")
    r = client.get("/login")
    check("13a. X-Frame-Options", r.headers.get("x-frame-options") == "DENY")
    check("13b. X-Content-Type-Options", r.headers.get("x-content-type-options") == "nosniff")
    check("13c. Referrer-Policy", "strict-origin" in r.headers.get("referrer-policy", ""))
    check("13d. CSP", "default-src" in r.headers.get("content-security-policy", ""))


def test_viewer_permissions(client, db, org_id):
    section("14. VIEWER PERMISSIONS (RBAC)")
    # Create a viewer with known password.
    from mcp_shield.cloud.auth import hash_password
    viewer = db.create_user(org_id, "view@test.com", hash_password("ViewerPass123!"), "viewer")
    login_limiter._buckets.clear()
    csrf = get_csrf(client)
    r = do_login(client, "view@test.com", "ViewerPass123!", csrf)
    check("14a. Viewer login -> 302", r.status_code == 302, f"got {r.status_code}")

    # Viewer can see dashboard.
    check("14b. Viewer dashboard", client.get("/dashboard").status_code == 200)

    # Viewer CANNOT manage users.
    check("14c. Viewer users page -> 403", client.get("/users").status_code == 403)

    # Viewer CANNOT manage keys.
    check("14d. Viewer keys page -> 403", client.get("/keys").status_code == 403)

    # Viewer CANNOT view audit.
    check("14e. Viewer audit -> 403", client.get("/audit").status_code == 403)

    # Viewer CANNOT delete users.
    admin = db.get_user_by_email("admin@mcp-shield.local")
    csrf = get_csrf(client)
    r = client.post(f"/users/{admin.id}/delete", data={"csrf_token": csrf}, follow_redirects=False)
    check("14f. Viewer delete user -> 403", r.status_code == 403)

    # Viewer CANNOT create keys.
    csrf = get_csrf(client)
    r = client.post("/keys", data={"label": "hack", "scopes": "ingest", "csrf_token": csrf}, follow_redirects=False)
    check("14g. Viewer create key -> 403", r.status_code == 403)


if __name__ == "__main__":
    sys.exit(main())
