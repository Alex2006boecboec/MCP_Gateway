"""Tests for auth: password hashing + session cookies."""
from mcp_shield.cloud.auth import hash_password, verify_password, SessionManager
from mcp_shield.cloud.models import User


def test_hash_and_verify_password():
    h = hash_password("s3cret")
    assert "$" in h
    assert verify_password("s3cret", h)
    assert not verify_password("wrong", h)


def test_hash_is_salt_unique():
    """Two hashes of the same password differ (random salt)."""
    h1 = hash_password("s3cret")
    h2 = hash_password("s3cret")
    assert h1 != h2
    assert verify_password("s3cret", h1)
    assert verify_password("s3cret", h2)


def test_verify_bad_hash():
    assert not verify_password("x", "")
    assert not verify_password("x", "no-dollar-sign")
    assert not verify_password("x", "badhex$also-bad")


def test_session_create_and_verify():
    sm = SessionManager(secret_key="test-secret")
    user = User(id="u1", org_id="o1", email="a@b.com", role="admin", created_at=0.0)
    token = sm.create_session(user)
    assert token
    payload = sm.verify_session(token)
    assert payload is not None
    assert payload["user_id"] == "u1"
    assert payload["org_id"] == "o1"
    assert payload["role"] == "admin"


def test_session_tampered_rejected():
    sm = SessionManager(secret_key="test-secret")
    user = User(id="u1", org_id="o1", email="a@b.com", role="admin", created_at=0.0)
    token = sm.create_session(user)
    # Tamper with the token.
    tampered = token[:-4] + "AAAA"
    assert sm.verify_session(tampered) is None


def test_session_wrong_secret_rejected():
    sm1 = SessionManager(secret_key="secret-1")
    sm2 = SessionManager(secret_key="secret-2")
    user = User(id="u1", org_id="o1", email="a@b.com", role="admin", created_at=0.0)
    token = sm1.create_session(user)
    # A different secret cannot verify the token.
    assert sm2.verify_session(token) is None


def test_session_empty_token():
    sm = SessionManager(secret_key="test-secret")
    assert sm.verify_session("") is None
    assert sm.verify_session(None) is None


def test_session_auto_secret():
    """If no secret given, one is auto-generated (random)."""
    sm = SessionManager()
    assert sm.secret_key
    user = User(id="u1", org_id="o1", email="a@b.com", role="admin", created_at=0.0)
    token = sm.create_session(user)
    assert sm.verify_session(token) is not None
