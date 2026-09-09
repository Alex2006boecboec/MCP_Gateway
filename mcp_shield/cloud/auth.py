"""Authentication for the cloud dashboard (Phase 5).

Two mechanisms:
  1. Password (MVP, always available) - pbkdf2_hmac (stdlib), signed session
     cookies via itsdangerous.
  2. SSO / OIDC (optional, configured via env) - not implemented in MVP;
     /sso/login returns 501 if OIDC env vars are unset.

No bcrypt dep (keep it stdlib for MVP). Session cookies are signed so they
cannot be forged.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import time
from typing import Optional

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from mcp_shield.cloud.models import User

# pbkdf2 parameters.
_PBKDF2_ITERATIONS = 200_000
_SALT_BYTES = 16
_HASH_ALGO = "sha256"

# Session cookie parameters.
_SESSION_MAX_AGE = 7 * 24 * 3600  # 7 days


def hash_password(password: str) -> str:
    """Hash a password with a random salt. Returns 'salt$hash' (both hex)."""
    salt = secrets.token_hex(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(_HASH_ALGO, password.encode("utf-8"),
                             bytes.fromhex(salt), _PBKDF2_ITERATIONS)
    return f"{salt}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored 'salt$hash' string."""
    if not stored_hash or "$" not in stored_hash:
        return False
    salt_hex, hash_hex = stored_hash.split("$", 1)
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac(_HASH_ALGO, password.encode("utf-8"),
                             salt, _PBKDF2_ITERATIONS)
    return secrets.compare_digest(dk, expected)


class SessionManager:
    """Signed session cookie management via itsdangerous."""

    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or os.environ.get("MCP_SHIELD_SESSION_SECRET") or secrets.token_hex(32)
        self._serializer = URLSafeTimedSerializer(self.secret_key, salt="mcp-shield-session")

    def create_session(self, user: User, token_version: int = 0) -> str:
        """Create a signed session token for a user. The token encodes
        (user_id, org_id, role, email, token_version) with a timestamp."""
        payload = {
            "user_id": user.id,
            "org_id": user.org_id,
            "role": user.role,
            "email": user.email,
            "token_version": token_version,
        }
        return self._serializer.dumps(payload)

    def verify_session(self, token: str) -> Optional[dict]:
        """Verify a signed session token. Returns the payload dict, or None
        if the token is invalid, expired, or tampered."""
        if not token:
            return None
        try:
            payload = self._serializer.loads(token, max_age=_SESSION_MAX_AGE)
        except (BadSignature, SignatureExpired):
            return None
        if not isinstance(payload, dict):
            return None
        return payload
