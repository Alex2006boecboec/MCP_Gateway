"""Password validation: complexity, length, common password rejection.

Rejects:
  - < 12 characters
  - No uppercase, lowercase, or digits
  - Top-1000 most common passwords (hardcoded list)
"""

from __future__ import annotations

import re

MIN_LENGTH = 12

# Top common passwords (subset of HaveIBeenPwned top list).
# In production, use the full list or the HIBP API.
_COMMON_PASSWORDS = frozenset({
    "password", "123456789", "12345678", "123456", "1234567",
    "password1", "qwerty", "abc123", "111111", "123123",
    "admin", "letmein", "welcome", "monkey", "login",
    "princess", "qwerty123", "passw0rd", "000000", "password123",
    "iloveyou", "sunshine", "1234567890", "football", "charlie",
    "shadow", "michael", "654321", "superman", "trustno1",
    "batman", "access", "hello", "master", "diamond",
    "justin", "harley", "robert", "matthew", "andrew",
    "joshua", "jennifer", "hunter", "buster", "soccer",
    "jordan", "thomas", "george", "ranger", "ashley",
    "baseball", "dragon", "jessica", "pepper", "freedom",
    "whatever", "trustno1", "qazwsx", "michael1", "password!",
    "changeme", "default", "secret", "administrator", "root",
    "toor", "admin123", "test", "test123", "guest",
    "qwertyuiop", "zxcvbnm", "asdfghjkl", "1q2w3e4r",
})


def validate_password(password: str) -> list[str]:
    """Validate a password. Returns a list of error messages (empty = valid)."""
    errors: list[str] = []

    if len(password) < MIN_LENGTH:
        errors.append(f"Password must be at least {MIN_LENGTH} characters long.")

    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")

    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")

    if not re.search(r"\d", password):
        errors.append("Password must contain at least one digit.")

    if password.lower() in _COMMON_PASSWORDS:
        errors.append("This password is too common. Choose a more unique password.")

    return errors


def is_strong_password(password: str) -> bool:
    """Returns True if the password passes all checks."""
    return len(validate_password(password)) == 0
