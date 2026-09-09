"""In-memory rate limiter for login and register endpoints.

Tracks:
  - Login: per-email failed attempts (5 per 15 min → lockout),
           per-IP (20/min → 429)
  - Register: per-IP (3/hour → 429)

For MVP this is in-memory (per-process). In production with multiple
workers, use Redis. The limiter is intentionally simple: sliding window
with cleanup of expired entries.

Thread-safe via a lock.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class _Bucket:
    """A counter bucket with a window."""
    count: int = 0
    first_seen: float = 0.0


class RateLimiter:
    """Sliding window rate limiter. Thread-safe."""

    def __init__(self):
        self._lock = threading.Lock()
        # key -> list of timestamps
        self._buckets: dict[str, list[float]] = defaultdict(list)

    def _cleanup(self, key: str, window: float, now: float) -> None:
        """Remove timestamps older than the window."""
        bucket = self._buckets[key]
        cutoff = now - window
        self._buckets[key] = [t for t in bucket if t > cutoff]

    def check(self, key: str, max_count: int, window: float) -> bool:
        """Check if a request is allowed. Returns True if allowed, False if rate limited.

        Records the attempt if allowed.
        """
        now = time.time()
        with self._lock:
            self._cleanup(key, window, now)
            bucket = self._buckets[key]
            if len(bucket) >= max_count:
                return False
            bucket.append(now)
            return True

    def record_failure(self, key: str) -> None:
        """Record a failed attempt for a key (for login lockout)."""
        now = time.time()
        with self._lock:
            self._buckets[key].append(now)

    def reset(self, key: str) -> None:
        """Reset the counter for a key (e.g. after successful login)."""
        with self._lock:
            self._buckets.pop(key, None)

    def count(self, key: str, window: float) -> int:
        """Get current count for a key within the window."""
        now = time.time()
        with self._lock:
            self._cleanup(key, window, now)
            return len(self._buckets[key])


# Global rate limiters.
login_limiter = RateLimiter()
register_limiter = RateLimiter()

# Login rate limit parameters.
LOGIN_MAX_PER_EMAIL = 5          # failed attempts per window
LOGIN_WINDOW_EMAIL = 15 * 60     # 15 minutes
LOGIN_MAX_PER_IP = 20             # attempts per minute
LOGIN_WINDOW_IP = 60             # 1 minute
LOGIN_DELAY_AFTER = 3            # start delaying after this many failures
LOGIN_DELAY_SECONDS = 2          # delay per failure above threshold

# Register rate limit parameters.
REGISTER_MAX_PER_IP = 3           # registrations per hour
REGISTER_WINDOW = 3600            # 1 hour


def check_login_allowed(email: str, ip: str) -> tuple[bool, str]:
    """Check if a login attempt is allowed. Returns (allowed, reason)."""
    ip_key = f"login:ip:{ip}"
    email_key = f"login:email:{email}"

    # Check IP rate limit.
    if not login_limiter.check(ip_key, LOGIN_MAX_PER_IP, LOGIN_WINDOW_IP):
        return False, "Too many login attempts from this IP. Try again later."

    # Check email lockout (failed attempts).
    failed = login_limiter.count(email_key, LOGIN_WINDOW_EMAIL)
    if failed >= LOGIN_MAX_PER_EMAIL:
        return False, "Account temporarily locked due to too many failed attempts. Try again later."

    return True, ""


def record_login_failure(email: str) -> None:
    """Record a failed login attempt for rate limiting and lockout."""
    login_limiter.record_failure(f"login:email:{email}")


def record_login_success(email: str) -> None:
    """Reset failed attempts counter after successful login."""
    login_limiter.reset(f"login:email:{email}")


def get_login_delay(email: str) -> float:
    """Get the delay (in seconds) to wait before responding to a login attempt.
    After 3 failures, each additional failure adds 2 seconds of delay.
    """
    failed = login_limiter.count(f"login:email:{email}", LOGIN_WINDOW_EMAIL)
    if failed <= LOGIN_DELAY_AFTER:
        return 0.0
    return (failed - LOGIN_DELAY_AFTER) * LOGIN_DELAY_SECONDS


def check_register_allowed(ip: str) -> tuple[bool, str]:
    """Check if a registration attempt is allowed. Returns (allowed, reason)."""
    ip_key = f"register:ip:{ip}"
    if not register_limiter.check(ip_key, REGISTER_MAX_PER_IP, REGISTER_WINDOW):
        return False, "Too many registrations from this IP. Try again later."
    return True, ""
