"""Sensitive source detection + fingerprinting (Phase 3).

A call is a "sensitive source" if its capability is a read-type AND its
arguments/response match a sensitive pattern. We detect three kinds:

  1. Sensitive file paths in request args (e.g. ~/.ssh/id_rsa).
  2. Secret content in the response, detected via the redactor's in-memory
     Redaction objects (we reuse Phase 1's redaction output — no new
     secret scanning, and the secret value never touches the log).
  3. Env-var-like content in the response (KEY=value lines where KEY
     looks like a secret name).

Fingerprinting: sha256(value)[:size]. The fingerprint lets the graph
match the same value later in a sink's arguments WITHOUT storing the
secret. In-memory only; never written to disk.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Optional

# (regex, label). Matched against any string value in request args.
SENSITIVE_PATH_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"~/\.ssh/(id_rsa|id_ed25519|id_ecdsa|id_dsa|config|authorized_keys)"), "secret:ssh_key"),
    (re.compile(r"~/\.aws/credentials"), "secret:aws_creds"),
    (re.compile(r"~/\.aws/config"), "secret:aws_config"),
    (re.compile(r"~/\.env(\.local|\.production|\.development)?$"), "secret:env_file"),
    (re.compile(r"~/\.netrc"), "secret:netrc"),
    (re.compile(r"~/\.npmrc"), "secret:npmrc"),
    (re.compile(r"~/\.pypirc"), "secret:pypirc"),
    (re.compile(r"~/\.config/([^/]+/)?credentials"), "secret:cloud_creds"),
    (re.compile(r"~/\.docker/config\.json"), "secret:docker_creds"),
    (re.compile(r"~/\.kube/config"), "secret:kube_creds"),
    (re.compile(r"/etc/(passwd|shadow|gshadow)"), "secret:system_file"),
    (re.compile(r"\.pem$"), "secret:pem_key"),
    (re.compile(r"\.key$"), "secret:key_file"),
]

# Env-var-like lines: KEY=value where value is non-trivial.
_ENV_VAR_RE = re.compile(r"(?m)^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(\S.{8,})\s*$")
# Key names that look like secrets.
_SECRET_KEY_NAMES = re.compile(r"(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CREDENTIAL|ACCESS_KEY)")

# Capabilities that count as "read-type" sources.
SOURCE_CAPS = {"read:filesystem", "read:secret", "read:env", "read:database", "read:network"}


def is_sensitive_source(
    tool: str,
    args: dict[str, Any],
    capabilities: list[str],
) -> tuple[bool, str]:
    """Return (is_sensitive, label).

    A call is sensitive if it has a read capability AND its args reference a
    sensitive path. The label is the taint label (e.g. "secret:ssh_key").
    """
    if not any(c in SOURCE_CAPS for c in capabilities):
        return False, ""
    # Scan all string values in args for sensitive paths.
    for value in _iter_string_values(args):
        for pat, label in SENSITIVE_PATH_PATTERNS:
            if pat.search(value):
                return True, label
    return False, ""


def extract_sensitive_values_from_response(
    redactions: list,  # list of Redaction objects (from the redactor)
    response_text: str,
) -> list[tuple[str, str]]:
    """Return [(label, value)] of sensitive values found in the response.

    Two sources:
      1. redactions: each Redaction has .original (in-memory secret) and
         .name (the pattern name, e.g. "aws_access_key_id"). We map the
         pattern name to a taint label.
      2. env-var scan: response text with KEY=value lines where KEY looks
         like a secret name.

    The VALUES are returned in-memory only for fingerprinting; the caller
    fingerprints them and discards. They are NEVER logged.
    """
    out: list[tuple[str, str]] = []
    # 1. From redactor redactions.
    for red in redactions:
        original = getattr(red, "original", None)
        name = getattr(red, "name", "")
        if original and isinstance(original, str) and len(original) >= 8:
            label = _redaction_name_to_label(name)
            out.append((label, original))
    # 2. From env-var scan.
    for m in _ENV_VAR_RE.finditer(response_text or ""):
        key, value = m.group(1), m.group(2)
        if _SECRET_KEY_NAMES.search(key) and len(value) >= 8:
            out.append((f"env:{key}", value))
    return out


def _redaction_name_to_label(name: str) -> str:
    """Map a redactor pattern name to a taint label."""
    return f"secret:{name}" if name else "secret:redacted"


def _iter_string_values(args: dict[str, Any]):
    """Yield all string values in a (possibly nested) args dict."""
    for value in args.values():
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for v in _iter_string_values(value):
                yield v
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    yield item
                elif isinstance(item, dict):
                    yield from _iter_string_values(item)


def fingerprint(value: str, size: int = 16) -> str:
    """sha256(value)[:size]. In-memory only; never logged.

    Used to match the same secret value later in a sink's arguments without
    storing the secret itself.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:size]


def fingerprint_arg_values(
    args: dict[str, Any],
    max_scan_chars: int = 50_000,
    fp_size: int = 16,
) -> set[str]:
    """Return the set of fingerprints of all string values in args.

    Used by the graph to check whether a sink call's arguments contain a
    value matching an active taint. We fingerprint each whole string value
    (the common exfil case: the agent passes the secret directly as an arg
    value). Secrets embedded inside a larger string are caught by Phase 1's
    redactor (which masks them in args before forwarding) — the graph also
    fingerprints the redactor's in-memory originals via a separate path.

    To bound cost, values longer than max_scan_chars are skipped (a 50KB arg
    is unlikely to be a single secret value).
    """
    fps: set[str] = set()
    for value in _iter_string_values(args):
        if not isinstance(value, str) or not value:
            continue
        if len(value) <= max_scan_chars:
            fps.add(fingerprint(value, fp_size))
    return fps


def fingerprint_redactions(
    redactions: list,
    fp_size: int = 16,
) -> set[str]:
    """Fingerprint the in-memory originals of redactions found in a sink's args.

    The redactor (Phase 1) masks secrets in request args and records each
    Redaction with .original (the raw secret, in memory only). The graph
    fingerprints those originals to match against taints — this catches the
    case where the agent passes a known-format secret (that the redactor
    recognized) into a sink's arguments.
    """
    fps: set[str] = set()
    for red in redactions:
        original = getattr(red, "original", None)
        if isinstance(original, str) and len(original) >= 8:
            fps.add(fingerprint(original, fp_size))
    return fps
