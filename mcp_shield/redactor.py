"""Secret redaction — strip credentials from arguments and responses.

We use a curated set of regex patterns for well-known credential
formats (AWS, GCP, GitHub, Slack, OpenAI, generic private keys). This is
deterministic and fast; it is NOT a substitute for a full DLP engine, but
it catches the common high-impact leaks that would otherwise end up in the
agent's context and the audit log.

Redaction is bidirectional:
- On the way IN:  strip secrets from arguments so they don't reach the
                  downstream MCP server in the clear.
- On the way OUT: strip secrets from responses so they don't reach the
                  agent's context (and from there, the next LLM call / logs).

Each redaction is recorded so the audit log can show what was masked.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# (name, pattern, mask-label)
# Patterns are intentionally anchored to avoid false positives on prose.
# Mask labels are ASCII-only to avoid encoding issues on Windows consoles.
_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    # AWS access key id -- 20 chars, uppercase alnum, AKIA prefix.
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws_access_key_id"),
    # AWS secret access key -- 40 chars base64-ish. We require a boundary
    # marker to avoid matching arbitrary base64.
    ("aws_secret_access_key", re.compile(r"\b(AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[=:]\s*([A-Za-z0-9/+=]{40})\b"), "aws_secret_access_key"),
    # GitHub personal access token (classic) -- ghp_ + 36 chars.
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "github_pat"),
    # GitHub fine-grained token -- github_pat_ + 82 chars (simplified).
    ("github_fine_grained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"), "github_fine_grained"),
    # Slack token -- xox + b/p + 10-13 + dash + 48+.
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,48}\b"), "slack_token"),
    # OpenAI / Anthropic API keys -- sk-... (OpenAI) and sk-ant-... (Anthropic).
    ("openai_api_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "openai_api_key"),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), "anthropic_api_key"),
    # Google API key -- AIza + 35 chars.
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "google_api_key"),
    # Generic private key PEM block (header line only).
    ("private_key_pem", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----"), "private_key_pem"),
    # Generic Bearer token in Authorization header.
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.=]{20,}\b"), "bearer_token"),
    # Connection string with embedded password.
    ("conn_string_password", re.compile(r"(postgres|mongodb|redis|amqp)://[^:\s]+:([^@\s]+)@"), "conn_string_password"),
]

# Pre-compile for speed.
_COMPILED = [(name, pat, mask) for name, pat, mask in _PATTERNS]


@dataclass
class Redaction:
    name: str
    original: str   # the matched substring (kept only in memory, never written to disk)
    replacement: str
    field: str       # which argument/response field it was found in


class SecretRedactor:
    """Scan and mask known credential patterns in strings."""

    def __init__(self, extra_patterns: list[tuple[str, re.Pattern[str], str]] | None = None):
        self.patterns = list(_COMPILED)
        if extra_patterns:
            self.patterns.extend(extra_patterns)

    def redact(self, value: str, field_name: str = "") -> tuple[str, list[Redaction]]:
        """Return (redacted_value, list_of_redactions)."""
        if not isinstance(value, str):
            value = str(value)
        redactions: list[Redaction] = []
        redacted = value
        for name, pat, mask in self.patterns:
            for m in pat.finditer(redacted):
                original = m.group(0)
                replacement = self._mask(original, mask)
                redacted = redacted.replace(original, replacement, 1)
                redactions.append(Redaction(name=name, original=original, replacement=replacement, field=field_name))
        return redacted, redactions

    def redact_dict(self, data: dict, container: str = "") -> tuple[dict, list[Redaction]]:
        """Recursively redact all string values in a dict. Returns (new_dict, redactions)."""
        all_redactions: list[Redaction] = []
        out: dict = {}
        for key, value in data.items():
            path = f"{container}.{key}" if container else key
            if isinstance(value, str):
                redacted, reds = self.redact(value, path)
                out[key] = redacted
                all_redactions.extend(reds)
            elif isinstance(value, dict):
                sub, reds = self.redact_dict(value, path)
                out[key] = sub
                all_redactions.extend(reds)
            elif isinstance(value, list):
                new_list = []
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        redacted, reds = self.redact(item, f"{path}[{i}]")
                        new_list.append(redacted)
                        all_redactions.extend(reds)
                    elif isinstance(item, dict):
                        sub, reds = self.redact_dict(item, f"{path}[{i}]")
                        new_list.append(sub)
                        all_redactions.extend(reds)
                    else:
                        new_list.append(item)
                out[key] = new_list
            else:
                out[key] = value
        return out, all_redactions

    @staticmethod
    def _mask(original: str, mask_label: str) -> str:
        # Keep first 4 and last 2 chars visible for debuggability, mask the middle.
        if len(original) <= 8:
            return f"[REDACTED:{mask_label}]"
        return f"{original[:4]}...[REDACTED:{mask_label}]...{original[-2:]}"
