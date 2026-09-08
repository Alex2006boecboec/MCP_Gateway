"""Layer 0 — Regex detection (mandatory, deterministic, stdlib only).

Scans normalized text against curated regex patterns. Also handles
base64 decode-and-rescan: a long base64 blob is decoded and rescanned,
and if the decoded text matches a high-confidence pattern, the base64
signal's score is boosted to 0.95.

Normalization defeats common obfuscation:
  - zero-width characters stripped
  - RTL/LTR override characters stripped
  - common Cyrillic/Greek homoglyphs converted to ASCII
  - whitespace collapsed (newlines preserved — they are a heuristic signal)
  - lowercased copy used for matching (original kept for detail)
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Optional

from mcp_shield.detector.patterns import REGEX_PATTERNS
from mcp_shield.detector.types import Signal

# Zero-width and directional formatting characters to strip.
_ZERO_WIDTH = {
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u2060",  # word joiner
    "\ufeff",  # zero-width no-break space (BOM)
}
_RTL_LTR = {
    "\u202a",  # LRE
    "\u202b",  # RLE
    "\u202c",  # PDF
    "\u202d",  # LRO
    "\u202e",  # RLO
    "\u202f",  # NARROW NO-BREAK SPACE
    "\u2066",  # LRI
    "\u2067",  # RLI
    "\u2068",  # FSI
    "\u2069",  # PDI
}

# Common homoglyphs -> ASCII. Not exhaustive; covers the most abused chars.
_HOMOGLYPHS = {
    # Cyrillic -> Latin
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0456": "i", "\u0443": "u",
    "\u044b": "y", "\u0449": "w", "\u043a": "k", "\u043c": "m",
    "\u0442": "t", "\u0432": "b", "\u043d": "h", "\u0437": "3",
    # Greek -> Latin
    "\u03b1": "a", "\u03b5": "e", "\u03bf": "o", "\u03c1": "p",
    "\u03c3": "c", "\u03c7": "x", "\u03b9": "i",
}

# Compile patterns once (module-level). IGNORECASE + MULTILINE so ^ matches
# line starts (needed for system_prompt_marker and role markers).
_COMPILED = [
    (name, re.compile(pat, re.IGNORECASE | re.MULTILINE), score)
    for name, pat, score in REGEX_PATTERNS
]

# Base64 blob pattern (compiled separately for the rescan step).
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")


def _normalize(text: str) -> str:
    """Strip obfuscation characters and convert homoglyphs to ASCII.

    Newlines are preserved (they are a heuristic signal in Layer 1).
    Other whitespace is collapsed to single spaces.
    """
    if not text:
        return ""
    out = []
    prev_ws = False
    for ch in text:
        if ch in _ZERO_WIDTH or ch in _RTL_LTR:
            continue
        if ch in _HOMOGLYPHS:
            out.append(_HOMOGLYPHS[ch])
            prev_ws = False
            continue
        # Collapse runs of spaces/tabs (but keep newlines).
        if ch in (" ", "\t"):
            if not prev_ws:
                out.append(" ")
                prev_ws = True
            continue
        out.append(ch)
        prev_ws = False
    return "".join(out)


def _printable_ratio(s: str) -> float:
    """Fraction of printable ASCII chars in s. Used to gate base64 rescan."""
    if not s:
        return 0.0
    printable = sum(1 for c in s if 32 <= ord(c) < 127 or c in "\n\r\t")
    return printable / len(s)


def _decode_base64_blobs(text: str) -> list[str]:
    """Find base64 blobs in text and decode the ones that look like text."""
    decoded = []
    for m in _BASE64_RE.finditer(text):
        blob = m.group(0)
        # Pad to multiple of 4 if needed (base64decode requires it).
        padded = blob + "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded_text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            continue
        if _printable_ratio(decoded_text) > 0.5 and len(decoded_text) > 10:
            decoded.append(decoded_text)
    return decoded


def scan_regex(
    text: str,
    *,
    extra_patterns: Optional[list[tuple[str, str, float]]] = None,
) -> list[Signal]:
    """Layer 0. Returns signals for every matched pattern (may be >1).

    Args:
        text: raw input text (will be normalized internally).
        extra_patterns: optional user-supplied (name, regex, score) tuples
            appended to the built-in patterns.
    """
    if not text:
        return []
    normalized = _normalize(text)
    if not normalized:
        return []

    patterns = list(_COMPILED)
    if extra_patterns:
        for name, pat, score in extra_patterns:
            try:
                patterns.append((name, re.compile(pat, re.IGNORECASE | re.MULTILINE), score))
            except re.error:
                # Skip user patterns that don't compile; don't crash the detector.
                continue

    signals: list[Signal] = []
    base64_matched = False

    for name, compiled, score in patterns:
        for m in compiled.finditer(normalized):
            if name == "base64_instruction":
                base64_matched = True
                # Don't emit a low-score base64 signal yet; rescan decides the score.
                continue
            # Truncate the match for the detail string (avoid huge logs).
            snippet = m.group(0)
            if len(snippet) > 80:
                snippet = snippet[:77] + "..."
            signals.append(Signal(
                layer="regex",
                name=name,
                score=score,
                detail=f"matched: {snippet!r}",
            ))

    # Base64 decode-and-rescan: if a base64 blob was found, decode and rescan.
    if base64_matched:
        decoded_texts = _decode_base64_blobs(normalized)
        boosted = False
        for decoded in decoded_texts:
            decoded_norm = _normalize(decoded)
            for name, compiled, score in _COMPILED:
                if name == "base64_instruction":
                    continue
                if compiled.search(decoded_norm):
                    boosted = True
                    snippet = compiled.search(decoded_norm).group(0)
                    if len(snippet) > 80:
                        snippet = snippet[:77] + "..."
                    signals.append(Signal(
                        layer="regex",
                        name=f"base64_decoded_{name}",
                        score=0.95,
                        detail=f"decoded base64 matched {name}: {snippet!r}",
                    ))
        if not boosted:
            # Base64 present but decoded text didn't match a high-confidence pattern.
            signals.append(Signal(
                layer="regex",
                name="base64_instruction",
                score=0.3,
                detail="base64 blob present but no injection decoded",
            ))

    return signals
