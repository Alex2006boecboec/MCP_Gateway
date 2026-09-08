"""Layer 1 — Heuristic detection (mandatory, deterministic, stdlib only).

Structural signals that don't map to a single regex but indicate injection
when they appear in combination or at density. Each heuristic returns a
Signal with a bounded score contribution; the Detector sums them (capped).

Heuristics are deliberately conservative — they produce moderate scores
that, combined with a regex hit, push a case over the block threshold,
or alone leave it in the "suspicious" band for the optional ML layers.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Optional

from mcp_shield.detector.types import Signal

# Imperative starters — words that issue commands to an agent.
_IMPERATIVE_RE = re.compile(
    r"\b(do not|don't|never|always|must|should|"
    r"you\s+(?:are|will|must|should|have\s+to|need\s+to|are\s+now|are\s+going\s+to))\b",
    re.IGNORECASE,
)

# Chat role markers at line start (e.g. "user:", "assistant:").
_ROLE_MARKER_RE = re.compile(r"(?m)^\s*(user|assistant|system|human|developer)\s*[:\-]\s")

# URL extraction (http/https).
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

# Exfiltration verbs near a URL.
_EXFIL_VERB_RE = re.compile(
    r"\b(send|post|upload|exfiltrate|transmit|forward|leak|curl|wget)\b",
    re.IGNORECASE,
)


def _sentence_split(text: str) -> list[str]:
    """Split text into sentences (rough). Good enough for the repeated_directive heuristic."""
    parts = re.split(r"(?<=[.!?])\s+", text)
    return [p.strip() for p in parts if p.strip()]


def _script_runs(text: str) -> set[str]:
    """Return the set of Unicode scripts present in text (latin, cyrillic, cjk, ...)."""
    scripts: set[str] = set()
    for ch in text:
        if ch.isspace() or ch in ".,;:!?-'\"()[]{}<>/\\@#$%^&*+=|~`":
            continue
        try:
            name = unicodedata.name(ch, "")
        except ValueError:
            continue
        if "LATIN" in name:
            scripts.add("latin")
        elif "CYRILLIC" in name:
            scripts.add("cyrillic")
        elif "CJK" in name or "HAN" in name or "HIRAGANA" in name or "KATAKANA" in name or "HANGUL" in name:
            scripts.add("cjk")
        elif "ARABIC" in name:
            scripts.add("arabic")
        elif "HEBREW" in name:
            scripts.add("hebrew")
    return scripts


def _extract_urls(text: str) -> set[str]:
    return {m.group(0).lower() for m in _URL_RE.finditer(text)}


def scan_heuristics(text: str, *, context: Optional[dict] = None) -> list[Signal]:
    """Layer 1. Returns heuristic signals. context may contain:
        - request_args: dict of the original tool call args (for url_not_in_request)
        - is_tool_description: bool (enables length_anomaly)
    Handles context=None gracefully (skips context-dependent heuristics).
    """
    if not text:
        return []
    signals: list[Signal] = []
    context = context or {}
    length = len(text)

    # 1. imperative_density
    imperatives = _IMPERATIVE_RE.findall(text)
    if imperatives:
        density = len(imperatives) / max(length, 1) * 1000
        score = min(density / 20, 1.0) * 0.6
        if score > 0:
            signals.append(Signal(
                layer="heuristic", name="imperative_density",
                score=round(score, 3),
                detail=f"{len(imperatives)} imperatives in {length} chars (density {density:.1f}/1000)",
            ))

    # 2. length_anomaly (only for tool descriptions)
    if context.get("is_tool_description") and length > 500:
        score = min((length - 500) / 1500, 1.0) * 0.4
        signals.append(Signal(
            layer="heuristic", name="length_anomaly",
            score=round(score, 3),
            detail=f"tool description is {length} chars (typical < 500)",
        ))

    # 3. newline_escape — newline followed by imperative starter
    newline_imperative = 0
    for m in re.finditer(r"\n\s*", text):
        tail = text[m.end():m.end() + 60]
        if _IMPERATIVE_RE.search(tail):
            newline_imperative += 1
    if newline_imperative:
        score = min(newline_imperative / 3, 1.0) * 0.7
        signals.append(Signal(
            layer="heuristic", name="newline_escape",
            score=round(score, 3),
            detail=f"{newline_imperative} newline-then-imperative occurrences",
        ))

    # 4. mixed_language_directives — multiple scripts + imperative present
    scripts = _script_runs(text)
    if len(scripts) > 1 and imperatives:
        signals.append(Signal(
            layer="heuristic", name="mixed_language_directives",
            score=0.6,
            detail=f"scripts {scripts} with imperatives present",
        ))

    # 5. role_marker_leak — chat role markers in tool output
    role_markers = _ROLE_MARKER_RE.findall(text)
    if role_markers:
        score = min(len(role_markers) / 2, 1.0) * 0.8
        signals.append(Signal(
            layer="heuristic", name="role_marker_leak",
            score=round(score, 3),
            detail=f"{len(role_markers)} role markers (user:/assistant:/system:)",
        ))

    # 6. url_not_in_request — new external URL in response + exfil verb nearby
    request_args = context.get("request_args")
    if isinstance(request_args, dict):
        request_urls = _extract_urls(str(request_args))
        response_urls = _extract_urls(text)
        new_urls = response_urls - request_urls
        if new_urls:
            # Check for an exfil verb within 40 chars of each new URL.
            exfil_near = False
            for url in new_urls:
                idx = text.lower().find(url)
                if idx >= 0:
                    window = text[max(0, idx - 40):idx + len(url) + 40]
                    if _EXFIL_VERB_RE.search(window):
                        exfil_near = True
                        break
            if exfil_near:
                signals.append(Signal(
                    layer="heuristic", name="url_not_in_request",
                    score=0.85,
                    detail=f"new URL(s) {new_urls} with exfiltration verb nearby",
                ))

    # 7. repeated_directive — same imperative sentence repeated 3+ times
    sentences = _sentence_split(text)
    imperative_sentences = [s for s in sentences if _IMPERATIVE_RE.search(s)]
    if imperative_sentences:
        counts: dict[str, int] = {}
        for s in imperative_sentences:
            key = re.sub(r"\s+", " ", s.lower().strip())[:80]
            counts[key] = counts.get(key, 0) + 1
        dups = sum(1 for c in counts.values() if c >= 3)
        if dups:
            score = min(dups / 3, 1.0) * 0.5
            signals.append(Signal(
                layer="heuristic", name="repeated_directive",
                score=round(score, 3),
                detail=f"{dups} imperative sentence(s) repeated 3+ times",
            ))

    return signals
