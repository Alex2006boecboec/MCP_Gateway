"""Verify all regex patterns compile and the corpus is well-formed."""
import re

from mcp_shield.detector.patterns import REGEX_PATTERNS, INJECTION_CORPUS


def test_all_regex_patterns_compile():
    for name, pat, score in REGEX_PATTERNS:
        re.compile(pat, re.IGNORECASE | re.MULTILINE)  # raises on bad pattern
    assert len(REGEX_PATTERNS) >= 10


def test_pattern_scores_in_range():
    for name, pat, score in REGEX_PATTERNS:
        assert 0.0 <= score <= 1.0, f"{name} score out of range: {score}"


def test_pattern_names_unique():
    names = [p[0] for p in REGEX_PATTERNS]
    assert len(names) == len(set(names)), "duplicate pattern names"


def test_corpus_is_nonempty_strings():
    assert len(INJECTION_CORPUS) >= 30
    for phrase in INJECTION_CORPUS:
        assert isinstance(phrase, str) and len(phrase) > 5


def test_corpus_phrases_unique():
    assert len(INJECTION_CORPUS) == len(set(INJECTION_CORPUS))


def test_no_catastrophic_backtracking():
    # Patterns with bounded quantifiers only; feed a pathological long input.
    import re
    long_input = "a" * 100000
    for name, pat, score in REGEX_PATTERNS:
        compiled = re.compile(pat, re.IGNORECASE | re.MULTILINE)
        # Should complete instantly (no nested unbounded quantifiers).
        compiled.search(long_input)
