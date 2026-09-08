"""Data structures shared across the detector layers.

Kept in a separate module so that every layer can import these types
without creating circular imports (e.g. regex_layer imports types, not
detector; detector imports regex_layer + types).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Signal:
    """One finding from one layer of the detector."""
    layer: str        # "regex" | "heuristic" | "embedding" | "llm"
    name: str         # e.g. "ignore_previous_instructions"
    score: float      # 0.0-1.0 contribution from this signal
    detail: str       # human-readable: what matched, where


@dataclass
class DetectionResult:
    """Outcome of scanning one piece of text."""
    score: float              # 0.0-1.0 combined
    verdict: str              # "clean" | "suspicious" | "blocked"
    signals: list[Signal] = field(default_factory=list)
    text_scanned: int = 0     # chars actually scanned (may be < len for big inputs)


@dataclass
class DetectorConfig:
    """Configuration for the Detector. All fields have safe defaults."""
    # Layer toggles
    enable_regex: bool = True
    enable_heuristics: bool = True
    enable_embeddings: bool = False   # requires sentence-transformers
    enable_llm: bool = False          # requires API key
    # Thresholds
    block_threshold: float = 0.9      # >= -> blocked
    suspicious_threshold: float = 0.5  # >= -> run optional layers
    # Limits (protect the detector itself)
    max_scan_chars: int = 100_000     # don't scan beyond this (perf)
    chunk_size: int = 8_000           # scan large text in chunks
    # Embeddings (Layer 2)
    embedding_model: str = "all-MiniLM-L6-v2"
    embedding_threshold: float = 0.82
    # LLM (Layer 3)
    llm_api_base: str = ""            # e.g. https://api.openai.com/v1
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"
    llm_threshold: float = 0.8
    llm_timeout: float = 10.0         # seconds
    # Extra user-supplied regex patterns: (name, pattern, score)
    extra_regex: Optional[list[tuple[str, str, float]]] = None
