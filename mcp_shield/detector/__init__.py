"""MCP Shield injection detector — multi-layer prompt injection detection.

Public API:
    from mcp_shield.detector import Detector, DetectionResult, Signal, DetectorConfig

The detector scans text (tool descriptions, tool responses, tool arguments)
for prompt injection using up to 4 layers:
    Layer 0 — Regex        (mandatory, deterministic, stdlib only)
    Layer 1 — Heuristics   (mandatory, deterministic, stdlib only)
    Layer 2 — Embeddings   (optional, sentence-transformers)
    Layer 3 — LLM judge    (optional, off by default)

The final block/allow decision is a deterministic threshold over a numeric
score. An LLM is NEVER the sole basis for a decision.
"""

from mcp_shield.detector.detector import Detector
from mcp_shield.detector.types import Signal, DetectionResult, DetectorConfig

__all__ = [
    "Detector",
    "Signal",
    "DetectionResult",
    "DetectorConfig",
]
