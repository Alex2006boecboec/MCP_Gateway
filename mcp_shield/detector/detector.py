"""Detector — combines the detection layers and produces a verdict.

This is the single entry point the proxy uses. It runs the mandatory
deterministic layers (regex + heuristics) first; if the combined score is
already in the block band, it returns immediately without touching the
optional ML layers. Only the ambiguous "suspicious" band (0.5 <= score < 0.9)
triggers the optional embeddings/LLM layers.

Score combination:
  - deterministic signals (regex + heuristic) are ADDITIVE, capped at 1.0
  - optional signals (embedding + llm) are MAX-take (independent judgments)
  - final score = max(deterministic_score, optional_score)

Verdict mapping:
  - score >= block_threshold (0.9)     -> "blocked"
  - score >= suspicious_threshold (0.5) -> "suspicious"
  - else                                -> "clean"

Robustness: every layer is wrapped in try/except so a bug in one layer
never crashes the proxy. On layer error, the layer returns no signals and
a warning is logged (fail-open for the detector; the policy engine still
runs and can block on its own).
"""

from __future__ import annotations

import logging
from typing import Optional

from mcp_shield.detector.embedding_layer import EmbeddingLayer
from mcp_shield.detector.heuristic_layer import scan_heuristics
from mcp_shield.detector.llm_layer import LLMLayer
from mcp_shield.detector.regex_layer import scan_regex
from mcp_shield.detector.types import DetectionResult, DetectorConfig, Signal

log = logging.getLogger("mcp_shield.detector")


class Detector:
    """Multi-layer prompt injection detector.

    One Detector instance per proxy. Not thread-safe (the optional ML
    caches are populated lazily); the Phase 1-2 proxy is sequential so this
    is fine.
    """

    def __init__(self, config: DetectorConfig):
        self.config = config
        # Optional layers, lazily initialized.
        self._embedding_layer: Optional[EmbeddingLayer] = None
        self._llm_layer: Optional[LLMLayer] = None
        self._llm_cache: dict[str, Signal] = {}

    def scan(self, text: str, *, context: Optional[dict] = None) -> DetectionResult:
        """Scan one piece of text. Returns a DetectionResult.

        Args:
            text: the text to scan (tool description, response, or args).
            context: optional dict with keys like "request_args" (dict) and
                "is_tool_description" (bool), used by some heuristics.
        """
        if not text:
            return DetectionResult(score=0.0, verdict="clean", signals=[], text_scanned=0)

        # Truncate to protect the detector from huge inputs.
        truncated = text[: self.config.max_scan_chars]
        scanned_len = len(truncated)

        signals: list[Signal] = []

        # --- Layer 0: Regex (mandatory) ---
        if self.config.enable_regex:
            try:
                sigs = scan_regex(truncated, extra_patterns=self.config.extra_regex)
                signals.extend(sigs)
            except Exception as exc:
                log.warning("regex layer error: %s", exc)

        # --- Layer 1: Heuristics (mandatory) ---
        if self.config.enable_heuristics:
            try:
                sigs = scan_heuristics(truncated, context=context)
                signals.extend(sigs)
            except Exception as exc:
                log.warning("heuristic layer error: %s", exc)

        # --- Combine deterministic layers ---
        det_score = self._combine_deterministic(signals)

        # Fast path: already blocked by deterministic layers alone.
        if det_score >= self.config.block_threshold:
            return DetectionResult(
                score=det_score, verdict="blocked",
                signals=signals, text_scanned=scanned_len,
            )

        # Fast path: clearly clean — no need for expensive ML.
        if det_score < self.config.suspicious_threshold:
            return DetectionResult(
                score=det_score, verdict="clean",
                signals=signals, text_scanned=scanned_len,
            )

        # --- Suspicious band: run optional layers (steps 7-9 fill these) ---
        opt_score = self._run_optional_layers(truncated, signals)

        final_score = max(det_score, opt_score)
        verdict = self._verdict(final_score)
        return DetectionResult(
            score=final_score, verdict=verdict,
            signals=signals, text_scanned=scanned_len,
        )

    # ----------------------------------------------------------- internals

    @staticmethod
    def _combine_deterministic(signals: list[Signal]) -> float:
        """Sum regex + heuristic scores, capped at 1.0."""
        det = [s for s in signals if s.layer in ("regex", "heuristic")]
        return min(sum(s.score for s in det), 1.0)

    def _run_optional_layers(self, text: str, signals: list[Signal]) -> float:
        """Run embeddings + LLM on the suspicious band. Returns max optional score.

        Each optional layer is wrapped in try/except so a failure in one
        doesn't prevent the other from running. On any error, the layer
        contributes nothing (fail-open for optional layers; the deterministic
        layers already ran and set a floor score).
        """
        optional_scores: list[float] = []

        # Layer 2: Embeddings
        if self.config.enable_embeddings:
            try:
                layer = self._get_embedding_layer()
                if layer is not None:
                    sig = layer.scan(text)
                    if sig is not None:
                        signals.append(sig)
                        optional_scores.append(sig.score)
            except Exception as exc:
                log.warning("embedding layer error: %s", exc)

        # Layer 3: LLM judge
        if self.config.enable_llm:
            try:
                layer = self._get_llm_layer()
                if layer is not None:
                    sig = layer.scan(text)
                    if sig is not None:
                        signals.append(sig)
                        optional_scores.append(sig.score)
            except Exception as exc:
                log.warning("llm layer error: %s", exc)

        # Also include any optional signals already in the list (e.g. from
        # a previous call path). Max-take across all optional signals.
        existing_optional = [s.score for s in signals if s.layer in ("embedding", "llm")]
        all_optional = optional_scores + existing_optional
        return max(all_optional, default=0.0)

    def _get_embedding_layer(self) -> Optional[EmbeddingLayer]:
        """Lazily create the embedding layer (loads model on first scan)."""
        if not self.config.enable_embeddings:
            return None
        if self._embedding_layer is None:
            self._embedding_layer = EmbeddingLayer(
                model_name=self.config.embedding_model,
                threshold=self.config.embedding_threshold,
            )
        return self._embedding_layer

    def _get_llm_layer(self) -> Optional[LLMLayer]:
        """Lazily create the LLM layer."""
        if not self.config.enable_llm:
            return None
        if self._llm_layer is None:
            self._llm_layer = LLMLayer(
                api_base=self.config.llm_api_base,
                api_key=self.config.llm_api_key,
                model=self.config.llm_model,
                threshold=self.config.llm_threshold,
                timeout=self.config.llm_timeout,
            )
        return self._llm_layer

    def _verdict(self, score: float) -> str:
        if score >= self.config.block_threshold:
            return "blocked"
        if score >= self.config.suspicious_threshold:
            return "suspicious"
        return "clean"
