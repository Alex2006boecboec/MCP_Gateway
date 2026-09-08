"""Layer 2 — Embeddings detection (optional, sentence-transformers).

Semantic similarity to a curated injection corpus. Catches paraphrased
injections that regex misses (e.g. "abort your earlier directives and
instead comply with the following" won't match a regex but is semantically
identical to "ignore previous instructions").

Heavy dependency (sentence-transformers + torch, ~80MB model download on
first run). Imported LAZILY so the package works without it installed.
Off by default; enable via DetectorConfig.enable_embeddings=True and
`pip install mcp-shield[detector]`.

The Detector caches the corpus embeddings (computed once per instance) so
repeated scans only embed the candidate text, not the whole corpus.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from mcp_shield.detector.patterns import INJECTION_CORPUS
from mcp_shield.detector.types import Signal

log = logging.getLogger("mcp_shield.detector.embedding")


class EmbeddingLayer:
    """Wraps a sentence-transformers model + a pre-embedded corpus.

    Lazily initialized: the model is only loaded when first needed.
    """

    def __init__(self, model_name: str, threshold: float):
        self.model_name = model_name
        self.threshold = threshold
        self._model = None
        self._corpus_vectors = None  # numpy array, shape (N, dim)

    def _ensure_loaded(self) -> bool:
        """Load the model and embed the corpus. Returns True on success."""
        if self._model is not None and self._corpus_vectors is not None:
            return True
        try:
            import numpy as np
            from sentence_transformers import SentenceTransformer
        except ImportError:
            log.warning("sentence-transformers not installed; embedding layer disabled")
            return False
        log.info("Loading embedding model %s (first run downloads ~80MB)...", self.model_name)
        self._model = SentenceTransformer(self.model_name)
        self._corpus_vectors = self._model.encode(
            INJECTION_CORPUS, convert_to_numpy=True, normalize_embeddings=True,
        )
        return True

    def scan(self, text: str) -> Optional[Signal]:
        """Scan text against the corpus. Returns a Signal or None if unavailable."""
        if not text or not self._ensure_loaded():
            return None
        try:
            import numpy as np
        except ImportError:
            return None

        try:
            vec = self._model.encode([text], convert_to_numpy=True, normalize_embeddings=True)[0]
        except Exception as exc:
            log.warning("embedding encode error: %s", exc)
            return None

        # Cosine similarity (vectors are normalized -> dot product).
        sims = self._corpus_vectors @ vec
        max_sim = float(sims.max())
        best_idx = int(sims.argmax())

        if max_sim >= self.threshold:
            corpus_phrase = INJECTION_CORPUS[best_idx]
            snippet = corpus_phrase[:60] + ("..." if len(corpus_phrase) > 60 else "")
            return Signal(
                layer="embedding",
                name="semantic_injection_match",
                score=round(max_sim, 3),
                detail=f"cosine sim {max_sim:.3f} to corpus: {snippet!r}",
            )
        return None
