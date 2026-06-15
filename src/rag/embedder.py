"""
Embedder — generates dense vector embeddings for RAG retrieval.

Uses sentence-transformers (all-MiniLM-L6-v2 by default) which is free,
runs locally, and requires no API key.

Place at: src/rag/embedder.py

Usage:
    from src.rag.embedder import Embedder
    embedder = Embedder()
    vectors  = embedder.embed(["Detect brute force", "SSH failed login"])
    vector   = embedder.embed_one("Find lateral movement via SMB")
"""

from __future__ import annotations

import numpy as np

from src.utils.exceptions import EmbeddingError
from src.utils.logger import get_logger

log = get_logger(__name__)

# Default model — free, local, fast, 384-dim embeddings
DEFAULT_MODEL = "all-MiniLM-L6-v2"

# Batch size for encoding large corpora
DEFAULT_BATCH_SIZE = 64


class Embedder:
    """
    Wraps sentence-transformers to produce fixed-size dense embeddings.

    Lazy-loads the model on first call so import is always fast.

    Args:
        model_name:  SentenceTransformer model name or local path.
        batch_size:  Number of texts to encode in one forward pass.
        normalize:   If True, L2-normalise embeddings (enables cosine sim via dot product).
        device:      'cpu' | 'cuda' | 'mps' | None (auto-detect).
    """

    def __init__(
        self,
        model_name: str        = DEFAULT_MODEL,
        batch_size: int        = DEFAULT_BATCH_SIZE,
        normalize:  bool       = True,
        device:     str | None = None,
    ) -> None:
        self.model_name = model_name
        self.batch_size = batch_size
        self.normalize  = normalize
        self.device     = device
        self._model     = None   # lazy init

    # ─────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────

    def embed(self, texts: list[str]) -> np.ndarray:
        """
        Embed a list of strings.

        Args:
            texts: List of strings to embed.

        Returns:
            np.ndarray of shape (len(texts), embedding_dim), dtype float32.

        Raises:
            EmbeddingError: If embedding fails.
        """
        if not texts:
            return np.empty((0, self.embedding_dim), dtype=np.float32)

        model = self._get_model()

        try:
            vectors = model.encode(
                texts,
                batch_size=self.batch_size,
                normalize_embeddings=self.normalize,
                show_progress_bar=len(texts) > 200,
                convert_to_numpy=True,
            )
            log.debug(
                "Embedded texts",
                extra={"n": len(texts), "dim": vectors.shape[1]},
            )
            return vectors.astype(np.float32)

        except Exception as exc:
            raise EmbeddingError(
                f"Embedding failed: {exc}",
                details={"model": self.model_name, "n_texts": len(texts)},
            ) from exc

    def embed_one(self, text: str) -> np.ndarray:
        """
        Embed a single string.

        Args:
            text: String to embed.

        Returns:
            1D np.ndarray of shape (embedding_dim,), dtype float32.
        """
        return self.embed([text])[0]

    def embed_chunks(self, chunks: list) -> tuple[list, np.ndarray]:
        """
        Embed a list of Chunk objects (from chunker.py).

        Args:
            chunks: List of Chunk objects with .text attribute.

        Returns:
            Tuple of (chunks, vectors) where vectors is shape (n, dim).
        """
        if not chunks:
            return [], np.empty((0, self.embedding_dim), dtype=np.float32)

        texts   = [c.text for c in chunks]
        vectors = self.embed(texts)
        return chunks, vectors

    @property
    def embedding_dim(self) -> int:
        """Return the embedding dimension of the loaded model."""
        return self._get_model().get_sentence_embedding_dimension()

    def warmup(self) -> None:
        """
        Force model load and encode a dummy sentence.
        Call once at startup to avoid latency on first real request.
        """
        self._get_model()
        self.embed_one("warmup")
        log.info("Embedder warmed up", extra={"model": self.model_name})

    # ─────────────────────────────────────────────
    # Internal
    # ─────────────────────────────────────────────

    def _get_model(self):
        """Lazy-load the SentenceTransformer model."""
        if self._model is not None:
            return self._model
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            raise EmbeddingError(
                "sentence-transformers not installed. "
                "Run: pip install sentence-transformers",
            )

        log.info("Loading embedding model", extra={"model": self.model_name})
        try:
            self._model = SentenceTransformer(
                self.model_name,
                device=self.device,
            )
            log.info(
                "Embedding model loaded",
                extra={
                    "model": self.model_name,
                    "dim":   self._model.get_sentence_embedding_dimension(),
                    "device": str(self._model.device),
                },
            )
        except Exception as exc:
            raise EmbeddingError(
                f"Failed to load model '{self.model_name}': {exc}",
                details={"model": self.model_name},
            ) from exc

        return self._model

    def __repr__(self) -> str:
        loaded = self._model is not None
        return f"Embedder(model={self.model_name!r}, loaded={loaded})"