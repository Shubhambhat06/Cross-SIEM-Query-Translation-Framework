"""
Vector Store — FAISS-backed index for dense similarity search.

Stores chunk embeddings + metadata. Supports:
  - Build from scratch (add vectors + metadata)
  - Persist to / load from disk (index.faiss + metadata.json)
  - Top-k similarity search
  - MMR (Maximal Marginal Relevance) re-ranking to reduce redundancy

Place at: src/rag/vector_store.py

Usage:
    from src.rag.vector_store import VectorStore
    store = VectorStore(dim=384)
    store.add(vectors, metadata_list)
    store.save("src/rag/store")
    store = VectorStore.load("src/rag/store")
    results = store.search(query_vector, k=5)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from src.utils.exceptions import VectorStoreError
from src.utils.logger import get_logger

log = get_logger(__name__)

# File suffixes for persistence
_INDEX_SUFFIX    = ".faiss"
_METADATA_SUFFIX = "_metadata.json"


@dataclass
class SearchResult:
    """A single search result from the vector store."""
    rank:     int    # 1-based rank
    score:    float  # cosine similarity (higher = more similar)
    text:     str    # chunk text
    source:   str    # origin file
    platform: str    # SIEM platform tag
    chunk_id: str    # unique chunk identifier
    metadata: dict   # additional metadata


class VectorStore:
    """
    FAISS-backed dense vector store.

    Uses IndexFlatIP (inner-product / cosine similarity on L2-normalised vectors).
    All embeddings are expected to be L2-normalised (Embedder normalizes by default).

    Args:
        dim: Embedding dimension (must match Embedder.embedding_dim).
    """

    def __init__(self, dim: int = 384) -> None:
        self.dim       = dim
        self._index    = None        # FAISS index (lazy)
        self._metadata: list[dict] = []  # parallel list to FAISS vectors

    # ─────────────────────────────────────────────
    # Build
    # ─────────────────────────────────────────────

    def add(
        self,
        vectors:   np.ndarray,
        metadata:  list[dict],
    ) -> None:
        """
        Add vectors and their metadata to the store.

        Args:
            vectors:  np.ndarray of shape (n, dim), dtype float32, L2-normalised.
            metadata: List of n dicts, one per vector. Each dict must contain
                      at least 'text', 'source', 'platform', 'chunk_id'.

        Raises:
            VectorStoreError: If shapes don't match or FAISS unavailable.
        """
        if len(vectors) != len(metadata):
            raise VectorStoreError(
                "add",
                f"vectors ({len(vectors)}) and metadata ({len(metadata)}) length mismatch",
            )
        if vectors.shape[1] != self.dim:
            raise VectorStoreError(
                "add",
                f"vector dim {vectors.shape[1]} != store dim {self.dim}",
            )

        index = self._get_or_create_index()
        index.add(vectors.astype(np.float32))
        self._metadata.extend(metadata)

        log.debug(
            "Added vectors to store",
            extra={"added": len(vectors), "total": index.ntotal},
        )

    def add_chunks(self, chunks: list, vectors: np.ndarray) -> None:
        """
        Convenience wrapper: add Chunk objects with their embeddings.

        Args:
            chunks:  List of Chunk objects from chunker.py.
            vectors: np.ndarray of shape (len(chunks), dim).
        """
        metadata = [
            {
                "text":     c.text,
                "source":   c.source,
                "platform": c.platform,
                "chunk_id": c.id,
                "metadata": c.metadata,
            }
            for c in chunks
        ]
        self.add(vectors, metadata)

    # ─────────────────────────────────────────────
    # Search
    # ─────────────────────────────────────────────

    def search(
        self,
        query_vector: np.ndarray,
        k:            int  = 5,
        platform:     str | None = None,
    ) -> list[SearchResult]:
        """
        Find the k most similar chunks.

        Args:
            query_vector: 1D np.ndarray of shape (dim,), L2-normalised.
            k:            Number of results to return.
            platform:     If given, filter results to this SIEM platform only.

        Returns:
            List of SearchResult objects, sorted by score descending.

        Raises:
            VectorStoreError: If the index is empty.
        """
        index = self._get_or_create_index()
        if index.ntotal == 0:
            raise VectorStoreError("search", "Index is empty — run ingest first")

        # FAISS expects 2D input
        q = query_vector.reshape(1, -1).astype(np.float32)

        # Fetch more candidates if filtering by platform
        fetch_k = k * 4 if platform else k
        fetch_k = min(fetch_k, index.ntotal)

        scores, indices = index.search(q, fetch_k)
        scores  = scores[0].tolist()
        indices = indices[0].tolist()

        results: list[SearchResult] = []
        for rank_raw, (score, idx) in enumerate(zip(scores, indices)):
            if idx < 0:          # FAISS uses -1 for "not found"
                continue
            meta = self._metadata[idx]

            # Platform filter
            if platform and meta.get("platform") != platform:
                continue

            results.append(SearchResult(
                rank     = len(results) + 1,
                score    = float(score),
                text     = meta.get("text", ""),
                source   = meta.get("source", ""),
                platform = meta.get("platform", ""),
                chunk_id = meta.get("chunk_id", str(idx)),
                metadata = meta.get("metadata", {}),
            ))

            if len(results) >= k:
                break

        log.debug(
            "Search complete",
            extra={"k": k, "returned": len(results), "platform_filter": platform},
        )
        return results

    def mmr_search(
        self,
        query_vector:  np.ndarray,
        k:             int   = 5,
        fetch_k:       int   = 20,
        lambda_mult:   float = 0.5,
        platform:      str | None = None,
    ) -> list[SearchResult]:
        """
        Maximal Marginal Relevance search — balances relevance vs diversity.

        Fetches fetch_k candidates, then greedily selects k results that
        maximise: lambda_mult * relevance - (1 - lambda_mult) * max_redundancy.

        Args:
            query_vector: Query embedding (1D, normalised).
            k:            Number of results to return.
            fetch_k:      Candidate pool size to draw from.
            lambda_mult:  0 = max diversity, 1 = max relevance. Default 0.5.
            platform:     Optional platform filter.

        Returns:
            List of SearchResult objects (diverse, relevant).
        """
        index = self._get_or_create_index()
        if index.ntotal == 0:
            return []

        q       = query_vector.reshape(1, -1).astype(np.float32)
        fetch_k = min(max(fetch_k, k * 2), index.ntotal)

        scores, indices = index.search(q, fetch_k)
        scores  = scores[0]
        indices = indices[0]

        # Filter valid and optionally by platform
        candidates: list[tuple[int, float, np.ndarray]] = []
        for score, idx in zip(scores, indices):
            if idx < 0:
                continue
            meta = self._metadata[idx]
            if platform and meta.get("platform") != platform:
                continue
            # Retrieve the stored vector for redundancy check
            vec = np.zeros(self.dim, dtype=np.float32)
            index.reconstruct(int(idx), vec)
            candidates.append((int(idx), float(score), vec))

        if not candidates:
            return []

        # MMR selection
        selected_ids: list[int] = []
        remaining    = list(candidates)

        while len(selected_ids) < k and remaining:
            # For each remaining candidate, compute MMR score
            best_score  = -float("inf")
            best_pos    = 0

            for i, (idx, rel_score, vec) in enumerate(remaining):
                if not selected_ids:
                    mmr_score = rel_score
                else:
                    # Max similarity to already-selected chunks
                    max_red = max(
                        float(np.dot(vec, self._get_vector(sel_idx)))
                        for sel_idx in selected_ids
                    )
                    mmr_score = lambda_mult * rel_score - (1 - lambda_mult) * max_red

                if mmr_score > best_score:
                    best_score = mmr_score
                    best_pos   = i

            chosen_idx, _, _ = remaining.pop(best_pos)
            selected_ids.append(chosen_idx)

        # Build SearchResult objects
        results = []
        for rank, idx in enumerate(selected_ids, start=1):
            meta = self._metadata[idx]
            results.append(SearchResult(
                rank     = rank,
                score    = float(scores[list(indices).index(idx)]) if idx in indices else 0.0,
                text     = meta.get("text", ""),
                source   = meta.get("source", ""),
                platform = meta.get("platform", ""),
                chunk_id = meta.get("chunk_id", str(idx)),
                metadata = meta.get("metadata", {}),
            ))

        return results

    # ─────────────────────────────────────────────
    # Persistence
    # ─────────────────────────────────────────────

    def save(self, path_prefix: str | Path) -> None:
        """
        Persist the FAISS index and metadata to disk.

        Creates two files:
          <path_prefix>.faiss           — FAISS binary index
          <path_prefix>_metadata.json   — JSON metadata list

        Args:
            path_prefix: Path without extension.
        """
        try:
            import faiss
        except ImportError:
            raise VectorStoreError("save", "faiss-cpu not installed. Run: pip install faiss-cpu")

        index = self._get_or_create_index()
        if index.ntotal == 0:
            log.warning("Saving empty VectorStore")

        prefix  = Path(path_prefix)
        prefix.parent.mkdir(parents=True, exist_ok=True)

        idx_path  = str(prefix) + _INDEX_SUFFIX
        meta_path = str(prefix) + _METADATA_SUFFIX

        faiss.write_index(index, idx_path)

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(self._metadata, f, ensure_ascii=False)

        log.info(
            "VectorStore saved",
            extra={
                "index":    idx_path,
                "vectors":  index.ntotal,
                "dim":      self.dim,
            },
        )

    @classmethod
    def load(cls, path_prefix: str | Path) -> "VectorStore":
        """
        Load a previously saved VectorStore from disk.

        Args:
            path_prefix: Same prefix used in save().

        Returns:
            Populated VectorStore instance.

        Raises:
            VectorStoreError: If files are missing or corrupt.
        """
        try:
            import faiss
        except ImportError:
            raise VectorStoreError("load", "faiss-cpu not installed. Run: pip install faiss-cpu")

        prefix    = Path(path_prefix)
        idx_path  = str(prefix) + _INDEX_SUFFIX
        meta_path = str(prefix) + _METADATA_SUFFIX

        if not Path(idx_path).exists():
            raise VectorStoreError(
                "load",
                f"FAISS index not found at {idx_path}. Run ingest_knowledge_base.py first.",
            )

        try:
            index = faiss.read_index(idx_path)
        except Exception as exc:
            raise VectorStoreError("load", f"Failed to read FAISS index: {exc}") from exc

        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                metadata = json.load(f)
        except Exception as exc:
            raise VectorStoreError("load", f"Failed to read metadata: {exc}") from exc

        store          = cls(dim=index.d)
        store._index   = index
        store._metadata = metadata

        log.info(
            "VectorStore loaded",
            extra={"vectors": index.ntotal, "dim": index.d},
        )
        return store

    # ─────────────────────────────────────────────
    # Properties
    # ─────────────────────────────────────────────

    @property
    def size(self) -> int:
        """Number of vectors in the store."""
        if self._index is None:
            return 0
        return self._index.ntotal

    @property
    def is_empty(self) -> bool:
        return self.size == 0

    # ─────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────

    def _get_or_create_index(self):
        """Lazy-create a FAISS IndexFlatIP index."""
        if self._index is not None:
            return self._index
        try:
            import faiss
        except ImportError:
            raise VectorStoreError(
                "init",
                "faiss-cpu not installed. Run: pip install faiss-cpu",
            )
        self._index = faiss.IndexFlatIP(self.dim)
        return self._index

    def _get_vector(self, idx: int) -> np.ndarray:
        """Retrieve a stored vector by its position index."""
        vec = np.zeros(self.dim, dtype=np.float32)
        self._index.reconstruct(idx, vec)
        return vec

    def __repr__(self) -> str:
        return f"VectorStore(dim={self.dim}, size={self.size})"