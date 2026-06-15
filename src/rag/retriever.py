"""
Retriever — ties Embedder + VectorStore to retrieve relevant SIEM docs for RAG.

Given a natural language query, returns the top-k most relevant
knowledge base chunks to inject as context into the LLM prompt.

Place at: src/rag/retriever.py

Usage:
    from src.rag.retriever import Retriever
    retriever = Retriever.from_store("src/rag/store")
    context   = retriever.retrieve("Detect brute force SSH", k=5)
    prompt_ctx = retriever.format_context(context)
"""

from __future__ import annotations

from pathlib import Path

from src.rag.embedder import Embedder
from src.rag.vector_store import SearchResult, VectorStore
from src.utils.exceptions import VectorStoreError
from src.utils.logger import get_logger

log = get_logger(__name__)

# Max characters per chunk included in formatted context
_MAX_CHUNK_CHARS = 800


class Retriever:
    """
    Retrieves relevant knowledge base chunks for RAG prompt augmentation.

    Args:
        embedder:     Embedder instance for query encoding.
        vector_store: VectorStore containing indexed knowledge base chunks.
        use_mmr:      If True, use MMR re-ranking for diversity (default False).
    """

    def __init__(
        self,
        embedder:     Embedder,
        vector_store: VectorStore,
        use_mmr:      bool = False,
    ) -> None:
        self.embedder     = embedder
        self.vector_store = vector_store
        self.use_mmr      = use_mmr

    # ─────────────────────────────────────────────
    # Factory methods
    # ─────────────────────────────────────────────

    @classmethod
    def from_store(
        cls,
        store_path:  str | Path = "src/rag/store",
        model_name:  str        = "all-MiniLM-L6-v2",
        use_mmr:     bool       = False,
    ) -> "Retriever":
        """
        Load a pre-built VectorStore from disk and return a ready Retriever.

        Args:
            store_path:  Path prefix used when the store was saved.
            model_name:  Embedding model name (must match the one used at ingest time).
            use_mmr:     Enable MMR diversity re-ranking.

        Returns:
            Retriever instance ready for queries.

        Raises:
            VectorStoreError: If the store files are not found.
        """
        store    = VectorStore.load(store_path)
        embedder = Embedder(model_name=model_name)
        log.info(
            "Retriever loaded",
            extra={
                "store":   str(store_path),
                "vectors": store.size,
                "mmr":     use_mmr,
            },
        )
        return cls(embedder=embedder, vector_store=store, use_mmr=use_mmr)

    # ─────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────

    def retrieve(
        self,
        query:    str,
        k:        int        = 5,
        platform: str | None = None,
    ) -> list[SearchResult]:
        """
        Retrieve the k most relevant chunks for a natural language query.

        Args:
            query:    Natural language query string.
            k:        Number of chunks to retrieve.
            platform: Optional SIEM platform filter (splunk / qradar / etc.).

        Returns:
            List of SearchResult objects, ranked by relevance.
        """
        if self.vector_store.is_empty:
            log.warning("VectorStore is empty — RAG context will be empty")
            return []

        query_vec = self.embedder.embed_one(query)

        if self.use_mmr:
            results = self.vector_store.mmr_search(
                query_vec,
                k=k,
                fetch_k=k * 4,
                platform=platform,
            )
        else:
            results = self.vector_store.search(
                query_vec,
                k=k,
                platform=platform,
            )

        log.debug(
            "Retrieved chunks",
            extra={
                "query":    query[:80],
                "k":        k,
                "returned": len(results),
                "platform": platform,
            },
        )
        return results

    def retrieve_for_prompt(
        self,
        query:    str,
        k:        int        = 5,
        platform: str | None = None,
    ) -> str:
        """
        Retrieve context and immediately format it for injection into a prompt.

        Args:
            query:    NL query to retrieve context for.
            k:        Number of chunks.
            platform: Optional platform filter.

        Returns:
            Formatted context string ready for prompt injection.
        """
        results = self.retrieve(query=query, k=k, platform=platform)
        return self.format_context(results)

    def format_context(
        self,
        results:    list[SearchResult],
        max_chars:  int = _MAX_CHUNK_CHARS,
    ) -> str:
        """
        Format a list of SearchResult objects into a readable context block.

        Each result is formatted as:
            [PLATFORM: splunk | SOURCE: spl_commands.txt | SCORE: 0.92]
            <chunk text truncated to max_chars>

        Args:
            results:   List of SearchResult objects.
            max_chars: Max characters per chunk in the output.

        Returns:
            Multi-line context string for prompt injection.
        """
        if not results:
            return ""

        lines: list[str] = ["=== RETRIEVED SIEM DOCUMENTATION CONTEXT ==="]
        for r in results:
            source_name = Path(r.source).name if r.source else "unknown"
            header      = f"[PLATFORM: {r.platform} | SOURCE: {source_name} | SCORE: {r.score:.3f}]"
            text        = r.text[:max_chars] + ("..." if len(r.text) > max_chars else "")
            lines.append(f"\n{header}\n{text}")
        lines.append("\n=== END CONTEXT ===")
        return "\n".join(lines)

    def retrieve_multi_platform(
        self,
        query: str,
        k_per_platform: int = 2,
    ) -> dict[str, list[SearchResult]]:
        """
        Retrieve k results per platform across all 5 SIEMs + MITRE.

        Useful when building prompts that need balanced coverage
        across all target platforms.

        Args:
            query:          NL query string.
            k_per_platform: Results per SIEM platform.

        Returns:
            Dict mapping platform → list of SearchResults.
        """
        platforms = ["splunk", "qradar", "elastic", "sentinel", "wazuh", "mitre"]
        return {
            p: self.retrieve(query=query, k=k_per_platform, platform=p)
            for p in platforms
        }

    @property
    def store_size(self) -> int:
        """Total number of vectors in the underlying store."""
        return self.vector_store.size

    def __repr__(self) -> str:
        return (
            f"Retriever(store_size={self.store_size}, "
            f"model={self.embedder.model_name!r}, mmr={self.use_mmr})"
        )