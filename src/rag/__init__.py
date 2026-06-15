"""
RAG — Retrieval-Augmented Generation layer.

Layer 4 of the NL-SIEM pipeline. Depends on Layer 0 (utils) and Layer 3 (llm).

Pipeline:
    knowledge_base/*.txt
         ↓  chunker.py      — sliding window, word-count chunks
         ↓  embedder.py     — sentence-transformers (all-MiniLM-L6-v2)
         ↓  vector_store.py — FAISS IndexFlatIP (cosine sim)
         ↓  retriever.py    — embed query → search → format context

Quickstart
----------
    # One-time setup: chunk + embed + index
    from src.rag.ingest import ingest_knowledge_base
    stats = ingest_knowledge_base()

    # Query time
    from src.rag import Retriever
    retriever = Retriever.from_store("src/rag/store")
    context   = retriever.retrieve_for_prompt("Detect brute force SSH login", k=5)
"""

from src.rag.chunker      import Chunk, Chunker
from src.rag.embedder     import Embedder
from src.rag.ingest       import ingest_knowledge_base, ingest_platform
from src.rag.retriever    import Retriever
from src.rag.vector_store import SearchResult, VectorStore

__all__ = [
    "Chunker", "Chunk",
    "Embedder",
    "VectorStore", "SearchResult",
    "Retriever",
    "ingest_knowledge_base", "ingest_platform",
]