"""
Ingest — one-time pipeline: chunk → embed → store all knowledge base documents.

Run once after populating knowledge_base/ with SIEM documentation.
Output is a FAISS index + metadata JSON that Retriever loads at query time.

Place at: src/rag/ingest.py

Usage (called by scripts/ingest_knowledge_base.py):
    from src.rag.ingest import ingest_knowledge_base
    stats = ingest_knowledge_base()
    print(stats)

Direct run:
    python -m src.rag.ingest
"""

from __future__ import annotations

import time
from pathlib import Path

from src.rag.chunker import Chunk, Chunker
from src.rag.embedder import Embedder
from src.rag.vector_store import VectorStore
from src.utils.config import settings
from src.utils.logger import get_logger

log = get_logger(__name__)

# Default paths
DEFAULT_KB_DIR    = Path("knowledge_base")
DEFAULT_STORE_PATH = Path("src/rag/store")
DEFAULT_GLOB      = "**/*.txt"


def ingest_knowledge_base(
    kb_dir:     Path | str = DEFAULT_KB_DIR,
    store_path: Path | str = DEFAULT_STORE_PATH,
    model_name: str        = "all-MiniLM-L6-v2",
    chunk_size: int        = 512,
    chunk_overlap: int     = 64,
    glob:       str        = DEFAULT_GLOB,
    overwrite:  bool       = True,
) -> dict:
    """
    Full ingestion pipeline: scan → chunk → embed → index → save.

    Args:
        kb_dir:        Root of knowledge_base/ directory.
        store_path:    Output path prefix for FAISS index + metadata.
        model_name:    Sentence-transformers model name.
        chunk_size:    Words per chunk.
        chunk_overlap: Overlap words between consecutive chunks.
        glob:          File pattern to scan.
        overwrite:     If False and store exists, skip ingestion.

    Returns:
        Stats dict with keys: files, chunks, vectors, elapsed_s.
    """
    kb_dir     = Path(kb_dir)
    store_path = Path(store_path)

    # Guard: skip if already indexed
    if not overwrite and (store_path.parent / (store_path.name + ".faiss")).exists():
        log.info("Store already exists, skipping ingest", extra={"store": str(store_path)})
        return {"skipped": True}

    if not kb_dir.exists():
        log.warning(
            "knowledge_base/ directory not found — creating empty store",
            extra={"kb_dir": str(kb_dir)},
        )
        kb_dir.mkdir(parents=True, exist_ok=True)

    t0 = time.monotonic()

    # ── Step 1: Chunk ──────────────────────────────────────────────────────
    log.info("Step 1/3 — Chunking knowledge base", extra={"kb_dir": str(kb_dir)})
    chunker    = Chunker(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
    all_chunks = chunker.chunk_directory(kb_dir, glob=glob)

    files = len(set(c.source for c in all_chunks))
    log.info(
        "Chunking complete",
        extra={"files": files, "chunks": len(all_chunks)},
    )

    if not all_chunks:
        log.warning(
            "No chunks produced — knowledge_base/ may be empty.\n"
            "Add .txt files to knowledge_base/splunk/, knowledge_base/elastic/, etc."
        )
        # Save empty store so downstream code doesn't crash
        store = VectorStore(dim=384)
        store.save(store_path)
        return {"files": 0, "chunks": 0, "vectors": 0, "elapsed_s": 0.0}

    # ── Step 2: Embed ──────────────────────────────────────────────────────
    log.info(
        "Step 2/3 — Embedding chunks",
        extra={"model": model_name, "chunks": len(all_chunks)},
    )
    embedder = Embedder(model_name=model_name, normalize=True)
    embedder.warmup()

    texts   = [c.text for c in all_chunks]
    vectors = embedder.embed(texts)

    log.info(
        "Embedding complete",
        extra={"vectors": vectors.shape[0], "dim": vectors.shape[1]},
    )

    # ── Step 3: Index + Save ───────────────────────────────────────────────
    log.info("Step 3/3 — Building FAISS index and saving")
    store = VectorStore(dim=vectors.shape[1])
    store.add_chunks(all_chunks, vectors)
    store.save(store_path)

    elapsed = round(time.monotonic() - t0, 2)
    stats   = {
        "files":     files,
        "chunks":    len(all_chunks),
        "vectors":   store.size,
        "elapsed_s": elapsed,
        "store":     str(store_path),
        "model":     model_name,
    }

    log.info("Ingestion complete", extra=stats)
    return stats


def ingest_platform(
    platform:   str,
    kb_dir:     Path | str = DEFAULT_KB_DIR,
    store_path: Path | str = DEFAULT_STORE_PATH,
    **kwargs,
) -> dict:
    """
    Re-ingest a single platform's documents (incremental update helper).

    Args:
        platform:   One of splunk / qradar / elastic / sentinel / wazuh / mitre.
        kb_dir:     Root knowledge_base directory.
        store_path: Output path prefix.
        **kwargs:   Forwarded to ingest_knowledge_base.

    Returns:
        Stats dict.
    """
    platform_dir = Path(kb_dir) / platform
    if not platform_dir.exists():
        log.warning(
            "Platform directory not found",
            extra={"platform": platform, "path": str(platform_dir)},
        )
        return {"platform": platform, "chunks": 0}

    log.info("Re-ingesting platform", extra={"platform": platform})
    return ingest_knowledge_base(kb_dir=platform_dir, store_path=store_path, **kwargs)


if __name__ == "__main__":
    """Allow direct execution: python -m src.rag.ingest"""
    import argparse

    parser = argparse.ArgumentParser(description="Ingest knowledge base into FAISS store")
    parser.add_argument("--kb-dir",      default=str(DEFAULT_KB_DIR))
    parser.add_argument("--store-path",  default=str(DEFAULT_STORE_PATH))
    parser.add_argument("--model",       default="all-MiniLM-L6-v2")
    parser.add_argument("--chunk-size",  type=int, default=512)
    parser.add_argument("--overlap",     type=int, default=64)
    parser.add_argument("--overwrite",   action="store_true", default=True)
    args = parser.parse_args()

    stats = ingest_knowledge_base(
        kb_dir        = args.kb_dir,
        store_path    = args.store_path,
        model_name    = args.model,
        chunk_size    = args.chunk_size,
        chunk_overlap = args.overlap,
        overwrite     = args.overwrite,
    )
    print("\n── Ingestion stats ──")
    for k, v in stats.items():
        print(f"  {k}: {v}")