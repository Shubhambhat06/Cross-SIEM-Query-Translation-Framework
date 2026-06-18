#!/usr/bin/env python3
"""
scripts/ingest_knowledge_base.py
=================================
One-time ingestion pipeline: scan knowledge_base/ → chunk → embed → FAISS index.

Run this ONCE after populating knowledge_base/ with SIEM documentation, and
again whenever new documents are added.  Output is a FAISS index + metadata
JSON that Retriever loads at query time.

Usage
-----
    # Full ingest (default paths)
    python scripts/ingest_knowledge_base.py

    # Custom paths
    python scripts/ingest_knowledge_base.py \\
        --kb-dir knowledge_base \\
        --store-path src/rag/store \\
        --model all-MiniLM-L6-v2 \\
        --chunk-size 512 \\
        --overlap 64

    # Re-ingest a single platform only
    python scripts/ingest_knowledge_base.py --platform splunk

    # Force re-ingest even if store already exists
    python scripts/ingest_knowledge_base.py --overwrite

    # Dry-run: count chunks without writing
    python scripts/ingest_knowledge_base.py --dry-run

Exit codes
----------
    0  — success
    1  — knowledge_base/ directory empty or missing (warning, not fatal)
    2  — fatal error (dependency missing, I/O failure, etc.)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# ── Make sure src/ is on the path when run as a script ───────────────────────
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.utils.logger import get_logger

log = get_logger("ingest_knowledge_base")

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_KB_DIR     = _ROOT / "knowledge_base"
DEFAULT_STORE_PATH = _ROOT / "src" / "rag" / "store"
DEFAULT_MODEL      = "all-MiniLM-L6-v2"
DEFAULT_CHUNK_SIZE = 512
DEFAULT_OVERLAP    = 64
DEFAULT_GLOB       = "**/*.txt"
PLATFORMS          = ("splunk", "qradar", "elastic", "sentinel", "wazuh", "mitre")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _print_banner(args: argparse.Namespace) -> None:
    print("\n" + "=" * 60)
    print("  NL-SIEM  |  Knowledge Base Ingestion Pipeline")
    print("=" * 60)
    print(f"  kb-dir    : {args.kb_dir}")
    print(f"  store-path: {args.store_path}")
    print(f"  model     : {args.model}")
    print(f"  chunk-size: {args.chunk_size}  overlap: {args.overlap}")
    if args.platform:
        print(f"  platform  : {args.platform} (single-platform mode)")
    if args.dry_run:
        print("  mode      : DRY-RUN (no files written)")
    print("=" * 60 + "\n")


def _print_stats(stats: dict) -> None:
    if stats.get("skipped"):
        print("\n[SKIPPED]  Store already exists. Use --overwrite to re-ingest.\n")
        return
    print("\n── Ingestion stats ─────────────────────────────────")
    for k, v in stats.items():
        print(f"  {k:<14}: {v}")
    print("────────────────────────────────────────────────────\n")


def _check_dependencies() -> None:
    """Fail fast with a clear message if required packages are missing."""
    missing = []
    for pkg in ("sentence_transformers", "faiss"):
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(
            f"\n[ERROR] Missing required packages: {missing}\n"
            f"  Run: pip install sentence-transformers faiss-cpu\n",
            file=sys.stderr,
        )
        sys.exit(2)


def _dry_run(kb_dir: Path, chunk_size: int, overlap: int) -> dict:
    """Count chunks without embedding or saving."""
    from src.rag.chunker import Chunker
    chunker    = Chunker(chunk_size=chunk_size, chunk_overlap=overlap)
    all_chunks = chunker.chunk_directory(kb_dir)
    files      = len(set(c.source for c in all_chunks))
    print(f"\n[DRY-RUN]  Would produce {len(all_chunks)} chunks from {files} files.")
    print(            "           No embedding or index written.\n")
    return {"files": files, "chunks": len(all_chunks), "dry_run": True}


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ingest knowledge_base/ into a FAISS vector store for RAG retrieval.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--kb-dir",     type=Path, default=DEFAULT_KB_DIR,
                        help="Root of knowledge_base/ directory")
    parser.add_argument("--store-path", type=Path, default=DEFAULT_STORE_PATH,
                        help="Output path prefix for FAISS index + metadata JSON")
    parser.add_argument("--model",      default=DEFAULT_MODEL,
                        help="SentenceTransformer model name")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE,
                        help="Words per chunk")
    parser.add_argument("--overlap",    type=int, default=DEFAULT_OVERLAP,
                        help="Overlap words between consecutive chunks")
    parser.add_argument("--platform",   choices=PLATFORMS, default=None,
                        help="Re-ingest a single platform only")
    parser.add_argument("--overwrite",  action="store_true", default=False,
                        help="Force re-ingest even if store already exists")
    parser.add_argument("--dry-run",    action="store_true", default=False,
                        help="Count chunks only; do not embed or write index")
    parser.add_argument("--quiet",      action="store_true", default=False,
                        help="Suppress progress output")
    args = parser.parse_args()

    if not args.quiet:
        _print_banner(args)

    # Dependency check (skip for dry-run)
    if not args.dry_run:
        _check_dependencies()

    t0 = time.monotonic()

    try:
        # ── Dry-run path ──────────────────────────────────────────────────────
        if args.dry_run:
            target = args.kb_dir / args.platform if args.platform else args.kb_dir
            stats  = _dry_run(target, args.chunk_size, args.overlap)
            return 0

        # ── Real ingest ───────────────────────────────────────────────────────
        if args.platform:
            from src.rag.ingest import ingest_platform
            stats = ingest_platform(
                platform      = args.platform,
                kb_dir        = args.kb_dir,
                store_path    = args.store_path,
                model_name    = args.model,
                chunk_size    = args.chunk_size,
                chunk_overlap = args.overlap,
                overwrite     = args.overwrite,
            )
        else:
            from src.rag.ingest import ingest_knowledge_base
            stats = ingest_knowledge_base(
                kb_dir        = args.kb_dir,
                store_path    = args.store_path,
                model_name    = args.model,
                chunk_size    = args.chunk_size,
                chunk_overlap = args.overlap,
                overwrite     = args.overwrite,
            )

        stats["wall_clock_s"] = round(time.monotonic() - t0, 2)

        if not args.quiet:
            _print_stats(stats)

        # Save a manifest alongside the store
        manifest_path = args.store_path.parent / "ingest_manifest.json"
        manifest_path.write_text(
            json.dumps({**stats, "kb_dir": str(args.kb_dir),
                        "model": args.model}, indent=2)
        )
        log.info("Manifest written", extra={"path": str(manifest_path)})

        # Exit 1 if nothing was indexed (warning, not fatal)
        if stats.get("chunks", 0) == 0 and not stats.get("skipped"):
            print(
                "[WARNING]  No chunks produced.\n"
                "           Add .txt files under knowledge_base/<platform>/\n"
                "           then re-run this script.",
                file=sys.stderr,
            )
            return 1

        print("[OK]  Ingestion complete.  Store ready at:", args.store_path)
        return 0

    except KeyboardInterrupt:
        print("\n[INTERRUPTED]  Ingestion cancelled by user.", file=sys.stderr)
        return 2
    except Exception as exc:
        log.exception("Ingestion failed")
        print(f"\n[ERROR]  {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())