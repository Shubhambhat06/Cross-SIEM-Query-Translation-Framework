"""
Chunker — splits knowledge base documents into overlapping text chunks for RAG.

Uses a sliding-window approach with configurable split strategies:
  - WORD:     sliding window over words (original behaviour, now the default)
  - SENTENCE: breaks at sentence boundaries to avoid mid-sentence splits
  - CHAR:     raw character window (useful for code files)

No ML dependencies — pure text processing.

Place at: src/rag/chunker.py

Usage:
    from src.rag.chunker import Chunker, SplitStrategy

    # Word-based (default)
    chunker = Chunker(chunk_size=512, chunk_overlap=64)
    chunks  = chunker.chunk_file(Path("knowledge_base/splunk/spl_commands.txt"))

    # Sentence-aware — cleaner chunk boundaries for prose documents
    chunker = Chunker(chunk_size=512, chunk_overlap=64,
                      strategy=SplitStrategy.SENTENCE)
    chunks  = chunker.chunk_text(text, source="splunk/spl_commands.txt",
                                 platform="splunk")

    # Serialise for vector DB ingestion
    records = [c.to_dict() for c in chunks]

    # Quick summary
    print(chunker.stats(chunks))
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator

from src.utils.logger import get_logger

log = get_logger(__name__)

# ── Type alias ────────────────────────────────────────────────────────────────
Metadata = dict[str, object]

# ── Platform tag extracted from knowledge base path ───────────────────────────
# knowledge_base/<platform>/<filename> → platform
_PLATFORM_RE = re.compile(r"knowledge_base[/\\](\w+)[/\\]")

# ── Sentence boundary: end of ., !, ? followed by whitespace or EOS ──────────
_SENTENCE_END_RE = re.compile(r"(?<=[.!?])\s+")


# ─────────────────────────────────────────────────────────────────────────────
# Split strategy
# ─────────────────────────────────────────────────────────────────────────────

class SplitStrategy(str, Enum):
    """How the source text is divided before windowing."""

    WORD     = "word"      # split on whitespace (original behaviour)
    SENTENCE = "sentence"  # split on sentence boundaries — cleaner for prose
    CHAR     = "char"      # raw character window — good for code / structured text


# ─────────────────────────────────────────────────────────────────────────────
# Chunk
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Chunk:
    """A single text chunk with provenance metadata."""

    text:       str        # chunk content
    source:     str        # relative path of origin file
    platform:   str        # splunk | qradar | elastic | sentinel | wazuh | mitre
    chunk_idx:  int        # 0-based index within the source file
    char_start: int        # character offset in the original text
    char_end:   int        # character offset in the original text
    metadata:   Metadata   = field(default_factory=dict)

    # ── dunder helpers ────────────────────────────────────────────────────────

    def __len__(self) -> int:
        return len(self.text)

    def __repr__(self) -> str:
        return (
            f"Chunk(id={self.id!r}, platform={self.platform!r}, "
            f"words={self.word_count}, chars={self.char_start}..{self.char_end})"
        )

    # ── computed properties ───────────────────────────────────────────────────

    @property
    def word_count(self) -> int:
        return len(self.text.split())

    @property
    def id(self) -> str:
        """Stable unique ID: source + chunk index."""
        safe_src = re.sub(r"[/\\]", "_", self.source)
        return f"{safe_src}__chunk_{self.chunk_idx:04d}"

    # ── convenience helpers ───────────────────────────────────────────────────

    def preview(self, max_chars: int = 120) -> str:
        """Return a truncated snippet — handy for logging / REPL inspection."""
        if len(self.text) <= max_chars:
            return self.text
        return self.text[:max_chars].rstrip() + " …"

    def to_dict(self) -> dict:
        """
        Serialise to a plain dict suitable for vector DB ingestion.
        All fields are JSON-safe.  ``metadata`` values must be primitives.
        """
        base = asdict(self)
        base["id"]         = self.id
        base["word_count"] = self.word_count
        return base


# ─────────────────────────────────────────────────────────────────────────────
# ChunkStats
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ChunkStats:
    """Summary statistics for a list of Chunk objects."""

    total_chunks:  int
    total_words:   int
    avg_words:     float
    min_words:     int
    max_words:     int
    source_files:  int
    coverage_pct:  float   # % of original words captured across all chunks

    def __str__(self) -> str:
        return (
            f"ChunkStats("
            f"chunks={self.total_chunks}, "
            f"words={self.total_words}, "
            f"avg={self.avg_words:.1f}, "
            f"min={self.min_words}, "
            f"max={self.max_words}, "
            f"sources={self.source_files}, "
            f"coverage={self.coverage_pct:.1f}%)"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Chunker
# ─────────────────────────────────────────────────────────────────────────────

class Chunker:
    """
    Sliding-window text chunker with configurable split strategy.

    Args:
        chunk_size:      Target chunk size in *units* (words, sentences, or chars
                         depending on ``strategy``).  Default 512.
        chunk_overlap:   Overlap in the same units between consecutive chunks.
                         Default 64.
        min_chunk_units: Discard chunks smaller than this many units.
                         Default 20.
        strategy:        One of ``SplitStrategy.WORD`` (default),
                         ``SplitStrategy.SENTENCE``, or ``SplitStrategy.CHAR``.
    """

    def __init__(
        self,
        chunk_size:      int           = 512,
        chunk_overlap:   int           = 64,
        min_chunk_units: int           = 20,
        strategy:        SplitStrategy = SplitStrategy.WORD,
    ) -> None:
        if chunk_overlap >= chunk_size:
            raise ValueError(
                f"chunk_overlap ({chunk_overlap}) must be < chunk_size ({chunk_size})"
            )
        self.chunk_size      = chunk_size
        self.chunk_overlap   = chunk_overlap
        self.min_chunk_units = min_chunk_units
        self.strategy        = strategy

    # ─────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────

    def chunk_text(
        self,
        text:     str,
        source:   str             = "unknown",
        platform: str             = "unknown",
        metadata: Metadata | None = None,
    ) -> list[Chunk]:
        """
        Chunk a raw text string.

        Args:
            text:     Full document text.
            source:   Origin filename / path (stored in metadata).
            platform: SIEM platform tag.
            metadata: Optional extra key-value pairs attached to every chunk.

        Returns:
            List of :class:`Chunk` objects.
        """
        if not text or not text.strip():
            return []

        text   = self._normalise(text)
        meta   = dict(metadata or {})
        units  = self._split(text)

        chunks = list(self._window(units, text, source, platform, meta))

        log.debug(
            "Chunked text",
            extra={
                "source":   source,
                "platform": platform,
                "strategy": self.strategy,
                "units":    len(units),
                "chunks":   len(chunks),
            },
        )
        return chunks

    def chunk_file(
        self,
        path:     Path,
        metadata: Metadata | None = None,
    ) -> list[Chunk]:
        """
        Load a file and chunk its contents.

        The platform tag is automatically extracted from the path when it
        follows the ``knowledge_base/<platform>/<filename>`` convention.

        Falls back from UTF-8 to *latin-1* on encoding errors instead of
        silently corrupting bytes.

        Args:
            path:     Path to the text file.
            metadata: Optional extra key-value pairs.

        Returns:
            List of :class:`Chunk` objects.
        """
        path = Path(path)
        if not path.exists():
            log.warning("Chunker: file not found", extra={"path": str(path)})
            return []

        text = self._read_file(path)
        if text is None:
            return []

        platform = self._infer_platform(path)
        source   = str(path)

        log.debug("Chunking file", extra={"path": source, "platform": platform})
        return self.chunk_text(text, source=source, platform=platform,
                               metadata=metadata)

    def chunk_directory(
        self,
        directory: Path,
        globs:     str | list[str] = "**/*.txt",
        metadata:  Metadata | None = None,
    ) -> list[Chunk]:
        """
        Recursively chunk all matching files in a directory.

        Args:
            directory: Root directory to scan.
            globs:     Glob pattern **or** list of patterns
                       (default: ``"**/*.txt"``).
                       Example: ``["**/*.txt", "**/*.md"]``
            metadata:  Optional extra key-value pairs added to every chunk.

        Returns:
            Flat list of all :class:`Chunk` objects from all files.
        """
        directory  = Path(directory)
        glob_list  = [globs] if isinstance(globs, str) else list(globs)
        all_chunks: list[Chunk] = []

        files: list[Path] = []
        for pattern in glob_list:
            files.extend(directory.glob(pattern))
        files = sorted(set(files))

        log.info(
            "Chunking directory",
            extra={"directory": str(directory), "files": len(files)},
        )

        for f in files:
            all_chunks.extend(self.chunk_file(f, metadata=metadata))

        log.info(
            "Directory chunking complete",
            extra={"total_chunks": len(all_chunks), "files": len(files)},
        )
        return all_chunks

    # ── Stats ─────────────────────────────────────────────────────────────────

    @staticmethod
    def stats(chunks: list[Chunk], original_word_count: int | None = None) -> ChunkStats:
        """
        Compute summary statistics for a list of chunks.

        Args:
            chunks:              The chunks to summarise.
            original_word_count: Word count of the source document(s).
                                 When provided, ``coverage_pct`` is meaningful;
                                 otherwise it is set to 0.

        Returns:
            A :class:`ChunkStats` instance.
        """
        if not chunks:
            return ChunkStats(
                total_chunks=0, total_words=0, avg_words=0.0,
                min_words=0, max_words=0, source_files=0, coverage_pct=0.0,
            )

        word_counts   = [c.word_count for c in chunks]
        total_words   = sum(word_counts)
        source_files  = len({c.source for c in chunks})
        coverage_pct  = (
            min(total_words / original_word_count * 100, 100.0)
            if original_word_count
            else 0.0
        )

        return ChunkStats(
            total_chunks  = len(chunks),
            total_words   = total_words,
            avg_words     = total_words / len(chunks),
            min_words     = min(word_counts),
            max_words     = max(word_counts),
            source_files  = source_files,
            coverage_pct  = coverage_pct,
        )

    # ── Iteration helper ──────────────────────────────────────────────────────

    def iter_chunks(
        self,
        path:     Path,
        metadata: Metadata | None = None,
    ) -> Iterator[Chunk]:
        """Yield chunks one at a time — memory-friendly for very large files."""
        yield from self.chunk_file(path, metadata=metadata)

    # ─────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────

    def _split(self, text: str) -> list[str]:
        """Tokenise *text* into units according to the chosen strategy."""
        if self.strategy == SplitStrategy.WORD:
            return text.split()
        if self.strategy == SplitStrategy.SENTENCE:
            return [s.strip() for s in _SENTENCE_END_RE.split(text) if s.strip()]
        if self.strategy == SplitStrategy.CHAR:
            return list(text)
        raise ValueError(f"Unknown strategy: {self.strategy}")  # pragma: no cover

    def _join(self, units: list[str]) -> str:
        """Re-join units into a string."""
        if self.strategy == SplitStrategy.CHAR:
            return "".join(units)
        return " ".join(units)

    def _window(
        self,
        units:    list[str],
        text:     str,
        source:   str,
        platform: str,
        metadata: Metadata,
    ) -> Iterator[Chunk]:
        """Slide a window over *units* and yield :class:`Chunk` objects."""
        n    = len(units)
        step = self.chunk_size - self.chunk_overlap

        # Pre-compute character offsets for each unit so we can annotate chunks.
        offsets = self._build_unit_offsets(text, units)

        chunk_num = 0
        pos       = 0

        while pos < n:
            end        = min(pos + self.chunk_size, n)
            window     = units[pos:end]

            if len(window) < self.min_chunk_units:
                break

            chunk_text = self._join(window)
            char_start = offsets[pos] if pos < len(offsets) else 0
            char_end   = (
                offsets[end - 1] + len(units[end - 1])
                if end <= len(offsets)
                else len(text)
            )

            yield Chunk(
                text       = chunk_text,
                source     = source,
                platform   = platform,
                chunk_idx  = chunk_num,
                char_start = char_start,
                char_end   = char_end,
                metadata   = dict(metadata),
            )

            chunk_num += 1
            pos       += step

    # ─────────────────────────────────────────────
    # Static helpers
    # ─────────────────────────────────────────────

    @staticmethod
    def _normalise(text: str) -> str:
        """
        Normalise whitespace: collapse runs of whitespace/newlines
        to a single space, strip leading/trailing whitespace.
        """
        text = re.sub(r"\r\n", "\n", text)
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    @staticmethod
    def _build_unit_offsets(text: str, units: list[str]) -> list[int]:
        """
        Return the character start position of each unit in *text*.

        Works for word, sentence, and char strategies by scanning forward
        for the first occurrence of each unit after the previous one.
        """
        offsets: list[int] = []
        cursor = 0
        for unit in units:
            idx = text.find(unit, cursor)
            if idx == -1:
                offsets.append(cursor)  # fallback — shouldn't happen
            else:
                offsets.append(idx)
                cursor = idx + len(unit)
        return offsets

    @staticmethod
    def _infer_platform(path: Path) -> str:
        """
        Extract platform from paths like ``knowledge_base/splunk/file.txt``.
        Returns ``'unknown'`` if the pattern doesn't match.
        """
        m = _PLATFORM_RE.search(str(path))
        return m.group(1) if m else "unknown"

    @staticmethod
    def _read_file(path: Path) -> str | None:
        """Read a file, trying UTF-8 first then latin-1 as a fallback."""
        for encoding in ("utf-8", "latin-1"):
            try:
                return path.read_text(encoding=encoding)
            except UnicodeDecodeError:
                continue
        log.error(
            "Chunker: could not decode file with utf-8 or latin-1",
            extra={"path": str(path)},
        )
        return None