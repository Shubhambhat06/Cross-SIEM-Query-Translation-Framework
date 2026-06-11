"""
File I/O utilities for NL-SIEM.

Handles JSON, JSONL, CSV, and plain text with consistent error handling
and path resolution relative to project root.

Usage:
    from src.utils.file_io import load_jsonl, save_json, load_csv
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterator

from src.utils.exceptions import DatasetLoadError
from src.utils.logger import get_logger

log = get_logger(__name__)


# ─────────────────────────────────────────────
# Path helpers
# ─────────────────────────────────────────────

def resolve_path(path: str | Path, root: str | Path | None = None) -> Path:
    """
    Resolve *path* to an absolute Path.

    If *path* is already absolute, returns it unchanged.
    If *root* is given, resolves relative to root.
    Otherwise resolves relative to cwd.
    """
    path = Path(path)
    if path.is_absolute():
        return path
    if root is not None:
        return (Path(root) / path).resolve()
    return path.resolve()


def ensure_parent(path: Path) -> Path:
    """Create parent directories if they do not exist."""
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


# ─────────────────────────────────────────────
# JSON
# ─────────────────────────────────────────────

def load_json(path: str | Path) -> Any:
    """
    Load and return a JSON file.

    Args:
        path: Path to the .json file.

    Returns:
        Parsed Python object (dict, list, etc.).

    Raises:
        DatasetLoadError: If the file is missing or malformed.
    """
    path = Path(path)
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        log.debug("Loaded JSON", extra={"path": str(path), "type": type(data).__name__})
        return data
    except FileNotFoundError:
        raise DatasetLoadError(str(path), "file not found")
    except json.JSONDecodeError as exc:
        raise DatasetLoadError(str(path), f"invalid JSON: {exc}")


def save_json(data: Any, path: str | Path, *, indent: int = 2) -> None:
    """
    Serialise *data* to a JSON file.

    Args:
        data: JSON-serialisable object.
        path: Destination path (parent dirs created automatically).
        indent: Pretty-print indent level.
    """
    path = ensure_parent(Path(path))
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=indent, ensure_ascii=False)
    log.debug("Saved JSON", extra={"path": str(path)})


# ─────────────────────────────────────────────
# JSONL  (one JSON object per line)
# ─────────────────────────────────────────────

def load_jsonl(path: str | Path) -> list[dict]:
    """
    Load all records from a JSONL file.

    Args:
        path: Path to the .jsonl file.

    Returns:
        List of dicts, one per line.

    Raises:
        DatasetLoadError: If the file is missing or a line is malformed.
    """
    path = Path(path)
    records: list[dict] = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise DatasetLoadError(
                        str(path), f"malformed JSON on line {lineno}: {exc}"
                    )
    except FileNotFoundError:
        raise DatasetLoadError(str(path), "file not found")
    log.debug("Loaded JSONL", extra={"path": str(path), "records": len(records)})
    return records


def stream_jsonl(path: str | Path) -> Iterator[dict]:
    """
    Lazily yield records from a JSONL file (memory-efficient for large files).

    Args:
        path: Path to the .jsonl file.

    Yields:
        One dict per line.
    """
    path = Path(path)
    with path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                log.warning(
                    "Skipping malformed JSONL line",
                    extra={"path": str(path), "line": lineno, "error": str(exc)},
                )


def save_jsonl(records: list[dict], path: str | Path) -> None:
    """
    Write a list of dicts to a JSONL file (one JSON object per line).

    Args:
        records: List of dicts to write.
        path: Destination path (parent dirs created automatically).
    """
    path = ensure_parent(Path(path))
    with path.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    log.debug("Saved JSONL", extra={"path": str(path), "records": len(records)})


def append_jsonl(record: dict, path: str | Path) -> None:
    """Append a single record to a JSONL file (creates file if absent)."""
    path = ensure_parent(Path(path))
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


# ─────────────────────────────────────────────
# CSV
# ─────────────────────────────────────────────

def load_csv(path: str | Path) -> list[dict]:
    """
    Load a CSV file with headers into a list of dicts.

    Args:
        path: Path to the .csv file.

    Returns:
        List of row dicts keyed by column headers.

    Raises:
        DatasetLoadError: If the file is missing.
    """
    path = Path(path)
    try:
        with path.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            rows = [dict(row) for row in reader]
        log.debug("Loaded CSV", extra={"path": str(path), "rows": len(rows)})
        return rows
    except FileNotFoundError:
        raise DatasetLoadError(str(path), "file not found")


def save_csv(
    records: list[dict],
    path: str | Path,
    fieldnames: list[str] | None = None,
) -> None:
    """
    Write a list of dicts to a CSV file.

    Args:
        records: Rows to write.
        path: Destination path.
        fieldnames: Column order. Inferred from first record if None.
    """
    if not records:
        log.warning("save_csv called with empty records list", extra={"path": str(path)})
        return
    path = ensure_parent(Path(path))
    fieldnames = fieldnames or list(records[0].keys())
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)
    log.debug("Saved CSV", extra={"path": str(path), "rows": len(records)})


# ─────────────────────────────────────────────
# Plain text
# ─────────────────────────────────────────────

def load_text(path: str | Path) -> str:
    """Read and return the full contents of a text file."""
    path = Path(path)
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise DatasetLoadError(str(path), "file not found")


def save_text(content: str, path: str | Path) -> None:
    """Write a string to a text file (creates parent dirs)."""
    path = ensure_parent(Path(path))
    path.write_text(content, encoding="utf-8")
    log.debug("Saved text", extra={"path": str(path), "chars": len(content)})


# ─────────────────────────────────────────────
# Directory helpers
# ─────────────────────────────────────────────

def list_files(directory: str | Path, pattern: str = "*") -> list[Path]:
    """
    Return sorted list of files matching *pattern* in *directory*.

    Args:
        directory: Directory to search.
        pattern: Glob pattern (e.g. "*.txt", "**/*.json").

    Returns:
        Sorted list of Path objects.
    """
    directory = Path(directory)
    return sorted(directory.glob(pattern))