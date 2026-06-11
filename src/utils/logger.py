"""
Structured logging for NL-SIEM.

Usage:
    from src.utils.logger import get_logger
    log = get_logger(__name__)
    log.info("Translating query", extra={"platform": "splunk"})

A unique run_id is generated at import time and attached to every log record.
All loggers share the same handlers; configure once via setup_logging().
"""

from __future__ import annotations

import logging
import sys
import uuid
from pathlib import Path
from typing import Any

from rich.logging import RichHandler

# ── Run ID ────────────────────────────────────────────────────────────────────
RUN_ID: str = str(uuid.uuid4())[:8]


class RunIDFilter(logging.Filter):
    """Injects run_id into every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.run_id = RUN_ID
        return True


class StructuredFormatter(logging.Formatter):
    """
    Plain-text formatter for file handlers.
    Format: LEVEL | run_id | name | message [key=val ...]
    """

    def format(self, record: logging.LogRecord) -> str:
        base = (
            f"{self.formatTime(record, '%Y-%m-%d %H:%M:%S')} "
            f"{record.levelname:<8} "
            f"[{getattr(record, 'run_id', '?')}] "
            f"{record.name} — {record.getMessage()}"
        )
        # Attach any extra keys passed via extra={}
        extras = {
            k: v
            for k, v in record.__dict__.items()
            if k not in logging.LogRecord.__dict__
            and k not in ("run_id", "message", "asctime")
            and not k.startswith("_")
        }
        if extras:
            kv = " ".join(f"{k}={v!r}" for k, v in extras.items())
            base += f" | {kv}"
        if record.exc_info:
            base += "\n" + self.formatException(record.exc_info)
        return base


def setup_logging(
    level: str = "INFO",
    log_file: Path | None = None,
    *,
    rich_console: bool = True,
) -> None:
    """
    Configure root logger. Call once at application startup.

    Args:
        level: Logging level string (DEBUG / INFO / WARNING / ERROR).
        log_file: Optional path to write structured logs.
        rich_console: Use RichHandler for pretty terminal output.
    """
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove any handlers added by libraries
    root.handlers.clear()

    run_filter = RunIDFilter()

    # ── Console handler ───────────────────────────────────────────────────
    if rich_console:
        console_handler = RichHandler(
            level=logging.DEBUG,
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
        )
    else:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(
            logging.Formatter("%(levelname)s | %(name)s | %(message)s")
        )

    console_handler.addFilter(run_filter)
    root.addHandler(console_handler)

    # ── File handler ──────────────────────────────────────────────────────
    if log_file is not None:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(StructuredFormatter())
        file_handler.addFilter(run_filter)
        root.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger. Automatically initialises logging with defaults
    if setup_logging() has not been called yet.

    Args:
        name: Typically __name__ of the calling module.

    Returns:
        logging.Logger instance.
    """
    if not logging.getLogger().handlers:
        # Lazy init with defaults — avoids needing explicit setup in tests
        setup_logging(level="INFO", rich_console=True)
    return logging.getLogger(name)


def log_event(
    logger: logging.Logger,
    level: str,
    message: str,
    **kwargs: Any,
) -> None:
    """
    Convenience wrapper to log a message with structured key-value extras.

    Args:
        logger: Logger instance.
        level: Log level string.
        message: Human-readable message.
        **kwargs: Additional key-value pairs attached to the log record.
    """
    log_fn = getattr(logger, level.lower(), logger.info)
    log_fn(message, extra=kwargs)