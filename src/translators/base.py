"""
Base SIEM Translator — abstract class all 5 platform formatters inherit from.

Every translator must implement:
  - translate(ir)       → platform query string
  - validate(query)     → bool (syntax check)
  - platform_name       → str property

Place at: src/translators/base.py
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from src.ir.schema import IRQuery, ActionType, ComparisonOperator
from src.translators.field_mapping import resolve, resolve_all
from src.utils.exceptions import TranslationError
from src.utils.logger import get_logger

log = get_logger(__name__)


class BaseSIEMTranslator(ABC):
    """
    Abstract base for all SIEM platform translators.

    Subclasses implement translate() and validate().
    Shared operator mapping and field resolution live here.
    """

    # ── Must be set by each subclass ──────────────────────────────────────
    PLATFORM: str = ""

    # ── Operator maps (subclasses override where platform differs) ─────────
    OP_MAP: dict[str, str] = {
        ComparisonOperator.EQ:       "=",
        ComparisonOperator.NEQ:      "!=",
        ComparisonOperator.GT:       ">",
        ComparisonOperator.GTE:      ">=",
        ComparisonOperator.LT:       "<",
        ComparisonOperator.LTE:      "<=",
        ComparisonOperator.CONTAINS: "contains",
        ComparisonOperator.REGEX:    "matches",
        ComparisonOperator.IN:       "in",
        ComparisonOperator.NOT_IN:   "not in",
    }

    # ─────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────

    @property
    def platform_name(self) -> str:
        return self.PLATFORM

    def translate(self, ir: IRQuery) -> str:
        """
        Translate an IRQuery into a platform-native query string.

        Args:
            ir: Validated IRQuery object from Layer 1.

        Returns:
            Platform-native query string.

        Raises:
            TranslationError: If translation fails.
        """
        try:
            log.debug(
                "Translating IR",
                extra={"platform": self.PLATFORM, "summary": ir.summary()},
            )
            result = self._translate(ir)
            log.debug(
                "Translation complete",
                extra={"platform": self.PLATFORM, "length": len(result)},
            )
            return result
        except TranslationError:
            raise
        except Exception as exc:
            raise TranslationError(
                f"[{self.PLATFORM}] Translation failed: {exc}",
                platform=self.PLATFORM,
                details={"ir_summary": ir.summary()},
            )

    @abstractmethod
    def _translate(self, ir: IRQuery) -> str:
        """Internal translation logic — implemented by each subclass."""
        ...

    @abstractmethod
    def validate(self, query: str) -> bool:
        """
        Syntactic check of a generated query string.

        Args:
            query: Generated platform query string.

        Returns:
            True if the query appears syntactically valid.
        """
        ...

    # ─────────────────────────────────────────────
    # Shared helpers (available to all subclasses)
    # ─────────────────────────────────────────────

    def _resolve(self, canonical: str) -> str:
        """Resolve a canonical field name to this platform's field name."""
        return resolve(canonical, self.PLATFORM)

    def _resolve_all(self, fields: list[str]) -> list[str]:
        """Resolve a list of canonical field names."""
        return resolve_all(fields, self.PLATFORM)

    def _map_op(self, op: str) -> str:
        """Map a ComparisonOperator enum value to this platform's operator string."""
        return self.OP_MAP.get(op, op)

    def _format_value(self, value: object) -> str:
        """
        Format a filter value for inclusion in a query string.
        Strings are quoted; numbers and booleans are unquoted.
        Lists are formatted as platform-appropriate syntax.
        """
        if isinstance(value, str):
            return f'"{value}"'
        if isinstance(value, list):
            items = ", ".join(self._format_value(v) for v in value)
            return f"({items})"
        return str(value)

    def _requires_aggregation(self, ir: IRQuery) -> bool:
        return ir.action in (
            ActionType.AGGREGATE,
            ActionType.FILTER_AGGREGATE,
        )