"""
Base SIEM Translator — abstract class all 5 platform formatters inherit from.

Every translator must implement:
  - _translate(ir)      → platform query string   (wrapped by translate())
  - validate(query)     → bool (syntax check)
  - PLATFORM             → str class attribute

Place at: src/translators/base.py
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from src.ir.schema import ActionType, ComparisonOperator, IRQuery, SequenceStep
from src.translators.field_mapping import resolve, resolve_all
from src.utils.exceptions import TranslationError
from src.utils.logger import get_logger

log = get_logger(__name__)

# Fields checked, in priority order, when no explicit correlation_key is
# given on a SequenceStep. Shared by every translator that builds
# multi-event sequence/correlation queries (Elastic EQL, Splunk transaction,
# Sentinel join) so the heuristic — and any future tuning of it — lives in
# exactly one place instead of being copy-pasted per platform.
_DEFAULT_CORRELATION_PRIORITY = ["user", "host", "src_ip", "user_id", "hostname"]


class BaseSIEMTranslator(ABC):
    """
    Abstract base for all SIEM platform translators.

    Subclasses implement _translate() and validate().
    Shared operator mapping, field resolution, value quoting, and
    sequence-correlation inference live here so platform modules only
    contain platform-specific syntax decisions.
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

    # Quote character this platform's string literals use. Overridden by
    # QRadar (AQL is SQL-like → single-quoted, doubled-quote escaping).
    QUOTE_CHAR: str = '"'

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
            ) from exc

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
    # Field resolution
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

    def _requires_aggregation(self, ir: IRQuery) -> bool:
        return ir.action in (
            ActionType.AGGREGATE,
            ActionType.FILTER_AGGREGATE,
        )

    # ─────────────────────────────────────────────
    # Value quoting / injection safety
    # ─────────────────────────────────────────────
    #
    # Every translator previously interpolated filter values into query
    # strings with a bare f'"{value}"' / f"'{value}'" — a value containing
    # the platform's own quote character (e.g. a username of
    # `admin" or "1"="1`, or a file path containing a literal `"`) would
    # break out of the string literal and inject additional query syntax.
    # This is exactly the class of bug a query-translation layer for a
    # *security* product cannot afford. All quoting now funnels through
    # _quote()/_format_value() below so the escaping logic exists in one
    # place and is applied consistently.

    def _escape(self, value: object) -> str:
        """
        Escape backslashes and the platform's quote character in a value,
        WITHOUT wrapping it in quotes. Used when a value is embedded inside
        a larger quoted literal (e.g. a wildcard pattern like "*{value}*")
        rather than standing alone as one — _quote() covers the standalone
        case and calls this internally.
        """
        q = self.QUOTE_CHAR
        return str(value).replace("\\", "\\\\").replace(q, "\\" + q)

    def _quote(self, value: object) -> str:
        """
        Safely quote a scalar value as a string literal for this platform.

        Escapes backslashes and the platform's quote character so a value
        cannot terminate its literal early and inject additional syntax.
        Non-string scalars (int/float/bool) are returned unquoted.
        """
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return str(value)
        q = self.QUOTE_CHAR
        return f"{q}{self._escape(value)}{q}"

    def _format_value(self, value: object) -> str:
        """
        Format a filter value for inclusion in a query string.
        Strings are safely quoted/escaped; numbers and booleans are
        unquoted; lists are formatted as platform-appropriate syntax.
        """
        if isinstance(value, list):
            items = ", ".join(self._format_value(v) for v in value)
            return f"({items})"
        if isinstance(value, str):
            return self._quote(value)
        return self._quote(value)  # bool/int/float — _quote leaves these unquoted

    # ─────────────────────────────────────────────
    # Sequence correlation-key inference
    # ─────────────────────────────────────────────
    #
    # Shared by any translator building a multi-event sequence/correlation
    # query (Elastic EQL `sequence by`, Splunk `transaction`, Sentinel
    # join). A SequenceStep may declare an explicit correlation_key; that
    # is always authoritative and takes priority over guessing. Only when
    # no step declares one do we fall back to a field-name heuristic.

    def _infer_correlation_fields(
        self,
        steps: list[SequenceStep],
        priority: list[str] | None = None,
    ) -> list[str]:
        """
        Determine which canonical field(s) correlate events across a
        sequence, resolved to this platform's field names.

        Priority:
            1. The first non-empty `correlation_key` declared on any step
               (explicit author intent — always wins).
            2. A heuristic match against `priority` (defaults to
               user > host > src_ip > user_id > hostname) over every field
               referenced in any step's filter conditions.

        Returns:
            List of platform-resolved field names (possibly empty if no
            correlation key can be determined — callers should handle
            that case, e.g. by omitting the correlation clause).
        """
        for step in steps:
            if step.correlation_key:
                return self._resolve_all(step.correlation_key)

        found_fields: set[str] = set()
        for step in steps:
            if step.filter:
                found_fields |= self._collect_condition_fields(step.filter)

        for candidate in (priority or _DEFAULT_CORRELATION_PRIORITY):
            if candidate in found_fields:
                return [self._resolve(candidate)]

        return []

    def _collect_condition_fields(self, group) -> set[str]:
        """Recursively collect every canonical field name referenced in a FilterGroup."""
        from src.ir.schema import FilterCondition, FilterGroup  # local import avoids cycle

        fields: set[str] = set()
        for cond in group.conditions:
            if isinstance(cond, FilterCondition):
                fields.add(cond.field)
            elif isinstance(cond, FilterGroup):
                fields |= self._collect_condition_fields(cond)
        return fields

    # ─────────────────────────────────────────────
    # Threshold / aggregation-alias consistency
    # ─────────────────────────────────────────────

    def _threshold_field(self, ir: IRQuery) -> str | None:
        """
        Resolve the field a post-aggregation ThresholdCondition should
        reference in generated syntax.

        ir.threshold.field is author-supplied free text (default "count")
        and is NOT guaranteed to match the alias actually emitted by the
        aggregation clause (ir.aggregation.alias / output_field). If they
        diverge, a HAVING/where clause silently references a column that
        doesn't exist in the query's output, which every downstream SIEM
        will reject at parse/run time. Prefer the aggregation's own alias
        whenever one is defined; fall back to the threshold's own field
        only when there is no aggregation alias to reconcile against.
        """
        if ir.aggregation and (ir.aggregation.alias or ir.aggregation.field):
            return ir.aggregation.alias or ir.aggregation.output_field
        if ir.threshold:
            return ir.threshold.field
        return None