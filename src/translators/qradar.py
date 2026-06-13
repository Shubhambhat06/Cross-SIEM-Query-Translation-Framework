"""
QRadar AQL Translator — IR → IBM QRadar Ariel Query Language.

AQL is SQL-like: SELECT ... FROM events WHERE ... GROUP BY ... HAVING ... LAST N HOURS
Key differences from SQL:
  - Time filter goes at the END: LAST 24 HOURS
  - Source names use LOGSOURCENAME(logsourceid)
  - Event names use QIDNAME(qid)
  - No subqueries in WHERE (use HAVING for post-aggregation filtering)

Place at: src/translators/qradar.py

Example output:
    SELECT sourceip, username, COUNT(*) AS attempt_count
    FROM events
    WHERE eventid = 4625
    GROUP BY sourceip, username
    HAVING attempt_count > 50
    ORDER BY attempt_count DESC
    LAST 24 HOURS
"""

from __future__ import annotations

from src.ir.schema import (
    ActionType,
    AggregationSpec,
    ComparisonOperator,
    FilterCondition,
    FilterGroup,
    IRQuery,
    LookupSpec,
    ThresholdCondition,
)
from src.translators.base import BaseSIEMTranslator
from src.utils.logger import get_logger

log = get_logger(__name__)


class QRadarTranslator(BaseSIEMTranslator):
    """Translates IRQuery objects into IBM QRadar AQL queries."""

    PLATFORM = "qradar"

    OP_MAP = {
        ComparisonOperator.EQ:       "=",
        ComparisonOperator.NEQ:      "<>",
        ComparisonOperator.GT:       ">",
        ComparisonOperator.GTE:      ">=",
        ComparisonOperator.LT:       "<",
        ComparisonOperator.LTE:      "<=",
        ComparisonOperator.CONTAINS: "ILIKE",
        ComparisonOperator.REGEX:    "MATCHES",
        ComparisonOperator.IN:       "IN",
        ComparisonOperator.NOT_IN:   "NOT IN",
    }

    def _translate(self, ir: IRQuery) -> str:
        lines: list[str] = []

        # ── SELECT ────────────────────────────────────────────────────────
        lines.append(self._build_select(ir))

        # ── FROM ──────────────────────────────────────────────────────────
        lines.append("FROM events")

        # ── WHERE ─────────────────────────────────────────────────────────
        if ir.filter:
            where_str = self._build_where(ir.filter)
            if where_str:
                lines.append(f"WHERE {where_str}")

        # ── GROUP BY ──────────────────────────────────────────────────────
        if self._requires_aggregation(ir) and ir.aggregation and ir.aggregation.group_by:
            group_fields = ", ".join(
                self._resolve(f) for f in ir.aggregation.group_by
            )
            lines.append(f"GROUP BY {group_fields}")

        # ── HAVING ────────────────────────────────────────────────────────
        if ir.threshold:
            lines.append(self._build_having(ir.threshold))

        # ── ORDER BY ──────────────────────────────────────────────────────
        if ir.sort_by:
            direction = "DESC" if ir.sort_order == "desc" else "ASC"
            lines.append(f"ORDER BY {self._resolve(ir.sort_by)} {direction}")
        elif ir.aggregation and ir.aggregation.alias:
            lines.append(f"ORDER BY {ir.aggregation.alias} DESC")

        # ── LIMIT ─────────────────────────────────────────────────────────
        if ir.limit:
            lines.append(f"LIMIT {ir.limit}")

        # ── TIME (always last in AQL) ──────────────────────────────────────
        if ir.time_window:
            lines.append(ir.time_window.to_aql)

        return "\n".join(lines)

    # ─────────────────────────────────────────────
    # Clause builders
    # ─────────────────────────────────────────────

    def _build_select(self, ir: IRQuery) -> str:
        """Build SELECT clause."""
        select_parts: list[str] = []

        # Explicit fields
        if ir.fields:
            select_parts.extend(self._resolve(f) for f in ir.fields)

        # Aggregation expression
        if self._requires_aggregation(ir) and ir.aggregation:
            agg_expr = self._build_agg_expr(ir.aggregation)
            # avoid duplicate if alias already in fields
            alias = ir.aggregation.alias or "count"
            if alias not in ir.fields:
                select_parts.append(agg_expr)

        if not select_parts:
            return "SELECT *"

        # Remove duplicates preserving order
        seen = set()
        unique = []
        for p in select_parts:
            if p not in seen:
                seen.add(p)
                unique.append(p)

        return f"SELECT {', '.join(unique)}"

    def _build_agg_expr(self, agg: AggregationSpec) -> str:
        """Build an AQL aggregation expression."""
        alias = agg.alias or agg.output_field
        fn    = agg.function.upper()

        if agg.function == "count":
            return f"COUNT(*) AS {alias}"
        elif agg.function == "distinct_count":
            field = self._resolve(agg.field) if agg.field else "*"
            return f"COUNT(DISTINCT {field}) AS {alias}"
        else:
            field = self._resolve(agg.field) if agg.field else "*"
            return f"{fn}({field}) AS {alias}"

    def _build_where(self, group: FilterGroup) -> str:
        """Recursively build WHERE clause from FilterGroup."""
        parts: list[str] = []
        op_str = f" {str(group.operator).upper()} "

        for cond in group.conditions:
            if isinstance(cond, FilterCondition):
                parts.append(self._build_condition(cond))
            elif isinstance(cond, FilterGroup):
                inner = self._build_where(cond)
                if inner:
                    parts.append(f"({inner})")

        return op_str.join(p for p in parts if p)

    def _build_condition(self, cond: FilterCondition) -> str:
        """Build a single AQL WHERE condition."""
        field = self._resolve(cond.field)
        op    = cond.op
        value = cond.value

        if op == ComparisonOperator.CONTAINS:
            val_str = f"'%{value}%'" if isinstance(value, str) else str(value)
            expr = f"{field} ILIKE {val_str}"

        elif op == ComparisonOperator.REGEX:
            expr = f"{field} MATCHES '{value}'"

        elif op in (ComparisonOperator.IN, ComparisonOperator.NOT_IN):
            not_kw = "NOT " if op == ComparisonOperator.NOT_IN else ""
            if isinstance(value, list):
                items = ", ".join(
                    f"'{v}'" if isinstance(v, str) else str(v) for v in value
                )
                expr = f"{field} {not_kw}IN ({items})"
            else:
                expr = f"{field} {not_kw}IN ('{value}')"

        else:
            mapped_op = self._map_op(op)
            val_str   = f"'{value}'" if isinstance(value, str) else str(value)
            expr = f"{field} {mapped_op} {val_str}"

        return f"NOT ({expr})" if cond.negate else expr

    def _build_having(self, th: ThresholdCondition) -> str:
        """Build HAVING clause from ThresholdCondition."""
        op = self._map_op(th.op)
        return f"HAVING {th.field} {op} {th.value}"

    def _build_lookup(self, lookup: LookupSpec) -> str:
        """AQL does not support native lookups — use REFERENCE SET pattern."""
        match_field = self._resolve(lookup.match_field)
        return f"AND {match_field} IN (SELECT value FROM {lookup.lookup_table})"

    # ─────────────────────────────────────────────
    # Syntax validator
    # ─────────────────────────────────────────────

    def validate(self, query: str) -> bool:
        """Basic AQL syntactic validation."""
        if not query or not isinstance(query, str):
            return False
        q = query.strip().upper()

        # Must start with SELECT
        if not q.startswith("SELECT"):
            return False

        # Must contain FROM events
        if "FROM EVENTS" not in q and "FROM FLOWS" not in q:
            return False

        # If GROUP BY present, SELECT must have an aggregate function
        if "GROUP BY" in q:
            has_agg = any(fn in q for fn in ("COUNT(", "SUM(", "AVG(", "MIN(", "MAX("))
            if not has_agg:
                log.warning("AQL: GROUP BY without aggregation function")
                return False

        return True