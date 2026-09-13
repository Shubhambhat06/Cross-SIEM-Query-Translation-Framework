"""
QRadar AQL Translator — IR → IBM QRadar Ariel Query Language.

AQL is SQL-like: SELECT ... FROM events WHERE ... GROUP BY ... HAVING ... LAST N HOURS
Key differences from SQL:
  - Time filter goes at the END: LAST 24 HOURS
  - Source names use LOGSOURCENAME(logsourceid)
  - Event names use QIDNAME(qid)
  - No subqueries in WHERE (use HAVING for post-aggregation filtering)
  - Reference-set membership uses the REFERENCESETCONTAINS() function —
    AQL has no SELECT-subquery form (`IN (SELECT ...)` is not valid AQL).

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

# Canonical fields that resolve to QIDNAME(qid) — a free-text event-name
# function, not a normalized enum column. Equality against it (`= 'failed'`)
# will almost never match real QRadar data; QIDNAME values are things like
# "Authentication Failure", not the literal canonical string. field_mapping.py
# documents this requirement — this is where it's actually enforced: EQ/NEQ
# on one of these fields is rewritten to a case-insensitive ILIKE/NOT ILIKE
# substring match instead of a straight comparison.
_QIDNAME_FIELDS = {"status", "action", "event_type"}


class QRadarTranslator(BaseSIEMTranslator):
    """Translates IRQuery objects into IBM QRadar AQL queries."""

    PLATFORM = "qradar"

    # AQL string literals are single-quoted, SQL-style (escape by doubling
    # the quote), not double-quoted/backslash-escaped like the other four
    # platforms — override the shared quoting helper accordingly.
    QUOTE_CHAR = "'"

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

    def _escape(self, value: object) -> str:
        """SQL-style escaping: double any embedded single quote."""
        return str(value).replace("'", "''")

    def _quote(self, value: object) -> str:
        """SQL-style single-quote escaping: double any embedded quote."""
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return str(value)
        return f"'{self._escape(value)}'"

    def _translate(self, ir: IRQuery) -> str:
        lines: list[str] = []

        # A non-filtering lookup (filter_on_match=False) is projected as a
        # SELECT column instead of a WHERE condition — computed once here
        # so _build_select can include it.
        project_lookup = (
            ir.lookup is not None and not ir.lookup.filter_on_match
        )

        # ── SELECT ────────────────────────────────────────────────────────
        lines.append(self._build_select(ir, project_lookup=project_lookup))

        # ── FROM ──────────────────────────────────────────────────────────
        lines.append("FROM events")

        # ── WHERE ─────────────────────────────────────────────────────────
        where_str = self._build_where(ir.filter) if ir.filter else ""
        lookup_clause = ""
        if ir.lookup and ir.lookup.filter_on_match:
            # (fixed) _build_lookup() existed but was never called from
            # _translate(), so any detection with action=lookup silently
            # produced a QRadar query with no lookup/enrichment logic at
            # all — the ir.lookup spec was dropped on the floor while
            # every other translator (Splunk, Elastic, Sentinel) honored
            # it. Append as an additional AND'd condition on WHERE.
            lookup_clause = self._build_lookup(ir.lookup)

        if where_str and lookup_clause:
            lines.append(f"WHERE {where_str} {lookup_clause}")
        elif where_str:
            lines.append(f"WHERE {where_str}")
        elif lookup_clause:
            # lookup_clause starts with "AND ..." — strip the leading
            # AND when it's the only WHERE condition present.
            lines.append(f"WHERE {lookup_clause[4:]}")

        # ── GROUP BY ──────────────────────────────────────────────────────
        if self._requires_aggregation(ir) and ir.aggregation and ir.aggregation.group_by:
            group_fields = ", ".join(
                self._resolve(f) for f in ir.aggregation.group_by
            )
            lines.append(f"GROUP BY {group_fields}")

        # ── HAVING ────────────────────────────────────────────────────────
        if ir.threshold:
            lines.append(self._build_having(ir))

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

        # ── MITRE ATT&CK provenance ──────────────────────────────────────
        # AQL has no clean way to inject a synthetic constant column
        # outside SELECT, so a trailing comment is the least surprising
        # option (consistent with Elastic's KQL path for the same reason).
        if ir.attck_labels:
            lines.append(f"-- MITRE ATT&CK: {', '.join(ir.attck_labels)}")

        return "\n".join(lines)

    # ─────────────────────────────────────────────
    # Clause builders
    # ─────────────────────────────────────────────

    def _build_select(self, ir: IRQuery, project_lookup: bool = False) -> str:
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

        # Non-filtering lookup enrichment column (filter_on_match=False)
        if project_lookup and ir.lookup:
            select_parts.append(self._build_lookup_projection(ir.lookup))

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

        # (fixed) status/action/event_type resolve to the free-text
        # QIDNAME(qid) function, not a normalized enum column. A straight
        # `QIDNAME(qid) = 'failed'` essentially never matches real QRadar
        # event-name text (e.g. "Authentication Failure"). Rewrite
        # EQ/NEQ on these fields to a case-insensitive substring match.
        if cond.field in _QIDNAME_FIELDS and op in (
            ComparisonOperator.EQ, ComparisonOperator.NEQ
        ):
            not_kw = "NOT " if op == ComparisonOperator.NEQ else ""
            expr = f"{not_kw}{field} ILIKE '%{self._escape(value)}%'"
            return f"NOT ({expr})" if cond.negate else expr

        if op == ComparisonOperator.CONTAINS:
            val_str = f"'%{self._escape(value)}%'" if isinstance(value, str) else str(value)
            expr = f"{field} ILIKE {val_str}"

        elif op == ComparisonOperator.REGEX:
            expr = f"{field} MATCHES {self._quote(value)}"

        elif op in (ComparisonOperator.IN, ComparisonOperator.NOT_IN):
            not_kw = "NOT " if op == ComparisonOperator.NOT_IN else ""
            if isinstance(value, list):
                items = ", ".join(
                    self._quote(v) if isinstance(v, str) else str(v) for v in value
                )
                expr = f"{field} {not_kw}IN ({items})"
            else:
                expr = f"{field} {not_kw}IN ({self._quote(value)})"

        else:
            mapped_op = self._map_op(op)
            val_str   = self._quote(value) if isinstance(value, str) else str(value)
            expr = f"{field} {mapped_op} {val_str}"

        return f"NOT ({expr})" if cond.negate else expr

    def _build_having(self, ir: IRQuery) -> str:
        """Build HAVING clause from ThresholdCondition."""
        th = ir.threshold
        op = self._map_op(th.op)
        # (fixed) th.field defaults to the literal string "count" and is
        # author-supplied free text — it is not guaranteed to match the
        # alias the aggregation clause actually emits (e.g. an
        # aggregation aliased "attempt_count" would previously produce
        # `HAVING count > 50`, referencing a column AQL never selected).
        # Reconcile against the aggregation's own alias when present.
        field = self._threshold_field(ir) or th.field
        return f"HAVING {field} {op} {th.value}"

    def _build_lookup(self, lookup: LookupSpec) -> str:
        """
        AQL reference-set membership check for WHERE filtering.

        Real AQL syntax is a function call — REFERENCESETCONTAINS('name',
        field) — not a SQL subquery; AQL does not support `IN (SELECT ...)`.
        """
        match_field = self._resolve(lookup.match_field)
        return f"AND REFERENCESETCONTAINS('{lookup.lookup_table}', {match_field})"

    def _build_lookup_projection(self, lookup: LookupSpec) -> str:
        """
        Non-filtering lookup (filter_on_match=False): project membership
        as a SELECT column instead of restricting WHERE, mirroring
        Splunk's `lookup ... OUTPUT` enrich-without-filter behavior.
        """
        match_field = self._resolve(lookup.match_field)
        alias = lookup.output_field or "is_match"
        return f"REFERENCESETCONTAINS('{lookup.lookup_table}', {match_field}) AS {alias}"

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