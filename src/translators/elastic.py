"""
Elastic Translator — IR → Elastic EQL (Event Query Language) or KQL.

Strategy:
  - SEQUENCE action   → EQL sequence query
  - FILTER only       → KQL (simpler, used in Kibana dashboards)
  - FILTER+AGGREGATE  → EQL with | stats pipe

EQL reference: elastic.co/guide/en/elasticsearch/reference/current/eql-syntax.html
KQL reference: elastic.co/guide/en/kibana/current/kuery-query.html

Place at: src/translators/elastic.py

Example EQL output:
    authentication where event.outcome == "failure"
      and source.ip != null
    | stats count() by source.ip, user.name
    | where count > 50
    | sort count desc

Example KQL output:
    event.outcome: "failure" AND source.ip: *
"""

from __future__ import annotations

from src.ir.schema import (
    ActionType,
    AggregationSpec,
    ComparisonOperator,
    EventType,
    FilterCondition,
    FilterGroup,
    IRQuery,
    LookupSpec,
    SequenceStep,
    ThresholdCondition,
)
from src.translators.base import BaseSIEMTranslator
from src.utils.logger import get_logger

log = get_logger(__name__)

# ECS event.category values per EventType
EVENT_CATEGORY_MAP: dict[str, str] = {
    EventType.AUTHENTICATION: "authentication",
    EventType.NETWORK:        "network",
    EventType.PROCESS:        "process",
    EventType.FILE:           "file",
    EventType.REGISTRY:       "registry",
    EventType.DNS:            "dns",
    EventType.HTTP:           "web",
    EventType.ANY:            "",
}


class ElasticTranslator(BaseSIEMTranslator):
    """Translates IRQuery objects into Elastic EQL or KQL queries."""

    PLATFORM = "elastic"

    OP_MAP = {
        ComparisonOperator.EQ:       "==",
        ComparisonOperator.NEQ:      "!=",
        ComparisonOperator.GT:       ">",
        ComparisonOperator.GTE:      ">=",
        ComparisonOperator.LT:       "<",
        ComparisonOperator.LTE:      "<=",
        ComparisonOperator.CONTAINS: "like",
        ComparisonOperator.REGEX:    "like~",
        ComparisonOperator.IN:       ":",
        ComparisonOperator.NOT_IN:   "not :",
    }

    def _translate(self, ir: IRQuery) -> str:
        # Sequence → EQL sequence block
        if ir.action == ActionType.SEQUENCE and ir.sequence:
            return self._build_sequence(ir.sequence)

        # Filter-only → KQL (simpler, no pipes)
        if ir.action == ActionType.FILTER and not ir.aggregation:
            return self._build_kql(ir)

        # Filter+Aggregate → EQL with pipes
        return self._build_eql(ir)

    # ─────────────────────────────────────────────
    # EQL builders
    # ─────────────────────────────────────────────

    def _build_eql(self, ir: IRQuery) -> str:
        """Build an EQL query with optional stats pipe."""
        parts: list[str] = []

        # Base event category + filters
        base = self._build_eql_base(ir)
        parts.append(base)

        # | stats
        if self._requires_aggregation(ir) and ir.aggregation:
            parts.append(self._build_eql_stats(ir.aggregation))

        # | where (threshold)
        if ir.threshold:
            parts.append(self._build_eql_where(ir.threshold))

        # | sort
        if ir.sort_by:
            direction = "desc" if ir.sort_order == "desc" else "asc"
            parts.append(f"| sort {self._resolve(ir.sort_by)} {direction}")
        elif ir.aggregation and ir.aggregation.alias:
            parts.append(f"| sort {ir.aggregation.alias} desc")

        # | head (limit)
        if ir.limit:
            parts.append(f"| head {ir.limit}")

        return "\n".join(parts)

    def _build_eql_base(self, ir: IRQuery) -> str:
        """Build EQL event category line and filter conditions."""
        category = EVENT_CATEGORY_MAP.get(ir.event_type, "")

        filter_parts: list[str] = []

        # Time is handled by Elastic's query API (range filter), not in EQL itself
        # but we add a comment for clarity
        if ir.time_window:
            filter_parts.append(f"// time window: {ir.time_window.duration}")

        # Filter conditions
        if ir.filter:
            filter_str = self._build_eql_filter_group(ir.filter)
            if filter_str:
                filter_parts.append(filter_str)

        if category:
            if filter_parts:
                # Remove comment lines for the where clause
                real_filters = [p for p in filter_parts if not p.startswith("//")]
                comment_lines = [p for p in filter_parts if p.startswith("//")]
                where_clause = "\n  and ".join(real_filters)
                base = f"{category} where {where_clause}"
                if comment_lines:
                    base = "\n".join(comment_lines) + "\n" + base
            else:
                base = category
        else:
            if filter_parts:
                real_filters = [p for p in filter_parts if not p.startswith("//")]
                base = "any where " + "\n  and ".join(real_filters)
            else:
                base = "any where true"

        return base

    def _build_eql_filter_group(self, group: FilterGroup) -> str:
        """Recursively build EQL filter expression."""
        parts: list[str] = []
        op_str = f" {str(group.operator).lower()} "

        for cond in group.conditions:
            if isinstance(cond, FilterCondition):
                parts.append(self._build_eql_condition(cond))
            elif isinstance(cond, FilterGroup):
                inner = self._build_eql_filter_group(cond)
                if inner:
                    parts.append(f"({inner})")

        return op_str.join(p for p in parts if p)

    def _build_eql_condition(self, cond: FilterCondition) -> str:
        """Build a single EQL field condition."""
        field = self._resolve(cond.field)
        op    = cond.op
        value = cond.value

        if op == ComparisonOperator.EQ:
            val_str = f'"{value}"' if isinstance(value, str) else str(value)
            expr = f"{field} == {val_str}"

        elif op == ComparisonOperator.NEQ:
            val_str = f'"{value}"' if isinstance(value, str) else str(value)
            expr = f"{field} != {val_str}"

        elif op == ComparisonOperator.CONTAINS:
            expr = f'{field} like "*{value}*"'

        elif op == ComparisonOperator.REGEX:
            expr = f'{field} like~ "{value}"'

        elif op == ComparisonOperator.IN:
            if isinstance(value, list):
                items = ", ".join(f'"{v}"' if isinstance(v, str) else str(v) for v in value)
                expr = f"{field} in ({items})"
            else:
                expr = f'{field} == "{value}"'

        elif op == ComparisonOperator.NOT_IN:
            if isinstance(value, list):
                items = ", ".join(f'"{v}"' if isinstance(v, str) else str(v) for v in value)
                expr = f"{field} not in ({items})"
            else:
                expr = f'{field} != "{value}"'

        else:
            mapped_op = self._map_op(op)
            val_str   = f'"{value}"' if isinstance(value, str) else str(value)
            expr = f"{field} {mapped_op} {val_str}"

        return f"not ({expr})" if cond.negate else expr

    def _build_eql_stats(self, agg: AggregationSpec) -> str:
        """Build | stats pipe."""
        alias = agg.alias or agg.output_field
        fn    = agg.function

        if fn == "count":
            agg_expr = f"count() as {alias}"
        elif fn == "distinct_count":
            field = self._resolve(agg.field) if agg.field else "*"
            agg_expr = f"count_distinct({field}) as {alias}"
        else:
            field = self._resolve(agg.field) if agg.field else "*"
            agg_expr = f"{fn}({field}) as {alias}"

        if agg.group_by:
            group_fields = ", ".join(self._resolve(f) for f in agg.group_by)
            return f"| stats {agg_expr} by {group_fields}"
        return f"| stats {agg_expr}"

    def _build_eql_where(self, th: ThresholdCondition) -> str:
        """Build | where threshold pipe."""
        op = self._map_op(th.op)
        return f"| where {th.field} {op} {th.value}"

    def _build_sequence(self, steps: list[SequenceStep]) -> str:
        """Build EQL sequence query."""
        lines = ["sequence"]
        for step in steps:
            category = EVENT_CATEGORY_MAP.get(step.event_type, "any")
            if step.filter:
                filter_str = self._build_eql_filter_group(step.filter)
                line = f"  [{category} where {filter_str}]"
            else:
                line = f"  [{category} where true]"
            if step.within:
                line += f" with maxspan={step.within}"
            lines.append(line)
        return "\n".join(lines)

    # ─────────────────────────────────────────────
    # KQL builders (filter-only queries)
    # ─────────────────────────────────────────────

    def _build_kql(self, ir: IRQuery) -> str:
        """Build a KQL query for simple filter-only cases."""
        parts: list[str] = []

        # Event category
        category = EVENT_CATEGORY_MAP.get(ir.event_type, "")
        if category:
            parts.append(f'event.category: "{category}"')

        # Filters
        if ir.filter:
            kql_filter = self._build_kql_filter_group(ir.filter)
            if kql_filter:
                parts.append(kql_filter)

        return " AND ".join(parts) if parts else "*"

    def _build_kql_filter_group(self, group: FilterGroup) -> str:
        """Build KQL filter expression."""
        parts: list[str] = []
        op_str = f" {str(group.operator).upper()} "

        for cond in group.conditions:
            if isinstance(cond, FilterCondition):
                parts.append(self._build_kql_condition(cond))
            elif isinstance(cond, FilterGroup):
                inner = self._build_kql_filter_group(cond)
                if inner:
                    parts.append(f"({inner})")

        return op_str.join(p for p in parts if p)

    def _build_kql_condition(self, cond: FilterCondition) -> str:
        """Build single KQL condition."""
        field = self._resolve(cond.field)
        op    = cond.op
        value = cond.value

        if op == ComparisonOperator.EQ:
            val_str = f'"{value}"' if isinstance(value, str) else str(value)
            expr = f"{field}: {val_str}"
        elif op == ComparisonOperator.NEQ:
            val_str = f'"{value}"' if isinstance(value, str) else str(value)
            expr = f"NOT {field}: {val_str}"
        elif op == ComparisonOperator.CONTAINS:
            expr = f"{field}: *{value}*"
        elif op == ComparisonOperator.IN and isinstance(value, list):
            items = " OR ".join(
                f'{field}: "{v}"' if isinstance(v, str) else f"{field}: {v}"
                for v in value
            )
            expr = f"({items})"
        elif op in (ComparisonOperator.GT, ComparisonOperator.GTE,
                    ComparisonOperator.LT, ComparisonOperator.LTE):
            mapped_op = self._map_op(op)
            expr = f"{field} {mapped_op} {value}"
        else:
            val_str = f'"{value}"' if isinstance(value, str) else str(value)
            expr = f"{field}: {val_str}"

        return f"NOT ({expr})" if cond.negate else expr

    # ─────────────────────────────────────────────
    # Syntax validator
    # ─────────────────────────────────────────────

    def validate(self, query: str) -> bool:
        """Basic EQL/KQL syntactic validation."""
        if not query or not isinstance(query, str):
            return False
        q = query.strip()

        EQL_CATEGORIES = {
            "authentication", "network", "process", "file",
            "registry", "dns", "web", "any", "sequence",
        }
        first_word = q.split()[0].lower() if q.split() else ""

        # EQL: starts with event category or sequence
        if first_word in EQL_CATEGORIES:
            if first_word == "sequence":
                return "[" in q
            return "where" in q.lower()

        # KQL: field: value pattern or *
        if ":" in q or q == "*":
            return True

        return False