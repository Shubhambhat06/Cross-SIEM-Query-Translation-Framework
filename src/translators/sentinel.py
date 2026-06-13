"""
Microsoft Sentinel KQL Translator — IR → Kusto Query Language.

Sentinel KQL uses a table-first pipeline:
    TableName
    | where TimeGenerated > ago(24h)
    | where EventID == 4625
    | summarize FailCount = count() by IpAddress, Account
    | where FailCount > 50
    | order by FailCount desc

Key tables used:
    SecurityEvent     → Windows security events
    Syslog            → Linux syslog
    SigninLogs        → Azure AD sign-ins
    NetworkAnalytics  → Network flows
    DnsEvents         → DNS queries
    DeviceProcessEvents → Defender process events

Place at: src/translators/sentinel.py
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

# EventType → Sentinel table mapping
TABLE_MAP: dict[str, str] = {
    EventType.AUTHENTICATION: "SecurityEvent",
    EventType.NETWORK:        "NetworkAnalytics",
    EventType.PROCESS:        "DeviceProcessEvents",
    EventType.FILE:           "DeviceFileEvents",
    EventType.REGISTRY:       "DeviceRegistryEvents",
    EventType.DNS:            "DnsEvents",
    EventType.HTTP:           "DeviceNetworkEvents",
    EventType.ANY:            "SecurityEvent",
}


class SentinelTranslator(BaseSIEMTranslator):
    """Translates IRQuery objects into Microsoft Sentinel KQL queries."""

    PLATFORM = "sentinel"

    OP_MAP = {
        ComparisonOperator.EQ:       "==",
        ComparisonOperator.NEQ:      "!=",
        ComparisonOperator.GT:       ">",
        ComparisonOperator.GTE:      ">=",
        ComparisonOperator.LT:       "<",
        ComparisonOperator.LTE:      "<=",
        ComparisonOperator.CONTAINS: "has",
        ComparisonOperator.REGEX:    "matches regex",
        ComparisonOperator.IN:       "in",
        ComparisonOperator.NOT_IN:   "!in",
    }

    def _translate(self, ir: IRQuery) -> str:
        pipes: list[str] = []

        # ── Table (FROM equivalent) ───────────────────────────────────────
        table = TABLE_MAP.get(ir.event_type, "SecurityEvent")
        pipes.append(table)

        # ── Time filter ───────────────────────────────────────────────────
        if ir.time_window:
            time_field = self._resolve("timestamp")
            pipes.append(f"where {time_field} > {ir.time_window.to_kql}")

        # ── WHERE filters ─────────────────────────────────────────────────
        if ir.filter:
            filter_str = self._build_where(ir.filter)
            if filter_str:
                pipes.append(f"where {filter_str}")

        # ── Sequence (join pattern) ───────────────────────────────────────
        if ir.action == ActionType.SEQUENCE and ir.sequence:
            pipes.extend(self._build_sequence(ir.sequence, table))

        # ── Lookup (externaldata or watchlist) ───────────────────────────
        if ir.lookup:
            pipes.append(self._build_lookup(ir.lookup))

        # ── Summarize (aggregation) ───────────────────────────────────────
        if self._requires_aggregation(ir) and ir.aggregation:
            pipes.append(self._build_summarize(ir.aggregation))

        # ── Post-aggregation where (threshold) ───────────────────────────
        if ir.threshold:
            pipes.append(self._build_threshold(ir.threshold))

        # ── Order by ──────────────────────────────────────────────────────
        if ir.sort_by:
            direction = "desc" if ir.sort_order == "desc" else "asc"
            pipes.append(f"order by {self._resolve(ir.sort_by)} {direction}")
        elif ir.aggregation and ir.aggregation.alias:
            pipes.append(f"order by {ir.aggregation.alias} desc")

        # ── Limit ─────────────────────────────────────────────────────────
        if ir.limit:
            pipes.append(f"top {ir.limit} by {ir.aggregation.alias if ir.aggregation and ir.aggregation.alias else 'TimeGenerated'}")

        # ── Project (select fields) ───────────────────────────────────────
        if ir.fields:
            resolved = self._resolve_all(ir.fields)
            pipes.append(f"project {', '.join(resolved)}")

        return "\n| ".join(pipes)

    # ─────────────────────────────────────────────
    # Clause builders
    # ─────────────────────────────────────────────

    def _build_where(self, group: FilterGroup) -> str:
        """Recursively build KQL where expression."""
        parts: list[str] = []
        op_str = f" {str(group.operator).lower()} "

        for cond in group.conditions:
            if isinstance(cond, FilterCondition):
                parts.append(self._build_condition(cond))
            elif isinstance(cond, FilterGroup):
                inner = self._build_where(cond)
                if inner:
                    parts.append(f"({inner})")

        return op_str.join(p for p in parts if p)

    def _build_condition(self, cond: FilterCondition) -> str:
        """Build single KQL where condition."""
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
            expr = f'{field} has "{value}"'

        elif op == ComparisonOperator.REGEX:
            expr = f'{field} matches regex "{value}"'

        elif op == ComparisonOperator.IN:
            if isinstance(value, list):
                items = ", ".join(f'"{v}"' if isinstance(v, str) else str(v) for v in value)
                expr = f"{field} in ({items})"
            else:
                expr = f'{field} == "{value}"'

        elif op == ComparisonOperator.NOT_IN:
            if isinstance(value, list):
                items = ", ".join(f'"{v}"' if isinstance(v, str) else str(v) for v in value)
                expr = f"{field} !in ({items})"
            else:
                expr = f'{field} != "{value}"'

        else:
            mapped_op = self._map_op(op)
            val_str   = f'"{value}"' if isinstance(value, str) else str(value)
            expr = f"{field} {mapped_op} {val_str}"

        return f"not ({expr})" if cond.negate else expr

    def _build_summarize(self, agg: AggregationSpec) -> str:
        """Build | summarize clause."""
        alias = agg.alias or agg.output_field
        fn    = agg.function

        if fn == "count":
            agg_expr = f"{alias} = count()"
        elif fn == "distinct_count":
            field = self._resolve(agg.field) if agg.field else "*"
            agg_expr = f"{alias} = dcount({field})"
        elif fn == "sum":
            field = self._resolve(agg.field) if agg.field else "*"
            agg_expr = f"{alias} = sum({field})"
        elif fn == "avg":
            field = self._resolve(agg.field) if agg.field else "*"
            agg_expr = f"{alias} = avg({field})"
        elif fn == "max":
            field = self._resolve(agg.field) if agg.field else "*"
            agg_expr = f"{alias} = max({field})"
        elif fn == "min":
            field = self._resolve(agg.field) if agg.field else "*"
            agg_expr = f"{alias} = min({field})"
        else:
            agg_expr = f"{alias} = count()"

        if agg.group_by:
            group_fields = ", ".join(self._resolve(f) for f in agg.group_by)
            return f"summarize {agg_expr} by {group_fields}"
        return f"summarize {agg_expr}"

    def _build_threshold(self, th: ThresholdCondition) -> str:
        """Build post-summarize where threshold."""
        op = self._map_op(th.op)
        return f"where {th.field} {op} {th.value}"

    def _build_lookup(self, lookup: LookupSpec) -> str:
        """Build Sentinel watchlist lookup using _GetWatchlist."""
        match_field = self._resolve(lookup.match_field)
        table = lookup.lookup_table
        return (
            f"join kind=inner (\n"
            f"    _GetWatchlist('{table}')\n"
            f"    | project SearchKey\n"
            f") on $left.{match_field} == $right.SearchKey"
        )

    def _build_sequence(self, steps: list[SequenceStep], base_table: str) -> list[str]:
        """Build sequence as KQL join chain."""
        pipes: list[str] = []
        for i, step in enumerate(steps[1:], start=2):
            if step.filter:
                filter_str = self._build_where(step.filter)
                sub = (
                    f"join kind=inner (\n"
                    f"    {base_table}\n"
                    f"    | where {filter_str}\n"
                    f") on Account, Computer"
                )
                if step.within:
                    sub += f"\n| where abs(datetime_diff('minute', TimeGenerated, TimeGenerated1)) <= {step.within.rstrip('m')}"
                pipes.append(sub)
        return pipes

    # ─────────────────────────────────────────────
    # Syntax validator
    # ─────────────────────────────────────────────

    def validate(self, query: str) -> bool:
        """Basic Sentinel KQL syntactic validation."""
        if not query or not isinstance(query, str):
            return False
        q = query.strip()

        SENTINEL_TABLES = {
            "SecurityEvent", "Syslog", "SigninLogs", "NetworkAnalytics",
            "DnsEvents", "DeviceProcessEvents", "DeviceFileEvents",
            "DeviceNetworkEvents", "DeviceRegistryEvents", "AzureActivity",
        }
        first_line = q.split("\n")[0].strip()
        if first_line not in SENTINEL_TABLES:
            log.warning(
                "KQL: unexpected table name",
                extra={"table": first_line},
            )

        # Must use pipe-based structure
        if "|" not in q:
            return False

        VALID_OPERATORS = {
            "where", "summarize", "project", "order", "top",
            "extend", "join", "union", "let", "render",
        }
        pipes = q.split("|")
        for segment in pipes[1:]:
            seg = segment.strip()
            cmd = seg.split()[0].lower() if seg.split() else ""
            if cmd not in VALID_OPERATORS:
                log.warning(
                    "KQL: unknown operator",
                    extra={"operator": cmd},
                )
                return False

        return True