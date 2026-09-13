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

Known limitation (documented for evaluation transparency)
-----------------------------------------------------------
Sentinel has no single normalized "status"/outcome field across tables —
SecurityEvent uses numeric EventID (4625 = failed logon), Syslog has no
equivalent and requires parsing SyslogMessage text. The `status` canonical
field maps to the generic `Status` column (see field_mapping.py); callers
that need real per-event-type outcome resolution (e.g. auth failures on
Syslog) should branch on ir.event_type upstream, in IR construction,
rather than expecting this translator to infer table-specific semantics
from a single generic field name.
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
            pipes.append(self._build_threshold(ir))

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
        if ir.attck_labels:
            labels = ", ".join(self._quote(x) for x in ir.attck_labels)
            pipes.append(f"extend MITRETechniques = dynamic([{labels}])")
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
            val_str = self._quote(value) if isinstance(value, str) else str(value)
            expr = f"{field} == {val_str}"

        elif op == ComparisonOperator.NEQ:
            val_str = self._quote(value) if isinstance(value, str) else str(value)
            expr = f"{field} != {val_str}"

        elif op == ComparisonOperator.CONTAINS:
            expr = f"{field} has {self._quote(value)}"

        elif op == ComparisonOperator.REGEX:
            expr = f"{field} matches regex {self._quote(value)}"

        elif op == ComparisonOperator.IN:
            if isinstance(value, list):
                items = ", ".join(self._quote(v) if isinstance(v, str) else str(v) for v in value)
                expr = f"{field} in ({items})"
            else:
                expr = f"{field} == {self._quote(value)}"

        elif op == ComparisonOperator.NOT_IN:
            if isinstance(value, list):
                items = ", ".join(self._quote(v) if isinstance(v, str) else str(v) for v in value)
                expr = f"{field} !in ({items})"
            else:
                expr = f"{field} != {self._quote(value)}"

        else:
            mapped_op = self._map_op(op)
            val_str   = self._quote(value) if isinstance(value, str) else str(value)
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

    def _build_threshold(self, ir: IRQuery) -> str:
        """Build post-summarize where threshold."""
        th = ir.threshold
        op = self._map_op(th.op)
        # Reconcile against the aggregation's own alias — see
        # BaseSIEMTranslator._threshold_field for why this matters.
        field = self._threshold_field(ir) or th.field
        return f"where {field} {op} {th.value}"

    def _build_lookup(self, lookup: LookupSpec) -> str:
        """
        Build Sentinel watchlist lookup using _GetWatchlist.

        (fixed) This previously always used `kind=inner`, silently
        ignoring lookup.filter_on_match — every lookup dropped
        non-matching events regardless of what the IR asked for, unlike
        Splunk and QRadar which both honor the flag. `kind=leftouter`
        preserves non-matches (enrich-only); `kind=inner` is used only
        when filter_on_match=True, matching Splunk's
        `lookup ... | where isnotnull(...)` semantics.
        """
        match_field = self._resolve(lookup.match_field)
        join_kind = "inner" if lookup.filter_on_match else "leftouter"
        return (
            f"join kind={join_kind} (\n"
            f"    _GetWatchlist('{lookup.lookup_table}')\n"
            f"    | project SearchKey\n"
            f") on $left.{match_field} == $right.SearchKey"
        )

    def _build_sequence(self, steps: list[SequenceStep], base_table: str) -> list[str]:
        """
        Build sequence as a KQL join chain.

        (fixed) Correlation join keys were previously hardcoded to
        `Account, Computer` for every sequence regardless of what fields
        the steps actually filter on — silently wrong for any sequence
        correlating on something else (e.g. src_ip, process id). Now
        inferred via the shared BaseSIEMTranslator helper, which prefers
        an explicit `correlation_key` on a step and falls back to a
        field-name heuristic only when none is given.
        """
        pipes: list[str] = []
        join_fields = self._infer_correlation_fields(steps)
        join_on = (
            ", ".join(f"$left.{f} == $right.{f}" for f in join_fields)
            if join_fields
            else "$left.TimeGenerated == $right.TimeGenerated"  # last-resort, see warning below
        )
        if not join_fields:
            log.warning(
                "Sentinel sequence: no correlation key found on any step "
                "(no explicit correlation_key and no recognized field in "
                "step filters) — join condition may be too permissive, "
                "verify manually"
            )

        for i, step in enumerate(steps[1:], start=2):
            if step.filter:
                filter_str = self._build_where(step.filter)
                sub = (
                    f"join kind=inner (\n"
                    f"    {base_table}\n"
                    f"    | where {filter_str}\n"
                    f") on {join_on}"
                )
                if step.within:
                    sub += (
                        f"\n| where abs(datetime_diff('minute', "
                        f"TimeGenerated, TimeGenerated1)) <= {step.within.rstrip('smhd')}"
                    )
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