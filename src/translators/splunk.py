"""
Splunk SPL Translator — IR → Splunk Search Processing Language.

SPL uses a pipeline model: search terms | command | command | ...
Time is expressed via earliest= / latest= modifiers.
Aggregation uses the `stats` command.
Post-aggregation filtering uses `where`.

Place at: src/translators/splunk.py

Example output:
    index=* EventCode=4625 earliest=-24h latest=now
    | stats count as attempt_count by src_ip, user
    | where attempt_count > 50
    | sort -attempt_count
    | table src_ip, user, attempt_count

Example sequence output:
    index=* earliest=-24h latest=now (user="alice" action="logon_failed") OR (user="alice" action="logon_success")
    | transaction user maxspan=30m startswith=(action="logon_failed") endswith=(action="logon_success")
"""

from __future__ import annotations

from src.ir.schema import (
    ActionType,
    ComparisonOperator,
    FilterCondition,
    FilterGroup,
    IRQuery,
    LookupSpec,
    SequenceStep,
    AggregationSpec,
    ThresholdCondition,
)
from src.translators.base import BaseSIEMTranslator
from src.utils.logger import get_logger

log = get_logger(__name__)


class SplunkTranslator(BaseSIEMTranslator):
    """Translates IRQuery objects into Splunk SPL queries."""

    PLATFORM = "splunk"

    # Splunk uses its own operator syntax in search terms
    OP_MAP = {
        ComparisonOperator.EQ:       "=",
        ComparisonOperator.NEQ:      "!=",
        ComparisonOperator.GT:       ">",
        ComparisonOperator.GTE:      ">=",
        ComparisonOperator.LT:       "<",
        ComparisonOperator.LTE:      "<=",
        ComparisonOperator.CONTAINS: "=*{value}*",   # handled specially
        ComparisonOperator.REGEX:    "=~",
        ComparisonOperator.IN:       "IN",
        ComparisonOperator.NOT_IN:   "NOT IN",
    }

    def _translate(self, ir: IRQuery) -> str:
        parts: list[str] = []

        # ── Base search (+ sequence candidate-event OR clause) ─────────────
        search_terms = self._build_search_terms(ir)
        transaction_pipe = None
        if ir.action == ActionType.SEQUENCE and ir.sequence:
            # (fixed) transaction needs a base search that actually
            # retrieves every candidate event across all steps first —
            # transaction only groups/bounds events already returned by
            # search, it does not filter per-step on its own. Previously
            # the transaction pipe was appended after a base search built
            # from ir.filter alone (usually None/empty for sequence
            # queries), so `transaction` ran over the *entire* index with
            # no startswith/endswith boundaries — effectively unbounded.
            search_suffix, transaction_pipe = self._build_sequence(ir)
            if search_suffix:
                search_terms = (
                    f"{search_terms} {search_suffix}" if search_terms else search_suffix
                )
        parts.append(search_terms)
        if transaction_pipe:
            parts.append(transaction_pipe)

        # ── Lookup ────────────────────────────────────────────────────────
        if ir.lookup:
            parts.append(self._build_lookup(ir.lookup))

        # ── Aggregation (stats) ───────────────────────────────────────────
        if self._requires_aggregation(ir) and ir.aggregation:
            parts.append(self._build_stats(ir.aggregation))

        # ── Threshold (where) ─────────────────────────────────────────────
        if ir.threshold:
            parts.append(self._build_where(ir))

        # ── MITRE ATT&CK provenance ──────────────────────────────────────
        if ir.attck_labels:
            labels = ",".join(ir.attck_labels)
            parts.append(f'eval MITRETechniques="{labels}"')

        # ── Sort ──────────────────────────────────────────────────────────
        if ir.sort_by:
            direction = "-" if ir.sort_order == "desc" else ""
            sort_field = self._resolve(ir.sort_by)
            parts.append(f"sort {direction}{sort_field}")
        elif ir.aggregation and ir.aggregation.alias:
            parts.append(f"sort -{ir.aggregation.alias}")

        # ── Limit ─────────────────────────────────────────────────────────
        if ir.limit:
            parts.append(f"head {ir.limit}")

        # ── Table (project fields) ────────────────────────────────────────
        if ir.fields:
            resolved = self._resolve_all(ir.fields)
            parts.append(f"table {', '.join(resolved)}")

        return "\n| ".join(p for p in parts if p)

    # ─────────────────────────────────────────────
    # Search term builders
    # ─────────────────────────────────────────────

    def _build_search_terms(self, ir: IRQuery) -> str:
        """Build the initial search string including index, time, and filters."""
        terms: list[str] = ["index=*"]

        # Time window
        if ir.time_window:
            terms.append(f"earliest={ir.time_window.to_splunk} latest=now")

        # Filter conditions
        if ir.filter:
            filter_str = self._build_filter_group(ir.filter, inline=True)
            if filter_str:
                terms.append(filter_str)

        return " ".join(terms)

    def _build_filter_group(self, group: FilterGroup, inline: bool = True) -> str:
        """Recursively build filter conditions as SPL search terms."""
        parts: list[str] = []
        op_str = " OR " if str(group.operator).lower() == "or" else " "

        for cond in group.conditions:
            if isinstance(cond, FilterCondition):
                parts.append(self._build_condition(cond))
            elif isinstance(cond, FilterGroup):
                inner = self._build_filter_group(cond)
                if inner:
                    parts.append(f"({inner})")

        return op_str.join(p for p in parts if p)

    def _build_condition(self, cond: FilterCondition) -> str:
        """Build a single SPL field=value search term."""
        field = self._resolve(cond.field)
        op    = cond.op
        value = cond.value

        # CONTAINS: use wildcard
        if op == ComparisonOperator.CONTAINS:
            val_str = f'"*{value}*"' if isinstance(value, str) else str(value)
            expr = f'{field}={val_str}'

        # IN: use field IN (v1, v2, ...)
        elif op == ComparisonOperator.IN and isinstance(value, list):
            vals = " ".join(self._quote(v) if isinstance(v, str) else str(v) for v in value)
            expr = f'{field} IN ({vals})'

        # NOT IN
        elif op == ComparisonOperator.NOT_IN and isinstance(value, list):
            vals = " ".join(self._quote(v) if isinstance(v, str) else str(v) for v in value)
            expr = f'NOT {field} IN ({vals})'

        # REGEX
        elif op == ComparisonOperator.REGEX:
            expr = f'{field}=~{self._quote(value)}'

        # Standard operators (=, !=, >, >=, <, <=)
        else:
            mapped_op = self._map_op(op)
            val_str   = self._quote(value) if isinstance(value, str) else str(value)
            expr = f'{field}{mapped_op}{val_str}'

        return f"NOT ({expr})" if cond.negate else expr

    def _build_stats(self, agg: AggregationSpec) -> str:
        """Build a | stats command from an AggregationSpec."""
        alias = agg.alias or agg.output_field
        fn    = agg.function

        if fn == "count":
            agg_expr = f"count as {alias}"
        elif fn == "distinct_count":
            field = self._resolve(agg.field) if agg.field else "_raw"
            agg_expr = f"dc({field}) as {alias}"
        else:
            field = self._resolve(agg.field) if agg.field else "_raw"
            agg_expr = f"{fn}({field}) as {alias}"

        if agg.group_by:
            group_fields = ", ".join(self._resolve(f) for f in agg.group_by)
            return f"stats {agg_expr} by {group_fields}"
        return f"stats {agg_expr}"

    def _build_where(self, ir: IRQuery) -> str:
        """Build a | where command from a ThresholdCondition."""
        th = ir.threshold
        op = self._map_op(th.op)
        # Reconcile against the aggregation's own alias — see
        # BaseSIEMTranslator._threshold_field for why this matters.
        field = self._threshold_field(ir) or th.field
        return f"where {field} {op} {th.value}"

    def _build_lookup(self, lookup: LookupSpec) -> str:
        """Build a | lookup command."""
        match_field = self._resolve(lookup.match_field)
        parts = [f"lookup {lookup.lookup_table} {match_field}"]
        if lookup.output_field:
            parts.append(f"OUTPUT {lookup.output_field}")
        cmd = " ".join(parts)
        if lookup.filter_on_match:
            cmd += f"\n| where isnotnull({lookup.output_field or match_field})"
        return cmd

    def _build_sequence(self, ir: IRQuery) -> tuple[str, str]:
        """
        Build the base-search OR clause and the `transaction` pipe for a
        sequence/correlation IRQuery.

        `transaction` only groups and time-bounds events a preceding
        `search` stage already returned — it applies no filtering of its
        own. This builds an OR across every step's filter as the search
        term (so all candidate events are actually retrieved), then a
        transaction command grouped by the inferred correlation field(s)
        with maxspan and startswith/endswith boundaries drawn from the
        first/last step.

        Returns:
            (search_suffix, transaction_pipe) — search_suffix is appended
            to the base search line; transaction_pipe is appended as its
            own pipe stage.
        """
        steps = ir.sequence

        step_terms: list[str] = []
        for step in steps:
            if step.filter:
                f = self._build_filter_group(step.filter)
                if f:
                    step_terms.append(f"({f})")
        search_suffix = " OR ".join(step_terms)

        correlation_fields = self._infer_correlation_fields(steps)
        if not correlation_fields:
            log.warning(
                "Splunk sequence: no correlation key found on any step "
                "(no explicit correlation_key and no recognized field in "
                "step filters) — transaction will group by default "
                "heuristics only, verify manually"
            )

        maxspan = "30m"
        for step in steps:
            if step.within:
                maxspan = step.within

        txn_parts = ["transaction"]
        if correlation_fields:
            txn_parts.append(", ".join(correlation_fields))
        txn_parts.append(f"maxspan={maxspan}")

        if steps[0].filter:
            first_f = self._build_filter_group(steps[0].filter)
            if first_f:
                txn_parts.append(f"startswith=({first_f})")
        if steps[-1].filter:
            last_f = self._build_filter_group(steps[-1].filter)
            if last_f:
                txn_parts.append(f"endswith=({last_f})")

        return search_suffix, " ".join(txn_parts)

    # ─────────────────────────────────────────────
    # Syntax validator
    # ─────────────────────────────────────────────

    def validate(self, query: str) -> bool:
        """
        Basic SPL syntactic validation.
        Checks for required structure and common keywords.
        """
        if not query or not isinstance(query, str):
            return False
        q = query.strip().lower()

        # Must start with a search term or index=
        if not (q.startswith("index=") or q.startswith("search") or q.startswith("*")):
            return False

        # Pipe structure: each segment after | must start with a valid command
        VALID_COMMANDS = {
            "stats", "where", "eval", "table", "sort", "head",
            "tail", "dedup", "rex", "lookup", "transaction",
            "timechart", "top", "rare", "fields", "rename",
        }
        pipes = q.split("|")
        for segment in pipes[1:]:
            seg = segment.strip()
            cmd = seg.split()[0] if seg.split() else ""
            if cmd not in VALID_COMMANDS:
                log.warning(
                    "Unknown SPL command",
                    extra={"command": cmd, "segment": seg[:60]},
                )
                return False

        return True