"""
Elastic Translator — IR → Elastic EQL (Event Query Language) or KQL.

Strategy:
  - SEQUENCE action   → EQL sequence query (with correct maxspan on sequence line)
  - FILTER only       → KQL (simpler, used in Kibana dashboards / SIEM rules)
  - FILTER+AGGREGATE  → EQL with pipe chain (correct EQL pipe ordering)
  - LOOKUP action     → KQL with enrichment policy syntax

EQL reference: elastic.co/guide/en/elasticsearch/reference/current/eql-syntax.html
KQL reference: elastic.co/guide/en/kibana/current/kuery-query.html

Place at: src/translators/elastic.py

Example EQL output (filter+aggregate):
    authentication where event.outcome == "failure"
    | stats count(*) as attempt_count by source.ip
    | where attempt_count > 50
    | sort attempt_count desc
    | head 100

Example EQL sequence output:
    sequence by user.name with maxspan=30m
      [authentication where event.outcome == "success"]
      [authentication where event.outcome == "success"
        and source.geo.country_name != null]

Example KQL output:
    event.category: "authentication" AND event.outcome: "failure"
      AND source.ip: *
    // Time range: apply via Kibana time picker, detection-rule schedule,
    //             or the search API's @timestamp range filter (last 24h)

Known limitation (documented for evaluation transparency)
-----------------------------------------------------------
The EQL/KQL text produced here is the platform-native *syntax* a security
engineer would write or paste into Kibana. It is NOT yet wrapped in the
Elasticsearch Query DSL JSON envelope or the EQL Search API request body
required for direct programmatic execution via `client.eql.search()` or
`client.search()`. Generating an executable wrapper is a distinct,
well-scoped extension (see execution_match.py in the evaluation layer) and
is intentionally out of scope for the translation layer itself, whose
contribution is the platform-syntax mapping captured in the Intermediate
Representation.
"""

from __future__ import annotations

import re

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

# ── ECS event.category per IR EventType ───────────────────────────────────
# These are the correct EQL event category keywords per the ECS specification.
EVENT_CATEGORY_MAP: dict[str, str] = {
    EventType.AUTHENTICATION: "authentication",
    EventType.NETWORK:        "network",
    EventType.PROCESS:        "process",
    EventType.FILE:           "file",
    EventType.REGISTRY:       "registry",
    EventType.DNS:            "dns",
    EventType.HTTP:           "web",
    EventType.ANY:            "any",
}

# ── ECS field names for common IR fields ──────────────────────────────────
# EQL works on ECS (Elastic Common Schema) field names.
# These supplement the field_mapping.py canonical → elastic mappings.
_ECS_STATUS_VALUES: dict[str, str] = {
    "failed":  "failure",   # ECS uses "failure" not "failed"
    "success": "success",
    "error":   "failure",
}


class ElasticTranslator(BaseSIEMTranslator):
    """Translates IRQuery objects into Elastic EQL or KQL queries."""

    PLATFORM = "elastic"

    # ── EQL comparison operators ───────────────────────────────────────────
    # EQL uses == and != (not = or <>), and has specific functions for
    # wildcard/regex matching — not inline operator syntax.
    OP_MAP = {
        ComparisonOperator.EQ:       "==",
        ComparisonOperator.NEQ:      "!=",
        ComparisonOperator.GT:       ">",
        ComparisonOperator.GTE:      ">=",
        ComparisonOperator.LT:       "<",
        ComparisonOperator.LTE:      "<=",
        ComparisonOperator.CONTAINS: "like",    # handled in _build_eql_condition
        ComparisonOperator.REGEX:    "match",   # handled in _build_eql_condition
        ComparisonOperator.IN:       "in",      # handled in _build_eql_condition
        ComparisonOperator.NOT_IN:   "not in",  # handled in _build_eql_condition
    }

    # ─────────────────────────────────────────────
    # Entry point
    # ─────────────────────────────────────────────

    def _translate(self, ir: IRQuery) -> str:
        # Sequence correlation → EQL sequence block
        if ir.action == ActionType.SEQUENCE and ir.sequence:
            return self._build_sequence(ir)

        # Threat-intel lookup → KQL with enrichment comment
        if ir.action == ActionType.LOOKUP and ir.lookup:
            return self._build_lookup_kql(ir)

        # Filter-only → KQL (no aggregation, simpler, used in Kibana rules)
        if ir.action == ActionType.FILTER and not ir.aggregation:
            return self._build_kql(ir)

        # Filter+Aggregate / Aggregate → EQL pipeline
        return self._build_eql_pipeline(ir)

    # ─────────────────────────────────────────────
    # EQL pipeline builder
    # ─────────────────────────────────────────────

    def _build_eql_pipeline(self, ir: IRQuery) -> str:
        """
        Build a full EQL pipeline query.

        Correct EQL pipeline ordering:
            <event_category> where <filters>
            | stats <agg>() as <alias> by <group_fields>
            | where <alias> <op> <threshold>        ← post-agg filter
            | sort <alias> desc
            | head <limit>
        """
        lines: list[str] = []

        # ── Base event filter line ────────────────────────────────────────
        lines.append(self._build_eql_base(ir))

        # ── Aggregation pipe ──────────────────────────────────────────────
        if self._requires_aggregation(ir) and ir.aggregation:
            lines.append(self._build_eql_stats(ir.aggregation))

        # ── Post-aggregation threshold filter ─────────────────────────────
        # Must come AFTER stats, BEFORE sort
        if ir.threshold:
            lines.append(self._build_eql_threshold(ir.threshold))

        # ── Sort ──────────────────────────────────────────────────────────
        if ir.sort_by:
            direction = "desc" if ir.sort_order == "desc" else "asc"
            lines.append(f"| sort {self._resolve(ir.sort_by)} {direction}")
        elif ir.aggregation and ir.aggregation.alias:
            lines.append(f"| sort {ir.aggregation.alias} desc")

        # ── Limit ─────────────────────────────────────────────────────────
        if ir.limit:
            lines.append(f"| head {ir.limit}")

        return "\n".join(lines)

    def _build_eql_base(self, ir: IRQuery) -> str:
        """
        Build the EQL base line: <event_category> where <conditions>.

        Time window in EQL is applied at the API level via the
        filter.range parameter, not inline in the query string.
        We add it as a trailing comment so analysts know to set it.
        """
        category = EVENT_CATEGORY_MAP.get(ir.event_type, "any")

        conditions: list[str] = []

        # Filter conditions
        if ir.filter:
            filter_str = self._build_eql_filter_group(ir.filter)
            if filter_str:
                conditions.append(filter_str)

        # Time window note (EQL time is set via the API's filter.range
        # parameter, not inline query syntax) — documented as a comment.
        time_comment = ""
        if ir.time_window:
            time_comment = f"  // set ?filter[range][@timestamp][gte]=now-{ir.time_window.duration}"

        if conditions:
            # Multi-condition: indent each condition with 'and' for readability
            if len(conditions) == 1:
                base = f"{category} where {conditions[0]}"
            else:
                first = conditions[0]
                rest  = "\n  and ".join(conditions[1:])
                base  = f"{category} where {first}\n  and {rest}"
        else:
            base = f"{category} where true"

        return base + time_comment

    # ─────────────────────────────────────────────
    # EQL filter builders
    # ─────────────────────────────────────────────

    def _build_eql_filter_group(self, group: FilterGroup) -> str:
        """Recursively build EQL boolean filter expression."""
        parts: list[str] = []
        logical_op = str(group.operator).lower()   # "and" / "or"
        joiner = f" {logical_op} "

        for cond in group.conditions:
            if isinstance(cond, FilterCondition):
                parts.append(self._build_eql_condition(cond))
            elif isinstance(cond, FilterGroup):
                inner = self._build_eql_filter_group(cond)
                if inner:
                    parts.append(f"({inner})")

        return joiner.join(p for p in parts if p)

    def _build_eql_condition(self, cond: FilterCondition) -> str:
        """
        Build a single EQL field condition.

        EQL operator reference:
          ==  !=  >  >=  <  <=          — standard comparisons
          like "pattern*"               — wildcard (case-sensitive)
          like~ "pattern*"              — wildcard (case-insensitive)
          match(field, "regex")         — regex match (correct EQL function)
          field in ("a", "b", "c")      — list membership
          field not in ("a", "b")       — list non-membership
          cidrMatch(field, "10.0.0.0/8")— CIDR for IP fields
        """
        field = self._resolve(cond.field)
        op    = cond.op
        value = cond.value

        # ── EQ ────────────────────────────────────────────────────────────
        if op == ComparisonOperator.EQ:
            # Normalise ECS status values (e.g. "failed" → "failure")
            if cond.field == "status" and isinstance(value, str):
                value = _ECS_STATUS_VALUES.get(value.lower(), value)
            val_str = f'"{value}"' if isinstance(value, str) else str(value)
            expr = f"{field} == {val_str}"

        # ── NEQ ───────────────────────────────────────────────────────────
        elif op == ComparisonOperator.NEQ:
            if cond.field == "status" and isinstance(value, str):
                value = _ECS_STATUS_VALUES.get(value.lower(), value)
            val_str = f'"{value}"' if isinstance(value, str) else str(value)
            expr = f"{field} != {val_str}"

        # ── CONTAINS → EQL like with wildcards ────────────────────────────
        # EQL like operator: case-sensitive wildcard matching
        # like~ : case-insensitive wildcard matching
        elif op == ComparisonOperator.CONTAINS:
            expr = f'{field} like~ "*{value}*"'

        # ── REGEX → EQL match() function ──────────────────────────────────
        # EQL does NOT support inline =~ — use match(field, "regex") instead
        elif op == ComparisonOperator.REGEX:
            expr = f'match({field}, "{value}")'

        # ── IN → EQL in tuple ─────────────────────────────────────────────
        elif op == ComparisonOperator.IN:
            if isinstance(value, list):
                items = ", ".join(
                    f'"{v}"' if isinstance(v, str) else str(v) for v in value
                )
                expr = f"{field} in ({items})"
            else:
                val_str = f'"{value}"' if isinstance(value, str) else str(value)
                expr = f"{field} == {val_str}"

        # ── NOT IN → EQL not in tuple ─────────────────────────────────────
        elif op == ComparisonOperator.NOT_IN:
            if isinstance(value, list):
                items = ", ".join(
                    f'"{v}"' if isinstance(v, str) else str(v) for v in value
                )
                expr = f"{field} not in ({items})"
            else:
                val_str = f'"{value}"' if isinstance(value, str) else str(value)
                expr = f"{field} != {val_str}"

        # ── Numeric comparisons (GT, GTE, LT, LTE) ────────────────────────
        else:
            mapped_op = self._map_op(op)
            val_str   = f'"{value}"' if isinstance(value, str) else str(value)
            expr = f"{field} {mapped_op} {val_str}"

        return f"not ({expr})" if cond.negate else expr

    # ─────────────────────────────────────────────
    # EQL aggregation + threshold
    # ─────────────────────────────────────────────

    def _build_eql_stats(self, agg: AggregationSpec) -> str:
        """
        Build EQL | stats pipe.

        EQL aggregation functions:
          count(*)                      — count all matched events
          count(field)                  — count non-null values
          unique_count(field)           — distinct count (EQL name, NOT count_distinct)
          sum(field)
          avg(field)
          min(field)
          max(field)
          values(field)                 — collect distinct values into array
        """
        alias = agg.alias or agg.output_field
        fn    = agg.function

        if fn == "count":
            # count(*) is correct EQL syntax — not count()
            agg_expr = f"count(*) as {alias}"

        elif fn == "distinct_count":
            # EQL uses unique_count(), NOT count_distinct()
            field = self._resolve(agg.field) if agg.field else "*"
            agg_expr = f"unique_count({field}) as {alias}"

        elif fn == "sum":
            field = self._resolve(agg.field) if agg.field else "*"
            agg_expr = f"sum({field}) as {alias}"

        elif fn == "avg":
            field = self._resolve(agg.field) if agg.field else "*"
            agg_expr = f"avg({field}) as {alias}"

        elif fn == "min":
            field = self._resolve(agg.field) if agg.field else "*"
            agg_expr = f"min({field}) as {alias}"

        elif fn == "max":
            field = self._resolve(agg.field) if agg.field else "*"
            agg_expr = f"max({field}) as {alias}"

        else:
            # Fallback to count
            agg_expr = f"count(*) as {alias}"

        if agg.group_by:
            group_fields = ", ".join(self._resolve(f) for f in agg.group_by)
            return f"| stats {agg_expr} by {group_fields}"
        return f"| stats {agg_expr}"

    def _build_eql_threshold(self, th: ThresholdCondition) -> str:
        """
        Build | where post-aggregation threshold filter.

        This comes AFTER | stats in the EQL pipeline.
        Uses standard comparison operators on the aggregated alias field.
        """
        op = self._map_op(th.op)
        return f"| where {th.field} {op} {th.value}"

    # ─────────────────────────────────────────────
    # EQL sequence builder
    # ─────────────────────────────────────────────

    def _build_sequence(self, ir: IRQuery) -> str:
        """
        Build a proper EQL sequence query.

        Correct EQL sequence syntax:
            sequence by <shared_field> with maxspan=<duration>
              [<category> where <filters>]
              [<category> where <filters>]

        Key properties:
          - maxspan is declared once on the SEQUENCE line, not per step
          - 'by <field>' groups correlated events by a shared correlation key
          - Steps are indented bracketed expressions
          - The shared grouping field is inferred from filter fields
        """
        steps = ir.sequence

        # Infer the maxspan from the LAST step's within clause
        # (EQL maxspan applies to the whole sequence, not per step)
        maxspan = None
        for step in steps:
            if step.within:
                maxspan = step.within

        # Infer a shared grouping field from common filter fields
        # (prefer user, host, src_ip as correlation keys)
        shared_field = self._infer_sequence_key(steps)

        # Build sequence header
        header_parts = ["sequence"]
        if shared_field:
            header_parts.append(f"by {shared_field}")
        if maxspan:
            header_parts.append(f"with maxspan={maxspan}")
        header = " ".join(header_parts)

        # Build each step
        step_lines: list[str] = [header]
        for step in steps:
            category = EVENT_CATEGORY_MAP.get(step.event_type, "any")
            if step.filter:
                filter_str = self._build_eql_filter_group(step.filter)
                step_line = f"  [{category} where {filter_str}]"
            else:
                step_line = f"  [{category} where true]"
            step_lines.append(step_line)

        return "\n".join(step_lines)

    def _infer_sequence_key(self, steps: list[SequenceStep]) -> str | None:
        """
        Infer the best 'by <field>' grouping key for a sequence query.

        Looks through filter conditions to find a shared correlation field.
        Priority: user > host > src_ip > user_id > hostname
        """
        CORRELATION_PRIORITY = ["user", "host", "src_ip", "user_id", "hostname"]
        found_fields: set[str] = set()

        for step in steps:
            if not step.filter:
                continue
            for cond in step.filter.conditions:
                if isinstance(cond, FilterCondition):
                    found_fields.add(cond.field)

        for candidate in CORRELATION_PRIORITY:
            if candidate in found_fields:
                return self._resolve(candidate)

        return None

    # ─────────────────────────────────────────────
    # KQL builders (filter-only queries)
    # ─────────────────────────────────────────────

    def _build_kql(self, ir: IRQuery) -> str:
        """
        Build a KQL query for filter-only cases.

        KQL is used in Kibana Discover, dashboards, and SIEM detection rules.
        It uses field:value syntax, not EQL event category syntax.

        Time range handling: KQL itself has no inline time-range syntax.
        In practice the range is supplied by whichever surface is running
        the query — the Kibana time picker, a detection rule's schedule,
        or the @timestamp range filter passed alongside the query in the
        Search API request body. We therefore surface the requested
        window as a trailing comment rather than fabricate non-standard
        inline syntax that Kibana would not parse as part of the query.
        """
        parts: list[str] = []

        # Always include event.category for specificity
        category = EVENT_CATEGORY_MAP.get(ir.event_type, "")
        if category and ir.event_type != "any":
            parts.append(f'event.category: "{category}"')

        # Filter conditions
        if ir.filter:
            kql_filter = self._build_kql_filter_group(ir.filter)
            if kql_filter:
                parts.append(kql_filter)

        if not parts:
            query = "*"
        elif len(parts) == 1:
            query = parts[0]
        else:
            query = " AND ".join(f"({p})" if " OR " in p else p for p in parts)

        # Time window — documented as a comment, not injected as KQL syntax.
        if ir.time_window:
            query += f"\n// Time range: last {ir.time_window.duration} " \
                     f"(apply via Kibana time picker, detection-rule schedule, " \
                     f"or the Search API's @timestamp range filter)"

        return query

    def _build_kql_filter_group(self, group: FilterGroup) -> str:
        """Build KQL boolean filter expression."""
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
        """
        Build a single KQL field condition.

        KQL operator reference:
          field: "value"         — exact match (KQL is case-insensitive)
          field: *value*         — wildcard
          field >= N             — numeric comparison
          field: ("a" or "b")   — list membership
          NOT field: "value"     — negation
        """
        field = self._resolve(cond.field)
        op    = cond.op
        value = cond.value

        # ── EQ ────────────────────────────────────────────────────────────
        if op == ComparisonOperator.EQ:
            if cond.field == "status" and isinstance(value, str):
                value = _ECS_STATUS_VALUES.get(value.lower(), value)
            val_str = f'"{value}"' if isinstance(value, str) else str(value)
            expr = f"{field}: {val_str}"

        # ── NEQ ───────────────────────────────────────────────────────────
        elif op == ComparisonOperator.NEQ:
            if cond.field == "status" and isinstance(value, str):
                value = _ECS_STATUS_VALUES.get(value.lower(), value)
            val_str = f'"{value}"' if isinstance(value, str) else str(value)
            expr = f"NOT {field}: {val_str}"

        # ── CONTAINS → KQL wildcard ────────────────────────────────────────
        elif op == ComparisonOperator.CONTAINS:
            expr = f"{field}: *{value}*"

        # ── REGEX → KQL doesn't support regex natively; use wildcard ──────
        # KQL has no regex operator — approximate with wildcard
        elif op == ComparisonOperator.REGEX:
            # Strip common regex anchors and use as wildcard approximation
            approx = str(value).strip("^$").replace(".*", "*").replace(".+", "*")
            expr = f"{field}: {approx}"
            log.warning(
                "KQL does not support regex — approximated with wildcard",
                extra={"field": field, "regex": value, "approx": approx},
            )

        # ── IN → KQL list membership ───────────────────────────────────────
        elif op == ComparisonOperator.IN:
            if isinstance(value, list):
                items = " or ".join(
                    f'"{v}"' if isinstance(v, str) else str(v) for v in value
                )
                expr = f"{field}: ({items})"
            else:
                val_str = f'"{value}"' if isinstance(value, str) else str(value)
                expr = f"{field}: {val_str}"

        # ── NOT IN → KQL negated list membership ──────────────────────────
        elif op == ComparisonOperator.NOT_IN:
            if isinstance(value, list):
                items = " or ".join(
                    f'"{v}"' if isinstance(v, str) else str(v) for v in value
                )
                expr = f"NOT {field}: ({items})"
            else:
                val_str = f'"{value}"' if isinstance(value, str) else str(value)
                expr = f"NOT {field}: {val_str}"

        # ── Numeric range comparisons ──────────────────────────────────────
        elif op in (
            ComparisonOperator.GT, ComparisonOperator.GTE,
            ComparisonOperator.LT, ComparisonOperator.LTE,
        ):
            mapped_op = self._map_op(op)
            expr = f"{field} {mapped_op} {value}"

        else:
            val_str = f'"{value}"' if isinstance(value, str) else str(value)
            expr = f"{field}: {val_str}"

        return f"NOT ({expr})" if cond.negate else expr

    # ─────────────────────────────────────────────
    # Lookup builder (KQL + enrichment policy note)
    # ─────────────────────────────────────────────

    def _build_lookup_kql(self, ir: IRQuery) -> str:
        """
        Build KQL with a threat-intel enrichment comment.

        Elastic threat-intel enrichment is handled via enrich processors
        or the Threat Intelligence module — not inline in KQL.
        We output the base filter + a comment explaining the enrichment needed.
        """
        parts: list[str] = []

        # Base filter
        if ir.filter:
            kql_filter = self._build_kql_filter_group(ir.filter)
            if kql_filter:
                parts.append(kql_filter)

        if ir.lookup:
            match_field = self._resolve(ir.lookup.match_field)
            table       = ir.lookup.lookup_table
            parts.append(
                f"// Enrich: match {match_field} against '{table}' "
                f"using Elastic Enrich Policy or Threat Intel module"
            )
            if ir.lookup.filter_on_match:
                parts.append(f"{match_field}: *")

        return "\n".join(parts) if parts else "*"

    # ─────────────────────────────────────────────
    # Syntax validator
    # ─────────────────────────────────────────────

    def static_validate(self, query: str) -> bool:
        """
        Static structural check of generated EQL / KQL text.

        IMPORTANT — scope of this check:
        This method performs a lightweight, string-level plausibility check.
        It confirms that the output *looks like* well-formed EQL or KQL
        (correct leading keyword, presence of 'where', balanced sequence
        brackets, recognised pipe commands). It is NOT a grammar parser and
        cannot detect semantically nonsensical conditions inside a syntactically
        well-formed clause — for example:

            authentication where some_undefined_field == "anything"

        passes this check because the structural shape is correct, even
        though `some_undefined_field` is not a real ECS field. Treat a
        ``True`` result as "did not fail an obvious structural check",
        not as "is guaranteed valid Elasticsearch EQL/KQL". For execution-
        verified correctness, see execution_match.py in the evaluation layer,
        which submits the query to a live Elasticsearch/EQL endpoint.

        Checks performed:
          EQL          — starts with a recognised event category + 'where'
          EQL sequence — starts with 'sequence' and contains bracketed steps
          KQL          — contains a 'field: value' colon pattern, is '*',
                         or contains a numeric range comparison

        Args:
            query: Generated EQL or KQL string to check.

        Returns:
            True if the query passes the structural plausibility check.
        """
        if not query or not isinstance(query, str):
            return False

        # Strip trailing comment lines (time-range / enrichment notes) before
        # structural inspection — comments are not part of the query grammar.
        query_no_comments = "\n".join(
            line for line in query.split("\n")
            if not line.strip().startswith("//")
        ).strip()

        q          = query_no_comments.strip()
        ql         = q.lower()
        first_word = ql.split()[0] if ql.split() else ""

        EQL_CATEGORIES = {
            "authentication", "network", "process", "file",
            "registry", "dns", "web", "any",
        }

        # EQL sequence
        if first_word == "sequence":
            has_steps = "[" in q and "]" in q
            if not has_steps:
                log.warning("EQL sequence missing bracketed steps")
                return False
            return True

        # EQL event query
        if first_word in EQL_CATEGORIES:
            if "where" not in ql:
                log.warning(
                    "EQL query missing 'where' clause",
                    extra={"category": first_word},
                )
                return False
            # Verify pipe commands are valid EQL pipes
            if "|" in q:
                VALID_EQL_PIPES = {"stats", "where", "sort", "head", "tail"}
                for segment in q.split("|")[1:]:
                    cmd = segment.strip().split()[0].lower() if segment.strip() else ""
                    if cmd and cmd not in VALID_EQL_PIPES:
                        log.warning(
                            "Unknown EQL pipe command",
                            extra={"command": cmd},
                        )
                        return False
            return True

        # KQL — must have field:value or be wildcard '*'
        if q == "*":
            return True

        if ":" in q:
            return True

        # KQL with only range comparison (field >= N)
        if re.search(r'\b\w[\w.]+\s*(>=|<=|>|<)\s*\d', q):
            return True

        log.warning(
            "Could not identify as valid EQL or KQL",
            extra={"first_word": first_word, "query_preview": q[:80]},
        )
        return False

    def validate(self, query: str) -> bool:
        """
        Deprecated alias for :meth:`static_validate`.

        Retained for backward compatibility with callers written against
        the original ``BaseSIEMTranslator.validate`` abstract method name.
        New code should call :meth:`static_validate` directly — the name
        makes explicit that this is a structural plausibility check, not
        a guarantee of executable correctness against a live SIEM backend.
        """
        return self.static_validate(query)