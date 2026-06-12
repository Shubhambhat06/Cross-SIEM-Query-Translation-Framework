"""
IR → Natural Language reverse mapper.

Converts an IRQuery back into a human-readable description.
Used for:
  1. Semantic verification — compare LLM-generated NL against original query
  2. Dataset augmentation — generate NL variants from known IRs
  3. Debugging — readable summaries in logs and error reports

Place at: src/ir/ir_to_nl.py

Usage:
    from src.ir.ir_to_nl import ir_to_nl
    description = ir_to_nl(ir_query)
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
    SequenceStep,
    ThresholdCondition,
    TimeWindow,
)
from src.utils.logger import get_logger

log = get_logger(__name__)


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def ir_to_nl(ir: IRQuery) -> str:
    """
    Convert an IRQuery into a natural language description.

    Args:
        ir: Validated IRQuery object.

    Returns:
        Human-readable string describing the detection intent.
    """
    parts: list[str] = []

    # ── Action verb ───────────────────────────────────────────────────────
    parts.append(_describe_action(ir.action))

    # ── Event type ────────────────────────────────────────────────────────
    parts.append(_describe_event_type(ir.event_type))

    # ── Filter ────────────────────────────────────────────────────────────
    if ir.filter:
        filter_text = _describe_filter_group(ir.filter)
        if filter_text:
            parts.append(f"where {filter_text}")

    # ── Sequence ──────────────────────────────────────────────────────────
    if ir.sequence:
        parts.append(_describe_sequence(ir.sequence))

    # ── Lookup ────────────────────────────────────────────────────────────
    if ir.lookup:
        parts.append(_describe_lookup(ir.lookup))

    # ── Aggregation ───────────────────────────────────────────────────────
    if ir.aggregation:
        parts.append(_describe_aggregation(ir.aggregation))

    # ── Threshold ─────────────────────────────────────────────────────────
    if ir.threshold:
        parts.append(_describe_threshold(ir.threshold))

    # ── Time window ───────────────────────────────────────────────────────
    if ir.time_window:
        parts.append(_describe_time_window(ir.time_window))

    # ── Tactic context ────────────────────────────────────────────────────
    if ir.tactic:
        tactic_label = ir.tactic.replace("_", " ")
        if ir.technique_id:
            parts.append(f"(MITRE ATT&CK: {tactic_label}, {ir.technique_id})")
        else:
            parts.append(f"(MITRE ATT&CK: {tactic_label})")

    description = " ".join(p for p in parts if p)
    log.debug("IR → NL", extra={"nl": description})
    return description


def ir_to_nl_variants(ir: IRQuery, n: int = 3) -> list[str]:
    """
    Generate multiple NL phrasings for the same IRQuery.
    Useful for dataset augmentation.

    Args:
        ir: IRQuery to describe.
        n:  Number of variants to generate (max 3 built-in).

    Returns:
        List of NL descriptions with different phrasing styles.
    """
    variants = [ir_to_nl(ir)]

    # Variant 2 — imperative phrasing
    v2 = _imperative_phrasing(ir)
    if v2 and v2 != variants[0]:
        variants.append(v2)

    # Variant 3 — question phrasing
    v3 = _question_phrasing(ir)
    if v3 and v3 not in variants:
        variants.append(v3)

    return variants[:n]


# ─────────────────────────────────────────────
# Internal description helpers
# ─────────────────────────────────────────────

# Action verb mapping
_ACTION_VERBS: dict[str, str] = {
    ActionType.FILTER:           "Find all",
    ActionType.AGGREGATE:        "Count",
    ActionType.FILTER_AGGREGATE: "Detect",
    ActionType.SEQUENCE:         "Correlate",
    ActionType.LOOKUP:           "Enrich and find",
}

# Event type labels
_EVENT_LABELS: dict[str, str] = {
    "authentication": "authentication events",
    "network":        "network connections",
    "process":        "process events",
    "file":           "file system events",
    "registry":       "registry events",
    "dns":            "DNS queries",
    "http":           "HTTP requests",
    "any":            "events",
}

# Operator natural language
_OP_LABELS: dict[str, str] = {
    ComparisonOperator.EQ:       "equals",
    ComparisonOperator.NEQ:      "does not equal",
    ComparisonOperator.GT:       "greater than",
    ComparisonOperator.GTE:      "greater than or equal to",
    ComparisonOperator.LT:       "less than",
    ComparisonOperator.LTE:      "less than or equal to",
    ComparisonOperator.IN:       "is one of",
    ComparisonOperator.NOT_IN:   "is not one of",
    ComparisonOperator.CONTAINS: "contains",
    ComparisonOperator.REGEX:    "matches pattern",
}

# Aggregation function labels
_AGG_LABELS: dict[str, str] = {
    "count":          "count",
    "sum":            "sum of",
    "avg":            "average of",
    "min":            "minimum of",
    "max":            "maximum of",
    "distinct_count": "distinct count of",
}

# Time unit labels
_TIME_LABELS: dict[str, str] = {
    "s": "second",
    "m": "minute",
    "h": "hour",
    "d": "day",
}


def _describe_action(action: str) -> str:
    return _ACTION_VERBS.get(action, "Query")


def _describe_event_type(event_type: str) -> str:
    return _EVENT_LABELS.get(event_type, f"{event_type} events")


def _describe_filter_condition(cond: FilterCondition) -> str:
    field = cond.field.replace("_", " ")
    op    = _OP_LABELS.get(cond.op, cond.op)
    value = cond.value

    if isinstance(value, list):
        value_str = "[" + ", ".join(str(v) for v in value) + "]"
    else:
        value_str = f"'{value}'" if isinstance(value, str) else str(value)

    text = f"{field} {op} {value_str}"
    if cond.negate:
        text = f"NOT ({text})"
    return text


def _describe_filter_group(group: FilterGroup) -> str:
    if not group.conditions:
        return ""

    parts = []
    for cond in group.conditions:
        if isinstance(cond, FilterCondition):
            parts.append(_describe_filter_condition(cond))
        elif isinstance(cond, FilterGroup):
            inner = _describe_filter_group(cond)
            if inner:
                parts.append(f"({inner})")

    joiner = f" {group.operator.upper()} " if hasattr(group.operator, 'upper') else f" {group.operator} "
    return joiner.join(p for p in parts if p)


def _describe_time_window(tw: TimeWindow) -> str:
    duration = tw.duration
    unit  = duration[-1]
    value = int(duration[:-1])
    label = _TIME_LABELS.get(unit, unit)
    plural = "s" if value != 1 else ""
    return f"in the last {value} {label}{plural}"


def _describe_aggregation(agg: AggregationSpec) -> str:
    fn = _AGG_LABELS.get(agg.function, agg.function)

    if agg.field:
        base = f"grouped by {fn} {agg.field.replace('_', ' ')}"
    else:
        base = f"grouped by {fn}"

    if agg.group_by:
        group_fields = ", ".join(f.replace("_", " ") for f in agg.group_by)
        base += f" per {group_fields}"

    return base


def _describe_threshold(th: ThresholdCondition) -> str:
    op    = _OP_LABELS.get(th.op, th.op)
    field = th.field.replace("_", " ")
    return f"with {field} {op} {th.value}"


def _describe_lookup(lookup: LookupSpec) -> str:
    field = lookup.match_field.replace("_", " ")
    table = lookup.lookup_table.replace("_", " ")
    text  = f"matched against {table} on {field}"
    if lookup.filter_on_match:
        text += " (only matching events)"
    return text


def _describe_sequence(steps: list[SequenceStep]) -> str:
    step_parts = []
    for i, step in enumerate(steps, start=1):
        et = _describe_event_type(step.event_type)
        if step.filter:
            ftext = _describe_filter_group(step.filter)
            step_desc = f"step {i}: {et} where {ftext}"
        else:
            step_desc = f"step {i}: {et}"
        if step.within:
            step_desc += f" (within {step.within})"
        step_parts.append(step_desc)
    return "following sequence — " + "; then ".join(step_parts)


# ─────────────────────────────────────────────
# NL variant phrasing styles
# ─────────────────────────────────────────────

def _imperative_phrasing(ir: IRQuery) -> str:
    """Alert-rule style: 'Alert when ...'"""
    event = _describe_event_type(ir.event_type)
    parts = [f"Alert when {event}"]
    if ir.filter:
        parts.append(_describe_filter_group(ir.filter))
    if ir.threshold and ir.aggregation:
        parts.append(_describe_threshold(ir.threshold))
    if ir.time_window:
        parts.append(_describe_time_window(ir.time_window))
    return " ".join(p for p in parts if p)


def _question_phrasing(ir: IRQuery) -> str:
    """Analyst investigation style: 'Which IPs had ...'"""
    if ir.aggregation and ir.aggregation.group_by:
        group = ir.aggregation.group_by[0].replace("_", " ")
        event = _describe_event_type(ir.event_type)
        parts = [f"Which {group} had {event}"]
        if ir.filter:
            parts.append(_describe_filter_group(ir.filter))
        if ir.threshold:
            parts.append(_describe_threshold(ir.threshold))
        if ir.time_window:
            parts.append(_describe_time_window(ir.time_window))
        return " ".join(p for p in parts if p) + "?"
    return ""