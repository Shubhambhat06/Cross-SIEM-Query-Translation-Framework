"""
IR Validator — validates and coerces raw dicts into IRQuery objects.

Sits between the LLM response parser and the SIEM translators.
Any dict that comes out of the LLM must pass through here before
being handed to a translator.

Place at: src/ir/validator.py

Usage:
    from src.ir.validator import validate_ir, coerce_ir
    ir = validate_ir(raw_dict)        # raises on invalid
    ir = coerce_ir(raw_dict)          # attempts to fix common issues first
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from src.ir.schema import (
    ActionType,
    AggregationFunction,
    AggregationSpec,
    ComparisonOperator,
    EventType,
    FilterCondition,
    FilterGroup,
    IRQuery,
    LogicalOperator,
    ThresholdCondition,
    TimeWindow,
)
from src.utils.exceptions import IRCoercionError, IRMissingFieldError, IRValidationError
from src.utils.logger import get_logger

log = get_logger(__name__)

# ── Required top-level fields ──────────────────────────────────────────────
REQUIRED_FIELDS = {"action"}

# ── Valid enum value sets (for coercion checks) ────────────────────────────
VALID_ACTIONS      = {e.value for e in ActionType}
VALID_EVENT_TYPES  = {e.value for e in EventType}
VALID_AGG_FUNCS    = {e.value for e in AggregationFunction}
VALID_CMP_OPS      = {e.value for e in ComparisonOperator}
VALID_LOG_OPS      = {e.value for e in LogicalOperator}

# ── Common LLM mistakes and their canonical mappings ─────────────────────
ACTION_ALIASES: dict[str, str] = {
    "filter_aggregate": "filter+aggregate",
    "filter+agg":       "filter+aggregate",
    "agg":              "aggregate",
    "search":           "filter",
    "query":            "filter",
    "detect":           "filter+aggregate",
    "count":            "aggregate",
    "correlate":        "sequence",
    "enrich":           "lookup",
}

EVENT_TYPE_ALIASES: dict[str, str] = {
    "auth":        "authentication",
    "login":       "authentication",
    "logon":       "authentication",
    "net":         "network",
    "networking":  "network",
    "proc":        "process",
    "processes":   "process",
    "files":       "file",
    "filesystem":  "file",
    "reg":         "registry",
    "regedit":     "registry",
    "web":         "http",
    "url":         "http",
    "*":           "any",
    "all":         "any",
}

OP_ALIASES: dict[str, str] = {
    "=":          "eq",
    "==":         "eq",
    "equals":     "eq",
    "!=":         "neq",
    "not_equals": "neq",
    ">":          "gt",
    ">=":         "gte",
    "<":          "lt",
    "<=":         "lte",
    "match":      "regex",
    "matches":    "regex",
    "like":       "contains",
    "includes":   "contains",
}


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def validate_ir(data: dict) -> IRQuery:
    """
    Validate a raw dict against the IRQuery schema.

    Args:
        data: Raw dict, typically parsed from LLM JSON output.

    Returns:
        Validated IRQuery instance.

    Raises:
        IRMissingFieldError: If a required field is absent.
        IRValidationError:   If Pydantic validation fails.
    """
    _check_required_fields(data)
    try:
        ir = IRQuery.from_dict(data)
        log.debug("IR validated", extra={"summary": ir.summary()})
        return ir
    except ValidationError as exc:
        errors = exc.errors()
        msg = "; ".join(
            f"{'.'.join(str(l) for l in e['loc'])}: {e['msg']}"
            for e in errors
        )
        raise IRValidationError(
            f"IR schema validation failed: {msg}",
            details={"errors": errors, "raw": data},
        )


def coerce_ir(data: dict) -> IRQuery:
    """
    Attempt to fix common LLM output issues before validation.

    Applies alias normalisation and type coercions, then calls validate_ir().

    Args:
        data: Raw dict from LLM output (may contain known issues).

    Returns:
        Validated IRQuery after coercion.

    Raises:
        IRCoercionError:   If a field cannot be coerced.
        IRValidationError: If validation still fails after coercion.
    """
    try:
        data = _deep_copy(data)
        data = _coerce_action(data)
        data = _coerce_event_type(data)
        data = _coerce_filter_ops(data)
        data = _coerce_time_window(data)
        data = _coerce_aggregation(data)
        data = _coerce_threshold(data)
        data = _strip_unknown_top_level(data)
        log.debug("IR coercion complete", extra={"action": data.get("action")})
        return validate_ir(data)
    except (IRValidationError, IRMissingFieldError):
        raise
    except Exception as exc:
        raise IRCoercionError(
            f"IR coercion failed: {exc}",
            details={"raw": data},
        )


def validate_batch(records: list[dict]) -> tuple[list[IRQuery], list[dict]]:
    """
    Validate a list of raw dicts. Returns (valid, failed) where failed
    contains the original dict plus an 'error' key.

    Args:
        records: List of raw IR dicts.

    Returns:
        Tuple of (list of valid IRQuery, list of failed dicts with errors).
    """
    valid:  list[IRQuery] = []
    failed: list[dict]    = []

    for i, record in enumerate(records):
        try:
            ir = coerce_ir(record)
            valid.append(ir)
        except (IRValidationError, IRCoercionError) as exc:
            log.warning(
                "IR validation failed",
                extra={"index": i, "error": str(exc)},
            )
            failed.append({**record, "error": str(exc)})

    log.info(
        "Batch validation complete",
        extra={"total": len(records), "valid": len(valid), "failed": len(failed)},
    )
    return valid, failed


# ─────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────

def _check_required_fields(data: dict) -> None:
    for field in REQUIRED_FIELDS:
        if field not in data or data[field] is None:
            raise IRMissingFieldError(field)


def _deep_copy(data: dict) -> dict:
    """Shallow-deep copy to avoid mutating caller's dict."""
    import json
    return json.loads(json.dumps(data))


def _coerce_action(data: dict) -> dict:
    action = str(data.get("action", "")).lower().strip()
    if action in ACTION_ALIASES:
        data["action"] = ACTION_ALIASES[action]
    elif action not in VALID_ACTIONS:
        raise IRCoercionError(
            f"Cannot coerce action='{action}' to a known ActionType.",
            details={"received": action, "valid": sorted(VALID_ACTIONS)},
        )
    return data


def _coerce_event_type(data: dict) -> dict:
    et = str(data.get("event_type", "any")).lower().strip()
    if et in EVENT_TYPE_ALIASES:
        data["event_type"] = EVENT_TYPE_ALIASES[et]
    elif et not in VALID_EVENT_TYPES:
        log.warning(
            "Unknown event_type, defaulting to 'any'",
            extra={"received": et},
        )
        data["event_type"] = "any"
    return data


def _coerce_filter_ops(data: dict) -> dict:
    """Recursively normalise operator aliases in filter conditions."""
    def _fix_group(group: Any) -> Any:
        if not isinstance(group, dict):
            return group
        # Normalise logical operator
        if "operator" in group:
            group["operator"] = str(group["operator"]).lower()
        # Recurse into conditions
        if "conditions" in group:
            fixed = []
            for cond in group["conditions"]:
                if "op" in cond:
                    op = str(cond["op"]).strip()
                    cond["op"] = OP_ALIASES.get(op, op)
                if "conditions" in cond:
                    cond = _fix_group(cond)
                fixed.append(cond)
            group["conditions"] = fixed
        return group

    if "filter" in data and isinstance(data["filter"], dict):
        data["filter"] = _fix_group(data["filter"])
    return data


def _coerce_time_window(data: dict) -> dict:
    """
    Accept shorthand time windows:
    - Plain integer → treat as hours: 24 → "24h"
    - "last 24 hours" style strings → "24h"
    """
    tw = data.get("time_window")
    if tw is None:
        return data
    if isinstance(tw, dict):
        duration = str(tw.get("duration", "")).strip()
        if duration.isdigit():
            tw["duration"] = duration + "h"
            data["time_window"] = tw
    elif isinstance(tw, str):
        # "24h" / "10m" shorthand passed as plain string
        import re
        m = re.match(r"^(\d+)\s*([smhd])?$", tw.strip().lower())
        if m:
            val  = m.group(1)
            unit = m.group(2) or "h"
            data["time_window"] = {"duration": f"{val}{unit}"}
    return data


def _coerce_aggregation(data: dict) -> dict:
    """Normalise aggregation function aliases."""
    agg = data.get("aggregation")
    if not isinstance(agg, dict):
        return data
    fn = str(agg.get("function", "")).lower().strip()
    aliases = {"cnt": "count", "number": "count", "sum_of": "sum", "average": "avg"}
    if fn in aliases:
        agg["function"] = aliases[fn]
    data["aggregation"] = agg
    return data


def _coerce_threshold(data: dict) -> dict:
    """
    Accept shorthand threshold:
    - threshold: 50           → {field: "count", op: "gt", value: 50}
    - threshold: ">50"        → {field: "count", op: "gt", value: 50}
    """
    th = data.get("threshold")
    if th is None:
        return data
    if isinstance(th, (int, float)):
        data["threshold"] = {"field": "count", "op": "gt", "value": th}
    elif isinstance(th, str):
        import re
        m = re.match(r"^([><=!]+)\s*(\d+\.?\d*)$", th.strip())
        if m:
            raw_op  = m.group(1)
            val     = float(m.group(2)) if "." in m.group(2) else int(m.group(2))
            op      = OP_ALIASES.get(raw_op, "gt")
            data["threshold"] = {"field": "count", "op": op, "value": val}
    return data


def _strip_unknown_top_level(data: dict) -> dict:
    """Remove top-level keys not in IRQuery's field set to prevent Pydantic errors."""
    known = {
        "id", "nl_query", "action", "event_type", "filter",
        "time_window", "aggregation", "threshold", "sequence",
        "lookup", "fields", "sort_by", "sort_order", "limit",
        "tactic", "technique_id",
    }
    unknown = set(data.keys()) - known
    for key in unknown:
        log.debug("Stripping unknown IR field", extra={"field": key})
        del data[key]
    return data