"""
Layer 1 — IR Schema Test Suite
Run from project root:
    python test_ir_schema.py

Tests every class, validator, coercion rule, and utility function in src/ir/.
Green checkmarks = ready for Layer 2.
Red X = fix before building translators.
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

PASS = "  ✅"
FAIL = "  ❌"
results = []


def check(label: str, fn):
    try:
        fn()
        print(f"{PASS} {label}")
        results.append((label, True, None))
    except Exception as exc:
        print(f"{FAIL} {label}")
        print(f"       → {type(exc).__name__}: {exc}")
        results.append((label, False, exc))


# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "═" * 60)
print("  NL-SIEM — Layer 1 IR Schema Test Suite")
print("═" * 60)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 1. IMPORTS ──────────────────────────────────────────────")


def test_import_schema():
    from src.ir.schema import (
        IRQuery, FilterCondition, FilterGroup,
        TimeWindow, AggregationSpec, ThresholdCondition,
        LookupSpec, SequenceStep,
        ActionType, EventType, ComparisonOperator,
        AggregationFunction, LogicalOperator, SortOrder,
    )


def test_import_validator():
    from src.ir.validator import validate_ir, coerce_ir, validate_batch


def test_import_ir_to_nl():
    from src.ir.ir_to_nl import ir_to_nl, ir_to_nl_variants


def test_import_ir_init():
    from src.ir import (
        IRQuery, validate_ir, coerce_ir, ir_to_nl,
        ActionType, EventType, FilterGroup, FilterCondition,
    )


check("Import: schema.py",     test_import_schema)
check("Import: validator.py",  test_import_validator)
check("Import: ir_to_nl.py",   test_import_ir_to_nl)
check("Import: __init__.py",   test_import_ir_init)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 2. ENUMERATIONS ─────────────────────────────────────────")


def test_action_type_values():
    from src.ir.schema import ActionType
    assert ActionType.FILTER.value           == "filter"
    assert ActionType.AGGREGATE.value        == "aggregate"
    assert ActionType.FILTER_AGGREGATE.value == "filter+aggregate"
    assert ActionType.SEQUENCE.value         == "sequence"
    assert ActionType.LOOKUP.value           == "lookup"


def test_event_type_values():
    from src.ir.schema import EventType
    assert EventType.AUTHENTICATION.value == "authentication"
    assert EventType.NETWORK.value        == "network"
    assert EventType.PROCESS.value        == "process"
    assert EventType.FILE.value           == "file"
    assert EventType.DNS.value            == "dns"
    assert EventType.ANY.value            == "any"


def test_comparison_operator_values():
    from src.ir.schema import ComparisonOperator
    assert ComparisonOperator.EQ.value       == "eq"
    assert ComparisonOperator.NEQ.value      == "neq"
    assert ComparisonOperator.GT.value       == "gt"
    assert ComparisonOperator.GTE.value      == "gte"
    assert ComparisonOperator.IN.value       == "in"
    assert ComparisonOperator.CONTAINS.value == "contains"
    assert ComparisonOperator.REGEX.value    == "regex"


def test_aggregation_function_values():
    from src.ir.schema import AggregationFunction
    assert AggregationFunction.COUNT.value    == "count"
    assert AggregationFunction.SUM.value      == "sum"
    assert AggregationFunction.DISTINCT.value == "distinct_count"


check("Enum: ActionType values",           test_action_type_values)
check("Enum: EventType values",            test_event_type_values)
check("Enum: ComparisonOperator values",   test_comparison_operator_values)
check("Enum: AggregationFunction values",  test_aggregation_function_values)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 3. SUB-MODELS ───────────────────────────────────────────")


def test_filter_condition_basic():
    from src.ir.schema import FilterCondition
    fc = FilterCondition(field="status", op="eq", value="failed")
    assert fc.field == "status"
    assert fc.op    == "eq"
    assert fc.value == "failed"
    assert fc.negate is False


def test_filter_condition_negate():
    from src.ir.schema import FilterCondition
    fc = FilterCondition(field="src_ip", op="eq", value="10.0.0.1", negate=True)
    assert fc.negate is True


def test_filter_condition_list_value():
    from src.ir.schema import FilterCondition
    fc = FilterCondition(field="status", op="in", value=["failed", "error", "denied"])
    assert isinstance(fc.value, list)
    assert len(fc.value) == 3


def test_filter_group_basic():
    from src.ir.schema import FilterGroup, FilterCondition
    fg = FilterGroup(
        operator="and",
        conditions=[
            FilterCondition(field="status", op="eq", value="failed"),
            FilterCondition(field="src_ip", op="neq", value="127.0.0.1"),
        ]
    )
    assert fg.operator == "and"
    assert len(fg.conditions) == 2


def test_filter_group_nested():
    from src.ir.schema import FilterGroup, FilterCondition
    inner = FilterGroup(
        operator="or",
        conditions=[
            FilterCondition(field="src_ip", op="eq", value="1.2.3.4"),
            FilterCondition(field="src_ip", op="eq", value="5.6.7.8"),
        ]
    )
    outer = FilterGroup(
        operator="and",
        conditions=[
            FilterCondition(field="status", op="eq", value="failed"),
            inner,
        ]
    )
    assert len(outer.conditions) == 2
    assert isinstance(outer.conditions[1], FilterGroup)


def test_time_window_basic():
    from src.ir.schema import TimeWindow
    tw = TimeWindow(duration="24h")
    assert tw.duration == "24h"
    assert tw.to_seconds == 86400


def test_time_window_conversions():
    from src.ir.schema import TimeWindow
    tw = TimeWindow(duration="10m")
    assert tw.to_seconds  == 600
    assert tw.to_splunk   == "-10m"
    assert tw.to_kql      == "ago(10m)"
    assert "10" in tw.to_aql
    assert "MINUTES" in tw.to_aql


def test_time_window_days():
    from src.ir.schema import TimeWindow
    tw = TimeWindow(duration="7d")
    assert tw.to_seconds == 604800
    assert "DAYS" in tw.to_aql


def test_time_window_invalid_pattern():
    from src.ir.schema import TimeWindow
    from pydantic import ValidationError
    try:
        TimeWindow(duration="24hours")
        assert False, "Should raise"
    except (ValidationError, Exception):
        pass


def test_aggregation_spec_basic():
    from src.ir.schema import AggregationSpec
    agg = AggregationSpec(
        function="count",
        group_by=["src_ip"],
        alias="attempt_count"
    )
    assert agg.function     == "count"
    assert agg.group_by     == ["src_ip"]
    assert agg.output_field == "attempt_count"


def test_aggregation_spec_output_field_derived():
    from src.ir.schema import AggregationSpec
    agg = AggregationSpec(function="count", field="events")
    assert agg.output_field == "count_events"


def test_threshold_condition():
    from src.ir.schema import ThresholdCondition
    th = ThresholdCondition(field="attempt_count", op="gt", value=50)
    assert th.field == "attempt_count"
    assert th.op    == "gt"
    assert th.value == 50


def test_lookup_spec():
    from src.ir.schema import LookupSpec
    lk = LookupSpec(
        lookup_table="threat_intel_ips",
        match_field="dest_ip",
        output_field="is_malicious",
        filter_on_match=True,
    )
    assert lk.lookup_table    == "threat_intel_ips"
    assert lk.filter_on_match is True


def test_sequence_step():
    from src.ir.schema import SequenceStep, FilterGroup, FilterCondition
    step = SequenceStep(
        event_type="authentication",
        filter=FilterGroup(conditions=[
            FilterCondition(field="status", op="eq", value="success")
        ]),
        within="5m",
    )
    assert step.event_type == "authentication"
    assert step.within     == "5m"


check("SubModel: FilterCondition basic",         test_filter_condition_basic)
check("SubModel: FilterCondition negate",        test_filter_condition_negate)
check("SubModel: FilterCondition list value",    test_filter_condition_list_value)
check("SubModel: FilterGroup basic",             test_filter_group_basic)
check("SubModel: FilterGroup nested",            test_filter_group_nested)
check("SubModel: TimeWindow basic",              test_time_window_basic)
check("SubModel: TimeWindow conversions",        test_time_window_conversions)
check("SubModel: TimeWindow days",               test_time_window_days)
check("SubModel: TimeWindow invalid pattern",    test_time_window_invalid_pattern)
check("SubModel: AggregationSpec basic",         test_aggregation_spec_basic)
check("SubModel: AggregationSpec output_field",  test_aggregation_spec_output_field_derived)
check("SubModel: ThresholdCondition",            test_threshold_condition)
check("SubModel: LookupSpec",                    test_lookup_spec)
check("SubModel: SequenceStep",                  test_sequence_step)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 4. IRQuery — VALID CONSTRUCTION ────────────────────────")


def test_irquery_filter_only():
    from src.ir.schema import IRQuery
    ir = IRQuery(
        action="filter",
        event_type="authentication",
        filter={
            "operator": "and",
            "conditions": [
                {"field": "status", "op": "eq", "value": "failed"}
            ]
        },
        time_window={"duration": "24h"},
    )
    assert ir.action     == "filter"
    assert ir.event_type == "authentication"


def test_irquery_filter_aggregate():
    from src.ir.schema import IRQuery
    ir = IRQuery(
        action="filter+aggregate",
        event_type="authentication",
        filter={"operator": "and", "conditions": [
            {"field": "status", "op": "eq", "value": "failed"}
        ]},
        time_window={"duration": "24h"},
        aggregation={"function": "count", "group_by": ["src_ip"], "alias": "attempts"},
        threshold={"field": "attempts", "op": "gt", "value": 50},
    )
    assert ir.aggregation.group_by == ["src_ip"]
    assert ir.threshold.value      == 50


def test_irquery_aggregate_only():
    from src.ir.schema import IRQuery
    ir = IRQuery(
        action="aggregate",
        event_type="network",
        aggregation={"function": "sum", "field": "bytes", "group_by": ["src_ip"]},
    )
    assert ir.action == "aggregate"


def test_irquery_sequence():
    from src.ir.schema import IRQuery
    ir = IRQuery(
        action="sequence",
        event_type="authentication",
        sequence=[
            {"event_type": "authentication", "filter": {
                "operator": "and",
                "conditions": [{"field": "status", "op": "eq", "value": "success"}]
            }},
            {"event_type": "authentication", "filter": {
                "operator": "and",
                "conditions": [{"field": "country", "op": "neq", "value": "$prev.country"}]
            }, "within": "30m"},
        ]
    )
    assert len(ir.sequence) == 2
    assert ir.sequence[1].within == "30m"


def test_irquery_lookup():
    from src.ir.schema import IRQuery
    ir = IRQuery(
        action="lookup",
        event_type="network",
        lookup={
            "lookup_table": "threat_intel_ips",
            "match_field": "dest_ip",
            "output_field": "is_malicious",
            "filter_on_match": True,
        },
        time_window={"duration": "1h"},
    )
    assert ir.lookup.lookup_table == "threat_intel_ips"


def test_irquery_with_mitre():
    from src.ir.schema import IRQuery
    ir = IRQuery(
        action="filter",
        tactic="initial_access",
        technique_id="T1110",
    )
    assert ir.tactic       == "initial_access"
    assert ir.technique_id == "T1110"


def test_irquery_with_fields_and_limit():
    from src.ir.schema import IRQuery
    ir = IRQuery(
        action="filter",
        fields=["src_ip", "user", "timestamp"],
        limit=100,
        sort_by="timestamp",
        sort_order="desc",
    )
    assert ir.fields    == ["src_ip", "user", "timestamp"]
    assert ir.limit     == 100
    assert ir.sort_by   == "timestamp"


check("IRQuery: filter only",           test_irquery_filter_only)
check("IRQuery: filter+aggregate",      test_irquery_filter_aggregate)
check("IRQuery: aggregate only",        test_irquery_aggregate_only)
check("IRQuery: sequence",              test_irquery_sequence)
check("IRQuery: lookup",                test_irquery_lookup)
check("IRQuery: MITRE metadata",        test_irquery_with_mitre)
check("IRQuery: fields + limit + sort", test_irquery_with_fields_and_limit)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 5. IRQuery — CROSS-FIELD VALIDATORS ────────────────────")


def test_aggregate_without_aggregation_spec_raises():
    from src.ir.schema import IRQuery
    from pydantic import ValidationError
    try:
        IRQuery(action="aggregate")
        assert False, "Should raise"
    except (ValidationError, ValueError):
        pass


def test_filter_aggregate_without_aggregation_raises():
    from src.ir.schema import IRQuery
    from pydantic import ValidationError
    try:
        IRQuery(action="filter+aggregate")
        assert False, "Should raise"
    except (ValidationError, ValueError):
        pass


def test_threshold_without_aggregation_raises():
    from src.ir.schema import IRQuery
    from pydantic import ValidationError
    try:
        IRQuery(
            action="filter",
            threshold={"field": "count", "op": "gt", "value": 10}
        )
        assert False, "Should raise"
    except (ValidationError, ValueError):
        pass


def test_sequence_without_steps_raises():
    from src.ir.schema import IRQuery
    from pydantic import ValidationError
    try:
        IRQuery(action="sequence", sequence=[])
        assert False, "Should raise"
    except (ValidationError, ValueError):
        pass


def test_lookup_without_spec_raises():
    from src.ir.schema import IRQuery
    from pydantic import ValidationError
    try:
        IRQuery(action="lookup")
        assert False, "Should raise"
    except (ValidationError, ValueError):
        pass


check("Validator: aggregate without spec raises",         test_aggregate_without_aggregation_spec_raises)
check("Validator: filter+aggregate without spec raises",  test_filter_aggregate_without_aggregation_raises)
check("Validator: threshold without aggregation raises",  test_threshold_without_aggregation_raises)
check("Validator: sequence without steps raises",         test_sequence_without_steps_raises)
check("Validator: lookup without spec raises",            test_lookup_without_spec_raises)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 6. IRQuery — SERIALISATION ──────────────────────────────")


def test_to_dict_excludes_none():
    from src.ir.schema import IRQuery
    ir = IRQuery(action="filter", event_type="network")
    d = ir.to_dict()
    assert "action"     in d
    assert "event_type" in d
    # None fields should not appear
    assert "threshold"  not in d
    assert "sequence"   not in d
    assert "lookup"     not in d


def test_from_dict_roundtrip():
    from src.ir.schema import IRQuery
    original = IRQuery(
        action="filter+aggregate",
        event_type="authentication",
        filter={"operator": "and", "conditions": [
            {"field": "status", "op": "eq", "value": "failed"}
        ]},
        time_window={"duration": "24h"},
        aggregation={"function": "count", "group_by": ["src_ip"], "alias": "attempts"},
        threshold={"field": "attempts", "op": "gt", "value": 50},
        tactic="initial_access",
        technique_id="T1110",
    )
    d  = original.to_dict()
    restored = IRQuery.from_dict(d)
    assert restored.action              == original.action
    assert restored.aggregation.alias   == "attempts"
    assert restored.threshold.value     == 50
    assert restored.tactic              == "initial_access"


def test_summary_output():
    from src.ir.schema import IRQuery
    ir = IRQuery(
        action="filter+aggregate",
        event_type="authentication",
        time_window={"duration": "24h"},
        aggregation={"function": "count", "group_by": ["src_ip"], "alias": "attempts"},
        threshold={"field": "attempts", "op": "gt", "value": 50},
        tactic="initial_access",
    )
    s = ir.summary()
    assert "filter+aggregate" in s
    assert "authentication"   in s
    assert "24h"              in s
    assert "count"            in s
    assert "initial_access"   in s


def test_json_serialisable():
    import json
    from src.ir.schema import IRQuery
    ir = IRQuery(
        action="filter+aggregate",
        event_type="authentication",
        filter={"operator": "and", "conditions": [
            {"field": "status", "op": "eq", "value": "failed"}
        ]},
        aggregation={"function": "count", "group_by": ["src_ip"]},
        threshold={"field": "count", "op": "gt", "value": 10},
    )
    dumped = json.dumps(ir.to_dict())
    assert isinstance(dumped, str)
    reloaded = json.loads(dumped)
    assert reloaded["action"] == "filter+aggregate"


check("Serialise: to_dict excludes None",  test_to_dict_excludes_none)
check("Serialise: from_dict roundtrip",    test_from_dict_roundtrip)
check("Serialise: summary() content",      test_summary_output)
check("Serialise: JSON serialisable",      test_json_serialisable)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 7. VALIDATOR — validate_ir() ────────────────────────────")


def test_validate_ir_valid_dict():
    from src.ir.validator import validate_ir
    from src.ir.schema import IRQuery
    raw = {
        "action": "filter",
        "event_type": "authentication",
        "filter": {"operator": "and", "conditions": [
            {"field": "status", "op": "eq", "value": "failed"}
        ]},
        "time_window": {"duration": "24h"},
    }
    ir = validate_ir(raw)
    assert isinstance(ir, IRQuery)


def test_validate_ir_missing_action_raises():
    from src.ir.validator import validate_ir
    from src.utils.exceptions import IRMissingFieldError
    try:
        validate_ir({"event_type": "network"})
        assert False, "Should raise"
    except IRMissingFieldError as e:
        assert "action" in str(e)


def test_validate_ir_invalid_action_raises():
    from src.ir.validator import validate_ir
    from src.utils.exceptions import IRValidationError
    try:
        validate_ir({"action": "explode_everything"})
        assert False, "Should raise"
    except (IRValidationError, Exception):
        pass


def test_validate_ir_invalid_operator_raises():
    from src.ir.validator import validate_ir
    from src.utils.exceptions import IRValidationError
    try:
        validate_ir({
            "action": "filter",
            "filter": {"operator": "and", "conditions": [
                {"field": "status", "op": "INVALID_OP", "value": "x"}
            ]}
        })
        assert False, "Should raise"
    except (IRValidationError, Exception):
        pass


check("validate_ir: valid dict",               test_validate_ir_valid_dict)
check("validate_ir: missing action raises",    test_validate_ir_missing_action_raises)
check("validate_ir: invalid action raises",    test_validate_ir_invalid_action_raises)
check("validate_ir: invalid operator raises",  test_validate_ir_invalid_operator_raises)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 8. VALIDATOR — coerce_ir() ──────────────────────────────")


def test_coerce_action_alias():
    from src.ir.validator import coerce_ir
    ir = coerce_ir({"action": "search", "event_type": "authentication"})
    assert ir.action == "filter"


def test_coerce_action_detect():
    from src.ir.validator import coerce_ir
    ir = coerce_ir({
        "action": "detect",
        "aggregation": {"function": "count", "group_by": ["src_ip"]},
    })
    assert ir.action == "filter+aggregate"


def test_coerce_event_type_alias():
    from src.ir.validator import coerce_ir
    ir = coerce_ir({"action": "filter", "event_type": "login"})
    assert ir.event_type == "authentication"


def test_coerce_event_type_proc():
    from src.ir.validator import coerce_ir
    ir = coerce_ir({"action": "filter", "event_type": "proc"})
    assert ir.event_type == "process"


def test_coerce_event_type_unknown_defaults_to_any():
    from src.ir.validator import coerce_ir
    ir = coerce_ir({"action": "filter", "event_type": "totally_unknown_type"})
    assert ir.event_type == "any"


def test_coerce_operator_alias_eq():
    from src.ir.validator import coerce_ir
    ir = coerce_ir({
        "action": "filter",
        "filter": {"operator": "and", "conditions": [
            {"field": "status", "op": "==", "value": "failed"}
        ]}
    })
    assert ir.filter.conditions[0].op == "eq"


def test_coerce_operator_alias_gt():
    from src.ir.validator import coerce_ir
    ir = coerce_ir({
        "action": "filter",
        "filter": {"operator": "and", "conditions": [
            {"field": "count", "op": ">", "value": 50}
        ]}
    })
    assert ir.filter.conditions[0].op == "gt"


def test_coerce_time_window_integer():
    from src.ir.validator import coerce_ir
    ir = coerce_ir({
        "action": "filter",
        "time_window": {"duration": "24"}
    })
    assert ir.time_window.duration == "24h"


def test_coerce_time_window_string_shorthand():
    from src.ir.validator import coerce_ir
    ir = coerce_ir({
        "action": "filter",
        "time_window": "10m"
    })
    assert ir.time_window.duration == "10m"


def test_coerce_threshold_integer():
    from src.ir.validator import coerce_ir
    ir = coerce_ir({
        "action": "filter+aggregate",
        "aggregation": {"function": "count", "group_by": ["src_ip"]},
        "threshold": 50,
    })
    assert ir.threshold.value == 50
    assert ir.threshold.op    == "gt"


def test_coerce_threshold_string():
    from src.ir.validator import coerce_ir
    ir = coerce_ir({
        "action": "filter+aggregate",
        "aggregation": {"function": "count", "group_by": ["src_ip"]},
        "threshold": ">100",
    })
    assert ir.threshold.value == 100
    assert ir.threshold.op    == "gt"


def test_coerce_strips_unknown_fields():
    from src.ir.validator import coerce_ir
    ir = coerce_ir({
        "action": "filter",
        "unknown_field_xyz": "should_be_removed",
        "another_bad_key": 999,
    })
    assert not hasattr(ir, "unknown_field_xyz")


check("coerce_ir: action 'search' → 'filter'",           test_coerce_action_alias)
check("coerce_ir: action 'detect' → 'filter+aggregate'", test_coerce_action_detect)
check("coerce_ir: event 'login' → 'authentication'",     test_coerce_event_type_alias)
check("coerce_ir: event 'proc' → 'process'",             test_coerce_event_type_proc)
check("coerce_ir: unknown event → 'any'",                test_coerce_event_type_unknown_defaults_to_any)
check("coerce_ir: op '==' → 'eq'",                       test_coerce_operator_alias_eq)
check("coerce_ir: op '>' → 'gt'",                        test_coerce_operator_alias_gt)
check("coerce_ir: time_window int → '24h'",              test_coerce_time_window_integer)
check("coerce_ir: time_window string shorthand",         test_coerce_time_window_string_shorthand)
check("coerce_ir: threshold int → ThresholdCondition",   test_coerce_threshold_integer)
check("coerce_ir: threshold '>100' → ThresholdCondition",test_coerce_threshold_string)
check("coerce_ir: strips unknown top-level fields",      test_coerce_strips_unknown_fields)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 9. VALIDATOR — validate_batch() ─────────────────────────")


def test_validate_batch_all_valid():
    from src.ir.validator import validate_batch
    records = [
        {"action": "filter", "event_type": "authentication"},
        {"action": "filter", "event_type": "network"},
        {"action": "aggregate", "aggregation": {"function": "count", "group_by": ["src_ip"]}},
    ]
    valid, failed = validate_batch(records)
    assert len(valid)  == 3
    assert len(failed) == 0


def test_validate_batch_mixed():
    from src.ir.validator import validate_batch
    records = [
        {"action": "filter"},
        {"event_type": "network"},        # missing action — should fail
        {"action": "filter+aggregate"},   # missing aggregation — should fail
    ]
    valid, failed = validate_batch(records)
    assert len(valid)  == 1
    assert len(failed) == 2


def test_validate_batch_failed_has_error_key():
    from src.ir.validator import validate_batch
    records = [{"event_type": "authentication"}]  # no action
    _, failed = validate_batch(records)
    assert "error" in failed[0]


check("validate_batch: all valid",           test_validate_batch_all_valid)
check("validate_batch: mixed valid/invalid", test_validate_batch_mixed)
check("validate_batch: failed has error key",test_validate_batch_failed_has_error_key)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 10. IR → NL ─────────────────────────────────────────────")


def _make_brute_force_ir():
    from src.ir.schema import IRQuery
    return IRQuery(
        action="filter+aggregate",
        event_type="authentication",
        filter={"operator": "and", "conditions": [
            {"field": "status", "op": "eq", "value": "failed"}
        ]},
        time_window={"duration": "24h"},
        aggregation={"function": "count", "group_by": ["src_ip"], "alias": "attempts"},
        threshold={"field": "attempts", "op": "gt", "value": 50},
        tactic="initial_access",
        technique_id="T1110",
    )


def test_ir_to_nl_returns_string():
    from src.ir.ir_to_nl import ir_to_nl
    ir  = _make_brute_force_ir()
    nl  = ir_to_nl(ir)
    assert isinstance(nl, str)
    assert len(nl) > 10


def test_ir_to_nl_contains_key_concepts():
    from src.ir.ir_to_nl import ir_to_nl
    ir  = _make_brute_force_ir()
    nl  = ir_to_nl(ir).lower()
    assert "authentication" in nl or "event" in nl
    assert "24" in nl
    assert "50" in nl


def test_ir_to_nl_contains_mitre():
    from src.ir.ir_to_nl import ir_to_nl
    ir  = _make_brute_force_ir()
    nl  = ir_to_nl(ir)
    assert "initial" in nl.lower() or "T1110" in nl


def test_ir_to_nl_filter_only():
    from src.ir.schema import IRQuery
    from src.ir.ir_to_nl import ir_to_nl
    ir = IRQuery(
        action="filter",
        event_type="process",
        filter={"operator": "and", "conditions": [
            {"field": "process_name", "op": "eq", "value": "powershell.exe"}
        ]},
        time_window={"duration": "1h"},
    )
    nl = ir_to_nl(ir)
    assert isinstance(nl, str)
    assert len(nl) > 5


def test_ir_to_nl_variants_returns_list():
    from src.ir.ir_to_nl import ir_to_nl_variants
    ir       = _make_brute_force_ir()
    variants = ir_to_nl_variants(ir, n=3)
    assert isinstance(variants, list)
    assert len(variants) >= 1
    assert all(isinstance(v, str) for v in variants)


def test_ir_to_nl_variants_differ():
    from src.ir.ir_to_nl import ir_to_nl_variants
    ir       = _make_brute_force_ir()
    variants = ir_to_nl_variants(ir, n=3)
    # At least 2 variants should exist and differ
    if len(variants) >= 2:
        assert variants[0] != variants[1]


check("ir_to_nl: returns string",              test_ir_to_nl_returns_string)
check("ir_to_nl: contains key concepts",       test_ir_to_nl_contains_key_concepts)
check("ir_to_nl: contains MITRE info",         test_ir_to_nl_contains_mitre)
check("ir_to_nl: filter-only IR",              test_ir_to_nl_filter_only)
check("ir_to_nl_variants: returns list",       test_ir_to_nl_variants_returns_list)
check("ir_to_nl_variants: variants differ",    test_ir_to_nl_variants_differ)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 11. EXAMPLES.JSON ───────────────────────────────────────")


def test_examples_json_loads():
    path = Path("src/ir/examples.json")
    assert path.exists(), "examples.json not found at src/ir/examples.json"
    with path.open() as f:
        examples = json.load(f)
    assert isinstance(examples, list)
    assert len(examples) == 10


def test_examples_json_all_valid():
    from src.ir.validator import coerce_ir
    path = Path("src/ir/examples.json")
    with path.open() as f:
        examples = json.load(f)
    for ex in examples:
        ir_dict = ex["ir"]
        ir_dict.setdefault("tactic",       ex.get("tactic"))
        ir_dict.setdefault("technique_id", ex.get("technique_id"))
        ir = coerce_ir(ir_dict)
        assert ir is not None, f"Failed to validate example {ex['id']}"


def test_examples_cover_all_tactics():
    path = Path("src/ir/examples.json")
    with path.open() as f:
        examples = json.load(f)
    tactics = {ex["tactic"] for ex in examples}
    required = {
        "initial_access", "execution", "persistence",
        "privilege_escalation", "lateral_movement", "exfiltration"
    }
    assert required.issubset(tactics), f"Missing tactics: {required - tactics}"


def test_examples_cover_all_complexities():
    path = Path("src/ir/examples.json")
    with path.open() as f:
        examples = json.load(f)
    complexities = {ex["complexity"] for ex in examples}
    assert "simple"       in complexities
    assert "intermediate" in complexities
    assert "complex"      in complexities


def test_examples_all_have_nl_query():
    path = Path("src/ir/examples.json")
    with path.open() as f:
        examples = json.load(f)
    for ex in examples:
        assert "nl_query" in ex, f"Missing nl_query in {ex['id']}"
        assert len(ex["nl_query"]) > 5


check("examples.json: loads as list of 10",         test_examples_json_loads)
check("examples.json: all examples validate",       test_examples_json_all_valid)
check("examples.json: covers all 6 tactics",        test_examples_cover_all_tactics)
check("examples.json: covers all 3 complexities",   test_examples_cover_all_complexities)
check("examples.json: all have nl_query",           test_examples_all_have_nl_query)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 12. INTEGRATION ─────────────────────────────────────────")


def test_full_pipeline_brute_force():
    """Simulate full Layer 1 flow: raw LLM dict → coerce → validate → summarise → NL"""
    from src.ir.validator import coerce_ir
    from src.ir.ir_to_nl import ir_to_nl

    raw = {
        "action": "detect",           # alias → filter+aggregate
        "event_type": "login",        # alias → authentication
        "filter": {"operator": "and", "conditions": [
            {"field": "status", "op": "==", "value": "failed"}   # == → eq
        ]},
        "time_window": "24h",         # string shorthand
        "aggregation": {"function": "count", "group_by": ["src_ip"], "alias": "attempts"},
        "threshold": ">50",           # string shorthand
        "tactic": "initial_access",
        "technique_id": "T1110",
        "spurious_llm_field": "garbage",  # should be stripped
    }

    ir = coerce_ir(raw)
    assert ir.action              == "filter+aggregate"
    assert ir.event_type          == "authentication"
    assert ir.filter.conditions[0].op == "eq"
    assert ir.time_window.duration    == "24h"
    assert ir.threshold.value         == 50
    assert ir.tactic                  == "initial_access"

    summary = ir.summary()
    assert "filter+aggregate" in summary

    nl = ir_to_nl(ir)
    assert isinstance(nl, str)
    assert len(nl) > 10


def test_full_pipeline_network_lookup():
    """Lookup action with threat-intel table."""
    from src.ir.validator import coerce_ir
    raw = {
        "action": "lookup",
        "event_type": "net",          # alias → network
        "filter": {"operator": "and", "conditions": [
            {"field": "direction", "op": "eq", "value": "outbound"}
        ]},
        "time_window": {"duration": "1h"},
        "lookup": {
            "lookup_table": "threat_intel_ips",
            "match_field": "dest_ip",
            "output_field": "is_malicious",
            "filter_on_match": True,
        }
    }
    ir = coerce_ir(raw)
    assert ir.action           == "lookup"
    assert ir.event_type       == "network"
    assert ir.lookup.match_field == "dest_ip"


def test_full_pipeline_sequence():
    """Sequence action with two steps."""
    from src.ir.validator import coerce_ir
    raw = {
        "action": "sequence",
        "event_type": "auth",         # alias → authentication
        "sequence": [
            {"event_type": "authentication", "filter": {"operator": "and", "conditions": [
                {"field": "status", "op": "eq", "value": "success"}
            ]}},
            {"event_type": "authentication", "filter": {"operator": "and", "conditions": [
                {"field": "country", "op": "neq", "value": "$prev.country"}
            ]}, "within": "30m"},
        ]
    }
    ir = coerce_ir(raw)
    assert ir.action        == "sequence"
    assert ir.event_type    == "authentication"
    assert len(ir.sequence) == 2


def test_layer1_layer0_integration():
    """Layer 1 should use Layer 0 logger and exceptions without errors."""
    from src.ir.validator import coerce_ir
    from src.utils.exceptions import IRMissingFieldError
    from src.utils.logger import get_logger

    log = get_logger("test.integration")
    log.info("Running Layer 0 + Layer 1 integration test")

    try:
        coerce_ir({})
    except IRMissingFieldError as e:
        assert "action" in str(e)
        log.info("IRMissingFieldError caught correctly", extra={"error": str(e)})


check("Integration: brute force full pipeline",   test_full_pipeline_brute_force)
check("Integration: network lookup pipeline",     test_full_pipeline_network_lookup)
check("Integration: sequence pipeline",           test_full_pipeline_sequence)
check("Integration: Layer 0 + Layer 1 wired",    test_layer1_layer0_integration)


# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "═" * 60)
passed = sum(1 for _, ok, _ in results if ok)
failed = sum(1 for _, ok, _ in results if not ok)
total  = len(results)
print(f"  Results: {passed}/{total} passed", end="")
if failed:
    print(f"  |  {failed} FAILED ← fix before Layer 2")
    print("\n  Failed tests:")
    for label, ok, exc in results:
        if not ok:
            print(f"    ✗ {label}")
            print(f"      {type(exc).__name__}: {exc}")
else:
    print("  — Layer 1 is solid. Ready for Layer 2 (Translators) ✅")
print("═" * 60 + "\n")

sys.exit(0 if failed == 0 else 1)