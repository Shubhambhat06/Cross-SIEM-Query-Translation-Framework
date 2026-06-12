"""
IR — Intermediate Representation layer.
The core technical contribution of NL-SIEM.
"""

from src.ir.schema import (
    IRQuery,
    FilterCondition,
    FilterGroup,
    TimeWindow,
    AggregationSpec,
    ThresholdCondition,
    LookupSpec,
    SequenceStep,
    ActionType,
    EventType,
    ComparisonOperator,
    AggregationFunction,
    LogicalOperator,
)
from src.ir.validator import validate_ir, coerce_ir, validate_batch
from src.ir.ir_to_nl import ir_to_nl, ir_to_nl_variants

__all__ = [
    "IRQuery",
    "FilterCondition",
    "FilterGroup",
    "TimeWindow",
    "AggregationSpec",
    "ThresholdCondition",
    "LookupSpec",
    "SequenceStep",
    "ActionType",
    "EventType",
    "ComparisonOperator",
    "AggregationFunction",
    "LogicalOperator",
    "validate_ir",
    "coerce_ir",
    "validate_batch",
    "ir_to_nl",
    "ir_to_nl_variants",
]