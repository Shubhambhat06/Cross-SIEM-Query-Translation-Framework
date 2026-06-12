"""
Intermediate Representation (IR) Schema — the core technical contribution of NL-SIEM.

The IR is a platform-agnostic JSON structure that captures detection intent:
field references, logical operators, temporal windows, aggregation functions,
and threshold conditions. Every SIEM translator receives an IRQuery object.

Pydantic v2 is used for validation, coercion, and serialisation.

Place at: src/ir/schema.py
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


# ─────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────

class LogicalOperator(str, Enum):
    AND = "and"
    OR  = "or"
    NOT = "not"


class ComparisonOperator(str, Enum):
    EQ       = "eq"         # ==
    NEQ      = "neq"        # !=
    GT       = "gt"         # >
    GTE      = "gte"        # >=
    LT       = "lt"         # <
    LTE      = "lte"        # <=
    IN       = "in"         # field in [list]
    NOT_IN   = "not_in"     # field not in [list]
    CONTAINS = "contains"   # substring match
    REGEX    = "regex"      # regular expression


class AggregationFunction(str, Enum):
    COUNT    = "count"
    SUM      = "sum"
    AVG      = "avg"
    MIN      = "min"
    MAX      = "max"
    DISTINCT = "distinct_count"


class ActionType(str, Enum):
    FILTER           = "filter"
    AGGREGATE        = "aggregate"
    FILTER_AGGREGATE = "filter+aggregate"
    SEQUENCE         = "sequence"    # multi-event correlation
    LOOKUP           = "lookup"      # threat-intel enrichment


class EventType(str, Enum):
    AUTHENTICATION = "authentication"
    NETWORK        = "network"
    PROCESS        = "process"
    FILE           = "file"
    REGISTRY       = "registry"
    DNS            = "dns"
    HTTP           = "http"
    ANY            = "any"


class SortOrder(str, Enum):
    ASC  = "asc"
    DESC = "desc"


# ─────────────────────────────────────────────
# Sub-models
# ─────────────────────────────────────────────

class FilterCondition(BaseModel):
    """A single field-level filter condition."""

    field: str = Field(
        ...,
        description="Canonical field name (e.g. 'src_ip', 'user', 'status').",
    )
    op: ComparisonOperator = Field(
        ...,
        description="Comparison operator.",
    )
    value: Any = Field(
        ...,
        description="Value to compare against. May be scalar, list, or regex string.",
    )
    negate: bool = Field(
        default=False,
        description="If True, wrap this condition in a logical NOT.",
    )

    model_config = {"use_enum_values": True}


class FilterGroup(BaseModel):
    """
    A group of FilterConditions joined by a logical operator.
    Supports nesting for complex boolean expressions.

    Example:
        FilterGroup(
            operator="and",
            conditions=[
                FilterCondition(field="status", op="eq", value="failed"),
                FilterCondition(field="src_ip", op="neq", value="192.168.1.1"),
            ]
        )
    """

    operator: LogicalOperator = Field(default=LogicalOperator.AND)
    conditions: list[FilterCondition | "FilterGroup"] = Field(default_factory=list)

    model_config = {"use_enum_values": True}


class TimeWindow(BaseModel):
    """
    Temporal constraint for the detection query.

    Duration uses a compact string format: <integer><unit>
    Units: s (seconds), m (minutes), h (hours), d (days)
    Examples: "24h", "10m", "7d", "30s"
    """

    duration: str = Field(
        ...,
        description="Duration string e.g. '24h', '10m', '7d'.",
        pattern=r"^\d+[smhd]$",
    )
    field: str = Field(
        default="_time",
        description="Timestamp field name in canonical schema.",
    )

    @property
    def to_seconds(self) -> int:
        """Convert duration string to total seconds."""
        unit_map = {"s": 1, "m": 60, "h": 3600, "d": 86400}
        unit  = self.duration[-1]
        value = int(self.duration[:-1])
        return value * unit_map[unit]

    @property
    def to_splunk(self) -> str:
        """Return Splunk earliest= modifier e.g. '-24h'."""
        return f"-{self.duration}"

    @property
    def to_kql(self) -> str:
        """Return KQL ago() expression e.g. 'ago(24h)'."""
        return f"ago({self.duration})"

    @property
    def to_aql(self) -> str:
        """Return QRadar LAST N HOURS/MINUTES/DAYS clause."""
        unit_map = {"s": "SECONDS", "m": "MINUTES", "h": "HOURS", "d": "DAYS"}
        unit  = self.duration[-1]
        value = self.duration[:-1]
        return f"LAST {value} {unit_map[unit]}"


class AggregationSpec(BaseModel):
    """Describes an aggregation operation (stats / summarize / GROUP BY)."""

    function: AggregationFunction = Field(
        ...,
        description="Aggregation function to apply.",
    )
    field: str | None = Field(
        default=None,
        description="Field to aggregate over. None implies count of all events.",
    )
    group_by: list[str] = Field(
        default_factory=list,
        description="Fields to group results by.",
    )
    alias: str | None = Field(
        default=None,
        description="Output alias for the aggregated value (e.g. 'attempt_count').",
    )

    model_config = {"use_enum_values": True}

    @property
    def output_field(self) -> str:
        """Return alias if set, otherwise derive from function."""
        if self.alias:
            return self.alias
        if self.field:
            return f"{self.function}_{self.field}"
        return self.function


class ThresholdCondition(BaseModel):
    """Post-aggregation threshold filter (HAVING / where count > N equivalent)."""

    field: str = Field(
        default="count",
        description="Aggregated field to threshold on.",
    )
    op: ComparisonOperator = Field(default=ComparisonOperator.GT)
    value: int | float = Field(..., description="Threshold value.")

    model_config = {"use_enum_values": True}


class LookupSpec(BaseModel):
    """Threat-intelligence or reference-data lookup/enrichment."""

    lookup_table: str = Field(
        ...,
        description="Name of the lookup / threat-intel table.",
    )
    match_field: str = Field(
        ...,
        description="Canonical field to match against the lookup.",
    )
    output_field: str | None = Field(
        default=None,
        description="Field returned from the lookup (e.g. 'is_malicious').",
    )
    filter_on_match: bool = Field(
        default=True,
        description="If True, only return events that matched the lookup.",
    )


class SequenceStep(BaseModel):
    """One step in a multi-event sequence / correlation rule."""

    event_type: EventType = Field(default=EventType.ANY)
    filter: FilterGroup | None = Field(default=None)
    within: str | None = Field(
        default=None,
        description="Max time between this step and the previous e.g. '5m'.",
        pattern=r"^\d+[smhd]$",
    )

    model_config = {"use_enum_values": True}


# ─────────────────────────────────────────────
# Root IR model
# ─────────────────────────────────────────────

class IRQuery(BaseModel):
    """
    Platform-agnostic Intermediate Representation of a SIEM detection query.

    This is the central data structure of NL-SIEM. The LLM parser agent
    produces one IRQuery per natural language input. Each SIEM translator
    consumes it and emits platform-native syntax.

    Design principles:
    - Every field uses canonical names independent of any SIEM platform.
    - The model captures *intent*, not syntax.
    - Cross-field validators enforce logical consistency.
    - Serialisation via .to_dict() produces clean JSON for storage/logging.
    """

    # ── Identity ──────────────────────────────────────────────────────────
    id: str | None = Field(
        default=None,
        description="Optional identifier (e.g. SIEMBench record ID 'SB-042').",
    )
    nl_query: str | None = Field(
        default=None,
        description="Original natural language query (preserved for traceability).",
    )

    # ── Core semantics ────────────────────────────────────────────────────
    action: ActionType = Field(
        ...,
        description="Primary operation type.",
    )
    event_type: EventType = Field(
        default=EventType.ANY,
        description="Category of log/event source.",
    )

    # ── Filtering ─────────────────────────────────────────────────────────
    filter: FilterGroup | None = Field(
        default=None,
        description="Top-level boolean filter expression.",
    )

    # ── Time ──────────────────────────────────────────────────────────────
    time_window: TimeWindow | None = Field(
        default=None,
        description="Temporal constraint.",
    )

    # ── Aggregation ───────────────────────────────────────────────────────
    aggregation: AggregationSpec | None = Field(
        default=None,
        description="Required when action includes 'aggregate'.",
    )
    threshold: ThresholdCondition | None = Field(
        default=None,
        description="Post-aggregation threshold. Requires aggregation.",
    )

    # ── Sequence correlation ───────────────────────────────────────────────
    sequence: list[SequenceStep] | None = Field(
        default=None,
        description="Ordered event steps for sequence/correlation rules.",
    )

    # ── Lookup / enrichment ───────────────────────────────────────────────
    lookup: LookupSpec | None = Field(
        default=None,
        description="Threat-intel or reference-data lookup spec.",
    )

    # ── Output control ────────────────────────────────────────────────────
    fields: list[str] = Field(
        default_factory=list,
        description="Fields to project in output (SELECT clause equivalent).",
    )
    sort_by: str | None = Field(default=None)
    sort_order: SortOrder = Field(default=SortOrder.DESC)
    limit: int | None = Field(default=None, ge=1)

    # ── MITRE ATT&CK metadata ─────────────────────────────────────────────
    tactic: str | None = Field(
        default=None,
        description="MITRE ATT&CK tactic label e.g. 'lateral_movement'.",
    )
    technique_id: str | None = Field(
        default=None,
        description="MITRE ATT&CK technique ID e.g. 'T1110'.",
    )

    model_config = {"use_enum_values": True}

    # ── Cross-field validation ─────────────────────────────────────────────
    @model_validator(mode="after")
    def check_consistency(self) -> "IRQuery":
        # Aggregation required for aggregate actions
        if self.action in (ActionType.AGGREGATE, ActionType.FILTER_AGGREGATE):
            if self.aggregation is None:
                raise ValueError(
                    f"action='{self.action}' requires an 'aggregation' spec."
                )
        # Threshold requires aggregation
        if self.threshold is not None and self.aggregation is None:
            raise ValueError(
                "'threshold' requires 'aggregation' to be set."
            )
        # Sequence action requires steps
        if self.action == ActionType.SEQUENCE:
            if not self.sequence:
                raise ValueError(
                    "action='sequence' requires at least one step in 'sequence'."
                )
        # Lookup action requires lookup spec
        if self.action == ActionType.LOOKUP and self.lookup is None:
            raise ValueError(
                "action='lookup' requires a 'lookup' spec."
            )
        return self

    # ── Serialisation helpers ─────────────────────────────────────────────
    def to_dict(self) -> dict:
        """Return a JSON-serialisable dict excluding None values."""
        return self.model_dump(exclude_none=True)

    @classmethod
    def from_dict(cls, data: dict) -> "IRQuery":
        """Construct an IRQuery from a raw dict (e.g. parsed LLM output)."""
        return cls.model_validate(data)

    def summary(self) -> str:
        """One-line human-readable summary for logging and debugging."""
        parts = [f"action={self.action}", f"event={self.event_type}"]
        if self.time_window:
            parts.append(f"window={self.time_window.duration}")
        if self.aggregation:
            grp = ",".join(self.aggregation.group_by) or "none"
            parts.append(f"agg={self.aggregation.function}(by=[{grp}])")
        if self.threshold:
            parts.append(
                f"threshold={self.threshold.field}"
                f"{self.threshold.op}"
                f"{self.threshold.value}"
            )
        if self.tactic:
            parts.append(f"tactic={self.tactic}")
        return " | ".join(parts)