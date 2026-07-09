"""
Intermediate Representation (IR) Schema — the core technical contribution of NL-SIEM.

The IR is a platform-agnostic JSON structure that captures detection intent:
field references, logical operators, temporal windows, aggregation functions,
and threshold conditions. Every SIEM translator receives an IRQuery object.

ATT&CK identity (tactic, technique_id, sub_technique_id) is a required
structural component of every IRQuery — not optional metadata. A schema-
invalid IR cannot proceed to translation. This is the primary mechanism
preventing ATT&CK Coverage Drift across platforms.

Pydantic v2 is used for validation, coercion, and serialisation.

Place at: src/ir/schema.py
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Union
from pydantic import BaseModel, Field, model_validator


# ─────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────

class LogicalOperator(str, Enum):
    AND = "and"
    OR  = "or"
    NOT = "not"


class ComparisonOperator(str, Enum):
    EQ       = "eq"           # ==
    NEQ      = "neq"          # !=
    GT       = "gt"           # >
    GTE      = "gte"          # >=
    LT       = "lt"           # <
    LTE      = "lte"          # <=
    IN       = "in"           # field in [list]
    NOT_IN   = "not_in"       # field not in [list]
    CONTAINS = "contains"     # substring match
    REGEX    = "regex"        # regular expression


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
    SEQUENCE         = "sequence"     # multi-event correlation
    LOOKUP           = "lookup"       # threat-intel enrichment


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
    """
    A single field-level filter condition.

    Example:
        FilterCondition(field="event.outcome", op="eq", value="failure")
        FilterCondition(field="source.ip", op="not_in", value=["10.0.0.0/8"])
    """

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
    Supports arbitrary nesting for complex boolean expressions.

    Example:
        FilterGroup(
            operator="and",
            conditions=[
                FilterCondition(field="status", op="eq", value="failed"),
                FilterGroup(
                    operator="or",
                    conditions=[
                        FilterCondition(field="src_ip", op="eq", value="1.2.3.4"),
                        FilterCondition(field="src_ip", op="eq", value="5.6.7.8"),
                    ]
                ),
            ]
        )
    """

    operator: LogicalOperator = Field(
        default=LogicalOperator.AND,
        validate_default=True,
        description="Logical operator joining all conditions in this group.",
    )
    conditions: list[Union[FilterCondition, "FilterGroup"]] = Field(
        default_factory=list,
        description="List of FilterCondition or nested FilterGroup objects.",
    )

    model_config = {"use_enum_values": True}


class TimeWindow(BaseModel):
    """
    Temporal constraint for the detection query.

    Duration uses a compact string format: <integer><unit>
    Units: s (seconds), m (minutes), h (hours), d (days)
    Examples: "24h", "10m", "7d", "30s"

    Translators call the platform-specific property rather than
    implementing unit conversion themselves:
        to_seconds  → int          (Wazuh <timeframe>)
        to_splunk   → "-24h"       (Splunk earliest= modifier)
        to_kql      → "ago(24h)"   (Sentinel / KQL)
        to_esql     → "24 hours"   (Elastic ES|QL)
        to_aql      → "LAST 24 HOURS" (QRadar AQL)
    """

    duration: str = Field(
        ...,
        description="Duration string e.g. '24h', '10m', '7d', '30s'.",
        pattern=r"^\d+[smhd]$",
    )
    field: str = Field(
        default="@timestamp",
        description=(
            "Timestamp field name in canonical schema. "
            "Defaults to '@timestamp' (ECS-aligned). "
            "Translators map this to platform-specific field names."
        ),
    )

    @property
    def to_seconds(self) -> int:
        """Convert duration string to total seconds (Wazuh <timeframe>)."""
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
    def to_esql(self) -> str:
        """
        Return ES|QL NOW() - N <unit> expression.
        ES|QL uses spelled-out unit names, not single-char abbreviations.
        """
        unit_map = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
        unit  = self.duration[-1]
        value = self.duration[:-1]
        return f"NOW() - {value} {unit_map[unit]}"

    @property
    def to_aql(self) -> str:
        """Return QRadar LAST N HOURS/MINUTES/DAYS clause."""
        unit_map = {"s": "SECONDS", "m": "MINUTES", "h": "HOURS", "d": "DAYS"}
        unit  = self.duration[-1]
        value = self.duration[:-1]
        return f"LAST {value} {unit_map[unit]}"


class AggregationSpec(BaseModel):
    """
    Describes an aggregation operation.

    Maps to:
        Splunk  → stats <function>(<field>) by <group_by>
        ES|QL   → STATS <alias> = <FUNCTION>(<field>) BY <group_by>
        KQL     → summarize <alias> = <function>(<field>) by <group_by>
        AQL     → SELECT <field>, COUNT(*) ... GROUP BY <group_by>
        Wazuh   → <frequency> + <same_source_ip/> declarative attributes
    """

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
        description="Canonical field names to group results by.",
    )
    alias: str | None = Field(
        default=None,
        description="Output alias for the aggregated value (e.g. 'failed_count').",
    )

    model_config = {"use_enum_values": True}

    @property
    def output_field(self) -> str:
        """Return alias if set, otherwise derive a sensible name from function+field."""
        if self.alias:
            return self.alias
        if self.field:
            return f"{self.function}_{self.field}"
        return self.function


class ThresholdCondition(BaseModel):
    """
    Post-aggregation threshold filter.

    Maps to:
        Splunk  → | where <field> <op> <value>
        ES|QL   → | WHERE <field> <op> <value>
        KQL     → | where <field> <op> <value>
        AQL     → HAVING <field> <op> <value>
        Wazuh   → <frequency><value></frequency>
    """

    field: str = Field(
        default="count",
        description="Aggregated field to threshold on.",
    )
    op: ComparisonOperator = Field(
        default=ComparisonOperator.GT,
        validate_default=True,
        description="Comparison operator for the threshold check.",
    )
    value: int | float = Field(
        ...,
        description="Threshold value.",
    )

    model_config = {"use_enum_values": True}


class LookupSpec(BaseModel):
    """
    Threat-intelligence or reference-data lookup / enrichment.

    Maps to:
        Splunk   → | lookup <lookup_table> <match_field> OUTPUT <output_field>
        ES|QL    → | ENRICH <lookup_table> ON <match_field>
        KQL      → | lookup kind=leftouter <lookup_table> on <match_field>
        AQL      → JOIN or REFERENCE SET depending on QRadar config
        Wazuh    → CDB list lookup via <list> element in rule
    """

    lookup_table: str = Field(
        ...,
        description="Name of the lookup / threat-intel table or CDB list.",
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
    """
    One step in a multi-event sequence / correlation rule.

    Used when action=sequence. Steps are ordered; each step optionally
    specifies a max time gap from the previous step via 'within'.

    Note: ES|QL has no native sequence operator. The esql_converter raises
    ESQLConversionError on IRQuery instances with action=sequence rather
    than emitting an approximate translation.
    """

    event_type: EventType = Field(
        default=EventType.ANY,
        validate_default=True,
        description="Event category this step matches against.",
    )
    filter: FilterGroup | None = Field(
        default=None,
        description="Filter conditions for this step.",
    )
    within: str | None = Field(
        default=None,
        description=(
            "Max time between this step and the previous step e.g. '5m'. "
            "Measures inter-event span, not distance from query time. "
            "Maps to EQL 'within', Splunk 'maxspan', Wazuh 'timeframe'."
        ),
        pattern=r"^\d+[smhd]$",
    )
    correlation_key: list[str] = Field(
        default_factory=list,
        description=(
            "Fields that must share values across steps (join key). "
            "e.g. ['process.entity_id'] to correlate events from the same process."
        ),
    )

    model_config = {"use_enum_values": True}


# ─────────────────────────────────────────────
# Root IR model
# ─────────────────────────────────────────────
class ATTCKMapping(BaseModel):
    tactic: str
    technique_id: str
    sub_technique_id: str | None = None
    confidence: float = 0.0
    rationale: str | None = None

    @property
    def label(self) -> str:
        return self.sub_technique_id or self.technique_id


class IRQuery(BaseModel):
    """
    Platform-agnostic Intermediate Representation of a SIEM detection query.

    This is the central data structure of NL-SIEM. The LLM parser agent
    produces one IRQuery per natural language input. Each SIEM translator
    consumes it and emits platform-native syntax.

    ATT&CK identity (tactic, technique_id, sub_technique_id) is REQUIRED.
    A schema-invalid IR — one missing tactic or technique_id — cannot be
    constructed and cannot proceed to translation. This structural requirement
    is the mechanism by which ATT&CK Coverage Drift is prevented: every
    downstream translation inherits the same ATT&CK-bound contract.

    Design principles:
        - ATT&CK identity is a required structural field, not optional metadata.
        - Every field uses canonical names independent of any SIEM platform.
        - The model captures *intent*, not syntax.
        - Cross-field validators enforce logical consistency at construction time.
        - TimeWindow exposes platform-specific properties so translators never
          implement unit conversion themselves.
        - Serialisation via .to_dict() produces clean JSON for storage/logging.

    Translator provenance injection:
        Use ir.attck_label for the most specific available ATT&CK identifier.
        ES|QL  → | EVAL mitre_technique = "<ir.attck_label>"
        Wazuh  → <mitre><id>T1110.001</id></mitre>
        Splunk → [mitre_attack] tag field in saved search metadata
    """

    # ── Identity ──────────────────────────────────────────────────────────
    id: str | None = Field(
        default=None,
        description="Optional record identifier (e.g. SIEMBench ID 'SB-042').",
    )
    nl_query: str | None = Field(
        default=None,
        description="Original natural language query (preserved for traceability).",
    )

    # ── ATT&CK identity (required — schema-invalid if absent) ─────────────
    tactic: str = Field(
        ...,
        description=(
            "MITRE ATT&CK tactic shortname e.g. 'credential-access'. "
            "Required. Pipeline halts if absent. "
            "Must be verified against live ATT&CK taxonomy before IR construction."
        ),
    )
    technique_id: str = Field(
        ...,
        description=(
            "MITRE ATT&CK technique ID e.g. 'T1110'. "
            "Required. Pipeline halts if absent."
        ),
        pattern=r"^T\d{4}$",
    )
    sub_technique_id: str | None = Field(
        default=None,
        description=(
            "MITRE ATT&CK sub-technique ID e.g. 'T1110.001'. "
            "Optional. When present, must be a verified child of technique_id."
        ),
        pattern=r"^T\d{4}\.\d{3}$",
    )
    attck_mappings: list[ATTCKMapping] = Field(
        default_factory=list,
        description=(
            "All ATT&CK mappings associated with this detection. "
            "The first entry corresponds to the primary "
            "tactic/technique_id/sub_technique_id fields."
        ),
    )

    # ── Core semantics ────────────────────────────────────────────────────
    action: ActionType = Field(
        ...,
        description="Primary detection operation type.",
    )
    event_type: EventType = Field(
        default=EventType.ANY,
        validate_default=True,
        description="Telemetry category (log source type).",
    )

    # ── Filtering ─────────────────────────────────────────────────────────
    filter: FilterGroup | None = Field(
        default=None,
        description=(
            "Top-level boolean filter expression. "
            "Supports arbitrary nesting of FilterGroup and FilterCondition."
        ),
    )

    # ── Temporal ──────────────────────────────────────────────────────────
    time_window: TimeWindow | None = Field(
        default=None,
        description=(
            "Temporal constraint in canonical form. "
            "Translators call to_seconds / to_splunk / to_kql / to_esql / to_aql "
            "rather than implementing unit conversion themselves."
        ),
    )

    # ── Aggregation ───────────────────────────────────────────────────────
    aggregation: AggregationSpec | None = Field(
        default=None,
        description="Required when action is 'aggregate' or 'filter+aggregate'.",
    )
    threshold: ThresholdCondition | None = Field(
        default=None,
        description=(
            "Post-aggregation threshold condition (HAVING / where count > N). "
            "Requires aggregation to be set."
        ),
    )

    # ── Sequence correlation ───────────────────────────────────────────────
    sequence: list[SequenceStep] | None = Field(
        default=None,
        description=(
            "Ordered event steps for sequence / correlation rules. "
            "Required when action='sequence'. "
            "Note: ES|QL has no native sequence operator — "
            "esql_converter raises ESQLConversionError on sequence IRQuery "
            "instances rather than emitting an approximate translation."
        ),
    )

    # ── Lookup / enrichment ───────────────────────────────────────────────
    lookup: LookupSpec | None = Field(
        default=None,
        description=(
            "Threat-intel or reference-data lookup spec. "
            "Required when action='lookup'."
        ),
    )

    # ── Output control ────────────────────────────────────────────────────
    fields: list[str] = Field(
        default_factory=list,
        description="Canonical fields to project in output (SELECT clause equivalent).",
    )
    sort_by: str | None = Field(
        default=None,
        description="Canonical field to sort results by.",
    )
    sort_order: SortOrder = Field(
        default=SortOrder.DESC,
        validate_default=True,
        description="Sort direction.",
    )
    limit: int | None = Field(
        default=None,
        ge=1,
        description="Maximum number of results to return.",
    )

    model_config = {"use_enum_values": True}

    # ── Cross-field validation ─────────────────────────────────────────────
    @model_validator(mode="after")
    def check_consistency(self) -> "IRQuery":
        """
        Enforce logical consistency across fields.

        Checks (in order):
            1. ATT&CK tactic is non-empty.
            2. ATT&CK technique_id is non-empty.
            3. sub_technique_id is a child of technique_id when present.
            4. Aggregation spec present for aggregate actions.
            5. Threshold only set when aggregation is set.
            6. Sequence steps present for sequence action.
            7. Lookup spec present for lookup action.
        """
        # ── ATT&CK identity ───────────────────────────────────────────────
        if not self.tactic or not self.tactic.strip():
            raise ValueError(
                "'tactic' is required and cannot be empty. "
                "Pipeline cannot proceed without a valid ATT&CK tactic. "
                "Use ATTCKClassifierAgent to resolve the tactic before "
                "constructing an IRQuery."
            )
        if not self.technique_id or not self.technique_id.strip():
            raise ValueError(
                "'technique_id' is required and cannot be empty. "
                "Pipeline cannot proceed without a valid ATT&CK technique. "
                "Use ATTCKClassifierAgent to resolve the technique before "
                "constructing an IRQuery."
            )
        if self.sub_technique_id is not None:
            parent = self.sub_technique_id.split(".")[0]
            if parent != self.technique_id:
                raise ValueError(
                    f"sub_technique_id '{self.sub_technique_id}' is not a child "
                    f"of technique_id '{self.technique_id}'. "
                    f"Expected parent '{parent}' to match technique_id."
                )

        # ── Aggregation ───────────────────────────────────────────────────
        if self.action in (ActionType.AGGREGATE, ActionType.FILTER_AGGREGATE):
            if self.aggregation is None:
                raise ValueError(
                    f"action='{self.action}' requires an 'aggregation' spec."
                )
        if self.threshold is not None and self.aggregation is None:
            raise ValueError(
                "'threshold' requires 'aggregation' to be set."
            )

        # ── Sequence ──────────────────────────────────────────────────────
        if self.action == ActionType.SEQUENCE:
            if not self.sequence:
                raise ValueError(
                    "action='sequence' requires at least one step in 'sequence'."
                )

        # ── Lookup ────────────────────────────────────────────────────────
        if self.action == ActionType.LOOKUP and self.lookup is None:
            raise ValueError(
                "action='lookup' requires a 'lookup' spec."
            )

        return self

    # ── ATT&CK provenance helpers ─────────────────────────────────────────
    @property
    def attck_label(self) -> str:
        """Most specific primary ATT&CK identifier."""
        return self.sub_technique_id or self.technique_id

    @property
    def attck_labels(self) -> list[str]:
        labels = [self.attck_label]

        for m in self.attck_mappings:
            label = m.label
            if label and label not in labels:
                labels.append(label)

        return labels

    @property
    def attck_full(self) -> dict[str, Any]:
        """
        Full ATT&CK binding as a dict.
        Useful for logging, audit trails, and coverage auditor calls.

        Returns:
            {
                "tactic":         "credential-access",
                "technique_id":   "T1110",
                "sub_technique_id": "T1110.001"   # or None
            }
        """
        return {
            "tactic": self.tactic,
            "technique_id": self.technique_id,
            "sub_technique_id": self.sub_technique_id,
            "all_mappings": [
                m.model_dump()
                for m in self.attck_mappings
            ],
        }

    # ── Serialisation helpers ─────────────────────────────────────────────
    def to_dict(self) -> dict:
        """
        Return a JSON-serialisable dict excluding None values.
        ATT&CK fields always present (required).
        """
        return self.model_dump(exclude_none=True)

    @classmethod
    def from_dict(cls, data: dict) -> "IRQuery":
        """Construct an IRQuery from a raw dict (e.g. parsed LLM output)."""
        return cls.model_validate(data)

    def summary(self) -> str:
        """
        One-line human-readable summary for logging and debugging.
        ATT&CK identity always shown first (required fields).
        """
        attck = self.attck_label
        parts = [
            f"attck={self.tactic}/{attck}",
            f"action={self.action}",
            f"event={self.event_type}",
        ]
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
        if self.sequence:
            parts.append(f"sequence_steps={len(self.sequence)}")
        if self.lookup:
            parts.append(f"lookup={self.lookup.lookup_table}")
        return " | ".join(parts)

    def __repr__(self) -> str:
        return f"IRQuery({self.summary()})"