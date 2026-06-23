"""
ATT&CK-Extended IR Schema — adds mandatory MITRE ATT&CK binding to the IR.

Rationale
---------
The base IRQuery (src/ir/schema.py) carries `tactic` and `technique_id` as
*optional* fields populated ad hoc, typically by the parser agent guessing
from context. For the ATT&CK coverage claims made in the paper and patent
disclosure (the 62% → 94% pre/post coverage lift metric), tactic/technique
binding must be:

  1. Mandatory, not optional — every IR instance used for coverage
     accounting must carry a resolvable ATT&CK identifier.
  2. Validated against the actual MITRE taxonomy, not just pattern-matched
     against a regex (T\\d{4} matches "T9999", which doesn't exist).
  3. Capable of carrying sub-technique granularity (T1110.001), which the
     base schema's flat `technique_id: str | None` does not model with
     parent/child structure.

AttckIRQuery subclasses IRQuery (Pydantic v2 model inheritance) rather than
replacing it, so every existing translator, validator, and agent that
accepts an `IRQuery` continues to accept an `AttckIRQuery` unchanged
(Liskov substitutability). Code that specifically requires ATT&CK binding
should type-hint against `AttckIRQuery`; code that doesn't care continues
to type-hint against the base `IRQuery`.

Validation against the live taxonomy is performed lazily via
`ATTCKTaxonomyLoader.get_technique()` so this module has no hard
dependency on the STIX bundle being present at import time — only at
validation time, when an actual lookup is attempted.

Place at: src/ir/attck_schema.py

Usage:
    from src.ir.attck_schema import AttckIRQuery

    ir = AttckIRQuery(
        action="filter+aggregate",
        event_type="authentication",
        tactic="credential-access",
        technique="T1110",
        sub_technique="T1110.001",
        filter=...,
    )
"""

from __future__ import annotations

import re
from typing import Optional

from pydantic import Field, field_validator, model_validator

from src.ir.schema import IRQuery
from src.utils.exceptions import IRValidationError
from src.utils.logger import get_logger

log = get_logger(__name__)

# ── ATT&CK identifier format ───────────────────────────────────────────────
# Technique:     T followed by exactly 4 digits          e.g. T1110
# Sub-technique: parent technique + '.' + 3 digits        e.g. T1110.001
_TECHNIQUE_ID_RE     = re.compile(r"^T\d{4}$")
_SUB_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}\.\d{3}$")


class AttckIRQuery(IRQuery):
    """
    Intermediate Representation with mandatory MITRE ATT&CK binding.

    Extends IRQuery with three required fields:
        tactic:        ATT&CK tactic shortname (e.g. "credential-access")
        technique:      ATT&CK technique ID (e.g. "T1110")
        sub_technique: Optional ATT&CK sub-technique ID (e.g. "T1110.001")

    Note on field naming: the base IRQuery already defines an *optional*
    `technique_id` field. AttckIRQuery introduces `technique` as the
    mandatory counterpart rather than overriding `technique_id` in place,
    to avoid silently changing the optionality contract of the base class
    for any code that already constructs a plain `IRQuery` with
    `technique_id` set. `technique` and `technique_id` are kept in sync
    by `_sync_legacy_technique_id` below so downstream code reading either
    field sees a consistent value.
    """

    tactic: str = Field(
        ...,
        description=(
            "MITRE ATT&CK tactic shortname, e.g. 'credential-access', "
            "'lateral-movement'. Must resolve against the loaded taxonomy."
        ),
    )
    technique: str = Field(
        ...,
        description="MITRE ATT&CK technique ID, e.g. 'T1110'.",
    )
    sub_technique: Optional[str] = Field(
        default=None,
        description=(
            "MITRE ATT&CK sub-technique ID, e.g. 'T1110.001'. "
            "Must share the technique prefix of `technique` when present."
        ),
    )

    # Set to False to skip live-taxonomy resolution (e.g. in unit tests
    # that construct synthetic technique IDs not present in any bundle).
    # Format validation (regex shape) always runs regardless of this flag.
    validate_against_taxonomy: bool = Field(
        default=True,
        exclude=True,  # not part of the serialised IR — a validation toggle only
        description="If True, resolve tactic/technique against the loaded ATT&CK taxonomy.",
    )

    # ── Field-level format validation ──────────────────────────────────────

    @field_validator("technique")
    @classmethod
    def _check_technique_format(cls, v: str) -> str:
        v = v.strip().upper()
        if not _TECHNIQUE_ID_RE.match(v):
            raise ValueError(
                f"technique '{v}' does not match ATT&CK technique ID format "
                f"'T####' (e.g. 'T1110')"
            )
        return v

    @field_validator("sub_technique")
    @classmethod
    def _check_sub_technique_format(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip().upper()
        if not _SUB_TECHNIQUE_ID_RE.match(v):
            raise ValueError(
                f"sub_technique '{v}' does not match ATT&CK sub-technique ID "
                f"format 'T####.###' (e.g. 'T1110.001')"
            )
        return v

    @field_validator("tactic")
    @classmethod
    def _normalise_tactic_shortname(cls, v: str) -> str:
        """Normalise to ATT&CK shortname convention: lowercase, hyphenated."""
        return v.strip().lower().replace(" ", "-").replace("_", "-")

    # ── Cross-field validation ──────────────────────────────────────────────

    @model_validator(mode="after")
    def _check_attck_consistency(self) -> "AttckIRQuery":
        # Sub-technique must be a child of the declared technique
        if self.sub_technique is not None:
            parent_prefix = self.sub_technique.split(".")[0]
            if parent_prefix != self.technique:
                raise ValueError(
                    f"sub_technique '{self.sub_technique}' is not a child of "
                    f"technique '{self.technique}' (expected prefix "
                    f"'{self.technique}.', got '{parent_prefix}.')"
                )

        # Resolve against the live taxonomy, if requested and available.
        if self.validate_against_taxonomy:
            self._resolve_against_taxonomy()

        # Keep the legacy optional fields on the base IRQuery in sync, so
        # any code reading `ir.tactic` / `ir.technique_id` on what it
        # believes to be a plain IRQuery still sees correct values.
        self._sync_legacy_fields()

        return self

    def _resolve_against_taxonomy(self) -> None:
        """
        Validate tactic/technique/sub_technique against the loaded MITRE
        ATT&CK taxonomy. Raises IRValidationError if the taxonomy bundle
        is unavailable (fail loudly rather than silently skip — a coverage
        metric computed against unverified technique IDs is not trustworthy)
        unless the caller explicitly set validate_against_taxonomy=False.
        """
        try:
            from src.knowledge_base.mitre.attck_taxonomy_loader import get_taxonomy
        except ImportError as exc:
            raise IRValidationError(
                "ATT&CK taxonomy loader unavailable — cannot validate "
                "technique binding. Set validate_against_taxonomy=False "
                "to bypass (not recommended for coverage-metric IR instances).",
                details={"import_error": str(exc)},
            ) from exc

        taxonomy = get_taxonomy()

        tactic_entry = taxonomy.get_tactic(self.tactic)
        if tactic_entry is None:
            raise IRValidationError(
                f"tactic '{self.tactic}' not found in loaded ATT&CK taxonomy",
                details={"tactic": self.tactic},
            )

        technique_entry = taxonomy.get_technique(self.technique)
        if technique_entry is None:
            raise IRValidationError(
                f"technique '{self.technique}' not found in loaded ATT&CK taxonomy",
                details={"technique": self.technique},
            )

        # Confirm the technique actually belongs to the declared tactic.
        # tactic_names on TechniqueEntry holds shortnames (e.g. "credential-access").
        if tactic_entry.shortname not in technique_entry.tactic_names:
            raise IRValidationError(
                f"technique '{self.technique}' is not associated with tactic "
                f"'{self.tactic}' in the ATT&CK taxonomy "
                f"(technique belongs to: {technique_entry.tactic_names})",
                details={
                    "tactic":              self.tactic,
                    "technique":           self.technique,
                    "technique_tactics":   technique_entry.tactic_names,
                },
            )

        if self.sub_technique is not None:
            sub_entry = taxonomy.get_technique(self.sub_technique)
            if sub_entry is None:
                raise IRValidationError(
                    f"sub_technique '{self.sub_technique}' not found in "
                    f"loaded ATT&CK taxonomy",
                    details={"sub_technique": self.sub_technique},
                )

        log.debug(
            "ATT&CK binding resolved against taxonomy",
            extra={
                "tactic":        self.tactic,
                "technique":     self.technique,
                "sub_technique": self.sub_technique,
            },
        )

    def _sync_legacy_fields(self) -> None:
        """
        Mirror tactic/technique onto the base IRQuery's optional `tactic` /
        `technique_id` fields (already declared on IRQuery) so translators
        and evaluators written against the base schema see consistent data
        without needing to know about AttckIRQuery at all.

        Pydantic model_validator(mode="after") runs after both this
        subclass's and the parent's field assignment, so direct attribute
        assignment here is safe and will not retrigger validation loops.
        """
        # IRQuery.tactic and IRQuery.technique_id are already plain
        # optional str fields — no validator collision since AttckIRQuery
        # defines NEW fields (`technique`, `sub_technique`) rather than
        # overriding the parent's `technique_id`.
        object.__setattr__(self, "technique_id", self.sub_technique or self.technique)

    # ── Convenience accessors ────────────────────────────────────────────────

    @property
    def attck_label(self) -> str:
        """Human-readable ATT&CK binding, e.g. 'credential-access / T1110.001'."""
        tid = self.sub_technique or self.technique
        return f"{self.tactic} / {tid}"

    def to_dict(self) -> dict:
        """
        Serialise including ATT&CK fields, excluding the internal
        validation toggle (already excluded via Field(exclude=True)).
        """
        return self.model_dump(exclude_none=True)

    @classmethod
    def from_ir_query(
        cls,
        base: IRQuery,
        tactic: str,
        technique: str,
        sub_technique: str | None = None,
        validate_against_taxonomy: bool = True,
    ) -> "AttckIRQuery":
        """
        Upgrade a plain IRQuery (e.g. produced by the existing ParserAgent,
        which has no ATT&CK awareness) into an AttckIRQuery by attaching
        a separately-inferred ATT&CK binding.

        This is the integration point used by ATTCKClassifierAgent: the
        base ParserAgent produces the structural IR, the classifier infers
        the ATT&CK binding independently, and this factory combines them.

        Args:
            base:          An already-validated IRQuery instance.
            tactic:        Inferred ATT&CK tactic shortname.
            technique:     Inferred ATT&CK technique ID.
            sub_technique: Optional inferred sub-technique ID.
            validate_against_taxonomy: Forwarded to the new instance.

        Returns:
            A new, independently-validated AttckIRQuery.
        """
        data = base.to_dict()
        data["tactic"]        = tactic
        data["technique"]     = technique
        data["sub_technique"] = sub_technique
        return cls.model_validate({
            **data,
            "validate_against_taxonomy": validate_against_taxonomy,
        })