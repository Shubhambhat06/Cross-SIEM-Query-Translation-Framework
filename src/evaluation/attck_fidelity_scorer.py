"""
ATT&CK Fidelity Scorer — verifies that ATT&CK technique binding is
preserved end-to-end across all five platform translations.

Purpose
-------
AttckIRQuery carries a single, taxonomy-verified tactic/technique binding.
Each of the five SIEM translators (Layer 2) independently renders that one
IR into platform-native syntax — Splunk SPL, QRadar AQL, Elastic EQL/KQL,
Sentinel KQL, and Wazuh XML. Only Wazuh's translator has a native MITRE
annotation slot in its output (`<mitre><id>T1110</id></mitre>`); the other
four platforms have no equivalent inline syntax, so the ATT&CK binding
must instead be tracked as translation *metadata* alongside each generated
query, not embedded inside it.

This module checks that:
  1. Every platform's translation metadata reports the SAME technique ID
     as the source AttckIRQuery (no silent drift across translators).
  2. Where a platform's native syntax DOES support inline ATT&CK
     annotation (currently: Wazuh), the inline annotation matches the
     IR's technique exactly.
  3. The aggregate fidelity score for a batch of translations, suitable
     for a paper table showing "ATT&CK Fidelity %" as a distinct row from
     "Syntactic Validity %" and "Semantic Equivalence" — this is a
     structural-consistency metric, not a syntax or semantics metric, and
     is reported separately for that reason.

This is intentionally a much narrower check than attck_coverage_auditor.py:
coverage asks "does technique T have at least one rule anywhere in the
rule set", fidelity asks "for THIS rule, did the technique binding survive
intact through all five independent translation paths".

Place at: src/evaluation/attck_fidelity_scorer.py

Usage:
    from src.evaluation.attck_fidelity_scorer import ATTCKFidelityScorer

    scorer = ATTCKFidelityScorer()
    report = scorer.score(attck_ir, translations, wazuh_xml=translations["wazuh"])
    print(report.summary())
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from src.ir.attck_schema import AttckIRQuery
from src.utils.logger import get_logger

log = get_logger(__name__)

_PLATFORMS = ("splunk", "qradar", "elastic", "sentinel", "wazuh")

# Platforms whose native output syntax has an inline ATT&CK annotation slot.
# Only Wazuh's XML rule format includes a structural <mitre><id> element;
# the other four carry no equivalent inline construct in the syntax emitted
# by ElasticTranslator/SplunkTranslator/QRadarTranslator/SentinelTranslator.
_INLINE_ANNOTATION_PLATFORMS = ("wazuh",)


@dataclass
class PlatformFidelityCheck:
    """Fidelity check result for a single platform's translation."""

    platform:              str
    metadata_technique:    str | None   # technique ID recorded in translation metadata
    inline_technique:      str | None   # technique ID parsed from the native query text, if applicable
    expected_technique:    str          # technique ID from the source AttckIRQuery
    metadata_matches:      bool
    inline_matches:        bool | None  # None if this platform has no inline annotation slot
    is_consistent:         bool         # overall pass/fail for this platform

    def to_dict(self) -> dict:
        return {
            "platform":           self.platform,
            "metadata_technique": self.metadata_technique,
            "inline_technique":   self.inline_technique,
            "expected_technique": self.expected_technique,
            "metadata_matches":   self.metadata_matches,
            "inline_matches":     self.inline_matches,
            "is_consistent":      self.is_consistent,
        }


@dataclass
class FidelityReport:
    """Full ATT&CK fidelity report for one IR's translation set."""

    nl_query:           str
    expected_tactic:    str
    expected_technique: str
    per_platform:       dict[str, PlatformFidelityCheck]

    @property
    def all_consistent(self) -> bool:
        return all(c.is_consistent for c in self.per_platform.values())

    @property
    def fidelity_score(self) -> float:
        """Fraction of platforms whose binding remained consistent."""
        if not self.per_platform:
            return 0.0
        return sum(1 for c in self.per_platform.values() if c.is_consistent) / len(self.per_platform)

    @property
    def inconsistent_platforms(self) -> list[str]:
        return [p for p, c in self.per_platform.items() if not c.is_consistent]

    def summary(self) -> str:
        lines = [
            f"ATT&CK Fidelity: {self.expected_tactic}/{self.expected_technique} "
            f"| score={self.fidelity_score:.0%} "
            f"({len(self.per_platform) - len(self.inconsistent_platforms)}/{len(self.per_platform)})"
        ]
        for platform, check in self.per_platform.items():
            icon = "✓" if check.is_consistent else "✗"
            lines.append(
                f"  {icon} {platform:<10} metadata={check.metadata_technique} "
                f"inline={check.inline_technique if check.inline_technique is not None else 'n/a'}"
            )
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "nl_query":            self.nl_query,
            "expected_tactic":     self.expected_tactic,
            "expected_technique":  self.expected_technique,
            "fidelity_score":      round(self.fidelity_score, 4),
            "all_consistent":      self.all_consistent,
            "inconsistent_platforms": self.inconsistent_platforms,
            "per_platform": {
                p: c.to_dict() for p, c in self.per_platform.items()
            },
        }


@dataclass
class BatchFidelityMetrics:
    """Aggregate fidelity metrics across a dataset of translation results."""

    total:               int
    fully_consistent:    int
    avg_fidelity_score:  float
    per_platform_consistency_rate: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "total":              self.total,
            "fully_consistent":   self.fully_consistent,
            "avg_fidelity_score": round(self.avg_fidelity_score, 4),
            "per_platform_consistency_rate": {
                k: round(v, 4) for k, v in self.per_platform_consistency_rate.items()
            },
        }


class ATTCKFidelityScorer:
    """
    Verifies that an AttckIRQuery's tactic/technique binding survives
    intact across all five independent SIEM translations.
    """

    # ─────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────

    def score(
        self,
        ir:                AttckIRQuery,
        translation_metadata: dict[str, str],
        native_queries:    dict[str, str] | None = None,
    ) -> FidelityReport:
        """
        Score ATT&CK binding fidelity for one IR's full translation set.

        Args:
            ir: The source AttckIRQuery with verified tactic/technique.
            translation_metadata:
                Dict mapping platform -> technique ID as recorded by
                whatever produced the translation (e.g. the orchestrator
                tagging each output with `ir.technique` at generation
                time). This is the PRIMARY signal — translators carry
                metadata even on platforms with no inline annotation slot.
            native_queries:
                Optional dict mapping platform -> generated query/rule
                text, used to additionally verify the Wazuh inline
                <mitre><id> annotation against the IR. If omitted, only
                metadata consistency is checked.

        Returns:
            FidelityReport with per-platform consistency checks.
        """
        expected = ir.sub_technique or ir.technique
        per_platform: dict[str, PlatformFidelityCheck] = {}

        for platform in _PLATFORMS:
            metadata_technique = translation_metadata.get(platform)
            metadata_matches = (metadata_technique == expected) if metadata_technique else False

            inline_technique = None
            inline_matches: bool | None = None

            if platform in _INLINE_ANNOTATION_PLATFORMS and native_queries:
                query_text = native_queries.get(platform, "")
                inline_technique = self._extract_inline_technique(platform, query_text)
                if inline_technique is not None:
                    inline_matches = (inline_technique == expected)
                else:
                    inline_matches = False   # expected an annotation slot but found none

            # Overall consistency: metadata must match. If the platform has
            # an inline annotation slot AND native_queries were supplied,
            # the inline annotation must ALSO match — a platform that has
            # the capability to carry the annotation but fails to populate
            # it correctly is a genuine fidelity defect, not a non-issue.
            if platform in _INLINE_ANNOTATION_PLATFORMS and native_queries is not None:
                is_consistent = metadata_matches and bool(inline_matches)
            else:
                is_consistent = metadata_matches

            per_platform[platform] = PlatformFidelityCheck(
                platform           = platform,
                metadata_technique = metadata_technique,
                inline_technique   = inline_technique,
                expected_technique = expected,
                metadata_matches   = metadata_matches,
                inline_matches     = inline_matches,
                is_consistent      = is_consistent,
            )

        report = FidelityReport(
            nl_query           = ir.nl_query or "",
            expected_tactic    = ir.tactic,
            expected_technique = expected,
            per_platform       = per_platform,
        )

        if not report.all_consistent:
            log.warning(
                "ATT&CK fidelity inconsistency detected",
                extra={
                    "expected":   expected,
                    "inconsistent_platforms": report.inconsistent_platforms,
                },
            )
        return report

    def score_batch(self, reports: list[FidelityReport]) -> BatchFidelityMetrics:
        """
        Aggregate a list of FidelityReport into dataset-wide metrics.

        Args:
            reports: List of per-query FidelityReport, e.g. one per
                     SIEMBench record.

        Returns:
            BatchFidelityMetrics summarising consistency across the dataset.
        """
        if not reports:
            return BatchFidelityMetrics(total=0, fully_consistent=0, avg_fidelity_score=0.0)

        total            = len(reports)
        fully_consistent = sum(1 for r in reports if r.all_consistent)
        avg_score        = sum(r.fidelity_score for r in reports) / total

        platform_hits: dict[str, int] = {p: 0 for p in _PLATFORMS}
        for r in reports:
            for platform, check in r.per_platform.items():
                if check.is_consistent:
                    platform_hits[platform] += 1

        per_platform_rate = {
            p: (count / total if total else 0.0) for p, count in platform_hits.items()
        }

        return BatchFidelityMetrics(
            total                          = total,
            fully_consistent               = fully_consistent,
            avg_fidelity_score             = avg_score,
            per_platform_consistency_rate  = per_platform_rate,
        )

    # ─────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────

    def _extract_inline_technique(self, platform: str, query_text: str) -> str | None:
        """
        Parse the inline ATT&CK technique annotation out of a platform's
        native query/rule text, if that platform's syntax supports one.

        Currently implemented for:
          wazuh — <mitre><id>T####[.###]</id></mitre> XML element
                  (matches the structure emitted by WazuhTranslator).

        Returns None if the platform has no recognised inline annotation,
        or if parsing failed.
        """
        if not query_text:
            return None

        if platform == "wazuh":
            try:
                root = ET.fromstring(query_text)
                mitre_el = root.find("mitre")
                if mitre_el is None:
                    return None
                id_el = mitre_el.find("id")
                if id_el is None or not id_el.text:
                    return None
                tid = id_el.text.strip().upper()
                if re.match(r"^T\d{4}(\.\d{3})?$", tid):
                    return tid
                log.debug(
                    "Wazuh <mitre><id> content did not match expected "
                    "ATT&CK ID format",
                    extra={"raw_value": id_el.text},
                )
                return None
            except ET.ParseError as exc:
                log.debug(
                    "Could not parse Wazuh XML for inline ATT&CK extraction",
                    extra={"error": str(exc)},
                )
                return None

        # No inline annotation convention defined for this platform.
        return None