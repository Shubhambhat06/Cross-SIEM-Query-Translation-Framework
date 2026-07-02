"""
ATT&CK Coverage Auditor — measures detection-rule coverage of the MITRE
ATT&CK technique space, per SIEM platform.

This module produces the pre/post deployment coverage-lift metric central
to the paper's operational-impact claim (e.g. "62% -> 94% technique
coverage after NL-SIEM deployment"). It is deliberately independent of
the translation pipeline itself: it accepts an arbitrary rule set —
whether hand-authored, NL-SIEM-generated, or a mix — and reports which
ATT&CK techniques have at least one detection rule bound to them, broken
down per platform and in aggregate.

Definitions
-----------
"Coverage" here means *declared binding*, not *empirically verified
detection efficacy*: a rule counts toward coverage of technique T if it
carries an ATT&CK annotation (tactic + technique[.sub_technique]) that
resolves against the loaded taxonomy. This module does not claim the
rule actually fires correctly against an attack matching that technique
— that correctness question is the concern of execution_match.py and
attck_fidelity_scorer.py. Coverage accounting and detection-quality
accounting are kept as separate, independently falsifiable metrics,
which matters both for scientific honesty in the paper and for precision
in describing what the system measures versus what it claims to verify
in a patent disclosure.

Place at: src/evaluation/attck_coverage_auditor.py

Usage:
    from src.evaluation.attck_coverage_auditor import ATTCKCoverageAuditor

    auditor = ATTCKCoverageAuditor()
    pre  = auditor.audit(existing_rule_set,   label="pre_deployment")
    post = auditor.audit(nlsiem_rule_set,     label="post_deployment")
    lift = auditor.compute_lift(pre, post)
    print(lift.summary())
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from src.knowledge_base.mitre.attck_taxonomy_loader import (
    TechniqueEntry,
    get_taxonomy,
)
from src.utils.logger import get_logger

log = get_logger(__name__)

_KNOWN_PLATFORMS = ("splunk", "qradar", "elastic", "sentinel", "wazuh")


# ── Result dataclasses ─────────────────────────────────────────────────────

@dataclass
class TechniqueCoverage:
    """Coverage status of a single ATT&CK technique for one platform."""

    technique_id:  str
    technique_name: str
    tactic_names:  list[str]
    is_covered:    bool
    rule_count:    int = 0
    rule_ids:      list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "technique_id":   self.technique_id,
            "technique_name": self.technique_name,
            "tactic_names":   self.tactic_names,
            "is_covered":     self.is_covered,
            "rule_count":     self.rule_count,
            "rule_ids":       self.rule_ids,
        }


@dataclass
class PlatformCoverageReport:
    """Coverage summary for a single SIEM platform."""

    platform:            str
    total_techniques:     int
    covered_techniques:   int
    coverage_pct:         float
    gaps:                 list[TechniqueCoverage]   # uncovered techniques
    covered:              list[TechniqueCoverage]   # covered techniques

    def to_dict(self) -> dict:
        return {
            "platform":           self.platform,
            "total_techniques":   self.total_techniques,
            "covered_techniques": self.covered_techniques,
            "coverage_pct":       round(self.coverage_pct, 4),
            "gap_count":          len(self.gaps),
            "gaps":               [g.to_dict() for g in self.gaps],
        }


@dataclass
class CoverageAuditResult:
    """Full audit output across all platforms for one rule set."""

    label:               str
    timestamp_unix:      float
    total_rules_audited: int
    per_platform:        dict[str, PlatformCoverageReport]
    aggregate_coverage_pct: float    # union coverage across all platforms
    aggregate_covered_techniques: int
    aggregate_total_techniques:   int

    def to_dict(self) -> dict:
        return {
            "label":                        self.label,
            "timestamp_unix":               self.timestamp_unix,
            "total_rules_audited":          self.total_rules_audited,
            "aggregate_coverage_pct":       round(self.aggregate_coverage_pct, 4),
            "aggregate_covered_techniques": self.aggregate_covered_techniques,
            "aggregate_total_techniques":   self.aggregate_total_techniques,
            "per_platform": {
                p: report.to_dict() for p, report in self.per_platform.items()
            },
        }

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False))
        log.info("Coverage audit saved", extra={"path": str(path), "label": self.label})


@dataclass
class CoverageLiftResult:
    """Pre/post coverage comparison — the headline metric for the paper."""

    pre_label:               str
    post_label:              str
    pre_aggregate_pct:       float
    post_aggregate_pct:      float
    lift_pct_points:         float
    newly_covered_techniques: list[str]    # technique IDs covered post but not pre
    still_uncovered:         list[str]    # technique IDs uncovered in both
    per_platform_lift:       dict[str, float]   # platform -> lift in percentage points

    def summary(self) -> str:
        lines = [
            f"ATT&CK Coverage Lift: {self.pre_label} -> {self.post_label}",
            f"  Aggregate: {self.pre_aggregate_pct:.1%} -> {self.post_aggregate_pct:.1%} "
            f"(+{self.lift_pct_points:.1f} pp)",
            f"  Newly covered techniques: {len(self.newly_covered_techniques)}",
            f"  Still uncovered: {len(self.still_uncovered)}",
        ]
        for platform, lift in self.per_platform_lift.items():
            lines.append(f"  {platform:<10}: +{lift:.1f} pp")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "pre_label":                 self.pre_label,
            "post_label":                self.post_label,
            "pre_aggregate_pct":         round(self.pre_aggregate_pct, 4),
            "post_aggregate_pct":        round(self.post_aggregate_pct, 4),
            "lift_pct_points":           round(self.lift_pct_points, 2),
            "newly_covered_techniques":  self.newly_covered_techniques,
            "still_uncovered":           self.still_uncovered,
            "per_platform_lift":         {k: round(v, 2) for k, v in self.per_platform_lift.items()},
        }


# ── Auditor ─────────────────────────────────────────────────────────────────

class ATTCKCoverageAuditor:
    """
    Computes ATT&CK technique coverage for a rule set, per platform and
    in aggregate, and compares two audits to produce a coverage-lift metric.

    A "rule" for this module's purposes is any dict with at minimum:
        {"platform": "<platform>", "technique": "T####", "id": "<rule_id>"}
    Additional keys are ignored. This intentionally decouples the auditor
    from any particular rule storage format — it accepts plain dicts so it
    can audit hand-authored legacy rule exports as easily as NL-SIEM's own
    AttckIRQuery-derived output.
    """

    def __init__(self) -> None:
        self._taxonomy = get_taxonomy()
        # Only non-sub-technique entries count as the denominator for
        # coverage percentage, matching how MITRE's own coverage heatmaps
        # report technique-level (not sub-technique-level) coverage by
        # default. A rule bound to a sub-technique counts as covering its
        # parent technique as well as the sub-technique itself.
        self._all_techniques: list[TechniqueEntry] = self._taxonomy.all_techniques()

    # ─────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────

    def audit(
        self,
        rules:     list[dict],
        label:     str,
        platforms: tuple[str, ...] = _KNOWN_PLATFORMS,
    ) -> CoverageAuditResult:
        """
        Audit a rule set's ATT&CK technique coverage.

        Args:
            rules:     List of rule dicts, each with at least 'platform'
                       and 'technique' (and optionally 'sub_technique', 'id').
            label:     Identifying label for this audit (e.g. "pre_deployment").
            platforms: Platforms to report on individually (default: all 5).

        Returns:
            CoverageAuditResult with per-platform and aggregate coverage.
        """
        t0 = time.monotonic()

        # Index rules by platform -> set of covered technique IDs -> rule IDs
        platform_technique_rules: dict[str, dict[str, list[str]]] = {
            p: {} for p in platforms
        }
        aggregate_covered: set[str] = set()
        skipped = 0

        for rule in rules:
            platform = str(rule.get("platform", "")).lower().strip()
            technique = str(rule.get("technique") or rule.get("technique_id") or "").upper().strip()
            sub_technique = str(rule.get("sub_technique") or "").upper().strip() or None
            rule_id = str(rule.get("id", rule.get("rule_id", "unknown")))

            if not technique:
                skipped += 1
                continue

            # Verify against the taxonomy — an unresolvable technique ID
            # does not count toward coverage (consistent with the
            # AttckIRQuery validation guarantee upstream).
            entry = self._taxonomy.get_technique(technique)
            if entry is None:
                log.warning(
                    "Skipping rule with unresolvable technique ID",
                    extra={"rule_id": rule_id, "technique": technique},
                )
                skipped += 1
                continue

            # A sub-technique covers both itself and its parent technique.
            covered_ids = {technique}
            if entry.is_subtechnique and entry.parent_id:
                covered_ids.add(entry.parent_id)
            if sub_technique:
                sub_entry = self._taxonomy.get_technique(sub_technique)
                if sub_entry is not None:
                    covered_ids.add(sub_technique)

            aggregate_covered |= covered_ids

            if platform in platform_technique_rules:
                for tid in covered_ids:
                    platform_technique_rules[platform].setdefault(tid, []).append(rule_id)
            else:
                log.debug(
                    "Rule references an unrecognised platform — counted in "
                    "aggregate coverage only",
                    extra={"rule_id": rule_id, "platform": platform},
                )

        # Build per-platform reports
        per_platform: dict[str, PlatformCoverageReport] = {}
        for platform in platforms:
            covered_map = platform_technique_rules[platform]
            per_platform[platform] = self._build_platform_report(platform, covered_map)

        total_techniques = len(self._all_techniques)
        aggregate_covered_count = len(aggregate_covered & {t.technique_id for t in self._all_techniques})
        aggregate_pct = aggregate_covered_count / total_techniques if total_techniques else 0.0

        result = CoverageAuditResult(
            label                          = label,
            timestamp_unix                 = time.time(),
            total_rules_audited            = len(rules) - skipped,
            per_platform                   = per_platform,
            aggregate_coverage_pct         = aggregate_pct,
            aggregate_covered_techniques   = aggregate_covered_count,
            aggregate_total_techniques     = total_techniques,
        )

        elapsed = round(time.monotonic() - t0, 3)
        log.info(
            "Coverage audit complete",
            extra={
                "label":           label,
                "rules_audited":   result.total_rules_audited,
                "skipped":         skipped,
                "aggregate_pct":   f"{aggregate_pct:.1%}",
                "elapsed_s":       elapsed,
            },
        )
        return result

    def compute_lift(
        self,
        pre:  CoverageAuditResult,
        post: CoverageAuditResult,
    ) -> CoverageLiftResult:
        """
        Compare two coverage audits and compute the coverage-lift metric.

        Args:
            pre:  Audit result before NL-SIEM deployment (or any baseline).
            post: Audit result after deployment.

        Returns:
            CoverageLiftResult with aggregate and per-platform lift.
        """
        all_technique_ids = {t.technique_id for t in self._all_techniques}

        pre_covered_ids  = self._covered_ids_from_report(pre)
        post_covered_ids = self._covered_ids_from_report(post)

        newly_covered = sorted(post_covered_ids - pre_covered_ids)
        still_uncovered = sorted(all_technique_ids - pre_covered_ids - post_covered_ids)

        per_platform_lift: dict[str, float] = {}
        for platform in pre.per_platform:
            pre_pct  = pre.per_platform[platform].coverage_pct
            post_pct = post.per_platform.get(platform)
            post_pct_val = post_pct.coverage_pct if post_pct else 0.0
            per_platform_lift[platform] = (post_pct_val - pre_pct) * 100

        lift = CoverageLiftResult(
            pre_label                = pre.label,
            post_label               = post.label,
            pre_aggregate_pct        = pre.aggregate_coverage_pct,
            post_aggregate_pct       = post.aggregate_coverage_pct,
            lift_pct_points          = (post.aggregate_coverage_pct - pre.aggregate_coverage_pct) * 100,
            newly_covered_techniques = newly_covered,
            still_uncovered          = still_uncovered,
            per_platform_lift        = per_platform_lift,
        )

        log.info("Coverage lift computed", extra={"lift_pp": round(lift.lift_pct_points, 2)})
        return lift

    def load_rules_from_jsonl(self, path: str | Path) -> list[dict]:
        """
        Convenience loader for rule sets stored as JSONL, where each line
        is a dict matching the `audit()` rule schema, or an AttckIRQuery
        serialisation (in which case 'technique'/'sub_technique'/'tactic'
        are read directly and 'platform' must be supplied per-line by the
        caller's export step, since a single AttckIRQuery fans out to five
        platform translations).
        """
        path = Path(path)
        rules: list[dict] = []
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    rules.append(json.loads(line))
        log.debug("Loaded rules from JSONL", extra={"path": str(path), "count": len(rules)})
        return rules

    # ─────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────

    def _build_platform_report(
        self,
        platform:    str,
        covered_map: dict[str, list[str]],
    ) -> PlatformCoverageReport:
        """Build a PlatformCoverageReport from a technique_id -> rule_ids map."""
        gaps: list[TechniqueCoverage] = []
        covered: list[TechniqueCoverage] = []

        for entry in self._all_techniques:
            rule_ids = covered_map.get(entry.technique_id, [])
            tc = TechniqueCoverage(
                technique_id   = entry.technique_id,
                technique_name = entry.name,
                tactic_names   = entry.tactic_names,
                is_covered     = len(rule_ids) > 0,
                rule_count     = len(rule_ids),
                rule_ids       = rule_ids,
            )
            (covered if tc.is_covered else gaps).append(tc)

        total   = len(self._all_techniques)
        n_covered = len(covered)

        return PlatformCoverageReport(
            platform            = platform,
            total_techniques     = total,
            covered_techniques   = n_covered,
            coverage_pct         = n_covered / total if total else 0.0,
            gaps                 = gaps,
            covered              = covered,
        )

    @staticmethod
    def _covered_ids_from_report(audit: CoverageAuditResult) -> set[str]:
        """Union of covered technique IDs across all platforms in an audit."""
        covered: set[str] = set()
        for report in audit.per_platform.values():
            covered |= {tc.technique_id for tc in report.covered}
        return covered