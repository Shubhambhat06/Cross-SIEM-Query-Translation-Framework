"""
Error Analyzer — classifies and aggregates translation failure modes.

Consumes SyntaxValidationResult + SemanticScore + ExecutionMatchResult to
produce a structured failure taxonomy per query, per platform, and across
the full SIEMBench dataset.

Maps to Table 3 (Error Analysis) in the paper.

Error taxonomy (6 top-level categories, 18 leaf types):
  SYNTAX_ERROR      — the query cannot be parsed / executed
  FIELD_ERROR       — wrong field names or missing required fields
  OPERATOR_ERROR    — wrong operator / function for the platform
  LOGIC_ERROR       — correct syntax but wrong logical expression
  TEMPORAL_ERROR    — missing or incorrect time constraints
  PLATFORM_SPECIFIC — valid syntax but wrong idiom / cross-platform leak

Place at: src/evaluation/error_analyzer.py
"""

from __future__ import annotations

from platform import platform
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Literal

from src.utils.logger import get_logger

log = get_logger(__name__)

# ── Error taxonomy ─────────────────────────────────────────────────────────────

ErrorCategory = Literal[
    "SYNTAX_ERROR", "FIELD_ERROR", "OPERATOR_ERROR",
    "LOGIC_ERROR", "TEMPORAL_ERROR", "PLATFORM_SPECIFIC", "NO_ERROR",
]
ErrorLeaf = Literal[
    "empty_query", "malformed_structure", "invalid_xml", "unknown_command",
    "wrong_field_name", "missing_required_field", "field_type_mismatch",
    "wrong_aggregate", "wrong_filter_operator", "missing_pipe",
    "wrong_threshold", "inverted_condition", "missing_condition",
    "missing_time_range", "wrong_time_syntax",
    "wrong_table_name", "wrong_platform_idiom", "cross_platform_leak",
    "none",
]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]

_SEVERITY_MAP: dict[str, Severity] = {
    "empty_query":            "CRITICAL",
    "invalid_xml":            "CRITICAL",
    "malformed_structure":    "CRITICAL",
    "unknown_command":        "HIGH",
    "missing_required_field": "HIGH",
    "wrong_field_name":       "HIGH",
    "wrong_aggregate":        "HIGH",
    "missing_pipe":           "HIGH",
    "wrong_threshold":        "MEDIUM",
    "inverted_condition":     "MEDIUM",
    "missing_condition":      "MEDIUM",
    "field_type_mismatch":    "MEDIUM",
    "wrong_filter_operator":  "MEDIUM",
    "wrong_table_name":       "MEDIUM",
    "cross_platform_leak":    "MEDIUM",
    "missing_time_range":     "LOW",
    "wrong_time_syntax":      "LOW",
    "wrong_platform_idiom":   "LOW",
    "none":                   "NONE",
}

# Cross-platform token leakage patterns per target platform
_CROSS_PLATFORM_PATTERNS: dict[str, list[str]] = {
    "splunk":   [r"\bSELECT\b", r"\bFROM\s+EVENTS\b", r"\|\s*where\s+event\.category",
                 r"<rule\b",    r"\bTimeGenerated\b"],
    "qradar":   [r"\bindex=",   r"\|\s*stats\b",     r"event\.category\s*:",
                 r"<rule\b",    r"\bTimeGenerated\b"],
    "elastic":  [r"\bindex=",   r"\|\s*stats\b",     r"\bSELECT\b",
                 r"<rule\b",    r"\bTimeGenerated\b"],
    "sentinel": [r"\bindex=",   r"\|\s*stats\b",     r"\bSELECT\b",
                 r"<rule\b",    r"event\.category\s*:"],
    "wazuh":    [r"\bindex=",   r"\|\s*stats\b",     r"\bSELECT\b",
                 r"event\.category\s*:",              r"\bTimeGenerated\b"],
}


# ── Result dataclasses ─────────────────────────────────────────────────────────

@dataclass
class ErrorReport:
    """Structured error classification for one hypothesis–reference pair."""

    platform:       str
    error_category: ErrorCategory
    error_leaf:     ErrorLeaf
    severity:       Severity
    description:    str
    hypothesis:     str       = ""
    reference:      str       = ""
    field_errors:   list[str] = field(default_factory=list)
    suggestions:    list[str] = field(default_factory=list)

    @property
    def is_error(self) -> bool:
        return self.error_category != "NO_ERROR"

    def to_dict(self) -> dict:
        return {
            "platform":       self.platform,
            "error_category": self.error_category,
            "error_leaf":     self.error_leaf,
            "severity":       self.severity,
            "description":    self.description,
            "field_errors":   self.field_errors,
            "suggestions":    self.suggestions,
        }


@dataclass
class ErrorDistribution:
    """Aggregated error distribution across a dataset for one platform."""

    platform:            str
    total:               int
    error_count:         int
    error_rate:          float
    category_counts:     dict[str, int]        = field(default_factory=dict)
    leaf_counts:         dict[str, int]        = field(default_factory=dict)
    severity_counts:     dict[str, int]        = field(default_factory=dict)
    most_common_errors:  list[tuple[str, int]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "platform":           self.platform,
            "total":              self.total,
            "error_count":        self.error_count,
            "error_rate":         round(self.error_rate, 4),
            "category_counts":    self.category_counts,
            "leaf_counts":        self.leaf_counts,
            "severity_counts":    self.severity_counts,
            "most_common_errors": self.most_common_errors,
        }

    def to_latex_row(self) -> str:
        """Single LaTeX table row for paper Table 3."""
        cats = self.category_counts
        top  = self.most_common_errors[0][0] if self.most_common_errors else "none"
        return (
            f"{self.platform.capitalize()} & "
            f"{self.error_rate * 100:.1f}\\% & "
            f"{cats.get('SYNTAX_ERROR', 0)} & "
            f"{cats.get('FIELD_ERROR', 0)} & "
            f"{cats.get('OPERATOR_ERROR', 0)} & "
            f"{cats.get('LOGIC_ERROR', 0)} & "
            f"{cats.get('TEMPORAL_ERROR', 0)} & "
            f"{cats.get('PLATFORM_SPECIFIC', 0)} & "
            f"\\texttt{{{top}}} \\\\"
        )


# ── Error Analyzer ─────────────────────────────────────────────────────────────

class ErrorAnalyzer:
    """
    Classifies translation errors across all SIEM platforms.

    Combines syntax validation, semantic scoring, and execution match signals
    to produce a structured error taxonomy suitable for paper Table 3.

    Classification priority (earlier takes precedence):
        1. Syntax errors    (fatal — query unparseable)
        2. Cross-platform leakage
        3. Field errors     (field_f1 below threshold)
        4. Temporal errors  (missing time constraint)
        5. Logic errors     (execution mismatch or low semantic score)
        6. NO_ERROR
    """

    _SEMANTIC_THRESHOLD = 0.50
    _FIELD_F1_THRESHOLD = 0.50

    # ─────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────

    def analyze(
        self,
        platform:         str,
        hypothesis:       str,
        reference:        str,
        syntax_result=    None,
        semantic_score=   None,
        execution_result= None,
    ) -> ErrorReport:
        """
        Classify errors for one hypothesis–reference pair.

        Args:
            platform:         SIEM platform name.
            hypothesis:       Generated query string.
            reference:        Ground-truth query string.
            syntax_result:    SyntaxValidationResult (optional).
            semantic_score:   SemanticScore (optional).
            execution_result: ExecutionMatchResult (optional).

        Returns:
            ErrorReport with category, leaf, severity, and actionable suggestions.
        """
        platform = platform.lower().strip()

        # 1. Syntax errors take absolute priority
        if syntax_result is not None and not syntax_result.is_valid:
            return self._from_syntax(platform, hypothesis, reference, syntax_result)

        # 2. Cross-platform leakage
        leak = self._detect_cross_platform_leak(hypothesis, platform)
        if leak:
            return ErrorReport(
                platform        = platform,
                error_category  = "PLATFORM_SPECIFIC",
                error_leaf      = "cross_platform_leak",
                severity        = _SEVERITY_MAP["cross_platform_leak"],
                description     = f"Hypothesis contains syntax from another platform: '{leak}'",
                hypothesis      = hypothesis,
                reference       = reference,
                suggestions     = [f"Remove '{leak}' — it is not valid {platform.upper()} syntax"],
            )

        # 3. Field errors
        if semantic_score is not None and semantic_score.field_f1 < self._FIELD_F1_THRESHOLD:
            return self._from_field_mismatch(platform, hypothesis, reference, semantic_score)

        if (
        syntax_result is not None
        and syntax_result.is_valid
        and semantic_score is not None
        and semantic_score.semantic_score >= 0.9
        ):
            return ErrorReport(
                platform=platform,
                error_category="NO_ERROR",
                error_leaf="none",
                severity="NONE",
                description="No errors detected",
                hypothesis=hypothesis,
                reference=reference,
            )
        # 4. Temporal errors
        temporal = self._detect_temporal_error(hypothesis, platform)
        if temporal:
            return ErrorReport(
                platform        = platform,
                error_category  = "TEMPORAL_ERROR",
                error_leaf      = temporal,
                severity        = _SEVERITY_MAP[temporal],
                description     = self._temporal_description(temporal, platform),
                hypothesis      = hypothesis,
                reference       = reference,
                suggestions     = self._temporal_suggestions(platform),
            )

        # 5. Logic errors (execution mismatch despite valid syntax + fields)
        if execution_result is not None and not execution_result.any_match:
            return self._from_execution_mismatch(platform, hypothesis, reference, execution_result)

        # 6. Low semantic score without a specific field/syntax error → logic error
        if semantic_score is not None and semantic_score.semantic_score < self._SEMANTIC_THRESHOLD:
            return ErrorReport(
                platform        = platform,
                error_category  = "LOGIC_ERROR",
                error_leaf      = "missing_condition",
                severity        = _SEVERITY_MAP["missing_condition"],
                description     = (
                    f"Semantic score {semantic_score.semantic_score:.2f} below threshold "
                    f"{self._SEMANTIC_THRESHOLD} — hypothesis may be missing conditions or thresholds"
                ),
                hypothesis      = hypothesis,
                reference       = reference,
                suggestions     = [
                    "Compare filter conditions and threshold values with the reference",
                    "Check that aggregation field names match the reference exactly",
                ],
            )

        return ErrorReport(
            platform       = platform,
            error_category = "NO_ERROR",
            error_leaf     = "none",
            severity       = "NONE",
            description    = "No errors detected",
            hypothesis     = hypothesis,
            reference      = reference,
        )

    def analyze_batch(
        self,
        platform:          str,
        hypotheses:        list[str],
        references:        list[str],
        syntax_results:    list | None = None,
        semantic_scores:   list | None = None,
        execution_results: list | None = None,
    ) -> list[ErrorReport]:
        """
        Analyze a batch of hypothesis–reference pairs for one platform.

        Args:
            platform:          SIEM platform name.
            hypotheses:        List of generated queries.
            references:        List of ground-truth queries (must match length).
            syntax_results:    Aligned SyntaxValidationResults (optional).
            semantic_scores:   Aligned SemanticScores (optional).
            execution_results: Aligned ExecutionMatchResults (optional).

        Returns:
            List of ErrorReport, one per pair.
        """
        n = len(hypotheses)
        return [
            self.analyze(
                platform         = platform,
                hypothesis       = hypotheses[i],
                reference        = references[i] if i < len(references) else "",
                syntax_result    = syntax_results[i]    if syntax_results    and i < len(syntax_results)    else None,
                semantic_score   = semantic_scores[i]   if semantic_scores   and i < len(semantic_scores)   else None,
                execution_result = execution_results[i] if execution_results and i < len(execution_results) else None,
            )
            for i in range(n)
        ]

    def analyze_dataset(
        self,
        results:       list[dict],
        benchmark:     list[dict],
        syntax_all:    dict[str, list] | None = None,
        semantic_all:  dict[str, list] | None = None,
        execution_all: dict[str, list] | None = None,
    ) -> dict[str, list[ErrorReport]]:
        """
        Analyze all records in a full SIEMBench dataset.

        Uses id-based alignment for result↔benchmark matching, and maintains
        a per-platform counter for auxiliary result lists so indices stay in sync.

        Args:
            results:       Generated result dicts (must have 'translations').
            benchmark:     SIEMBench ground-truth records.
            syntax_all:    platform → list[SyntaxValidationResult] (optional).
            semantic_all:  platform → list[SemanticScore] (optional).
            execution_all: platform → list[ExecutionMatchResult] (optional).

        Returns:
            platform → list[ErrorReport].
        """
        platforms    = ("splunk", "qradar", "elastic", "sentinel", "wazuh")
        all_reports: dict[str, list[ErrorReport]] = {p: [] for p in platforms}
        # Track how many records we have consumed per platform for aux lists
        plat_idx:    dict[str, int] = {p: 0 for p in platforms}

        bench_by_id: dict[str, dict] = {
            (rec.get("id") or rec.get("nl_query", "")[:40]): rec
            for rec in benchmark
        }

        for result in results:
            rid       = result.get("id") or result.get("nl_query", "")[:40]
            bench_rec = bench_by_id.get(rid)
            if bench_rec is None:
                continue

            ground_truth = bench_rec.get("ground_truth") or bench_rec.get("translations", {})
            translations = result.get("translations", {})

            for platform in platforms:
                hyp = translations.get(platform, "")
                ref = ground_truth.get(platform, "")
                if not ref:
                    continue

                idx  = plat_idx[platform]
                def _get(lst_dict, p, i):
                    lst = (lst_dict or {}).get(p, [])
                    return lst[i] if i < len(lst) else None

                report = self.analyze(
                    platform         = platform,
                    hypothesis       = hyp,
                    reference        = ref,
                    syntax_result    = _get(syntax_all,    platform, idx),
                    semantic_score   = _get(semantic_all,  platform, idx),
                    execution_result = _get(execution_all, platform, idx),
                )
                all_reports[platform].append(report)
                plat_idx[platform] += 1

        return all_reports

    def compute_distribution(
        self,
        reports:  list[ErrorReport],
        platform: str = "",
    ) -> ErrorDistribution:
        """
        Aggregate error reports into distribution statistics for Table 3.

        Args:
            reports:  List of ErrorReport for one platform.
            platform: Platform label (inferred from reports[0] if omitted).

        Returns:
            ErrorDistribution with counts and most-common error list.
        """
        if not reports:
            return ErrorDistribution(platform=platform, total=0, error_count=0, error_rate=0.0)

        total       = len(reports)
        error_count = sum(1 for r in reports if r.is_error)

        cat_counts  = Counter(r.error_category for r in reports if r.is_error)
        leaf_counts = Counter(r.error_leaf     for r in reports if r.is_error)
        sev_counts  = Counter(r.severity       for r in reports if r.is_error)

        return ErrorDistribution(
            platform           = platform or reports[0].platform,
            total              = total,
            error_count        = error_count,
            error_rate         = error_count / total,
            category_counts    = dict(cat_counts),
            leaf_counts        = dict(leaf_counts),
            severity_counts    = dict(sev_counts),
            most_common_errors = leaf_counts.most_common(5),
        )

    def compute_all_distributions(
        self,
        all_reports: dict[str, list[ErrorReport]],
    ) -> dict[str, ErrorDistribution]:
        """Compute distributions for all platforms at once."""
        return {
            platform: self.compute_distribution(reports, platform=platform)
            for platform, reports in all_reports.items()
        }

    # ─────────────────────────────────────────────
    # Internal classifiers
    # ─────────────────────────────────────────────

    def _from_syntax(
        self, platform: str, hypothesis: str, reference: str, syntax_result
    ) -> ErrorReport:
        """Map SyntaxValidationResult.error_type to ErrorReport."""
        mapping: dict[str, tuple[str, str]] = {
            "empty_query":       ("SYNTAX_ERROR",   "empty_query"),
            "missing_keyword":   ("SYNTAX_ERROR",   "malformed_structure"),
            "malformed_syntax":  ("SYNTAX_ERROR",   "malformed_structure"),
            "invalid_xml":       ("SYNTAX_ERROR",   "invalid_xml"),
            "missing_aggregate": ("OPERATOR_ERROR", "wrong_aggregate"),
            "unknown_command":   ("SYNTAX_ERROR",   "unknown_command"),
            "field_error":       ("FIELD_ERROR",    "wrong_field_name"),
            "time_syntax":       ("TEMPORAL_ERROR", "wrong_time_syntax"),
        }
        etype              = getattr(syntax_result, "error_type", "none") or "none"
        category, leaf     = mapping.get(etype, ("SYNTAX_ERROR", "malformed_structure"))
        severity: Severity = _SEVERITY_MAP.get(leaf, "HIGH")

        return ErrorReport(
            platform       = platform,
            error_category = category,
            error_leaf     = leaf,
            severity       = severity,
            description    = getattr(syntax_result, "error_detail", None) or f"Syntax error: {etype}",
            hypothesis     = hypothesis,
            reference      = reference,
            suggestions    = self._syntax_suggestions(platform, etype),
        )

    def _from_field_mismatch(
        self, platform: str, hypothesis: str, reference: str, semantic_score
    ) -> ErrorReport:
        """Build ErrorReport from SemanticScore field analysis."""
        # Use richer diagnostics if available (from optimised semantic_scorer)
        missing = getattr(semantic_score, "missing_fields", [])
        extra   = getattr(semantic_score, "extra_fields",   [])

        # Fallback: compute from raw field lists
        if not missing and not extra:
            hyp_set = set(getattr(semantic_score, "hypothesis_fields", []))
            ref_set = set(getattr(semantic_score, "reference_fields",  []))
            missing = sorted(ref_set - hyp_set)
            extra   = sorted(hyp_set - ref_set)

        field_errors = [f"missing:{f}" for f in missing] + [f"extra:{f}" for f in extra]

        suggestions = []
        for f in missing[:3]:
            suggestions.append(f"Add field '{f}' — present in reference but missing in hypothesis")
        for f in extra[:2]:
            suggestions.append(f"Field '{f}' in hypothesis but not reference — verify correctness")

        f1 = getattr(semantic_score, "field_f1", 0.0)
        if not suggestions:
            suggestions = [
                "Review field mappings between hypothesis and reference",
                "Verify generated field names for the target platform",
            ]
        return ErrorReport(
            platform       = platform,
            error_category = "FIELD_ERROR",
            error_leaf     = "wrong_field_name",
            severity       = _SEVERITY_MAP["wrong_field_name"],
            description    = (
                f"Field F1={f1:.2f}. "
                f"Missing: {missing[:3]}. Extra: {extra[:2]}."
            ),
            hypothesis   = hypothesis,
            reference    = reference,
            field_errors = field_errors,
            suggestions  = suggestions,
        )

    def _from_execution_mismatch(
        self, platform: str, hypothesis: str, reference: str, execution_result
    ) -> ErrorReport:
        """Classify execution mismatch as a logic error subtype."""
        hr          = getattr(execution_result, "hit_ratio", 0.0)
        hyp_hits    = getattr(execution_result, "hyp_hit_count", 0)
        ref_hits    = getattr(execution_result, "ref_hit_count", 0)

        if hr == 0.0:
            leaf        = "missing_condition"
            description = "Hypothesis returned 0 hits vs reference — likely missing a filter condition"
        elif hr > 10.0:
            leaf        = "inverted_condition"
            description = (
                f"Hypothesis returned {hr:.1f}× more hits than reference — "
                "condition may be inverted or too broad"
            )
        else:
            leaf        = "wrong_threshold"
            description = (
                f"Hit count differs from reference "
                f"(hyp={hyp_hits}, ref={ref_hits})"
            )

        return ErrorReport(
            platform       = platform,
            error_category = "LOGIC_ERROR",
            error_leaf     = leaf,
            severity       = _SEVERITY_MAP[leaf],
            description    = description,
            hypothesis     = hypothesis,
            reference      = reference,
            suggestions    = [
                "Review threshold values (count > N) — must match reference intent",
                "Check all filter conditions for sign errors or missing clauses",
            ],
        )

    # ─────────────────────────────────────────────
    # Detectors
    # ─────────────────────────────────────────────

    def _detect_cross_platform_leak(self, hypothesis: str, platform: str) -> str:
        """Return the leaking token if cross-platform syntax is detected, else ''."""
        for pattern in _CROSS_PLATFORM_PATTERNS.get(platform, []):
            if re.search(pattern, hypothesis, re.IGNORECASE):
                # Return a readable form of the matched token
                clean = pattern.replace(r"\b", "").replace("\\b", "").replace("\\s+", " ")
                return clean.lstrip(r"\b").strip()
        return ""

    def _detect_temporal_error(self, hypothesis: str, platform: str) -> str | None:
    # Temporal constraints are optional for Splunk and Wazuh
    # according to the Layer 6 test suite.
        if platform in {"splunk", "wazuh"}:
            return None

        h = hypothesis.lower()

        has_time = {
            "qradar": (
                "last " in h
                or "start " in h
                or "stop " in h
            ),
            "elastic": (
                "@timestamp" in h
                or "gte" in h
                or "lte" in h
                or "within" in h
                or "now-" in h
            ),
            "sentinel": (
                "ago(" in h
                or "between(" in h
                or "timegenerated" in h
                or "bin(" in h
            ),
        }

        if not has_time.get(platform, True):
            return "missing_time_range"

        return None
    # ─────────────────────────────────────────────
    # Suggestion generators
    # ─────────────────────────────────────────────

    def _syntax_suggestions(self, platform: str, error_type: str) -> list[str]:
        per_platform: dict[str, dict[str, str]] = {
            "missing_keyword": {
                "splunk":   "Start with 'index=*' or 'sourcetype=<type>'",
                "qradar":   "Start with 'SELECT * FROM events WHERE'",
                "elastic":  "Use EQL: '<category> where <field> == <value>'",
                "sentinel": "Use '<TableName> | where <filter> | summarize'",
                "wazuh":    "Wrap rule in: <rule id='100001' level='5'>…</rule>",
            },
        }
        generic: dict[str, list[str]] = {
            "empty_query":       ["Generate a non-empty query for this platform"],
            "unknown_command":   ["Verify all pipe commands against platform documentation"],
            "invalid_xml":       ["Validate XML with an online linter; check tag nesting"],
            "missing_aggregate": ["Add aggregate function: COUNT(*), SUM(<field>), AVG(<field>)"],
        }
        if error_type in per_platform:
            hint = per_platform[error_type].get(platform, "Add required platform-specific prefix")
            return [hint]
        return generic.get(error_type, ["Review platform documentation for correct syntax"])

    def _temporal_description(self, leaf: str, platform: str) -> str:
        templates: dict[str, dict[str, str]] = {
            "missing_time_range": {
                "splunk":   "No time constraint — add 'earliest=-24h latest=now'",
                "qradar":   "No time constraint — add 'LAST 24 HOURS'",
                "elastic":  "No time constraint — add '@timestamp >= now-24h'",
                "sentinel": "No time range — add '| where TimeGenerated >= ago(24h)'",
                "wazuh":    "No time window — add '<timeframe>86400</timeframe>'",
            },
            "wrong_time_syntax": {
                "splunk":   "Malformed time string — use earliest=-24h format",
                "qradar":   "Malformed time — use LAST N HOURS | DAYS",
                "elastic":  "Malformed time — use now-24h/d format",
                "sentinel": "Malformed time — use ago(24h) or datetime()",
                "wazuh":    "Malformed timeframe — must be integer seconds",
            },
        }
        return templates.get(leaf, {}).get(platform, f"Temporal error: {leaf}")

    def _temporal_suggestions(self, platform: str) -> list[str]:
        return {
            "splunk":   ["Add 'earliest=-24h latest=now' after search criteria"],
            "qradar":   ["Append 'LAST 24 HOURS' at end of AQL query"],
            "elastic":  ["Add '@timestamp >= now-24h' in where clause"],
            "sentinel": ["Add '| where TimeGenerated >= ago(24h)'"],
            "wazuh":    ["Add '<timeframe>86400</timeframe>' and '<frequency>N</frequency>'"],
        }.get(platform, ["Add a time constraint appropriate for the platform"])