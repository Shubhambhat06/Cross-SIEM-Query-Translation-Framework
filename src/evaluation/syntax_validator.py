"""
Syntax Validator — per-SIEM regex + structural validators for evaluation.

Differs from ValidatorAgent (Layer 5) in purpose:
  - ValidatorAgent: gates pipeline execution, fast pass/fail
  - SyntaxValidator: measures syntactic validity % for paper Table 2,
    classifies error types, tracks detailed per-query metrics with
    structural_score (partial credit) and keyword_coverage.

Place at: src/evaluation/syntax_validator.py

Usage:
    from src.evaluation.syntax_validator import SyntaxValidator
    validator = SyntaxValidator()
    result  = validator.validate("splunk", "index=* | stats count by src_ip")
    batch   = validator.validate_batch(translations_dict)
    metrics = validator.compute_metrics(results_list, platform="splunk")
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Literal

from src.utils.logger import get_logger

log = get_logger(__name__)

Platform  = Literal["splunk", "qradar", "elastic", "sentinel", "wazuh"]
ErrorType = Literal[
    "empty_query",
    "missing_keyword",
    "malformed_syntax",
    "invalid_xml",
    "missing_aggregate",
    "unknown_command",
    "field_error",
    "time_syntax",
    "none",
]


# ── Result dataclass ───────────────────────────────────────────────────────────

@dataclass
class SyntaxValidationResult:
    """Per-query syntax validation output."""

    platform:         str
    query:            str
    is_valid:         bool
    error_type:       ErrorType  = "none"
    error_detail:     str        = ""
    structural_score: float      = 1.0   # 0.0–1.0 partial credit
    keyword_coverage: float      = 1.0   # fraction of expected keywords present
    warnings:         list[str]  = field(default_factory=list)

    @property
    def status(self) -> str:
        return "PASS" if self.is_valid else "FAIL"

    def to_dict(self) -> dict:
        return {
            "platform":         self.platform,
            "is_valid":         self.is_valid,
            "error_type":       self.error_type,
            "error_detail":     self.error_detail,
            "structural_score": round(self.structural_score, 4),
            "keyword_coverage": round(self.keyword_coverage, 4),
            "warnings":         self.warnings,
        }


@dataclass
class SyntaxMetrics:
    """Aggregated syntax validation metrics across a dataset for one platform."""

    platform:        str
    total:           int
    valid:           int
    invalid:         int
    validity_pct:    float
    avg_structural:  float
    avg_keyword_cov: float
    error_breakdown: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "platform":        self.platform,
            "total":           self.total,
            "valid":           self.valid,
            "invalid":         self.invalid,
            "validity_pct":    round(self.validity_pct,    4),
            "avg_structural":  round(self.avg_structural,  4),
            "avg_keyword_cov": round(self.avg_keyword_cov, 4),
            "error_breakdown": self.error_breakdown,
        }

    def to_latex_row(self) -> str:
        """Single LaTeX table row for paper Table 2 syntax columns."""
        return (
            f"{self.platform.capitalize()} & "
            f"{self.validity_pct * 100:.1f}\\% & "
            f"{self.avg_structural:.3f} & "
            f"{self.avg_keyword_cov:.3f} \\\\"
        )


# ── Platform keyword sets ──────────────────────────────────────────────────────

_SPLUNK_COMMANDS = {
    "stats", "where", "eval", "table", "sort", "head", "tail", "dedup",
    "rex", "lookup", "transaction", "timechart", "top", "rare", "fields",
    "rename", "search", "tstats", "bin", "chart", "streamstats",
    "eventstats", "appendcols", "join", "append", "inputlookup", "outputlookup",
    "makeresults", "iplocation", "fillnull", "filldown", "foreach",
}
_QRADAR_OPTIONAL = {"where", "group by", "having", "order by", "last"}

_ELASTIC_CATEGORIES = {
    "authentication", "network", "process", "file",
    "registry", "dns", "web", "any", "sequence",
}
# ES|QL commands (pipe-based, 8.11+)
_ESQL_COMMANDS = {
    "from", "where", "stats", "sort", "limit", "eval", "keep",
    "drop", "rename", "dissect", "grok", "enrich", "mv_expand",
}

_SENTINEL_TABLES = {
    "securityevent", "syslog", "signinlogs", "networkanalytics",
    "dnsevents", "deviceprocessevents", "devicefileevents",
    "devicenetworkevents", "deviceregistryevents", "azureactivity",
    "auditlogs", "aadnoninteractiveusersigninlogs", "officeactivity",
    "commonsecuritylog", "windowsevent", "heartbeat", "alert",
    "securityalert", "securityincident", "threatintelligenceindicator",
}
_SENTINEL_OPS = {
    "where", "summarize", "project", "project-away", "project-rename",
    "order", "sort", "top", "extend", "join", "union", "let",
    "render", "take", "limit", "count", "distinct", "evaluate",
    "parse", "mv-expand", "make-series", "bin", "range",
}
_WAZUH_VALID_CHILDREN = {
    "if_sid", "if_group", "if_level", "match", "regex", "field",
    "same_source_ip", "same_destination_ip", "same_user", "same_location",
    "frequency", "timeframe", "group", "description", "mitre", "id",
    "options", "check_if_ignored", "list", "action", "decoded_as",
    "category", "program_name", "hostname", "extra_data",
}


# ── Syntax Validator ───────────────────────────────────────────────────────────

class SyntaxValidator:
    """
    Comprehensive per-platform syntax validator for evaluation metrics.

    Validates generated SIEM queries and produces structured metrics
    for inclusion in paper Table 2 (Syntactic Validity %).
    Includes structural_score for partial credit and keyword_coverage
    as a proxy for query completeness.
    """

    # ─────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────

    def validate(self, platform: str, query: str) -> SyntaxValidationResult:
        """
        Validate a single platform query.

        Args:
            platform: SIEM platform name (case-insensitive).
            query:    Generated query string.

        Returns:
            SyntaxValidationResult with full diagnostic information.
        """
        platform = platform.lower().strip()
        fn       = getattr(self, f"_validate_{platform}", self._validate_unknown)
        result   = fn(query)
        log.debug(
            "Syntax validation",
            extra={"platform": platform, "valid": result.is_valid, "error": result.error_type},
        )
        return result

    def validate_batch(
        self,
        translations: dict[str, str],
    ) -> dict[str, SyntaxValidationResult]:
        """
        Validate all platform queries from one translation result.

        Args:
            translations: Dict mapping platform → query string.

        Returns:
            Dict mapping platform → SyntaxValidationResult.
        """
        return {p: self.validate(p, q) for p, q in translations.items()}

    def validate_dataset(
        self,
        records:          list[dict],
        translations_key: str = "translations",
    ) -> dict[str, list[SyntaxValidationResult]]:
        """
        Validate all translations across a full SIEMBench dataset.

        Args:
            records:          List of result dicts (from run_evaluation.py).
            translations_key: Key in each record containing the translations dict.

        Returns:
            Dict mapping platform → list of SyntaxValidationResult.
        """
        platforms   = ("splunk", "qradar", "elastic", "sentinel", "wazuh")
        all_results: dict[str, list[SyntaxValidationResult]] = {p: [] for p in platforms}

        for record in records:
            translations = record.get(translations_key, {})
            batch        = self.validate_batch(translations)
            for platform, result in batch.items():
                if platform in all_results:
                    all_results[platform].append(result)

        return all_results

    def compute_metrics(
        self,
        results:  list[SyntaxValidationResult],
        platform: str = "",
    ) -> SyntaxMetrics:
        """
        Aggregate a list of SyntaxValidationResult into per-platform metrics.

        Args:
            results:  List of validation results for one platform.
            platform: Platform label (inferred from results[0] if omitted).

        Returns:
            SyntaxMetrics with validity %, structural score, error breakdown.
        """
        if not results:
            return SyntaxMetrics(
                platform=platform, total=0, valid=0, invalid=0,
                validity_pct=0.0, avg_structural=0.0, avg_keyword_cov=0.0,
            )

        total   = len(results)
        valid   = sum(1 for r in results if r.is_valid)
        invalid = total - valid

        error_breakdown: dict[str, int] = {}
        for r in results:
            if not r.is_valid and r.error_type:
                error_breakdown[r.error_type] = error_breakdown.get(r.error_type, 0) + 1

        return SyntaxMetrics(
            platform        = platform or (results[0].platform if results else ""),
            total           = total,
            valid           = valid,
            invalid         = invalid,
            validity_pct    = valid / total,
            avg_structural  = sum(r.structural_score  for r in results) / total,
            avg_keyword_cov = sum(r.keyword_coverage  for r in results) / total,
            error_breakdown = error_breakdown,
        )

    def compute_all_metrics(
        self,
        all_results: dict[str, list[SyntaxValidationResult]],
    ) -> dict[str, SyntaxMetrics]:
        """Compute metrics for all platforms from validate_dataset output."""
        return {
            platform: self.compute_metrics(results, platform=platform)
            for platform, results in all_results.items()
        }

    # ─────────────────────────────────────────────
    # Per-platform validators
    # ─────────────────────────────────────────────

    def _validate_splunk(self, query: str) -> SyntaxValidationResult:
        q  = (query or "").strip()
        ql = q.lower()

        if not q:
            return self._fail("splunk", q, "empty_query", "Empty query", 0.0, 0.0)

        # Must start with recognised prefix
        starts_ok = (
            ql.startswith("index=") or
            ql.startswith("sourcetype=") or
            ql.startswith("search ") or
            ql.startswith("* ") or
            ql == "*"
        )
        if not starts_ok:
            return self._fail(
                "splunk", q, "missing_keyword",
                "SPL must start with 'index=', 'sourcetype=', 'search', or '*'",
                structural_score=0.2, keyword_coverage=0.0,
            )

        # Validate each pipe segment
        pipes   = q.split("|")
        good_cmds: list[str] = []
        for seg in pipes[1:]:
            seg_stripped = seg.strip()
            if not seg_stripped:
                continue
            cmd = seg_stripped.split()[0].lower()
            if cmd not in _SPLUNK_COMMANDS:
                return self._fail(
                    "splunk", q, "unknown_command",
                    f"Unknown SPL command after pipe: '{cmd}'",
                    structural_score=0.6,
                    keyword_coverage=len(good_cmds) / max(len(pipes) - 1, 1),
                )
            good_cmds.append(cmd)

        # keyword_coverage = fraction of pipe segments that used known commands
        pipe_count = max(len(pipes) - 1, 0)
        coverage   = (len(good_cmds) / pipe_count) if pipe_count > 0 else 1.0

        warnings = []
        if "| stats" in ql and " by " not in ql:
            warnings.append("stats without 'by' clause — aggregating all events into one row")
        if "earliest=" not in ql and "latest=" not in ql:
            warnings.append("No time constraint (earliest=/latest=) — may scan all indexed data")

        return SyntaxValidationResult(
            platform="splunk", query=q, is_valid=True,
            structural_score=1.0, keyword_coverage=min(coverage, 1.0),
            warnings=warnings,
        )

    def _validate_qradar(self, query: str) -> SyntaxValidationResult:
        q  = (query or "").strip()
        qu = q.upper()

        if not q:
            return self._fail("qradar", q, "empty_query", "Empty query", 0.0, 0.0)

        if not qu.startswith("SELECT"):
            return self._fail(
                "qradar", q, "missing_keyword",
                "AQL must start with SELECT",
                structural_score=0.1, keyword_coverage=0.0,
            )

        if "FROM EVENTS" not in qu and "FROM FLOWS" not in qu and "FROM ASSETS" not in qu:
            return self._fail(
                "qradar", q, "missing_keyword",
                "AQL must contain FROM EVENTS (or FROM FLOWS / FROM ASSETS)",
                structural_score=0.4, keyword_coverage=0.3,
            )

        optional_present = sum(1 for kw in _QRADAR_OPTIONAL if kw in qu.lower())
        coverage         = min((2 + optional_present) / (2 + len(_QRADAR_OPTIONAL)), 1.0)

        if "GROUP BY" in qu:
            agg_fns = ("COUNT(", "SUM(", "AVG(", "MIN(", "MAX(", "COUNT(DISTINCT")
            if not any(fn in qu for fn in agg_fns):
                return self._fail(
                    "qradar", q, "missing_aggregate",
                    "GROUP BY present but no aggregate function (COUNT, SUM, AVG, MIN, MAX)",
                    structural_score=0.7, keyword_coverage=coverage,
                )

        if "HAVING" in qu and "GROUP BY" not in qu:
            return self._fail(
                "qradar", q, "malformed_syntax",
                "HAVING clause requires GROUP BY",
                structural_score=0.7, keyword_coverage=coverage,
            )

        warnings = []
        if "LAST" not in qu and "START" not in qu:
            warnings.append("No time range (LAST N HOURS / START-STOP) — may return all-time data")

        return SyntaxValidationResult(
            platform="qradar", query=q, is_valid=True,
            structural_score=1.0, keyword_coverage=coverage,
            warnings=warnings,
        )

    def _validate_elastic(self, query: str) -> SyntaxValidationResult:
        q  = (query or "").strip()
        ql = q.lower()

        if not q:
            return self._fail("elastic", q, "empty_query", "Empty query", 0.0, 0.0)

        first_word = ql.split()[0] if ql.split() else ""

        # ── EQL path ──────────────────────────────────────────────────────
        if first_word in _ELASTIC_CATEGORIES:
            if first_word == "sequence":
                if "[" not in q or "]" not in q:
                    return self._fail(
                        "elastic", q, "malformed_syntax",
                        "EQL sequence query must contain bracketed steps [...]",
                        structural_score=0.5, keyword_coverage=0.5,
                    )
                n_steps  = q.count("[")
                coverage = min(n_steps / 2, 1.0)
                return SyntaxValidationResult(
                    platform="elastic", query=q, is_valid=True,
                    structural_score=1.0, keyword_coverage=coverage,
                )
            else:
                if "where" not in ql:
                    return self._fail(
                        "elastic", q, "missing_keyword",
                        f"EQL event query missing 'where' after category '{first_word}'",
                        structural_score=0.5, keyword_coverage=0.3,
                    )
                n_pipes  = ql.count("| stats") + ql.count("| where")
                coverage = min((1 + n_pipes) / 3, 1.0)
                return SyntaxValidationResult(
                    platform="elastic", query=q, is_valid=True,
                    structural_score=1.0, keyword_coverage=coverage,
                )

        # ── ES|QL path (FROM … | WHERE … | STATS …) ───────────────────────
        if first_word == "from" and "|" in q:
            pipes  = q.split("|")
            good   = 0
            for seg in pipes[1:]:
                tok = seg.strip().split()[0].lower() if seg.strip() else ""
                if tok in _ESQL_COMMANDS:
                    good += 1
            coverage = good / max(len(pipes) - 1, 1)
            return SyntaxValidationResult(
                platform="elastic", query=q, is_valid=True,
                structural_score=1.0, keyword_coverage=min(coverage, 1.0),
            )

        # ── KQL path: field: value or * or comparison operators ────────────
        if ":" in q or q.strip() == "*":
            n_clauses = max(1, q.count(" AND ") + q.count(" OR ") + 1)
            coverage  = min(n_clauses / 3, 1.0)
            return SyntaxValidationResult(
                platform="elastic", query=q, is_valid=True,
                structural_score=1.0, keyword_coverage=coverage,
            )

        if re.search(r"\b\w+\s*(>|>=|<|<=)\s*\d+", q):
            return SyntaxValidationResult(
                platform="elastic", query=q, is_valid=True,
                structural_score=1.0, keyword_coverage=0.5,
            )

        return self._fail(
            "elastic", q, "malformed_syntax",
            "Could not identify as EQL (event_category + where), sequence, ES|QL (FROM | …), or KQL (field: value)",
            structural_score=0.2, keyword_coverage=0.0,
        )

    def _validate_sentinel(self, query: str) -> SyntaxValidationResult:
        q  = (query or "").strip()
        ql = q.lower()

        if not q:
            return self._fail("sentinel", q, "empty_query", "Empty query", 0.0, 0.0)

        # Support 'let' statements at the top (valid KQL)
        effective = ql
        if ql.startswith("let "):
            # Strip all leading let statements to find the first table
            effective = re.sub(r"^(let\s+\w+\s*=\s*[^\n;]+[;\n]?\s*)+", "", ql, flags=re.MULTILINE).strip()

        if "|" not in q:
            return self._fail(
                "sentinel", q, "malformed_syntax",
                "KQL query must contain at least one pipe '|' operator",
                structural_score=0.2, keyword_coverage=0.0,
            )

        # First non-let line should be a known table
        warnings  = []
        first_line = effective.split("\n")[0].split("|")[0].strip().lower()
        if first_line and first_line not in _SENTINEL_TABLES:
            warnings.append(
                f"Table '{first_line}' is not a standard Sentinel table — verify it exists in your workspace"
            )

        # Validate pipe operators
        pipes     = q.split("|")
        found_ops: list[str] = []
        for seg in pipes[1:]:
            seg_stripped = seg.strip()
            if not seg_stripped:
                continue
            first_token = seg_stripped.split()[0].lower()
            if first_token not in _SENTINEL_OPS:
                return self._fail(
                    "sentinel", q, "unknown_command",
                    f"Unknown KQL operator: '{first_token}'",
                    structural_score=0.6,
                    keyword_coverage=len(found_ops) / max(len(pipes) - 1, 1),
                )
            found_ops.append(first_token)

        coverage = len(found_ops) / max(len(pipes) - 1, 1) if len(pipes) > 1 else 1.0

        return SyntaxValidationResult(
            platform="sentinel", query=q, is_valid=True,
            structural_score=1.0, keyword_coverage=min(coverage, 1.0),
            warnings=warnings,
        )

    def _validate_wazuh(self, query: str) -> SyntaxValidationResult:
        q = (query or "").strip()

        if not q:
            return self._fail("wazuh", q, "empty_query", "Empty query", 0.0, 0.0)

        try:
            root = ET.fromstring(q)
        except ET.ParseError as exc:
            return self._fail(
                "wazuh", q, "invalid_xml",
                f"XML parse error: {exc}",
                structural_score=0.0, keyword_coverage=0.0,
            )

        if root.tag != "rule":
            return self._fail(
                "wazuh", q, "malformed_syntax",
                f"Root element must be <rule>, got <{root.tag}>",
                structural_score=0.3, keyword_coverage=0.0,
            )

        if "id" not in root.attrib:
            return self._fail("wazuh", q, "field_error",
                              "Missing 'id' attribute on <rule>",
                              structural_score=0.5, keyword_coverage=0.5)
        if "level" not in root.attrib:
            return self._fail("wazuh", q, "field_error",
                              "Missing 'level' attribute on <rule>",
                              structural_score=0.6, keyword_coverage=0.5)

        if root.find("description") is None:
            return self._fail(
                "wazuh", q, "missing_keyword",
                "Rule must contain <description>",
                structural_score=0.7, keyword_coverage=0.5,
            )

        # keyword_coverage = fraction of valid child elements (expect ≥4 for a complete rule)
        child_tags     = {child.tag for child in root}
        valid_children = child_tags & _WAZUH_VALID_CHILDREN
        coverage       = min(len(valid_children) / 4, 1.0)

        warnings = []
        try:
            rule_id = int(root.attrib["id"])
            if rule_id < 100000:
                warnings.append(
                    f"Rule ID {rule_id} is in reserved range (<100000) — use IDs >= 100000 for custom rules"
                )
        except (ValueError, KeyError):
            return self._fail("wazuh", q, "field_error",
                              "Rule 'id' must be a valid integer",
                              structural_score=0.7, keyword_coverage=coverage)

        try:
            level = int(root.attrib.get("level", "0"))
            if not 0 <= level <= 15:
                warnings.append(f"Rule level {level} is outside valid range 0–15")
        except ValueError:
            warnings.append("Rule 'level' attribute is not a valid integer")

        return SyntaxValidationResult(
            platform="wazuh", query=q, is_valid=True,
            structural_score=1.0, keyword_coverage=coverage,
            warnings=warnings,
        )

    def _validate_unknown(self, query: str) -> SyntaxValidationResult:
        q = (query or "").strip()
        if not q:
            return self._fail("unknown", q, "empty_query", "Empty query", 0.0, 0.0)
        return SyntaxValidationResult(
            platform="unknown", query=q, is_valid=True,
            structural_score=1.0, keyword_coverage=1.0,
            warnings=["No validator defined for this platform — skipping syntax check"],
        )

    # ─────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────

    @staticmethod
    def _fail(
        platform:         str,
        query:            str,
        error_type:       ErrorType,
        detail:           str,
        structural_score: float = 0.0,
        keyword_coverage: float = 0.0,
    ) -> SyntaxValidationResult:
        return SyntaxValidationResult(
            platform         = platform,
            query            = query,
            is_valid         = False,
            error_type       = error_type,
            error_detail     = detail,
            structural_score = max(0.0, min(1.0, structural_score)),
            keyword_coverage = max(0.0, min(1.0, keyword_coverage)),
        )