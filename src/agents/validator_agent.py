"""
Validator Agent — per-SIEM syntax checker for LLM-generated queries.

Runs immediately after each SIEM formatter produces output.
Catches malformed queries before they reach the evaluation layer or the user.

Checks performed per platform:
    Splunk   — pipeline structure, valid commands after each |
    QRadar   — SELECT … FROM events, GROUP BY needs aggregate function
    Elastic  — EQL category + where / KQL colon pattern / sequence brackets
    Sentinel — pipe structure, valid KQL operators, known table names
    Wazuh    — well-formed XML, <rule> root, id + level attrs, <description>

Returns a ValidationReport per query with:
    - per-platform pass/fail
    - error type classification (missing_keyword, malformed_syntax, etc.)
    - a corrected_query suggestion where trivially fixable

Place at: src/agents/validator_agent.py

Usage:
    from src.agents.validator_agent import ValidatorAgent
    validator = ValidatorAgent()
    report = validator.validate(translations)   # dict[platform → query_str]
    print(report.summary())
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Literal

from src.utils.logger import get_logger

log = get_logger(__name__)

Platform = Literal["splunk", "qradar", "elastic", "sentinel", "wazuh"]

# ── Error taxonomy ─────────────────────────────────────────────────────────
ErrorType = Literal[
    "missing_keyword",
    "malformed_syntax",
    "invalid_xml",
    "missing_aggregate",
    "unknown_command",
    "empty_query",
    "field_error",
    "time_syntax",
    "other",
]


@dataclass
class PlatformValidation:
    """Validation result for a single platform query."""

    platform:        Platform
    query:           str
    is_valid:        bool
    error_type:      ErrorType | None  = None
    error_detail:    str               = ""
    corrected_query: str | None        = None  # auto-fix if trivial
    warnings:        list[str]         = field(default_factory=list)

    @property
    def status(self) -> str:
        return "PASS" if self.is_valid else "FAIL"


@dataclass
class ValidationReport:
    """Full validation output for one NL query translated to all 5 SIEMs."""

    nl_query:    str
    results:     dict[str, PlatformValidation]  # platform → result
    elapsed_s:   float = 0.0

    @property
    def all_valid(self) -> bool:
        return all(r.is_valid for r in self.results.values())

    @property
    def valid_platforms(self) -> list[str]:
        return [p for p, r in self.results.items() if r.is_valid]

    @property
    def failed_platforms(self) -> list[str]:
        return [p for p, r in self.results.items() if not r.is_valid]

    @property
    def pass_rate(self) -> float:
        if not self.results:
            return 0.0
        return len(self.valid_platforms) / len(self.results)

    def summary(self) -> str:
        lines = [f"ValidationReport  pass={self.pass_rate:.0%}  ({len(self.valid_platforms)}/{len(self.results)} platforms)"]
        for platform, r in self.results.items():
            icon = "✓" if r.is_valid else "✗"
            detail = f"  [{r.error_type}] {r.error_detail}" if not r.is_valid else ""
            lines.append(f"  {icon} {platform:<10}{detail}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "nl_query":        self.nl_query,
            "pass_rate":       self.pass_rate,
            "valid_platforms": self.valid_platforms,
            "failed_platforms": self.failed_platforms,
            "elapsed_s":       self.elapsed_s,
            "results": {
                p: {
                    "is_valid":        r.is_valid,
                    "error_type":      r.error_type,
                    "error_detail":    r.error_detail,
                    "corrected_query": r.corrected_query,
                    "warnings":        r.warnings,
                }
                for p, r in self.results.items()
            },
        }


# ── Validator Agent ────────────────────────────────────────────────────────
class ValidatorAgent:
    """
    Validates generated SIEM queries against per-platform syntax rules.

    Validation is purely static (no SIEM sandbox needed).
    Use execution_match.py for live execution testing.
    """

    # ─────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────

    def validate(
        self,
        translations: dict[str, str],
        nl_query:     str = "",
    ) -> ValidationReport:
        """
        Validate a dict of platform → query string pairs.

        Args:
            translations: Dict mapping platform name to query string.
                          Usually the output of translate_all(ir).
            nl_query:     Original NL query (for report context).

        Returns:
            ValidationReport with per-platform PlatformValidation objects.
        """
        import time
        t0      = time.monotonic()
        results = {}

        for platform, query in translations.items():
            validator_fn = getattr(self, f"_validate_{platform}", self._validate_unknown)
            result       = validator_fn(query)
            result.platform = platform  # ensure set even if returned bare
            results[platform] = result

            log.debug(
                "Platform validated",
                extra={
                    "platform": platform,
                    "valid":    result.is_valid,
                    "error":    result.error_type,
                },
            )

        elapsed = round(time.monotonic() - t0, 4)
        report  = ValidationReport(
            nl_query  = nl_query,
            results   = results,
            elapsed_s = elapsed,
        )

        log.info(
            "Validation complete",
            extra={
                "pass_rate": f"{report.pass_rate:.0%}",
                "failed":    report.failed_platforms,
            },
        )
        return report

    def validate_single(self, platform: str, query: str) -> PlatformValidation:
        """Validate a single platform query."""
        validator_fn = getattr(self, f"_validate_{platform}", self._validate_unknown)
        result       = validator_fn(query)
        result.platform = platform
        return result

    # ─────────────────────────────────────────────
    # Per-platform validators
    # ─────────────────────────────────────────────

    def _validate_splunk(self, query: str) -> PlatformValidation:
        """Splunk SPL validator."""
        q = (query or "").strip()

        if not q:
            return self._fail("splunk", q, "empty_query", "Query is empty")

        ql = q.lower()

        # Must start with index= or search or *
        if not (ql.startswith("index=") or ql.startswith("search") or ql.startswith("*")):
            return self._fail(
                "splunk", q, "missing_keyword",
                "SPL must start with 'index=', 'search', or '*'",
                corrected = f"index=* {q}" if not ql.startswith("index") else None,
            )

        # Every pipe segment must start with a known command
        VALID_CMDS = {
            "stats", "where", "eval", "table", "sort", "head", "tail",
            "dedup", "rex", "lookup", "transaction", "timechart", "top",
            "rare", "fields", "rename", "search", "inputlookup", "outputlookup",
            "tstats", "mstats", "bin", "chart", "geostats", "streamstats",
            "eventstats", "appendcols", "join", "append",
        }
        warnings = []
        pipes = q.split("|")
        for seg in pipes[1:]:
            cmd = seg.strip().split()[0].lower() if seg.strip() else ""
            if cmd and cmd not in VALID_CMDS:
                return self._fail(
                    "splunk", q, "unknown_command",
                    f"Unknown SPL command: '{cmd}'",
                )

        # Warn if stats used without group_by (unusual but not invalid)
        if "| stats" in ql and " by " not in ql:
            warnings.append("stats without 'by' clause — aggregating over all events")

        return PlatformValidation(
            platform="splunk", query=q, is_valid=True, warnings=warnings
        )

    def _validate_qradar(self, query: str) -> PlatformValidation:
        """QRadar AQL validator."""
        q  = (query or "").strip()
        qu = q.upper()

        if not q:
            return self._fail("qradar", q, "empty_query", "Query is empty")

        if not qu.startswith("SELECT"):
            return self._fail(
                "qradar", q, "missing_keyword",
                "AQL must start with SELECT",
            )

        if "FROM EVENTS" not in qu and "FROM FLOWS" not in qu and "FROM ASSETS" not in qu:
            return self._fail(
                "qradar", q, "missing_keyword",
                "AQL must contain FROM EVENTS (or FROM FLOWS / FROM ASSETS)",
            )

        # GROUP BY requires an aggregate function
        if "GROUP BY" in qu:
            agg_fns = ("COUNT(", "SUM(", "AVG(", "MIN(", "MAX(", "COUNT(DISTINCT")
            if not any(fn in qu for fn in agg_fns):
                return self._fail(
                    "qradar", q, "missing_aggregate",
                    "GROUP BY present but no aggregate function (COUNT, SUM, AVG, MIN, MAX) in SELECT",
                )

        # HAVING requires GROUP BY
        if "HAVING" in qu and "GROUP BY" not in qu:
            return self._fail(
                "qradar", q, "malformed_syntax",
                "HAVING clause requires GROUP BY",
            )

        warnings = []
        if "LAST" not in qu and "START" not in qu and "STOP" not in qu:
            warnings.append("No time range specified (LAST N HOURS / START-STOP) — may return all-time data")

        return PlatformValidation(
            platform="qradar", query=q, is_valid=True, warnings=warnings
        )

    def _validate_elastic(self, query: str) -> PlatformValidation:
        """Elastic EQL / KQL validator."""
        q  = (query or "").strip()
        ql = q.lower()

        if not q:
            return self._fail("elastic", q, "empty_query", "Query is empty")

        EQL_CATEGORIES = {
            "authentication", "network", "process", "file",
            "registry", "dns", "web", "any",
        }
        first_word = ql.split()[0] if ql.split() else ""

        # EQL path
        if first_word in EQL_CATEGORIES:
            if "where" not in ql and first_word != "any":
                return self._fail(
                    "elastic", q, "missing_keyword",
                    f"EQL event query must contain 'where' after the category '{first_word}'",
                )
            return PlatformValidation(platform="elastic", query=q, is_valid=True)

        # EQL sequence path
        if first_word == "sequence":
            if "[" not in q or "]" not in q:
                return self._fail(
                    "elastic", q, "malformed_syntax",
                    "EQL sequence query must contain bracketed steps [...]",
                )
            return PlatformValidation(platform="elastic", query=q, is_valid=True)

        # KQL path — must contain field: value or *
        if ":" in q or q.strip() == "*":
            return PlatformValidation(platform="elastic", query=q, is_valid=True)

        # Could be KQL with only comparison operators (field > N)
        kql_ops = re.search(r'\b\w+\s*(>|>=|<|<=)\s*\d+', q)
        if kql_ops:
            return PlatformValidation(platform="elastic", query=q, is_valid=True)

        return self._fail(
            "elastic", q, "malformed_syntax",
            "Could not identify as EQL (missing event category + 'where') or KQL (missing 'field:' pattern)",
        )

    def _validate_sentinel(self, query: str) -> PlatformValidation:
        """Microsoft Sentinel KQL validator."""
        q  = (query or "").strip()

        if not q:
            return self._fail("sentinel", q, "empty_query", "Query is empty")

        SENTINEL_TABLES = {
            "securityevent", "syslog", "signinlogs", "networkanalytics",
            "dnsevents", "deviceprocessevents", "devicefileevents",
            "devicenetworkevents", "deviceregistryevents", "azureactivity",
            "auditlogs", "aadnoninteractiveusersigninlogs", "officeactivity",
            "commonsecuritylog", "windowsevent", "heartbeat",
        }

        # Must have at least one pipe operator
        if "|" not in q:
            return self._fail(
                "sentinel", q, "malformed_syntax",
                "KQL query must contain at least one pipe '|' operator",
            )

        # First line should be a known Sentinel table
        first_line = q.split("\n")[0].split("|")[0].strip().lower()
        warnings   = []
        if first_line not in SENTINEL_TABLES:
            warnings.append(
                f"Table '{first_line}' is not a standard Sentinel table — verify it exists in your workspace"
            )

        # All pipe operators must be valid KQL
        VALID_KQL_OPS = {
            "where", "summarize", "project", "project-away", "project-rename",
            "order", "sort", "top", "extend", "join", "union", "let",
            "render", "take", "limit", "count", "distinct", "evaluate",
            "parse", "mv-expand", "make-series", "bin", "range",
        }
        pipes = q.split("|")
        for seg in pipes[1:]:
            seg_stripped = seg.strip()
            if not seg_stripped:
                continue
            # Handle multi-line segments (join kind=inner ...)
            first_token = seg_stripped.split()[0].lower() if seg_stripped.split() else ""
            if first_token and first_token not in VALID_KQL_OPS:
                return self._fail(
                    "sentinel", q, "unknown_command",
                    f"Unknown KQL operator: '{first_token}'",
                )

        return PlatformValidation(
            platform="sentinel", query=q, is_valid=True, warnings=warnings
        )

    def _validate_wazuh(self, query: str) -> PlatformValidation:
        """Wazuh XML rule validator."""
        q = (query or "").strip()

        if not q:
            return self._fail("wazuh", q, "empty_query", "Query is empty")

        # Must be valid XML
        try:
            root = ET.fromstring(q)
        except ET.ParseError as exc:
            return self._fail(
                "wazuh", q, "invalid_xml",
                f"XML parse error: {exc}",
            )

        # Root must be <rule>
        if root.tag != "rule":
            return self._fail(
                "wazuh", q, "malformed_syntax",
                f"Root element must be <rule>, got <{root.tag}>",
            )

        # Must have id and level attributes
        if "id" not in root.attrib:
            return self._fail("wazuh", q, "field_error", "Missing required 'id' attribute on <rule>")
        if "level" not in root.attrib:
            return self._fail("wazuh", q, "field_error", "Missing required 'level' attribute on <rule>")

        # Must have <description>
        if root.find("description") is None:
            return self._fail(
                "wazuh", q, "missing_keyword",
                "Rule must contain a <description> element",
            )

        # Rule ID must be in custom range (>= 100000)
        warnings = []
        try:
            rule_id = int(root.attrib["id"])
            if rule_id < 100000:
                warnings.append(
                    f"Rule ID {rule_id} is in the Wazuh reserved range (<100000) — "
                    "use IDs >= 100000 for custom rules to avoid conflicts"
                )
        except (ValueError, KeyError):
            return self._fail("wazuh", q, "field_error", "Rule 'id' attribute must be a valid integer")

        # Level must be 0-15
        try:
            level = int(root.attrib["level"])
            if not 0 <= level <= 15:
                warnings.append(f"Rule level {level} is outside valid range 0-15")
        except (ValueError, KeyError):
            return self._fail("wazuh", q, "field_error", "Rule 'level' must be an integer 0-15")

        return PlatformValidation(
            platform="wazuh", query=q, is_valid=True, warnings=warnings
        )

    def _validate_unknown(self, query: str) -> PlatformValidation:
        """Fallback for unrecognised platform — passes if query is non-empty."""
        q = (query or "").strip()
        if not q:
            return self._fail("unknown", q, "empty_query", "Query is empty")
        return PlatformValidation(
            platform="unknown", query=q, is_valid=True,
            warnings=["No validator defined for this platform — skipping syntax check"],
        )

    # ─────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────

    @staticmethod
    def _fail(
        platform:  str,
        query:     str,
        error_type: ErrorType,
        detail:    str,
        corrected: str | None = None,
    ) -> PlatformValidation:
        log.debug(
            "Syntax validation failed",
            extra={"platform": platform, "error_type": error_type, "detail": detail},
        )
        return PlatformValidation(
            platform        = platform,
            query           = query,
            is_valid        = False,
            error_type      = error_type,
            error_detail    = detail,
            corrected_query = corrected,
        )