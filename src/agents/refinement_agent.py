"""
Refinement Agent — self-critique loop that improves generated SIEM queries.

When the ValidatorAgent reports failures, the RefinementAgent:
    1. Analyses which platforms failed and why (error taxonomy)
    2. Selects the right refinement strategy per error type
    3. Re-prompts the LLM with structured correction instructions
    4. Validates the refined output
    5. Repeats up to max_iterations times until all platforms pass

Refinement strategies:
    - IR-level fix    → re-run ParserAgent with correction hint (fixes structural issues)
    - Query-level fix → re-prompt translator directly with the specific error
    - Hybrid          → re-generate IR if >2 platforms fail, else patch individual queries

This implements the Reflexion-style self-critique loop described in:
    Shinn et al. (2023) "Reflexion: Language Agents with Verbal Reinforcement Learning"
    arXiv:2303.11366

Place at: src/agents/refinement_agent.py

Usage:
    from src.agents.refinement_agent import RefinementAgent

    agent = RefinementAgent(client=llm_client, parser_agent=parser)
    refined = agent.refine(
        nl_query     = "Detect brute force SSH",
        translations = {"splunk": "...", "qradar": "...", ...},
        report       = validation_report,
        ir           = original_ir,
    )
    print(refined.final_translations)
    print(refined.summary())
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from src.agents.validator_agent import ValidatorAgent, ValidationReport, PlatformValidation
from src.ir.schema import IRQuery
from src.ir.validator import coerce_ir
from src.llm.response_parser import ResponseParser
from src.translators import translate_all, translate_one
from src.utils.exceptions import NLSIEMError, TranslationError
from src.utils.logger import get_logger

log = get_logger(__name__)


# ── Refinement result ─────────────────────────────────────────────────────

@dataclass
class RefinementResult:
    """Full output of a single RefinementAgent.refine() call."""

    nl_query:             str
    original_translations: dict[str, str]
    final_translations:   dict[str, str]
    final_ir:             IRQuery
    iterations:           int
    platforms_fixed:      list[str]
    platforms_still_failed: list[str]
    strategy_used:        str          # "ir_reparse" | "query_patch" | "hybrid"
    elapsed_s:            float
    iteration_log:        list[dict]   = field(default_factory=list)

    @property
    def improvement_rate(self) -> float:
        """Fraction of originally-failed platforms that were fixed."""
        originally_failed = len(self.platforms_fixed) + len(self.platforms_still_failed)
        if originally_failed == 0:
            return 1.0
        return len(self.platforms_fixed) / originally_failed

    @property
    def all_valid(self) -> bool:
        return len(self.platforms_still_failed) == 0

    def summary(self) -> str:
        lines = [
            f"RefinementResult | strategy={self.strategy_used} | "
            f"iterations={self.iterations} | "
            f"fixed={self.platforms_fixed} | "
            f"still_failed={self.platforms_still_failed} | "
            f"elapsed={self.elapsed_s}s"
        ]
        for log_entry in self.iteration_log:
            lines.append(
                f"  iter {log_entry['iteration']}: "
                f"fixed={log_entry.get('fixed', [])} | "
                f"still_failing={log_entry.get('still_failing', [])}"
            )
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "nl_query":               self.nl_query,
            "iterations":             self.iterations,
            "platforms_fixed":        self.platforms_fixed,
            "platforms_still_failed": self.platforms_still_failed,
            "strategy_used":          self.strategy_used,
            "improvement_rate":       self.improvement_rate,
            "elapsed_s":              self.elapsed_s,
            "final_ir":               self.final_ir.to_dict(),
            "iteration_log":          self.iteration_log,
        }


# ── Per-platform fix prompt templates ────────────────────────────────────

_FIX_PROMPTS: dict[str, str] = {
    "splunk": """Fix this Splunk SPL query. It has the following syntax error:
Error: {error_detail}

Original query:
{query}

Rules:
- Must start with 'index=*' or a sourcetype filter
- Each pipe segment must start with a valid SPL command: stats, where, eval, table, sort, head, lookup, dedup, rex, transaction, timechart, top, rare, fields, rename
- stats command syntax: | stats count as alias by field1, field2
- where command syntax: | where field > value
- time window syntax: earliest=-24h latest=now (in the initial search, NOT in a pipe)

Output ONLY the corrected SPL query. No explanation.""",

    "qradar": """Fix this IBM QRadar AQL query. It has the following syntax error:
Error: {error_detail}

Original query:
{query}

Rules:
- Must start with SELECT
- Must contain FROM EVENTS (not FROM logs or FROM data)
- If GROUP BY is present, SELECT must include COUNT(*) or SUM() or AVG() etc.
- HAVING requires GROUP BY
- Time range goes at the END: LAST 24 HOURS (not in WHERE)
- String values use single quotes: WHERE status = 'failed'

Output ONLY the corrected AQL query. No explanation.""",

    "elastic": """Fix this Elastic EQL/KQL query. It has the following syntax error:
Error: {error_detail}

Original query:
{query}

Rules for EQL:
- Must start with an event category: authentication, network, process, file, registry, dns, web, any
- Must contain 'where' after the category: authentication where event.outcome == "failure"
- Aggregation uses pipes: | stats count() as cnt by source.ip
- Threshold: | where cnt > 50
- Sequence format: sequence [step1] [step2]

Rules for KQL (simple filter only):
- field: value syntax: event.category: "authentication"
- Boolean: field1: "val" AND field2: "val"

Output ONLY the corrected query. No explanation.""",

    "sentinel": """Fix this Microsoft Sentinel KQL query. It has the following syntax error:
Error: {error_detail}

Original query:
{query}

Rules:
- First line must be a valid Sentinel table: SecurityEvent, Syslog, SigninLogs, NetworkAnalytics, DnsEvents, DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceRegistryEvents
- All subsequent lines start with | (pipe)
- Valid operators after |: where, summarize, project, order, sort, top, extend, join, union, let, render, take, limit, count, distinct, evaluate, parse, mv-expand, make-series, bin
- Time filter: | where TimeGenerated > ago(24h)
- Aggregation: | summarize count() by FieldName
- Threshold: | where count_ > 50

Output ONLY the corrected KQL query. No explanation.""",

    "wazuh": """Fix this Wazuh XML rule. It has the following syntax error:
Error: {error_detail}

Original rule:
{query}

Rules:
- Must be valid XML
- Root element must be <rule id="100001" level="10">
- Rule ID must be >= 100000 (custom range)
- Level must be 0-15
- Must contain <description>Rule description here</description>
- Common child elements: <if_sid>, <match>, <regex>, <field name="fieldname">, <same_source_ip/>, <frequency>, <timeframe>, <group>, <mitre><id>T1110</id></mitre>

Output ONLY the corrected XML rule. No explanation.""",
}


# ── Refinement Agent ──────────────────────────────────────────────────────

class RefinementAgent:
    """
    Self-critique refinement loop for SIEM query translation.

    Implements Reflexion-style iterative improvement:
        1. Identify failed platforms and their error types
        2. Select strategy: re-parse IR or patch individual queries
        3. Re-prompt LLM with targeted correction instructions
        4. Re-validate outputs
        5. Repeat until convergence or max_iterations

    Args:
        client:         LLMClient instance.
        parser_agent:   ParserAgent for IR-level re-parsing (optional).
        validator:      ValidatorAgent instance.
        max_iterations: Max refinement rounds (default 2).
        strategy:       "auto" | "ir_reparse" | "query_patch"
    """

    def __init__(
        self,
        client,
        parser_agent=None,
        validator:      ValidatorAgent | None = None,
        max_iterations: int = 2,
        strategy:       str = "auto",
    ) -> None:
        self.client         = client
        self.parser_agent   = parser_agent
        self.validator      = validator or ValidatorAgent()
        self.max_iterations = max_iterations
        self.strategy       = strategy
        self._parser        = ResponseParser()

        log.info(
            "RefinementAgent initialised",
            extra={
                "max_iterations": max_iterations,
                "strategy":       strategy,
                "has_parser":     parser_agent is not None,
            },
        )

    # ─────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────

    def refine(
        self,
        nl_query:     str,
        translations: dict[str, str],
        report:       ValidationReport,
        ir:           IRQuery,
    ) -> RefinementResult:
        """
        Attempt to fix failed SIEM queries through iterative self-critique.

        Args:
            nl_query:     Original natural language query.
            translations: Dict of platform → query string (from translate_all).
            report:       ValidationReport from ValidatorAgent.validate().
            ir:           The IRQuery that produced these translations.

        Returns:
            RefinementResult with final translations and improvement metrics.
        """
        t0 = time.monotonic()

        originally_failed = list(report.failed_platforms)
        if not originally_failed:
            # Nothing to fix
            return RefinementResult(
                nl_query               = nl_query,
                original_translations  = translations,
                final_translations     = translations,
                final_ir               = ir,
                iterations             = 0,
                platforms_fixed        = [],
                platforms_still_failed = [],
                strategy_used          = "none",
                elapsed_s              = 0.0,
            )

        log.info(
            "Starting refinement",
            extra={
                "failed_platforms": originally_failed,
                "strategy":         self.strategy,
            },
        )

        # Select strategy
        strategy = self._select_strategy(originally_failed, report)

        current_translations = dict(translations)
        current_ir           = ir
        iteration_log:  list[dict]  = []
        platforms_fixed: list[str]  = []

        for iteration in range(1, self.max_iterations + 1):
            still_failing = [
                p for p in originally_failed
                if p not in platforms_fixed
            ]
            if not still_failing:
                break

            log.info(
                "Refinement iteration",
                extra={
                    "iteration":      iteration,
                    "still_failing":  still_failing,
                    "strategy":       strategy,
                },
            )

            # ── Strategy: IR re-parse ──────────────────────────────────────
            if strategy == "ir_reparse" and self.parser_agent is not None:
                try:
                    new_ir, new_translations = self._reparse_ir(
                        nl_query=nl_query,
                        current_report=report,
                        current_ir=current_ir,
                    )
                    current_ir           = new_ir
                    current_translations.update(new_translations)
                except Exception as exc:
                    log.warning("IR re-parse failed", extra={"error": str(exc)})

            # ── Strategy: query-level patch ───────────────────────────────
            else:
                for platform in still_failing:
                    result = report.results.get(platform)
                    if result and not result.is_valid:
                        try:
                            fixed_query = self._patch_query(
                                platform     = platform,
                                query        = current_translations.get(platform, ""),
                                error_detail = result.error_detail,
                            )
                            if fixed_query:
                                current_translations[platform] = fixed_query
                        except Exception as exc:
                            log.warning(
                                "Query patch failed",
                                extra={"platform": platform, "error": str(exc)},
                            )

            # Re-validate
            new_report = self.validator.validate(
                translations=current_translations,
                nl_query=nl_query,
            )
            report = new_report

            # Track what was fixed this iteration
            fixed_this_iter   = [p for p in still_failing if p in new_report.valid_platforms]
            still_failing_now = [p for p in still_failing if p not in new_report.valid_platforms]

            platforms_fixed.extend(fixed_this_iter)
            iteration_log.append({
                "iteration":     iteration,
                "strategy":      strategy,
                "fixed":         fixed_this_iter,
                "still_failing": still_failing_now,
                "pass_rate":     new_report.pass_rate,
            })

            log.info(
                "Iteration complete",
                extra={
                    "iteration":     iteration,
                    "fixed":         fixed_this_iter,
                    "still_failing": still_failing_now,
                    "pass_rate":     f"{new_report.pass_rate:.0%}",
                },
            )

        platforms_still_failed = [
            p for p in originally_failed if p not in platforms_fixed
        ]

        elapsed = round(time.monotonic() - t0, 3)
        result  = RefinementResult(
            nl_query               = nl_query,
            original_translations  = translations,
            final_translations     = current_translations,
            final_ir               = current_ir,
            iterations             = len(iteration_log),
            platforms_fixed        = platforms_fixed,
            platforms_still_failed = platforms_still_failed,
            strategy_used          = strategy,
            elapsed_s              = elapsed,
            iteration_log          = iteration_log,
        )

        log.info(
            "Refinement complete",
            extra={
                "fixed":       platforms_fixed,
                "still_failed": platforms_still_failed,
                "improvement": f"{result.improvement_rate:.0%}",
                "elapsed_s":   elapsed,
            },
        )
        return result

    # ─────────────────────────────────────────────
    # Strategy selection
    # ─────────────────────────────────────────────

    def _select_strategy(
        self,
        failed_platforms: list[str],
        report:           ValidationReport,
    ) -> str:
        """
        Select refinement strategy based on failure pattern.

        Rules:
        - "ir_reparse" if >2 platforms fail or error is structural
          (missing_keyword on multiple platforms suggests bad IR)
        - "query_patch" if 1–2 platforms fail with fixable syntax errors
        - "auto" defers to this logic
        """
        if self.strategy != "auto":
            return self.strategy

        n_failed = len(failed_platforms)

        # Many failures → likely IR-level issue
        if n_failed >= 3 and self.parser_agent is not None:
            return "ir_reparse"

        # Check error types — structural errors suggest IR problem
        structural_errors = {"missing_keyword", "missing_aggregate"}
        n_structural = sum(
            1 for p in failed_platforms
            if report.results.get(p) and
               report.results[p].error_type in structural_errors
        )
        if n_structural >= 2 and self.parser_agent is not None:
            return "ir_reparse"

        # Few failures with known fixable errors → patch individually
        return "query_patch"

    # ─────────────────────────────────────────────
    # Strategy implementations
    # ─────────────────────────────────────────────

    def _reparse_ir(
        self,
        nl_query:       str,
        current_report: ValidationReport,
        current_ir:     IRQuery,
    ) -> tuple[IRQuery, dict[str, str]]:
        """
        Re-run the parser agent with a correction hint derived from validation failures.
        Returns new IR and new translations.
        """
        # Build correction hint from all failures
        error_lines = []
        for platform, result in current_report.results.items():
            if not result.is_valid:
                error_lines.append(
                    f"  - {platform}: [{result.error_type}] {result.error_detail}"
                )

        correction_hint = (
            "The previous IR produced invalid queries for these platforms:\n"
            + "\n".join(error_lines)
            + "\n\nFix the IR so all 5 platforms generate valid queries. "
            "Pay special attention to: correct action type, aggregation spec when needed, "
            "and valid canonical field names."
        )

        # Re-parse via parser agent
        parse_result = self.parser_agent.parse(nl_query)
        new_ir       = parse_result.ir

        # Re-translate with new IR
        new_translations = {}
        try:
            new_translations = translate_all(new_ir)
        except Exception as exc:
            log.warning("Re-translation failed after IR re-parse", extra={"error": str(exc)})

        log.debug(
            "IR re-parsed",
            extra={
                "new_summary":   new_ir.summary(),
                "translations":  list(new_translations.keys()),
            },
        )
        return new_ir, new_translations

    def _patch_query(
        self,
        platform:     str,
        query:        str,
        error_detail: str,
    ) -> str | None:
        """
        Send a targeted fix prompt to the LLM for a single platform query.

        Returns the fixed query string, or None if patching failed.
        """
        template = _FIX_PROMPTS.get(platform)
        if not template:
            log.warning("No fix prompt template for platform", extra={"platform": platform})
            return None

        prompt = template.format(
            error_detail=error_detail,
            query=query,
        )

        messages = [
            {
                "role": "system",
                "content": (
                    f"You are a {platform.upper()} SIEM query expert. "
                    "Fix syntax errors in queries precisely. "
                    "Output ONLY the corrected query, nothing else."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        try:
            response = self.client.complete(
                messages   = messages,
                max_tokens = 1024,
                temperature = 0.0,
            )
            fixed = self._clean_response(response, platform)
            log.debug(
                "Query patched",
                extra={"platform": platform, "chars": len(fixed)},
            )
            return fixed if fixed else None

        except Exception as exc:
            log.warning(
                "Patch LLM call failed",
                extra={"platform": platform, "error": str(exc)},
            )
            return None

    # ─────────────────────────────────────────────
    # Response cleaning
    # ─────────────────────────────────────────────

    def _clean_response(self, response: str, platform: str) -> str:
        """
        Strip markdown fences and preamble from LLM fix response.
        For Wazuh, extract XML; for others, extract the query text.
        """
        if not response:
            return ""

        response = response.strip()

        # Strip markdown code fences
        import re
        fence_match = re.search(r"```(?:\w+)?\s*([\s\S]*?)```", response)
        if fence_match:
            return fence_match.group(1).strip()

        # For Wazuh, find XML block
        if platform == "wazuh":
            xml_match = re.search(r"(<rule[\s\S]*?</rule>)", response, re.IGNORECASE)
            if xml_match:
                return xml_match.group(1).strip()

        # For SQL-like (QRadar), find SELECT block
        if platform == "qradar":
            sel_match = re.search(r"(SELECT[\s\S]+)", response, re.IGNORECASE)
            if sel_match:
                return sel_match.group(1).strip()

        # For Sentinel/Splunk, find first table or index line
        if platform in ("sentinel", "splunk"):
            lines = response.split("\n")
            # Find first non-empty, non-preamble line
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped and not stripped.startswith(("#", "//", "Note:", "Fixed:", "Here")):
                    return "\n".join(lines[i:]).strip()

        return response

    def __repr__(self) -> str:
        return (
            f"RefinementAgent("
            f"strategy={self.strategy!r}, "
            f"max_iterations={self.max_iterations}, "
            f"has_parser={self.parser_agent is not None})"
        )