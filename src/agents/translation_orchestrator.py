"""
Translation Orchestrator — the main NL-SIEM pipeline entry point.

Wires together all five layers into a single coherent pipeline:

    NL Query
        ↓
    ParserAgent          (Layer 5) — NL → IR via LLM + RAG
        ↓
    translate_all()      (Layer 2) — IR → 5 SIEM query strings
        ↓
    ValidatorAgent       (Layer 5) — syntax check all 5 outputs
        ↓
    [RefinementAgent]    (Layer 5) — self-critique fix loop (if failures)
        ↓
    TranslationResult    — final outputs + full metadata

Design:
    - Single entry point: orchestrator.translate(nl_query) → TranslationResult
    - Configurable: swap providers, conditions, enable/disable RAG + refinement
    - Evaluation-ready: every result carries the full audit trail
    - Batch: orchestrator.translate_batch(queries) → list[TranslationResult]
    - Ablation-ready: run with different PromptCondition values for comparison

Place at: src/agents/translation_orchestrator.py

Usage:
    from src.agents.translation_orchestrator import TranslationOrchestrator

    # Minimal setup (Groq, few-shot, no RAG)
    orc = TranslationOrchestrator.from_env()
    result = orc.translate("Detect SSH brute force exceeding 50 attempts in 10 minutes")

    print(result.splunk)
    print(result.qradar)
    print(result.elastic)
    print(result.sentinel)
    print(result.wazuh)
    print(result.summary())

    # With RAG
    orc = TranslationOrchestrator.from_env(enable_rag=True)

    # Ablation study
    for condition in ["zero_shot", "few_shot", "rag"]:
        orc = TranslationOrchestrator.from_env(condition=condition)
        result = orc.translate(query)
        save_result(result, condition)
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from src.agents.parser_agent import ParseResult, ParserAgent
from src.agents.refinement_agent import RefinementAgent, RefinementResult
from src.agents.validator_agent import ValidatorAgent, ValidationReport
from src.ir.schema import IRQuery
from src.translators import translate_all
from src.utils.exceptions import NLSIEMError, TranslationError
from src.utils.logger import get_logger
from src.agents.execution_agent import ExecutionAgent, ExecutionResult
log = get_logger(__name__)
from src.agents.rule_deployment_agent import (
    RuleDeploymentAgent
)
PromptCondition = Literal["zero_shot", "few_shot", "rag"]


# ── Translation Result ────────────────────────────────────────────────────

@dataclass
class TranslationResult:
    """
    Complete output of the NL-SIEM pipeline for a single query.

    Contains the final SIEM queries, IR, validation report,
    and full provenance for evaluation and paper metrics.
    """

    # ── Identity ──────────────────────────────────────────────────────────
    run_id:    str
    nl_query:  str

    # ── Final SIEM outputs ────────────────────────────────────────────────
    splunk:   str
    qradar:   str
    elastic:  str
    sentinel: str
    wazuh:    str

    # ── IR ────────────────────────────────────────────────────────────────
    ir: IRQuery

    # ── Pipeline metadata ─────────────────────────────────────────────────
    parse_result:       ParseResult
    validation_report:  ValidationReport
    refinement_result:  RefinementResult | None
    condition:          str       # few_shot | zero_shot | rag
    provider:           str       # groq | gemini | ollama | openrouter
    model:              str

    # ── Timing ────────────────────────────────────────────────────────────
    elapsed_s:          float

    # ── Evaluation helpers ────────────────────────────────────────────────
    warnings: list[str] = field(default_factory=list)
    execution_results: dict[str, ExecutionResult] | None = None
    deployment_result: Any | None = None

    # ─────────────────────────────────────────────
    # Convenience accessors
    # ─────────────────────────────────────────────

    @property
    def translations(self) -> dict[str, str]:
        return {
            "splunk":   self.splunk,
            "qradar":   self.qradar,
            "elastic":  self.elastic,
            "sentinel": self.sentinel,
            "wazuh":    self.wazuh,
        }

    @property
    def all_valid(self) -> bool:
        return self.validation_report.all_valid

    @property
    def valid_platforms(self) -> list[str]:
        return self.validation_report.valid_platforms

    @property
    def failed_platforms(self) -> list[str]:
        return self.validation_report.failed_platforms

    @property
    def pass_rate(self) -> float:
        return self.validation_report.pass_rate

    @property
    def parse_attempts(self) -> int:
        return self.parse_result.attempts

    @property
    def refinement_used(self) -> bool:
        return self.refinement_result is not None

    # ─────────────────────────────────────────────
    # Serialisation
    # ─────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Full JSON-serialisable representation for storing results."""
        return {
            "run_id":           self.run_id,
            "nl_query":         self.nl_query,
            "ir":               self.ir.to_dict(),
            "execution_results": (
                    {
                        k: {
                            "success": v.success,
                            "execution_time": v.execution_time,
                            "error": v.error,
                        }
                        for k, v in self.execution_results.items()
                    }
                    if self.execution_results
                    else None
                ),
            "translations":     self.translations,
            "condition":        self.condition,
            "provider":         self.provider,
            "model":            self.model,
            "elapsed_s":        self.elapsed_s,
            "parse_attempts":   self.parse_attempts,
            "rag_used":         self.parse_result.rag_used,
            "refinement_used":  self.refinement_used,
            "validation": {
                "pass_rate":       self.pass_rate,
                "valid_platforms": self.valid_platforms,
                "failed_platforms": self.failed_platforms,
            },
            "warnings": self.warnings,
            "refinement": self.refinement_result.to_dict() if self.refinement_result else None,
        }

    def summary(self) -> str:
        """Human-readable one-block summary for CLI output."""

        lines = [
            f"{'─' * 60}",
            f"NL-SIEM Translation Result",
            f"{'─' * 60}",
            f"Query:      {self.nl_query}",
            f"IR:         {self.ir.summary()}",
            f"Condition:  {self.condition}  |  Model: {self.model}",
            f"Elapsed:    {self.elapsed_s}s  |  Parse attempts: {self.parse_attempts}",
            f"Validation: {self.pass_rate:.0%} ({len(self.valid_platforms)}/5 platforms)",
        ]

        if self.execution_results:
            lines.append("")
            lines.append("Execution Results")
            lines.append("─" * 60)

            for platform, result in self.execution_results.items():

                status = (
                    "SUCCESS"
                    if result.success
                    else "FAILED"
                )

                lines.append(
                    f"{platform}: {status} "
                    f"({result.execution_time:.3f}s)"
                )

                if result.error:
                    lines.append(
                        f"  Error: {result.error}"
                    )

        lines.extend([
            "",
            f"── Splunk SPL {'─' * 44}",
            self.splunk,
            "",
            f"── QRadar AQL {'─' * 44}",
            self.qradar,
            "",
            f"── Elastic EQL {'─' * 43}",
            self.elastic,
            "",
            f"── Sentinel KQL {'─' * 42}",
            self.sentinel,
            "",
            f"── Wazuh XML {'─' * 45}",
            self.wazuh,
            f"{'─' * 60}",
        ])

        if self.failed_platforms:
            lines.append(
                f"⚠ Failed platforms: {self.failed_platforms}"
            )

        if self.warnings:
            for warning in self.warnings:
                lines.append(
                    f"⚠ {warning}"
                )

        return "\n".join(lines)

# ── Translation Orchestrator ──────────────────────────────────────────────

class TranslationOrchestrator:
    """
    Main pipeline entry point for the NL-SIEM system.

    Orchestrates: ParserAgent → translate_all → ValidatorAgent → [RefinementAgent]

    Args:
        parser_agent:       Configured ParserAgent (LLM + prompts + optional RAG).
        validator:          ValidatorAgent for syntax checking.
        refinement_agent:   Optional RefinementAgent. If None, skips refinement.
        enable_refinement:  Toggle refinement on/off (default True).
        provider:           Provider label for result metadata.
        model:              Model label for result metadata.
        condition:          Prompt condition for result metadata.
    """

    def __init__(
        self,
        parser_agent:       ParserAgent,
        execution_agent: ExecutionAgent | None = None,
        validator:          ValidatorAgent | None        = None,
        refinement_agent:   RefinementAgent | None       = None,
        enable_refinement:  bool                         = True,
        provider:           str                          = "groq",
        model:              str                          = "llama-3.1-70b-versatile",
        condition:          PromptCondition               = "few_shot",
    ) -> None:
        self.parser_agent      = parser_agent
        self.validator         = validator or ValidatorAgent()
        self.refinement_agent  = refinement_agent
        self.enable_refinement = enable_refinement
        self.provider          = provider
        self.model             = model
        self.execution_agent = execution_agent
        self.condition         = condition
        self.rule_deployment_agent = (
            RuleDeploymentAgent()
        )
        log.info(
            "TranslationOrchestrator initialised",
            extra={
                "condition":   condition,
                "provider":    provider,
                "model":       model,
                "refinement":  enable_refinement and refinement_agent is not None,
                "rag": getattr(parser_agent, "retriever", None) is not None,
            },
        )

    # ─────────────────────────────────────────────
    # Factory methods
    # ─────────────────────────────────────────────

    @classmethod
    def from_env(
        cls,
        condition:        PromptCondition = "few_shot",
        enable_rag:       bool            = False,
        enable_refinement: bool           = True,
        store_path:       str             = "src/rag/store",
    ) -> "TranslationOrchestrator":
        """
        Build a fully configured orchestrator from environment variables.

        Reads:
            LLM_PROVIDER, LLM_MODEL, GROQ_API_KEY / GOOGLE_API_KEY,
            TEMPERATURE, MAX_TOKENS, LLM_TIMEOUT, LLM_MAX_RETRIES

        Args:
            condition:         Prompt strategy (zero_shot | few_shot | rag).
            enable_rag:        Load RAG retriever from store_path.
            enable_refinement: Enable self-critique refinement loop.
            store_path:        Path prefix for FAISS store (used when enable_rag=True).

        Returns:
            Configured TranslationOrchestrator ready for use.
        """
        import os
        from src.llm.client import LLMClient

        # Build LLM client
        client   = LLMClient.from_env()
        provider = client.provider
        model    = client.model

        # Build RAG retriever (optional)
        retriever = None
        if enable_rag or condition == "rag":
            try:
                from src.rag.retriever import Retriever
                retriever = Retriever.from_store(store_path)
                log.info("RAG retriever loaded", extra={"store": store_path})
            except Exception as exc:
                log.warning(
                    "RAG store not found — falling back to few_shot without RAG. "
                    "Run: python scripts/ingest_knowledge_base.py",
                    extra={"error": str(exc)},
                )
                if condition == "rag":
                    condition = "few_shot"

        # Build parser agent
        parser = ParserAgent(
            client    = client,
            retriever = retriever,
            condition = condition,
            provider  = provider,
        )

        # Build refinement agent
        refinement = None
        if enable_refinement:
            refinement = RefinementAgent(
                client       = client,
                parser_agent = parser,
            )
        from src.agents.execution_agent import ExecutionAgent

        execution_agent = ExecutionAgent(
            connector_configs={
                "wazuh": {
                    "host": "https://localhost:55000",
                    "username": "wazuh",
                    "password": "u.PDwheS.PDWdPtREknLuyv5SFVrW+I7"
                },


                # Fill later when Splunk is running
                "splunk": {
                    "host": "https://localhost:8089",
                    "username": "admin",
                    "password": "changeme"
                }
            }
        )    

        return cls(
            parser_agent      = parser,
            execution_agent    = execution_agent,
            refinement_agent  = refinement,
            enable_refinement = enable_refinement,
            provider          = provider,
            model             = model,
            condition         = condition,
        )

    @classmethod
    def for_ablation(
        cls,
        condition: PromptCondition,
        store_path: str = "src/rag/store",
    ) -> "TranslationOrchestrator":
        """
        Build an orchestrator configured for an ablation study condition.

        Maps cleanly to the three ablation conditions in Table 2:
            zero_shot → no examples, no RAG
            few_shot  → 3 examples, no RAG
            rag       → 3 examples + retrieved SIEM docs

        Args:
            condition:  "zero_shot" | "few_shot" | "rag"
            store_path: FAISS store path (only used for "rag").

        Returns:
            Configured TranslationOrchestrator.
        """
        enable_rag = (condition == "rag")
        return cls.from_env(
            condition         = condition,
            enable_rag        = enable_rag,
            enable_refinement = False,  # disabled in ablation for clean comparison
        )

    # ─────────────────────────────────────────────
    # Core pipeline
    # ─────────────────────────────────────────────

    def translate(self, nl_query: str , execute : bool = False) -> TranslationResult:
        """
        Run the full NL-SIEM pipeline for a single natural language query.

        Pipeline:
            1. ParserAgent: NL → IRQuery (with retries)
            2. translate_all: IRQuery → 5 platform queries
            3. ValidatorAgent: syntax check all 5 outputs
            4. RefinementAgent: fix failures (if enabled + failures exist)
            5. Return TranslationResult

        Args:
            nl_query: Free-text security detection description.

        Returns:
            TranslationResult with all 5 SIEM queries and full metadata.

        Raises:
            NLSIEMError: If parsing fails after all retries.
        """
        t0     = time.monotonic()
        run_id = str(uuid.uuid4())[:8]
        warnings: list[str] = []

        log.info(
            "Pipeline start",
            extra={"run_id": run_id, "query": nl_query[:80]},
        )

        # ── Step 1: Parse NL → IR ─────────────────────────────────────────
        parse_result = self.parser_agent.parse(nl_query)
        ir           = parse_result.ir
        warnings.extend(parse_result.warnings)

        log.info(
            "IR parsed",
            extra={
                "run_id":   run_id,
                "attempts": parse_result.attempts,
                "ir":       ir.summary(),
            },
        )

        # ── Step 2: Translate IR → 5 SIEM queries ────────────────────────
        raw_translations = self._safe_translate_all(ir, run_id)
        warnings.extend([
            f"{p}: translation error — {q[len('ERROR:'):]}"
            for p, q in raw_translations.items()
            if q.startswith("ERROR:")
        ])

        # ── Step 3: Validate all outputs ─────────────────────────────────
        validation_report = self.validator.validate(
            translations = raw_translations,
            nl_query     = nl_query,
        )

        log.info(
            "Validation complete",
            extra={
                "run_id":    run_id,
                "pass_rate": f"{validation_report.pass_rate:.0%}",
                "failed":    validation_report.failed_platforms,
            },
        )

        # ── Step 4: Refinement (if enabled and failures exist) ────────────
        refinement_result = None
        final_translations = raw_translations

        if (
            self.enable_refinement
            and self.refinement_agent is not None
            and not validation_report.all_valid
        ):
            log.info(
                "Starting refinement",
                extra={
                    "run_id":  run_id,
                    "failing": validation_report.failed_platforms,
                },
            )
            refinement_result = self.refinement_agent.refine(
                nl_query     = nl_query,
                translations = raw_translations,
                report       = validation_report,
                ir           = ir,
            )
            final_translations = refinement_result.final_translations
            ir                 = refinement_result.final_ir

            # Re-validate after refinement
            validation_report = self.validator.validate(
                translations = final_translations,
                nl_query     = nl_query,
            )

            log.info(
                "Post-refinement validation",
                extra={
                    "run_id":    run_id,
                    "pass_rate": f"{validation_report.pass_rate:.0%}",
                    "fixed":     refinement_result.platforms_fixed,
                },
            )
        execution_results = None

        if (
            execute
            and self.execution_agent is not None
        ):
            execution_results = (
                self.execution_agent.execute_all(
                    {
                        "splunk": final_translations.get("splunk", ""),
                        "elastic": final_translations.get("elastic", ""),
                        "wazuh": final_translations.get("wazuh", ""),
                    }
                )
            )
        deployment_result = None
        if (
            execute
            and final_translations.get("wazuh")
        ):
            deployment_result = (
                self.rule_deployment_agent.deploy(
                    final_translations["wazuh"]
                )
            )
            print("\nDEPLOYMENT RESULT:")
            print(deployment_result)
        elapsed = round(time.monotonic() - t0, 3)

        result = TranslationResult(
            execution_results = execution_results,
            run_id             = run_id,
            nl_query           = nl_query,
            deployment_result   = deployment_result,
            splunk             = final_translations.get("splunk",   ""),
            qradar             = final_translations.get("qradar",   ""),
            elastic            = final_translations.get("elastic",  ""),
            sentinel           = final_translations.get("sentinel", ""),
            wazuh              = final_translations.get("wazuh",    ""),
            ir                 = ir,
            parse_result       = parse_result,
            validation_report  = validation_report,
            refinement_result  = refinement_result,
            condition          = self.condition,
            provider           = self.provider,
            model              = self.model,
            elapsed_s          = elapsed,
            warnings           = warnings,
        )

        log.info(
            "Pipeline complete",
            extra={
                "run_id":    run_id,
                "pass_rate": f"{result.pass_rate:.0%}",
                "elapsed_s": elapsed,
                "refined":   refinement_result is not None,
            },
        )
        return result

    def translate_batch(
        self,
        nl_queries:   list[str],
        delay_s:      float = 0.5,
        save_path:    Path | None = None,
    ) -> tuple[list[TranslationResult], list[dict]]:
        """
        Translate a list of NL queries through the full pipeline.

        Args:
            nl_queries: List of natural language query strings.
            delay_s:    Delay between queries (rate limit management).
            save_path:  Optional JSONL file to append results incrementally.

        Returns:
            Tuple of (successful TranslationResults, list of failure dicts).
        """
        successes: list[TranslationResult] = []
        failures:  list[dict]              = []

        log.info(
            "Batch translation start",
            extra={"total": len(nl_queries), "condition": self.condition},
        )

        for i, query in enumerate(nl_queries):
            try:
                result = self.translate(query)
                successes.append(result)

                # Incremental save
                if save_path is not None:
                    self._append_result(result, save_path)

                log.info(
                    "Batch progress",
                    extra={
                        "done":  i + 1,
                        "total": len(nl_queries),
                        "query": query[:60],
                        "valid": result.pass_rate >= 1.0,
                    },
                )

            except NLSIEMError as exc:
                log.error(
                    "Batch translation failure",
                    extra={"index": i, "query": query[:60], "error": str(exc)},
                )
                failures.append({
                    "index":    i,
                    "nl_query": query,
                    "error":    str(exc),
                    "details":  exc.details,
                })

            if delay_s > 0 and i < len(nl_queries) - 1:
                time.sleep(delay_s)

        log.info(
            "Batch translation complete",
            extra={
                "total":    len(nl_queries),
                "success":  len(successes),
                "failures": len(failures),
                "avg_pass_rate": (
                    sum(r.pass_rate for r in successes) / len(successes)
                    if successes else 0.0
                ),
            },
        )
        return successes, failures

    # ─────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────

    def _safe_translate_all(self, ir: IRQuery, run_id: str) -> dict[str, str]:
        """
        Call translate_all and gracefully handle per-platform failures.
        Returns dict with ERROR: prefix for failed platforms.
        """
        try:
            translations = translate_all(ir)
        except Exception as exc:
            log.error(
                "translate_all failed entirely",
                extra={"run_id": run_id, "error": str(exc)},
            )
            translations = {
                p: f"ERROR: translate_all failed: {exc}"
                for p in ("splunk", "qradar", "elastic", "sentinel", "wazuh")
            }

        # Log any per-platform errors
        for platform, query in translations.items():
            if query.startswith("ERROR:"):
                log.warning(
                    "Translation error for platform",
                    extra={"run_id": run_id, "platform": platform, "error": query},
                )

        return translations

    @staticmethod
    def _append_result(result: TranslationResult, path: Path) -> None:
        """Append a single result to a JSONL file."""
        import json
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(result.to_dict(), ensure_ascii=False) + "\n")

    def __repr__(self) -> str:
        return (
            f"TranslationOrchestrator("
            f"condition={self.condition!r}, "
            f"provider={self.provider!r}, "
            f"model={self.model!r}, "
            f"rag={getattr(self.parser_agent, 'retriever', None) is not None}, "
            f"refinement={self.enable_refinement and self.refinement_agent is not None})"
        )