"""
Parser Agent — converts a natural language security query into a validated IRQuery.

Pipeline for a single NL input:
    1. (Optional) RAG: retrieve relevant SIEM doc chunks as context
    2. Build few-shot / chain-of-thought prompt via PromptBuilder
    3. Call LLM (Groq / Gemini / Ollama) with JSON mode
    4. Parse + extract JSON via ResponseParser
    5. Coerce + validate via IR validator
    6. Return IRQuery or raise with structured error detail

Retry logic:
    On parse or validation failure the agent re-prompts up to max_retries times,
    injecting the previous error as a correction hint so the LLM can self-fix.

Place at: src/agents/parser_agent.py

Usage:
    from src.agents.parser_agent import ParserAgent
    from src.llm import groq_client

    agent = ParserAgent(client=groq_client())
    ir    = agent.parse("Detect SSH brute force exceeding 20 attempts in 5 minutes")
    print(ir.summary())
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from src.ir.schema import IRQuery
from src.ir.validator import coerce_ir
from src.llm.prompts import PromptBuilder, PromptCondition, ProviderHint
from src.llm.response_parser import ResponseParser
from src.utils.exceptions import (
    IRCoercionError,
    IRValidationError,
    LLMError,
    NLSIEMError,
)
from src.utils.logger import get_logger

log = get_logger(__name__)


# ── Parse result dataclass ────────────────────────────────────────────────
@dataclass
class ParseResult:
    """Full output of a single ParserAgent.parse() call."""

    ir:           IRQuery            # validated intermediate representation
    nl_query:     str                # original NL input
    attempts:     int                # LLM calls made (1 = success on first try)
    elapsed_s:    float              # wall-clock seconds
    rag_used:     bool               # whether RAG context was injected
    condition:    str                # prompt condition used (few_shot / chain_of_thought / rag)
    warnings:     list[str] = field(default_factory=list)  # non-fatal coercion warnings
    raw_response: str = ""           # last LLM response (for debugging)

    def to_dict(self) -> dict:
        return {
            "nl_query":  self.nl_query,
            "ir":        self.ir.to_dict(),
            "attempts":  self.attempts,
            "elapsed_s": self.elapsed_s,
            "rag_used":  self.rag_used,
            "condition": self.condition,
            "warnings":  self.warnings,
        }


# ── Parser Agent ──────────────────────────────────────────────────────────
class ParserAgent:
    """
    Converts natural language security queries to validated IRQuery objects.

    Args:
        client:       LLMClient instance (Groq, Gemini, Ollama, OpenRouter).
        retriever:    Optional RAG Retriever. If provided, context is injected.
        condition:    Prompting strategy: few_shot | zero_shot | chain_of_thought | rag.
        max_retries:  Number of correction re-prompts on parse/validation failure.
        provider:     Provider hint for prompt formatting (groq / gemini / ollama).
        rag_k:        Number of RAG chunks to retrieve per query.
    """

    def __init__(
        self,
        client,
        retriever=None,
        condition:   PromptCondition = "few_shot",
        max_retries: int             = 3,
        provider:    ProviderHint    = "auto",
        rag_k:       int             = 5,
    ) -> None:
        self.client      = client
        self.retriever   = retriever
        self.condition   = condition
        self.max_retries = max_retries
        self.provider    = provider
        self.rag_k       = rag_k

        self._prompt_builder = PromptBuilder()
        self._response_parser = ResponseParser()

        log.info(
            "ParserAgent initialised",
            extra={
                "condition":   condition,
                "max_retries": max_retries,
                "rag":         retriever is not None,
                "provider":    provider,
            },
        )

    # ─────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────

    def parse(self, nl_query: str) -> ParseResult:
        """
        Parse a natural language query into a validated IRQuery.

        Args:
            nl_query: Free-text detection intent from the analyst.

        Returns:
            ParseResult containing the IRQuery and run metadata.

        Raises:
            NLSIEMError: If all retry attempts fail.
        """
        t0 = time.monotonic()

        # ── Step 1: RAG context retrieval ─────────────────────────────────
        rag_context = ""
        rag_used    = False
        if self.retriever is not None:
            try:
                rag_context = self.retriever.retrieve_for_prompt(
                    nl_query, k=self.rag_k
                )
                rag_used = bool(rag_context)
                log.debug("RAG context retrieved", extra={"chars": len(rag_context)})
            except Exception as exc:
                log.warning("RAG retrieval failed, continuing without context",
                            extra={"error": str(exc)})

        # ── Step 2: Determine effective condition ──────────────────────────
        effective_condition: PromptCondition = (
            "rag" if (rag_used and self.condition != "zero_shot") else self.condition
        )

        # ── Step 3: Retry loop ────────────────────────────────────────────
        last_error: str = ""
        warnings:   list[str] = []
        raw_response: str = ""

        for attempt in range(1, self.max_retries + 1):
            try:
                log.debug(
                    "Parse attempt",
                    extra={"attempt": attempt, "condition": effective_condition},
                )

                # Build prompt — inject error hint on retries
                messages = self._prompt_builder.build_ir_prompt(
                    nl_query         = nl_query,
                    condition        = effective_condition,
                    provider         = self.provider,
                    rag_context      = rag_context if rag_used else None,
                    correction_hint  = last_error if attempt > 1 else None,
                )

                # LLM call with JSON mode
                raw_response = self.client.complete(
                    messages  = messages,
                    json_mode = True,
                )

                log.debug("LLM responded", extra={"chars": len(raw_response), "attempt": attempt})

                # Parse JSON from LLM output
                ir_dict, parse_warnings = self._response_parser.extract_and_validate(raw_response)
                warnings.extend(parse_warnings)

                # Inject original NL for traceability
                ir_dict.setdefault("nl_query", nl_query)

                # Coerce + validate against IR schema
                ir = coerce_ir(ir_dict)

                elapsed = round(time.monotonic() - t0, 3)
                log.info(
                    "IR parsed successfully",
                    extra={
                        "attempts": attempt,
                        "elapsed":  elapsed,
                        "summary":  ir.summary(),
                    },
                )

                return ParseResult(
                    ir           = ir,
                    nl_query     = nl_query,
                    attempts     = attempt,
                    elapsed_s    = elapsed,
                    rag_used     = rag_used,
                    condition    = effective_condition,
                    warnings     = warnings,
                    raw_response = raw_response,
                )

            except (IRValidationError, IRCoercionError) as exc:
                last_error = (
                    f"The previous IR was invalid: {exc.message}. "
                    f"Fix these issues and try again: {exc.details}"
                )
                log.warning(
                    "IR validation failed — will retry",
                    extra={"attempt": attempt, "error": str(exc)},
                )

            except LLMError as exc:
                print("\n" + "=" * 80)
                print("LLM ERROR")
                print("=" * 80)
                print(type(exc))
                print(exc)
                print("=" * 80)

                raise

            except Exception as exc:
                import traceback

                print("\n" + "=" * 80)
                print("UNEXPECTED PARSE ERROR")
                print("=" * 80)
                traceback.print_exc()
                print("=" * 80)

                last_error = str(exc)
                raise
            # Exponential backoff between retries (skip on last)
            if attempt < self.max_retries:
                time.sleep(min(2 ** attempt, 10))

        # All retries exhausted
        elapsed = round(time.monotonic() - t0, 3)
        raise NLSIEMError(
            f"ParserAgent failed after {self.max_retries} attempts for query: '{nl_query[:80]}'",
            details={
                "nl_query":     nl_query,
                "last_error":   last_error,
                "attempts":     self.max_retries,
                "elapsed_s":    elapsed,
                "raw_response": raw_response[:500],
            },
        )

    def parse_batch(
        self,
        nl_queries: list[str],
        delay_s:    float = 0.0,
    ) -> tuple[list[ParseResult], list[dict]]:
        """
        Parse a list of NL queries, collecting successes and failures separately.

        Args:
            nl_queries: List of natural language query strings.
            delay_s:    Optional delay between queries (useful for rate-limited APIs).

        Returns:
            Tuple of (successful ParseResults, list of failure dicts).
        """
        successes: list[ParseResult] = []
        failures:  list[dict]        = []

        for i, query in enumerate(nl_queries):
            try:
                result = self.parse(query)
                successes.append(result)
                log.info(
                    "Batch parse progress",
                    extra={"done": i + 1, "total": len(nl_queries), "query": query[:60]},
                )
            except NLSIEMError as exc:
                log.error(
                    "Batch parse failure",
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
            "Batch parse complete",
            extra={
                "total":    len(nl_queries),
                "success":  len(successes),
                "failures": len(failures),
            },
        )
        return successes, failures

    # ─────────────────────────────────────────────
    # Configuration helpers
    # ─────────────────────────────────────────────

    def with_condition(self, condition: PromptCondition) -> "ParserAgent":
        """Return a copy of this agent with a different prompt condition."""
        return ParserAgent(
            client      = self.client,
            retriever   = self.retriever,
            condition   = condition,
            max_retries = self.max_retries,
            provider    = self.provider,
            rag_k       = self.rag_k,
        )

    def __repr__(self) -> str:
        return (
            f"ParserAgent("
            f"condition={self.condition!r}, "
            f"max_retries={self.max_retries}, "
            f"rag={self.retriever is not None})"
        )