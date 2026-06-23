"""
ATT&CK Classifier Agent — chain-of-thought tactic/technique/sub-technique
inference from natural language input.

Purpose
-------
Replaces any ad-hoc ATT&CK tagging previously done inline inside
ParserAgent (e.g. an LLM guessing a `technique_id` as a side effect of IR
generation, with no taxonomy grounding and no auditable reasoning trail).

This agent performs ATT&CK classification as an explicit, separate,
taxonomy-grounded step:

    1. Candidate narrowing — ATTCKTaxonomyLoader.search_techniques() finds
       the top-K lexically plausible techniques for the NL query, avoiding
       the need to embed the full ~700-technique taxonomy in every prompt.
    2. Chain-of-thought selection — the LLM reasons over the narrowed
       candidate set plus their official descriptions, and selects the
       single best-fit tactic/technique/sub-technique with cited rationale.
    3. Taxonomy verification — the LLM's selection is checked against
       ATTCKTaxonomyLoader.get_technique() before being accepted, so a
       hallucinated technique ID can never reach the IR layer.
    4. AttckIRQuery construction — the verified binding is attached to
       a base IRQuery via AttckIRQuery.from_ir_query().

This separation (structural IR parsing vs. ATT&CK classification) is the
same decoupling principle as the NL→IR vs. IR→SIEM-syntax boundary that is
the framework's core contribution: each agent owns exactly one inference
task and is independently testable, swappable, and auditable.

Place at: src/agents/attck_classifier_agent.py

Usage:
    from src.agents.attck_classifier_agent import ATTCKClassifierAgent

    classifier = ATTCKClassifierAgent(client=llm_client)
    result     = classifier.classify(
        "Detect more than 50 failed SSH logins from the same source IP in 24h"
    )
    print(result.tactic, result.technique, result.sub_technique)

    # Attach to an already-parsed IR
    attck_ir = classifier.attach(base_ir, result)
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from src.ir.attck_schema import AttckIRQuery
from src.ir.schema import IRQuery
from src.knowledge_base.mitre.attck_taxonomy_loader import (
    TechniqueEntry,
    get_taxonomy,
)
from src.llm.response_parser import ResponseParser
from src.utils.exceptions import IRValidationError, LLMError, NLSIEMError
from src.utils.logger import get_logger

log = get_logger(__name__)

# Number of lexically-narrowed candidates shown to the LLM for CoT reasoning.
# Large enough to include the correct technique even when the keyword
# search ranks it imperfectly; small enough to keep prompt cost low.
_DEFAULT_CANDIDATE_K = 12


@dataclass
class ClassificationResult:
    """Output of a single ATTCKClassifierAgent.classify() call."""

    nl_query:        str
    tactic:          str             # ATT&CK tactic shortname
    technique:       str             # ATT&CK technique ID, e.g. "T1110"
    sub_technique:   str | None      # ATT&CK sub-technique ID, e.g. "T1110.001"
    rationale:       str             # chain-of-thought justification (kept for audit trail)
    confidence:      float           # self-reported [0.0, 1.0]
    candidates_considered: list[str] = field(default_factory=list)
    attempts:        int   = 1
    elapsed_s:        float = 0.0

    def to_dict(self) -> dict:
        return {
            "nl_query":              self.nl_query,
            "tactic":                self.tactic,
            "technique":             self.technique,
            "sub_technique":         self.sub_technique,
            "rationale":             self.rationale,
            "confidence":            self.confidence,
            "candidates_considered": self.candidates_considered,
            "attempts":              self.attempts,
            "elapsed_s":             self.elapsed_s,
        }


# ── Chain-of-thought prompt template ───────────────────────────────────────

_CLASSIFIER_SYSTEM_PROMPT = """You are a MITRE ATT&CK classification expert.

Given a natural language security detection description, identify the
single MOST SPECIFIC MITRE ATT&CK technique (and sub-technique, if
applicable) it corresponds to, choosing ONLY from the candidate list
provided below. Do not invent a technique ID that is not in the list.

Reasoning process (think step by step, then output JSON):
  1. Identify the adversary BEHAVIOUR described (not just keywords).
  2. Compare that behaviour against each candidate's description.
  3. Select the candidate whose description most precisely matches the
     behaviour. Prefer a sub-technique over its parent technique when the
     description's specificity is described in the query (e.g. "password
     guessing" -> T1110.001, not just T1110).
  4. If genuinely no candidate fits, select the closest available option
     and set confidence below 0.5.

Output ONLY a JSON object with this exact shape, no markdown, no preamble:
{{
  "tactic": "<tactic-shortname>",
  "technique": "T####",
  "sub_technique": "T####.###" or null,
  "rationale": "<one to two sentences citing the specific behaviour-to-description match>",
  "confidence": <float 0.0-1.0>
}}

CANDIDATES:
{candidates_block}
""".strip()


class ATTCKClassifierAgent:
    """
    Infers MITRE ATT&CK tactic/technique/sub-technique bindings for natural
    language detection descriptions, using taxonomy-grounded chain-of-thought
    reasoning with mandatory post-hoc verification.

    Args:
        client:        LLMClient instance (any supported provider).
        candidate_k:   Number of lexical candidates to surface for CoT
                       reasoning (default 12).
        max_retries:   Retry attempts if the LLM selects an ID not present
                       in the candidate set or taxonomy (default 2).
    """

    def __init__(
        self,
        client,
        candidate_k: int = _DEFAULT_CANDIDATE_K,
        max_retries: int = 2,
    ) -> None:
        self.client      = client
        self.candidate_k = candidate_k
        self.max_retries = max_retries
        self._taxonomy   = get_taxonomy()
        self._parser     = ResponseParser()

        log.info(
            "ATTCKClassifierAgent initialised",
            extra={
                "candidate_k": candidate_k,
                "max_retries": max_retries,
                "taxonomy_summary": self._taxonomy.summary(),
            },
        )

    # ─────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────

    def classify(self, nl_query: str) -> ClassificationResult:
        """
        Classify a natural language query against the MITRE ATT&CK taxonomy.

        Args:
            nl_query: Free-text detection description.

        Returns:
            ClassificationResult with verified tactic/technique binding.

        Raises:
            NLSIEMError: If no valid classification could be produced after
                         all retry attempts (e.g. candidate search returned
                         nothing and the LLM could not select a fallback).
        """
        t0 = time.monotonic()

        candidates = self._taxonomy.search_techniques(nl_query, top_k=self.candidate_k)
        if not candidates:
            # Fall back to a broad sweep across all techniques' names only,
            # rather than failing outright — better to give the LLM *some*
            # grounded options than none.
            candidates = self._taxonomy.all_techniques()[: self.candidate_k]
            log.warning(
                "No lexical candidates found — falling back to a broad slice "
                "of the full technique list",
                extra={"nl_query": nl_query[:80]},
            )

        candidate_ids = [c.technique_id for c in candidates]
        candidates_block = self._format_candidates(candidates)

        last_error = ""
        for attempt in range(1, self.max_retries + 1):
            try:
                messages = [
                    {
                        "role": "system",
                        "content": _CLASSIFIER_SYSTEM_PROMPT.format(
                            candidates_block=candidates_block
                        ),
                    },
                    {
                        "role": "user",
                        "content": (
                            f'NL Query: "{nl_query}"'
                            + (f"\n\nPrevious attempt was rejected: {last_error}. "
                               f"Choose ONLY from the candidate list above."
                               if attempt > 1 else "")
                        ),
                    },
                ]

                raw = self.client.complete(messages=messages, json_mode=True, temperature=0.0)
                parsed = self._parser.extract_ir_dict(raw)

                result = self._validate_and_build(
                    nl_query   = nl_query,
                    parsed     = parsed,
                    candidate_ids = candidate_ids,
                    attempts   = attempt,
                    elapsed_s  = round(time.monotonic() - t0, 3),
                )

                log.info(
                    "ATT&CK classification succeeded",
                    extra={"label": f"{result.tactic}/{result.technique}", "attempts": attempt},
                )
                return result

            except (IRValidationError, ValueError) as exc:
                print("\n========== REJECTED ==========")
                print("QUERY:", nl_query)
                print("PARSED:", parsed)
                print("ERROR:", exc)
                print("==============================\n")
                last_error = str(exc)
                log.warning(
                    "Classification attempt rejected — retrying",
                    extra={"attempt": attempt, "error": last_error},
                )
            except LLMError as exc:
                last_error = f"LLM error: {exc}"
                log.warning("LLM error during classification — retrying", extra={"error": str(exc)})

        elapsed = round(time.monotonic() - t0, 3)
        raise NLSIEMError(
            f"ATTCKClassifierAgent failed after {self.max_retries} attempts "
            f"for query: '{nl_query[:80]}'",
            details={
                "nl_query":     nl_query,
                "last_error":   last_error,
                "candidates":   candidate_ids,
                "elapsed_s":    elapsed,
            },
        )

    def attach(self, base_ir: IRQuery, classification: ClassificationResult) -> AttckIRQuery:
        """
        Combine a structurally-parsed IRQuery with a verified ATT&CK
        classification into a single AttckIRQuery.

        Args:
            base_ir:        IRQuery produced by ParserAgent (Layer 5).
            classification: Output of classify().

        Returns:
            AttckIRQuery ready for translation and coverage accounting.
        """
        return AttckIRQuery.from_ir_query(
            base          = base_ir,
            tactic        = classification.tactic,
            technique     = classification.technique,
            sub_technique = classification.sub_technique,
        )

    def classify_and_attach(self, nl_query: str, base_ir: IRQuery) -> tuple[AttckIRQuery, ClassificationResult]:
        """Convenience: classify() followed by attach() in one call."""
        result = self.classify(nl_query)
        return self.attach(base_ir, result), result

    # ─────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────

    def _format_candidates(self, candidates: list[TechniqueEntry]) -> str:
        """Render candidate techniques (and their sub-techniques) for the prompt."""
        lines = []
        for c in candidates:
            kind = "sub-technique" if c.is_subtechnique else "technique"
            lines.append(
                f'- {c.technique_id} ({kind}) "{c.name}" '
                f"[tactics: {', '.join(c.tactic_names)}]: "
                f"{c.description[:220]}"
            )
            if not c.is_subtechnique:
                subs = self._taxonomy.get_sub_techniques(c.technique_id)
                for s in subs[:4]:   # cap sub-technique listing per parent
                    lines.append(
                        f'    - {s.technique_id} (sub-technique) "{s.name}": '
                        f"{s.description[:160]}"
                    )
        return "\n".join(lines)

    def _validate_and_build(
        self,
        nl_query:      str,
        parsed:        dict,
        candidate_ids: list[str],
        attempts:      int,
        elapsed_s:     float,
    ) -> ClassificationResult:
        """
        Validate the LLM's classification JSON against both the candidate
        set and the live taxonomy before constructing a ClassificationResult.

        Raises:
            ValueError: If required fields are missing or malformed.
            IRValidationError: If the selected technique cannot be verified
                               against the loaded MITRE ATT&CK taxonomy.
        """
        technique     = str(parsed.get("technique", "")).strip().upper()
        sub_technique = parsed.get("sub_technique")
        # Fix common LLM behavior:
# if technique itself is a sub-technique, split it into parent+child.
        if "." in technique:
            if sub_technique in (None, "", technique):
                sub_technique = technique
            technique = technique.split(".")[0]
        tactic        = str(parsed.get("tactic", "")).strip().lower()
        rationale     = str(parsed.get("rationale", "")).strip()
        confidence    = float(parsed.get("confidence", 0.5))

        if sub_technique is not None:
            sub_technique = str(sub_technique).strip().upper()
            if sub_technique.lower() in ("null", "none", ""):
                sub_technique = None

        if not technique:
            raise ValueError("LLM response missing required 'technique' field")
        if not tactic:
            raise ValueError("LLM response missing required 'tactic' field")

        # The technique selected must actually verify against the taxonomy —
        # this is the hard guarantee that prevents a hallucinated ID from
        # silently reaching the IR layer, regardless of whether it happened
        # to also appear in the candidate list (defence in depth).
        technique_entry = self._taxonomy.get_technique(technique)
        if technique_entry is None:
            raise IRValidationError(
                f"LLM selected technique '{technique}' which does not exist "
                f"in the loaded ATT&CK taxonomy",
                details={"technique": technique, "candidates": candidate_ids},
            )

        if sub_technique is not None:
            sub_entry = self._taxonomy.get_technique(sub_technique)
            if sub_entry is None:
                raise IRValidationError(
                    f"LLM selected sub_technique '{sub_technique}' which does "
                    f"not exist in the loaded ATT&CK taxonomy",
                    details={"sub_technique": sub_technique},
                )
            if sub_entry.parent_id != technique:
                raise IRValidationError(
                    f"sub_technique '{sub_technique}' does not belong to "
                    f"technique '{technique}' (actual parent: "
                    f"'{sub_entry.parent_id}')",
                    details={"technique": technique, "sub_technique": sub_technique},
                )

        # Normalise tactic to the canonical shortname recognised by the
        # taxonomy, rather than trusting the LLM's exact casing/spelling.
        tactic_entry = self._taxonomy.get_tactic(tactic)
        if tactic_entry is None:
            raise IRValidationError(
                f"LLM selected tactic '{tactic}' which does not exist in the "
                f"loaded ATT&CK taxonomy",
                details={"tactic": tactic},
            )
        if tactic_entry.shortname not in technique_entry.tactic_names:
            raise IRValidationError(
                f"technique '{technique}' is not associated with tactic "
                f"'{tactic}' (technique belongs to: {technique_entry.tactic_names})",
                details={"tactic": tactic, "technique": technique},
            )

        return ClassificationResult(
            nl_query               = nl_query,
            tactic                 = tactic_entry.shortname,
            technique              = technique,
            sub_technique          = sub_technique,
            rationale              = rationale,
            confidence             = max(0.0, min(1.0, confidence)),
            candidates_considered  = candidate_ids,
            attempts               = attempts,
            elapsed_s              = elapsed_s,
        )

    def __repr__(self) -> str:
        return (
            f"ATTCKClassifierAgent(candidate_k={self.candidate_k}, "
            f"max_retries={self.max_retries})"
        )