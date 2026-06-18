"""
Prompts — system prompts and few-shot templates for NL → IR generation.

Loads few-shot examples from src/ir/examples.json at import time.
Builds platform-specific prompt variants:
  - few_shot    (default): inject N diverse examples
  - zero_shot:  schema only, no examples
  - rag:        few_shot + retrieved SIEM documentation context
  - chain_of_thought: step-by-step reasoning before JSON output

Provider-aware formatting:
  - Groq (Llama):   plain system/user split, strict JSON instruction
  - Gemini:         system instruction via SDK param, user content only
  - Ollama (Llama/Mistral): same as Groq; note JSON mode availability

Place at: src/llm/prompts.py

Usage:
    from src.llm.prompts import PromptBuilder
    builder = PromptBuilder()
    messages = builder.build_ir_prompt("Find failed logins in 24h")

    # Provider-tuned
    messages = builder.build_ir_prompt(
        "Detect port scan from single IP",
        condition="chain_of_thought",
        provider="gemini",
    )
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from src.utils.logger import get_logger

log = get_logger(__name__)

# Path to few-shot examples
EXAMPLES_PATH = Path("src/ir/examples.json")

# Number of few-shot examples to inject per prompt
FEW_SHOT_N = 3

# Valid prompting conditions
PromptCondition = Literal["few_shot", "zero_shot", "rag", "chain_of_thought"]

# Valid providers for formatting tuning
ProviderHint = Literal["groq", "gemini", "ollama", "openrouter", "auto"]


# ── IR Schema ─────────────────────────────────────────────────────────────
IR_SCHEMA_DESCRIPTION = """
The IR is a JSON object with these fields:

REQUIRED:
  "action": one of "filter" | "filter+aggregate" | "aggregate" | "sequence" | "lookup"

OPTIONAL:
  "event_type": one of "authentication" | "network" | "process" | "file" | "registry" | "dns" | "http" | "any"
  "filter": {
    "operator": "and" | "or",
    "conditions": [
      { "field": "<canonical_field>", "op": "<operator>", "value": "<value>", "negate": false }
    ]
  }
  "time_window": { "duration": "<N><unit>", "field": "_time" }
      duration units: s=seconds, m=minutes, h=hours, d=days  (e.g. "24h", "10m", "7d")
  "aggregation": {
    "function": "count" | "sum" | "avg" | "min" | "max" | "distinct_count",
    "field": "<field_to_aggregate>",
    "group_by": ["<field1>", "<field2>"],
    "alias": "<output_name>"
  }
  "threshold": { "field": "<alias>", "op": "gt" | "gte" | "lt" | "lte" | "eq", "value": <number> }
  "sequence": [ { "event_type": "...", "filter": {...}, "within": "5m" }, ... ]
  "lookup": { "lookup_table": "<name>", "match_field": "<field>", "output_field": "<field>", "filter_on_match": true }
  "fields": ["<field1>", "<field2>"]
  "tactic": "<mitre_tactic>"
  "technique_id": "<T####>"

CANONICAL FIELD NAMES (use these exactly):
  Identity:  src_ip, dest_ip, src_port, dest_port, user, domain, hostname, host
  Auth:      status, auth_type, country
  Process:   process_name, process_id, parent_process, command_line, target_process
  Network:   protocol, direction, bytes_in, bytes_out
  File:      file_name, file_path, file_hash
  DNS:       query_domain, response_size
  Event:     event_id, event_type, severity, timestamp, action, category

COMPARISON OPERATORS:
  eq, neq, gt, gte, lt, lte, in, not_in, contains, regex
""".strip()


# ── System prompt templates ────────────────────────────────────────────────

# Standard few-shot / RAG
_SYSTEM_FEW_SHOT = """\
You are NL-SIEM, a precision security query translator.

Convert natural language threat detection descriptions into structured \
Intermediate Representation (IR) JSON.

{schema}

RULES:
1. Output ONLY valid JSON. No explanation, no markdown fences, no preamble.
2. Use ONLY the canonical field names listed above.
3. Counting/grouping → action "filter+aggregate" + aggregation block.
4. Threshold ("more than N times") → add "threshold" field.
5. Time window → add "time_window" with correct duration unit.
6. Unknown field → use "any" for event_type or omit optional fields.

{few_shot_block}

Convert the following query to IR JSON:""".strip()

# Zero-shot (no examples)
_SYSTEM_ZERO_SHOT = """\
You are NL-SIEM, a precision security query translator.

Convert natural language threat detection descriptions into structured \
Intermediate Representation (IR) JSON.

{schema}

RULES:
1. Output ONLY valid JSON — no markdown, no explanation, no preamble.
2. Use ONLY the canonical field names listed above.

Convert the following query to IR JSON:""".strip()

# Chain-of-thought: model reasons first, then outputs JSON
_SYSTEM_COT = """\
You are NL-SIEM, a precision security query translator.

Convert natural language threat detection descriptions into structured \
Intermediate Representation (IR) JSON.

{schema}

APPROACH:
Step 1 — Event type: identify what kind of event this is (authentication, network, process, file, dns, http, or any).
Step 2 — Filter conditions: list every field constraint mentioned.
Step 3 — Aggregation: decide if counting/grouping is needed, and if so, which fields.
Step 4 — Time constraint: extract any time window and convert to duration string (e.g. "24h").
Step 5 — Output JSON: produce the final IR object following ALL rules above.

RULES:
1. Think through steps 1–4 briefly (a sentence each), then output the JSON on a new line.
2. The JSON must be valid. No trailing commas, no comments.
3. Use ONLY canonical field names.

{few_shot_block}

Convert the following query:""".strip()

# Refinement (self-critique after validation failure)
_SYSTEM_REFINE = """\
You are NL-SIEM, a precision security query translator fixing a previously generated IR.

{schema}

RULES:
1. Output ONLY the corrected IR JSON. No explanation.
2. Fix EVERY listed error.
3. Use ONLY canonical field names.

{few_shot_block}

Now correct the IR:""".strip()

# Reverse: IR → natural language (for semantic round-trip verification)
_SYSTEM_NL_FROM_IR = """\
You are a senior security analyst. Given a detection rule in IR JSON format, \
describe in ONE clear sentence what the rule detects. \
Output ONLY the sentence — no preamble, no JSON, no bullet points."""


class PromptBuilder:
    """
    Builds prompts for NL → IR generation, IR refinement, and reverse verification.

    Provider awareness:
      - "gemini"  → system instruction delivered separately via SDK (not in messages list).
                    build_ir_prompt returns only [user_message] when provider="gemini".
      - "groq" / "ollama" / "openrouter" → standard [system, user] pair.
      - "auto"   → detect from LLM_PROVIDER env, default groq format.
    """

    def __init__(
        self,
        examples_path: Path = EXAMPLES_PATH,
        n_examples:    int  = FEW_SHOT_N,
    ):
        self.n_examples = n_examples
        self.examples   = self._load_examples(examples_path)
        log.debug(
            "PromptBuilder initialised",
            extra={"examples": len(self.examples), "n_few_shot": n_examples},
        )

    # ─────────────────────────────────────────────
    # Main build entry point
    # ─────────────────────────────────────────────

    def build_ir_prompt(
        self,
        nl_query:    str,
        condition:   PromptCondition = "few_shot",
        rag_context: str | None      = None,
        tactic_hint: str | None      = None,
        provider:    ProviderHint    = "auto",
        correction_hint: str | None = None,
    ) -> list[dict]:
        """
        Build the full message list for NL → IR translation.

        Args:
            nl_query:    Natural language detection query.
            condition:   Prompting strategy: few_shot | zero_shot | rag | chain_of_thought.
            rag_context: Retrieved SIEM documentation (for RAG condition).
            tactic_hint: Optional MITRE ATT&CK tactic hint.
            provider:    Provider hint to tune message format. "gemini" returns
                         only a user message (system is passed via SDK separately).

        Returns:
            List of {"role": ..., "content": ...} dicts.
        """
        resolved_provider = self._resolve_provider(provider)

        # Build the system text
        system_text = self._build_system_text(condition)

        # Build the user message
        user_parts: list[str] = []
        if correction_hint:
            user_parts.append(
                f"""
        Previous attempt failed.

        Validation/Parse Error:
        {correction_hint}

        Generate a corrected IR JSON.
        """
            )
        if rag_context:
            user_parts.append(
                f"Relevant SIEM documentation:\n{rag_context}\n---"
            )

        if tactic_hint:
            user_parts.append(f"MITRE ATT&CK tactic hint: {tactic_hint}")

        user_parts.append(f'NL Query: "{nl_query}"')

        # For chain-of-thought: prompt the model to reason then output JSON
        if condition == "chain_of_thought":
            user_parts.append(
                "\nThink through the four steps briefly, then output the IR JSON:"
            )
        else:
            user_parts.append("IR JSON:")

        user_content = "\n".join(user_parts)

        return self._format_messages(system_text, user_content, resolved_provider)

    # ─────────────────────────────────────────────
    # Refinement / self-critique
    # ─────────────────────────────────────────────

    def build_refinement_prompt(
        self,
        nl_query:          str,
        previous_ir:       dict,
        validation_errors: list[str],
        rag_context:       str | None = None,
        provider:          ProviderHint = "auto",
    ) -> list[dict]:
        """
        Build a self-critique prompt when IR failed validation.

        Args:
            nl_query:          Original NL query.
            previous_ir:       The invalid IR dict.
            validation_errors: List of error strings from the validator.
            rag_context:       Optional retrieved context.
            provider:          Provider hint for message formatting.

        Returns:
            Message list for the refinement request.
        """
        resolved_provider = self._resolve_provider(provider)
        errors_text  = "\n".join(f"  • {e}" for e in validation_errors)
        prev_ir_text = json.dumps(previous_ir, indent=2)

        few_shot_block = self._build_few_shot_block(2)
        system_text    = _SYSTEM_REFINE.format(
            schema=IR_SCHEMA_DESCRIPTION,
            few_shot_block=few_shot_block,
        )

        rag_prefix = f"Relevant context:\n{rag_context}\n---\n\n" if rag_context else ""

        user_content = (
            f"{rag_prefix}"
            f'NL Query: "{nl_query}"\n\n'
            f"Errors in previous IR:\n{errors_text}\n\n"
            f"Previous (invalid) IR:\n{prev_ir_text}\n\n"
            f"Corrected IR JSON:"
        )

        return self._format_messages(system_text, user_content, resolved_provider)

    # ─────────────────────────────────────────────
    # Reverse: IR → NL (semantic round-trip)
    # ─────────────────────────────────────────────

    def build_nl_from_ir_prompt(
        self,
        ir:       dict,
        provider: ProviderHint = "auto",
    ) -> list[dict]:
        """
        Build a prompt to reverse-generate NL from IR (semantic verification).

        Args:
            ir:       IR dict to describe.
            provider: Provider hint.

        Returns:
            Message list asking the model to describe the IR in one sentence.
        """
        resolved_provider = self._resolve_provider(provider)
        ir_text      = json.dumps(ir, indent=2)
        user_content = f"IR JSON:\n{ir_text}\n\nDescribe what this detects (one sentence):"
        return self._format_messages(_SYSTEM_NL_FROM_IR, user_content, resolved_provider)

    # ─────────────────────────────────────────────
    # Gemini-specific: extract just the system instruction
    # ─────────────────────────────────────────────

    def get_gemini_system_instruction(
        self,
        condition: PromptCondition = "few_shot",
    ) -> str:
        """
        Return the system prompt text for use as Gemini's system_instruction.

        Since Gemini receives system instructions separately from the chat history,
        this lets callers pass system text directly to GenerativeModel().

        Args:
            condition: Prompting strategy.

        Returns:
            System instruction string.
        """
        return self._build_system_text(condition)

    # ─────────────────────────────────────────────
    # Example helpers
    # ─────────────────────────────────────────────

    def get_example_by_tactic(self, tactic: str) -> dict | None:
        """Return the first example matching a given MITRE tactic."""
        for ex in self.examples:
            if ex.get("tactic") == tactic:
                return ex
        return None

    def get_example_by_action(self, action: str) -> list[dict]:
        """Return all examples with the given IR action."""
        return [ex for ex in self.examples if ex.get("ir", {}).get("action") == action]

    def get_example_by_complexity(
        self,
        complexity: Literal["simple", "intermediate", "complex"],
    ) -> list[dict]:
        """Return all examples matching a complexity level."""
        return [ex for ex in self.examples if ex.get("complexity") == complexity]

    def add_example(self, nl_query: str, ir: dict, tactic: str = "", complexity: str = "intermediate") -> None:
        """
        Add a new example to the in-memory example pool (for dynamic few-shot).

        Args:
            nl_query:   The natural language query.
            ir:         The correct IR dict.
            tactic:     Optional MITRE tactic label.
            complexity: "simple" | "intermediate" | "complex".
        """
        self.examples.append({
            "nl_query":   nl_query,
            "ir":         ir,
            "tactic":     tactic,
            "complexity": complexity,
        })
        log.debug("Example added to pool", extra={"total": len(self.examples)})

    # ─────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────

    def _build_system_text(self, condition: PromptCondition) -> str:
        """Return the rendered system prompt string for the given condition."""
        if condition == "zero_shot":
            return _SYSTEM_ZERO_SHOT.format(schema=IR_SCHEMA_DESCRIPTION)

        few_shot_block = self._build_few_shot_block(self.n_examples)

        if condition == "chain_of_thought":
            return _SYSTEM_COT.format(
                schema=IR_SCHEMA_DESCRIPTION,
                few_shot_block=few_shot_block,
            )

        # few_shot and rag both use the standard template
        return _SYSTEM_FEW_SHOT.format(
            schema=IR_SCHEMA_DESCRIPTION,
            few_shot_block=few_shot_block,
        )

    def _format_messages(
        self,
        system_text:       str,
        user_content:      str,
        resolved_provider: str,
    ) -> list[dict]:
        """
        Build the final messages list, tuned for the provider.

        Gemini:
          - Returns only the user message; system text is injected via SDK.
          - However, we embed a brief system reminder at the top of user content
            so the intent is clear even without the SDK param.
        Groq / Ollama / OpenRouter:
          - Standard [system, user] pair.
        """
        if resolved_provider == "gemini":
            # Gemini: system_instruction is passed to GenerativeModel() separately.
            # We add a brief one-line reminder inside the user message as a fallback.
            gemini_reminder = (
                "[You are NL-SIEM. Output ONLY valid JSON — no markdown, no explanation.]\n\n"
            )
            return [
                {"role": "user", "content": gemini_reminder + user_content}
            ]

        return [
            {"role": "system", "content": system_text},
            {"role": "user",   "content": user_content},
        ]

    def _resolve_provider(self, provider: ProviderHint) -> str:
        """Resolve "auto" by reading LLM_PROVIDER from env."""
        if provider != "auto":
            return provider.lower()
        import os
        return os.getenv("LLM_PROVIDER", "groq").lower()

    def _load_examples(self, path: Path) -> list[dict]:
        """Load examples from JSON file."""
        try:
            with path.open("r", encoding="utf-8") as f:
                examples = json.load(f)
            log.debug("Examples loaded", extra={"count": len(examples), "path": str(path)})
            return examples
        except FileNotFoundError:
            log.warning(
                "examples.json not found — few-shot disabled",
                extra={"path": str(path)},
            )
            return []
        except Exception as exc:
            log.error("Failed to load examples", extra={"error": str(exc)})
            return []

    def _build_few_shot_block(self, n: int) -> str:
        """
        Build the few-shot block for the system prompt.

        Selection strategy:
          1. One example per action type (prioritise diversity).
          2. Fill remaining slots with unused examples.
          3. Within each slot, prefer examples with a different event_type.
        """
        if not self.examples:
            return ""

        action_priority = [
            "filter+aggregate",
            "filter",
            "sequence",
            "lookup",
            "aggregate",
        ]

        selected:     list[dict] = []
        used_actions: set[str]   = set()
        used_events:  set[str]   = set()

        # Pass 1 — one per action type, prefer unseen event types
        for action in action_priority:
            if len(selected) >= n:
                break
            for ex in self.examples:
                ir         = ex.get("ir", {})
                evt        = ir.get("event_type", "any")
                ex_action  = ir.get("action")
                if ex_action == action and action not in used_actions:
                    if evt not in used_events or len(used_events) >= 4:
                        selected.append(ex)
                        used_actions.add(action)
                        used_events.add(evt)
                        break

        # Pass 2 — fill remaining
        for ex in self.examples:
            if len(selected) >= n:
                break
            if ex not in selected:
                selected.append(ex)

        selected = selected[:n]

        # Format
        lines = ["EXAMPLES (study these carefully):"]
        for i, ex in enumerate(selected, start=1):
            lines.append(f"\nExample {i}:")
            lines.append(f'NL Query: "{ex["nl_query"]}"')
            if ex.get("tactic"):
                lines.append(f'# MITRE tactic: {ex["tactic"]}')
            lines.append(f'IR JSON:\n{json.dumps(ex["ir"], indent=2)}')

        lines.append("\n---")
        return "\n".join(lines)