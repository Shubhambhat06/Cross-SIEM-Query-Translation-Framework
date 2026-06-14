"""
Response Parser — extracts clean JSON from LLM output.

LLMs commonly wrap JSON in markdown code fences, add preamble text,
or produce near-valid JSON with minor syntax errors. This module
handles all of these cases robustly.

Place at: src/llm/response_parser.py

Usage:
    from src.llm.response_parser import ResponseParser
    parser = ResponseParser()
    ir_dict = parser.extract_json(llm_output)

    # Streaming accumulation
    parser.feed_chunk(chunk)    # call for each streamed chunk
    result = parser.flush()     # call once streaming ends
"""

from __future__ import annotations

import json
import re
from typing import Any

from src.utils.exceptions import LLMResponseParseError
from src.utils.logger import get_logger

log = get_logger(__name__)


class ResponseParser:
    """
    Extracts structured JSON from raw LLM output strings.

    Handles:
      - Markdown code fences (```json ... ``` or ``` ... ```)
      - XML-style tag wrappers (<json>...</json>, <output>...</output>)
      - Preamble / postamble text surrounding JSON
      - Single-quoted keys/values (common Llama/Mistral quirk)
      - Trailing commas in objects/arrays
      - Python boolean/None literals (True, False, None)
      - Truncated JSON (best-effort bracket completion)
      - Streaming chunk accumulation with incremental parse detection
      - Partial IR schema coercion (field name normalisation)
    """

    # ── Compiled patterns ─────────────────────────────────────────────────
    _JSON_FENCE      = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.IGNORECASE)
    _XML_JSON_TAG    = re.compile(r"<(?:json|output|result|ir)>([\s\S]*?)</(?:json|output|result|ir)>", re.IGNORECASE)
    _JSON_BLOCK      = re.compile(r"(\{[\s\S]*\}|\[[\s\S]*\])")
    _TRAILING_COMMA  = re.compile(r",\s*([}\]])")
    _PYTHON_TRUE     = re.compile(r'\bTrue\b')
    _PYTHON_FALSE    = re.compile(r'\bFalse\b')
    _PYTHON_NONE     = re.compile(r'\bNone\b')
    _COMMENT_LINE    = re.compile(r'^\s*//.*$', re.MULTILINE)   # JS-style comments
    _COMMENT_INLINE  = re.compile(r'(?<=[,{\["])\s*//[^\n]*')

    # Known field aliases → canonical names (handles common model deviations)
    _FIELD_ALIASES: dict[str, str] = {
        "ip_address":      "src_ip",
        "source_ip":       "src_ip",
        "dest":            "dest_ip",
        "destination_ip":  "dest_ip",
        "username":        "user",
        "user_name":       "user",
        "proc_name":       "process_name",
        "cmd_line":        "command_line",
        "cmdline":         "command_line",
        "file":            "file_name",
        "hash":            "file_hash",
        "dns_query":       "query_domain",
        "query":           "query_domain",
        "event":           "event_type",
    }

    def __init__(self) -> None:
        self._stream_buffer: list[str] = []

    # ─────────────────────────────────────────────
    # Streaming support
    # ─────────────────────────────────────────────

    def feed_chunk(self, chunk: str) -> None:
        """
        Accumulate a streamed chunk. Call for each chunk as it arrives.

        Args:
            chunk: Partial text from a streaming LLM response.
        """
        self._stream_buffer.append(chunk)

    def flush(self, coerce_fields: bool = False) -> dict | list | None:
        """
        Parse accumulated stream buffer and reset.

        Args:
            coerce_fields: If True, normalise field names in conditions.

        Returns:
            Parsed object, or None on failure.
        """
        full_text = "".join(self._stream_buffer)
        self._stream_buffer.clear()
        result = self.safe_extract(full_text)
        if result and coerce_fields and isinstance(result, dict):
            return self._coerce_field_names(result)
        return result

    def reset_stream(self) -> None:
        """Discard any accumulated streaming data."""
        self._stream_buffer.clear()

    # ─────────────────────────────────────────────
    # Core extraction
    # ─────────────────────────────────────────────

    def extract_json(self, text: str) -> dict | list:
        """
        Extract and parse the first JSON object or array from text.

        Tries six strategies in order, from cheapest to most aggressive:
          1. Direct parse — model returned clean JSON
          2. Markdown code fence
          3. XML/HTML tag wrapper
          4. Balanced bracket extraction from raw text
          5. Clean-and-retry (fix Python literals, trailing commas, etc.)
          6. Truncated JSON repair — try completing broken JSON

        Args:
            text: Raw LLM output string.

        Returns:
            Parsed Python dict or list.

        Raises:
            LLMResponseParseError: If no valid JSON can be extracted.
        """
        if not text or not isinstance(text, str):
            raise LLMResponseParseError(
                raw_output=str(text),
                reason="Empty or non-string response from LLM",
            )

        text = text.strip()

        # Strategy 1 — direct parse
        result = self._try_parse(text)
        if result is not None:
            return result

        # Strategy 2 — markdown code fence
        fence_match = self._JSON_FENCE.search(text)
        if fence_match:
            result = self._try_parse(fence_match.group(1).strip())
            if result is not None:
                return result

        # Strategy 3 — XML/HTML tag wrappers
        xml_match = self._XML_JSON_TAG.search(text)
        if xml_match:
            result = self._try_parse(xml_match.group(1).strip())
            if result is not None:
                return result

        # Strategy 4 — balanced bracket extraction
        result = self._extract_first_json_block(text)
        if result is not None:
            return result

        # Strategy 5 — clean and retry
        cleaned = self._clean(text)
        result  = self._try_parse(cleaned)
        if result is not None:
            return result

        result = self._extract_first_json_block(cleaned)
        if result is not None:
            return result

        # Strategy 6 — truncated JSON repair
        result = self._repair_truncated(text)
        if result is not None:
            log.warning("Truncated JSON recovered with bracket completion")
            return result

        raise LLMResponseParseError(
            raw_output=text[:500],
            reason="Could not extract valid JSON after all six strategies",
        )

    def extract_ir_dict(self, text: str, coerce_fields: bool = True) -> dict:
        """
        Extract and return a JSON dict specifically (for IR extraction).

        Args:
            text:          Raw LLM output.
            coerce_fields: Normalise field names in filter conditions.

        Returns:
            Dict parsed from JSON.

        Raises:
            LLMResponseParseError: If result is not a dict.
        """
        result = self.extract_json(text)
        if not isinstance(result, dict):
            raise LLMResponseParseError(
                raw_output=text,
                reason=f"Expected JSON object (dict), got {type(result).__name__}",
            )

        if coerce_fields:
            result = self._coerce_field_names(result)

        log.debug("IR dict extracted", extra={"keys": list(result.keys())[:8]})
        return result

    def safe_extract(self, text: str, default: Any = None) -> dict | list | None:
        """
        Extract JSON without raising — returns default on failure.

        Args:
            text:    Raw LLM output.
            default: Value to return on parse failure.
        """
        try:
            return self.extract_json(text)
        except LLMResponseParseError as exc:
            log.warning(
                "JSON extraction failed (safe mode)",
                extra={"reason": exc.details.get("reason", str(exc))},
            )
            return default

    # ─────────────────────────────────────────────
    # Internal strategies
    # ─────────────────────────────────────────────

    def _try_parse(self, text: str) -> dict | list | None:
        """Attempt direct JSON parse. Returns None on failure."""
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    def _extract_first_json_block(self, text: str) -> dict | list | None:
        """
        Find the first { or [ and extract the balanced block.
        Handles nested structures, escaped chars, and string boundaries.
        """
        for start_char, end_char in [('{', '}'), ('[', ']')]:
            start_idx = text.find(start_char)
            if start_idx == -1:
                continue

            depth   = 0
            in_str  = False
            escape  = False
            end_idx = -1

            for i, ch in enumerate(text[start_idx:], start=start_idx):
                if escape:
                    escape = False
                    continue
                if ch == '\\' and in_str:
                    escape = True
                    continue
                if ch == '"' and not escape:
                    in_str = not in_str
                    continue
                if in_str:
                    continue
                if ch == start_char:
                    depth += 1
                elif ch == end_char:
                    depth -= 1
                    if depth == 0:
                        end_idx = i
                        break

            if end_idx != -1:
                candidate = text[start_idx:end_idx + 1]
                result    = self._try_parse(candidate)
                if result is not None:
                    return result
                result = self._try_parse(self._clean(candidate))
                if result is not None:
                    return result

        return None

    def _clean(self, text: str) -> str:
        """
        Apply fixups to near-valid JSON strings.

        Fixes:
          - Markdown fences
          - Trailing commas before } or ]
          - Python True/False/None → JSON true/false/null
          - Single-quoted strings → double-quoted
          - JavaScript-style // comments
          - Leading/trailing text around JSON
        """
        # Strip markdown fences
        text = self._JSON_FENCE.sub(r"\1", text).strip()

        # Remove JS-style line comments
        text = self._COMMENT_LINE.sub("", text)

        # Fix trailing commas
        text = self._TRAILING_COMMA.sub(r"\1", text)

        # Python literals → JSON
        text = self._PYTHON_TRUE.sub("true", text)
        text = self._PYTHON_FALSE.sub("false", text)
        text = self._PYTHON_NONE.sub("null", text)

        # Fix single-quoted strings
        try:
            text = self._fix_single_quotes(text)
        except Exception:
            pass

        return text

    def _fix_single_quotes(self, text: str) -> str:
        """
        Replace single-quoted strings with double-quoted equivalents.
        Avoids converting apostrophes inside double-quoted strings.
        """
        result   = []
        in_double = False
        i = 0
        while i < len(text):
            ch = text[i]
            prev = text[i - 1] if i > 0 else ""
            if ch == '"' and prev != '\\':
                in_double = not in_double
                result.append(ch)
            elif ch == "'" and not in_double:
                result.append('"')
            else:
                result.append(ch)
            i += 1
        return "".join(result)

    def _repair_truncated(self, text: str) -> dict | list | None:
        """
        Attempt to fix truncated JSON by completing unclosed brackets.

        Useful when a model hits max_tokens mid-output.
        """
        # Find the last valid JSON start
        start = -1
        start_char = None
        for i, ch in enumerate(text):
            if ch in ('{', '['):
                start      = i
                start_char = ch
                break

        if start == -1:
            return None

        fragment = text[start:]

        # Count unclosed brackets/braces
        depth    = 0
        in_str   = False
        escape   = False
        closings = []

        for ch in fragment:
            if escape:
                escape = False
                continue
            if ch == '\\' and in_str:
                escape = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch == '{':
                depth += 1
                closings.append('}')
            elif ch == '[':
                depth += 1
                closings.append(']')
            elif ch in ('}', ']'):
                if closings and closings[-1] == ch:
                    closings.pop()
                    depth -= 1

        if depth == 0 and not closings:
            # Already balanced — clean and try again
            return self._try_parse(self._clean(fragment))

        # Close any open string
        if in_str:
            fragment += '"'

        # Strip trailing commas before we close
        fragment = self._TRAILING_COMMA.sub(r"\1", fragment.rstrip().rstrip(","))

        # Append missing closings in reverse
        completion = "".join(reversed(closings))
        repaired   = fragment + completion

        result = self._try_parse(repaired)
        if result is not None:
            return result
        return self._try_parse(self._clean(repaired))

    # ─────────────────────────────────────────────
    # Field normalisation
    # ─────────────────────────────────────────────

    def _coerce_field_names(self, ir: dict) -> dict:
        """
        Normalise field names in IR filter conditions.

        Some models use slightly different field names (e.g. "username" instead
        of "user"). This maps them to canonical names before validation.

        Args:
            ir: Raw IR dict from the model.

        Returns:
            IR dict with normalised field names.
        """
        if "filter" not in ir or not isinstance(ir["filter"], dict):
            return ir

        conditions = ir["filter"].get("conditions", [])
        for cond in conditions:
            if isinstance(cond, dict) and "field" in cond:
                original = cond["field"]
                cond["field"] = self._FIELD_ALIASES.get(original, original)

        # Also normalise group_by fields in aggregation
        if "aggregation" in ir and isinstance(ir["aggregation"], dict):
            group_by = ir["aggregation"].get("group_by", [])
            ir["aggregation"]["group_by"] = [
                self._FIELD_ALIASES.get(f, f) for f in group_by
            ]

        return ir

    # ─────────────────────────────────────────────
    # Structural validation
    # ─────────────────────────────────────────────

    def validate_ir_structure(self, data: dict) -> list[str]:
        """
        Light structural check on extracted IR dict before passing to validator.

        Args:
            data: Extracted dict from LLM output.

        Returns:
            List of warning strings (empty = looks good).
        """
        warnings: list[str] = []

        VALID_ACTIONS = {"filter", "filter+aggregate", "aggregate", "sequence", "lookup"}
        action = data.get("action")
        if not action:
            warnings.append("Missing required field: 'action'")
        elif action not in VALID_ACTIONS:
            warnings.append(f"'action' value '{action}' not in {sorted(VALID_ACTIONS)}")

        if "filter" in data:
            f = data["filter"]
            if not isinstance(f, dict):
                warnings.append(f"'filter' should be a dict, got {type(f).__name__}")
            else:
                if "conditions" not in f:
                    warnings.append("'filter' missing 'conditions' list")
                elif not isinstance(f["conditions"], list):
                    warnings.append(f"'filter.conditions' should be a list")
                else:
                    for i, cond in enumerate(f["conditions"]):
                        if not isinstance(cond, dict):
                            continue
                        for req_key in ("field", "op", "value"):
                            if req_key not in cond:
                                warnings.append(f"condition[{i}] missing '{req_key}'")

        if "time_window" in data:
            tw = data["time_window"]
            if isinstance(tw, dict) and "duration" not in tw:
                warnings.append("'time_window' missing 'duration' field")
            elif isinstance(tw, str):
                warnings.append("'time_window' should be a dict with 'duration', not a string")

        if "aggregation" in data:
            agg = data["aggregation"]
            if isinstance(agg, dict) and "function" not in agg:
                warnings.append("'aggregation' missing 'function' field")

        if "threshold" in data and action not in ("filter+aggregate", "aggregate"):
            warnings.append("'threshold' present but action is not aggregate-based")

        if "sequence" in data:
            seq = data["sequence"]
            if not isinstance(seq, list):
                warnings.append("'sequence' should be a list of event steps")
            elif len(seq) < 2:
                warnings.append("'sequence' should have at least 2 steps")

        if warnings:
            log.debug("IR structure warnings", extra={"count": len(warnings), "warnings": warnings})

        return warnings

    def extract_and_validate(self, text: str) -> tuple[dict, list[str]]:
        """
        Convenience: extract IR dict and run structural validation in one call.

        Returns:
            Tuple of (ir_dict, warnings). Raises LLMResponseParseError on parse failure.
        """
        ir       = self.extract_ir_dict(text, coerce_fields=True)
        warnings = self.validate_ir_structure(ir)
        return ir, warnings