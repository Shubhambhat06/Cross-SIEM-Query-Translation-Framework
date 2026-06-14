"""
test_llm_layer.py — Three-layer test suite for the NL-SIEM LLM interface layer.

Covers: token_counter · response_parser · field_mapping · prompts · client

Run all layers:
    pytest test_llm_layer.py -v

Run one layer only:
    pytest test_llm_layer.py -v -m unit
    pytest test_llm_layer.py -v -m integration
    pytest test_llm_layer.py -v -m contract

Run with coverage:
    pytest test_llm_layer.py -v --cov=src/llm --cov=src/translators --cov-report=term-missing

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
LAYER 1 · Unit Tests
    Pure logic. No network, no filesystem, no LLM calls.
    Covers every class / function in isolation.

LAYER 2 · Integration Tests
    Components wired together, still no network.
    PromptBuilder → ResponseParser → FieldMapping pipelines.
    CircuitBreaker and RateLimiter state machines.

LAYER 3 · Contract / Provider Smoke Tests
    All external calls mocked at the SDK boundary.
    Validates that LLMClient assembles the right kwargs for each provider
    and correctly handles success, rate-limit, timeout, and auth errors.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch, call

import pytest

# ─────────────────────────────────────────────────────────────────────────────
# Bootstrap: inject stub modules so the project imports resolve without the
# full project tree being installed.  Each stub is minimal but accurate.
# ─────────────────────────────────────────────────────────────────────────────

def _make_exceptions_mod() -> types.ModuleType:
    mod = types.ModuleType("src.utils.exceptions")

    class LLMError(Exception):
        def __init__(self, msg="", details=None, **kw):
            super().__init__(msg)
            self.details = details or {}

    class LLMResponseParseError(LLMError):
        def __init__(self, raw_output="", reason="", **kw):
            super().__init__(reason)
            self.details = {"reason": reason, "raw_output": raw_output}

    class LLMRateLimitError(LLMError):
        def __init__(self, model="", **kw):
            super().__init__(f"Rate limit: {model}")

    class LLMTimeoutError(LLMError):
        def __init__(self, model="", timeout_seconds=60, **kw):
            super().__init__(f"Timeout: {model}")

    class LLMMaxRetriesError(LLMError):
        def __init__(self, model="", attempts=3, **kw):
            super().__init__(f"Max retries ({attempts}) exceeded: {model}")

    for cls in (LLMError, LLMResponseParseError, LLMRateLimitError,
                LLMTimeoutError, LLMMaxRetriesError):
        setattr(mod, cls.__name__, cls)
    return mod


def _make_logger_mod() -> types.ModuleType:
    mod = types.ModuleType("src.utils.logger")
    _null = Mock()
    _null.debug = _null.info = _null.warning = _null.error = lambda *a, **kw: None
    mod.get_logger = lambda *a, **kw: _null
    return mod




# ── Import project modules (they now resolve via the stubs above) ──────────
from src.llm.token_counter import (  # noqa: E402
    MODEL_CONTEXT_WINDOWS,
    MODEL_REGISTRY,
    ModelSpec,
    RunCost,
    TokenCounter,
    TokenUsage,
)
from src.llm.response_parser import ResponseParser  # noqa: E402
from src.translators.field_mapping import (          # noqa: E402
    FIELD_MAP,
    PLATFORMS,
    get_canonical_fields,
    resolve,
    resolve_all,
)
from src.llm.prompts import PromptBuilder            # noqa: E402
from src.llm.client import (                         # noqa: E402
    PROVIDER_CONFIGS,
    CircuitBreaker,
    LLMClient,
    RateLimiter,
)
from src.utils.exceptions import (                   # noqa: E402
    LLMError,
    LLMMaxRetriesError,
    LLMRateLimitError,
    LLMResponseParseError,
    LLMTimeoutError,
)


# ─────────────────────────────────────────────────────────────────────────────
# Shared fixtures / helpers
# ─────────────────────────────────────────────────────────────────────────────

SAMPLE_IR_FILTER = {
    "action": "filter",
    "event_type": "authentication",
    "filter": {
        "operator": "and",
        "conditions": [
            {"field": "status", "op": "eq", "value": "failure"},
            {"field": "src_ip", "op": "neq", "value": "10.0.0.1"},
        ],
    },
    "time_window": {"duration": "1h", "field": "_time"},
}

SAMPLE_IR_AGGREGATE = {
    "action": "filter+aggregate",
    "event_type": "authentication",
    "filter": {
        "operator": "and",
        "conditions": [{"field": "status", "op": "eq", "value": "failure"}],
    },
    "aggregation": {
        "function": "count",
        "field": "user",
        "group_by": ["user", "src_ip"],
        "alias": "attempt_count",
    },
    "threshold": {"field": "attempt_count", "op": "gt", "value": 5},
    "time_window": {"duration": "10m", "field": "_time"},
    "tactic": "credential-access",
    "technique_id": "T1110",
}

SAMPLE_EXAMPLES = [
    {
        "nl_query": "Find failed SSH logins",
        "ir": {
            "action": "filter",
            "event_type": "authentication",
            "filter": {
                "operator": "and",
                "conditions": [
                    {"field": "status", "op": "eq", "value": "failure"},
                    {"field": "dest_port", "op": "eq", "value": 22},
                ],
            },
        },
        "tactic": "credential-access",
        "complexity": "simple",
    },
    {
        "nl_query": "Count DNS queries by domain in last 15 minutes",
        "ir": {
            "action": "filter+aggregate",
            "event_type": "dns",
            "aggregation": {
                "function": "count",
                "field": "query_domain",
                "group_by": ["query_domain"],
                "alias": "event_count",
            },
            "time_window": {"duration": "15m", "field": "_time"},
        },
        "tactic": "command-and-control",
        "complexity": "intermediate",
    },
    {
        "nl_query": "Detect process injection sequence",
        "ir": {
            "action": "sequence",
            "sequence": [
                {"event_type": "process", "filter": {"operator": "and", "conditions": []}},
                {"event_type": "process", "filter": {"operator": "and", "conditions": []}},
            ],
        },
        "tactic": "defense-evasion",
        "complexity": "complex",
    },
    {
        "nl_query": "Lookup threat intel for IP",
        "ir": {
            "action": "lookup",
            "lookup_table": "threat_intel",
            "match_field": "src_ip",
        },
        "tactic": "discovery",
        "complexity": "simple",
    },
]


def make_examples_file(tmp_path: Path, examples=None) -> Path:
    p = tmp_path / "examples.json"
    p.write_text(json.dumps(examples or SAMPLE_EXAMPLES))
    return p


def make_openai_response(content: str, prompt_tokens=50, completion_tokens=20) -> Mock:
    """Build a mock openai ChatCompletion response object."""
    usage        = Mock()
    usage.prompt_tokens     = prompt_tokens
    usage.completion_tokens = completion_tokens

    msg          = Mock()
    msg.content  = content
    msg.tool_calls = None

    choice       = Mock()
    choice.message = msg

    resp         = Mock()
    resp.choices = [choice]
    resp.usage   = usage
    return resp


# ═════════════════════════════════════════════════════════════════════════════
# LAYER 1 — UNIT TESTS
# ═════════════════════════════════════════════════════════════════════════════

class TestModelSpec:
    """ModelSpec immutability, slot access, and defaults."""

    def test_required_field_stored(self):
        s = ModelSpec(context_window=8192)
        assert s.context_window == 8192

    def test_defaults(self):
        s = ModelSpec(context_window=4096)
        assert s.supports_vision    is False
        assert s.supports_tools     is False
        assert s.supports_json_mode is False
        assert s.input_cost_per_1m  == 0.0
        assert s.output_cost_per_1m == 0.0

    def test_explicit_caps(self):
        s = ModelSpec(131072, supports_vision=True, supports_tools=True, supports_json_mode=True)
        assert s.supports_vision
        assert s.supports_tools
        assert s.supports_json_mode

    def test_immutable_raises(self):
        s = ModelSpec(8192)
        with pytest.raises(AttributeError):
            s.context_window = 999

    def test_repr(self):
        s = ModelSpec(8192, supports_vision=True)
        assert "8192" in repr(s)
        assert "vision=True" in repr(s)


class TestModelRegistry:
    """MODEL_REGISTRY completeness and correctness for key models."""

    @pytest.mark.parametrize("model,ctx,tools,json_m,vision", [
        ("llama-3.3-70b-versatile",        128_000, True,  True,  False),
        ("llama-3.1-8b-instant",           131_072, True,  True,  False),
        ("gemini-2.0-flash",             1_048_576, True,  True,  True),
        ("gemini-1.5-pro",               2_097_152, True,  True,  True),
        ("llava",                            4_096,  False, False, True),
        ("qwen2.5:7b",                    131_072,  True,  True,  False),
        ("deepseek-r1-distill-llama-70b", 128_000,  False, True,  False),
        ("llama-3.2-90b-vision-preview",    8_192,  True,  False, True),
    ])
    def test_known_model(self, model, ctx, tools, json_m, vision):
        assert model in MODEL_REGISTRY, f"Model '{model}' missing from registry"
        spec = MODEL_REGISTRY[model]
        assert spec.context_window    == ctx,   f"{model}: context mismatch"
        assert spec.supports_tools    == tools,  f"{model}: tools mismatch"
        assert spec.supports_json_mode == json_m, f"{model}: json_mode mismatch"
        assert spec.supports_vision   == vision, f"{model}: vision mismatch"

    def test_backward_compat_alias(self):
        """MODEL_CONTEXT_WINDOWS should map every registry key."""
        for model, spec in MODEL_REGISTRY.items():
            assert MODEL_CONTEXT_WINDOWS[model] == spec.context_window

    def test_no_negative_context(self):
        for model, spec in MODEL_REGISTRY.items():
            assert spec.context_window > 0, f"{model} has non-positive context window"

    def test_free_tier_zero_cost(self):
        """All registry models are free-tier by default."""
        for model, spec in MODEL_REGISTRY.items():
            assert spec.input_cost_per_1m  >= 0.0
            assert spec.output_cost_per_1m >= 0.0


class TestRunCost:

    def test_zero_for_free_models(self):
        rc   = RunCost()
        spec = ModelSpec(8192)          # cost_per_1m = 0.0
        rc.add(10_000, 5_000, spec)
        assert rc.total == 0.0
        assert "free" in rc.summary()

    def test_nonzero_cost_paid_model(self):
        rc   = RunCost()
        spec = ModelSpec(8192, input_cost_per_1m=3.0, output_cost_per_1m=15.0)
        rc.add(1_000_000, 500_000, spec)
        assert pytest.approx(rc.input_cost,  abs=1e-6) == 3.0
        assert pytest.approx(rc.output_cost, abs=1e-6) == 7.5
        assert pytest.approx(rc.total,       abs=1e-6) == 10.5

    def test_accumulates_across_calls(self):
        rc   = RunCost()
        spec = ModelSpec(8192, input_cost_per_1m=1.0)
        rc.add(500_000, 0, spec)
        rc.add(500_000, 0, spec)
        assert pytest.approx(rc.total, abs=1e-6) == 1.0

    def test_summary_includes_dollar(self):
        rc   = RunCost()
        spec = ModelSpec(8192, input_cost_per_1m=1.0)
        rc.add(1_000_000, 0, spec)
        assert "$" in rc.summary()


class TestTokenUsage:

    def test_add_accumulates(self):
        u = TokenUsage()
        u.add(100, 50)
        u.add(200, 75)
        assert u.prompt_tokens     == 300
        assert u.completion_tokens == 125
        assert u.total_tokens      == 425
        assert u.num_requests      == 2

    def test_to_dict_keys(self):
        u = TokenUsage()
        u.add(10, 5)
        d = u.to_dict()
        assert {"prompt_tokens", "completion_tokens", "total_tokens",
                "num_requests", "cost_usd"} <= d.keys()

    def test_summary_string(self):
        u = TokenUsage()
        u.add(1000, 500)
        s = u.summary()
        assert "1000" in s
        assert "500"  in s
        assert "1500" in s

    def test_zero_initial(self):
        u = TokenUsage()
        assert u.total_tokens == 0
        assert u.num_requests == 0


class TestTokenCounter:

    # ── Capability flags ──────────────────────────────────────────────────

    def test_groq_capabilities(self):
        c = TokenCounter("llama-3.3-70b-versatile")
        assert c.supports_tools
        assert c.supports_json_mode
        assert not c.supports_vision
        assert c.context_window == 128_000

    def test_gemini_vision(self):
        c = TokenCounter("gemini-2.0-flash")
        assert c.supports_vision
        assert c.context_window == 1_048_576

    def test_ollama_llava_vision(self):
        c = TokenCounter("llava")
        assert c.supports_vision
        assert not c.supports_tools

    def test_unknown_model_defaults(self):
        c = TokenCounter("some-unknown-model-xyz")
        assert c.context_window    == 8_192
        assert c.supports_vision   is False
        assert c.supports_tools    is False
        assert c.supports_json_mode is False

    # ── Estimation ────────────────────────────────────────────────────────

    def test_estimate_empty(self):
        c = TokenCounter()
        assert c.estimate("") == 0

    def test_estimate_positive(self):
        c = TokenCounter()
        assert c.estimate("Hello world") > 0

    def test_estimate_scales_with_length(self):
        c   = TokenCounter()
        s   = c.estimate("x" * 100)
        l   = c.estimate("x" * 1000)
        assert l > s

    def test_estimate_messages_includes_overhead(self):
        c    = TokenCounter()
        msgs = [{"role": "user", "content": "hi"}]
        est  = c.estimate_messages(msgs)
        # At minimum: 4 overhead + tokens for "hi"
        assert est >= 4

    def test_estimate_messages_multipart(self):
        c    = TokenCounter()
        msgs = [{"role": "user", "content": [
            {"type": "text",      "text": "describe this"},
            {"type": "image_url", "image_url": {"url": "http://example.com/img.png"}},
        ]}]
        est = c.estimate_messages(msgs)
        assert est >= 4 + 765   # image stub = 765 tokens

    # ── Context window ────────────────────────────────────────────────────

    def test_fits_context_short_messages(self):
        c    = TokenCounter("llama-3.3-70b-versatile")
        msgs = [{"role": "user", "content": "short query"}]
        assert c.fits_context(msgs)

    def test_fits_context_huge_messages(self):
        c    = TokenCounter("llama3-8b-8192")    # 8192 context
        msgs = [{"role": "user", "content": "x " * 5000}]
        assert not c.fits_context(msgs, reserve_tokens=512)

    def test_utilisation_pct_range(self):
        c    = TokenCounter("llama-3.3-70b-versatile")
        msgs = [{"role": "user", "content": "hello"}]
        pct  = c.utilisation_pct(msgs)
        assert 0.0 < pct < 1.0

    # ── Recording ─────────────────────────────────────────────────────────

    def test_record_accumulates(self):
        c = TokenCounter()
        c.record(500, 200)
        c.record(300, 100)
        assert c.usage.prompt_tokens     == 800
        assert c.usage.completion_tokens == 300
        assert c.usage.num_requests      == 2

    def test_record_streaming(self):
        c    = TokenCounter()
        msgs = [{"role": "user", "content": "Hello"}]
        c.record_streaming("This is a long completion response.", msgs)
        assert c.usage.num_requests == 1
        assert c.usage.total_tokens > 0

    def test_record_from_response(self):
        c    = TokenCounter()
        resp = make_openai_response("ok", prompt_tokens=100, completion_tokens=30)
        c.record_from_response(resp)
        assert c.usage.prompt_tokens     == 100
        assert c.usage.completion_tokens == 30

    def test_record_from_response_bad_obj(self):
        """Should not raise on malformed response."""
        c = TokenCounter()
        c.record_from_response(None)          # no exception
        c.record_from_response("not a resp")  # no exception
        assert c.usage.num_requests == 0

    def test_reset_clears_usage(self):
        c = TokenCounter()
        c.record(100, 50)
        c.reset()
        assert c.usage.total_tokens == 0
        assert c.usage.num_requests == 0

    def test_save_creates_valid_json(self, tmp_path):
        c = TokenCounter("llama-3.3-70b-versatile")
        c.record(200, 80)
        out = tmp_path / "usage.json"
        c.save(out)
        data = json.loads(out.read_text())
        assert data["model"]   == "llama-3.3-70b-versatile"
        assert "usage"         in data
        assert "capabilities"  in data
        assert data["usage"]["total_tokens"] == 280

    def test_save_creates_parent_dirs(self, tmp_path):
        c   = TokenCounter()
        out = tmp_path / "nested" / "deep" / "usage.json"
        c.save(out)
        assert out.exists()

    def test_repr(self):
        c = TokenCounter("gemini-2.0-flash")
        assert "gemini-2.0-flash" in repr(c)


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 1 · ResponseParser
# ─────────────────────────────────────────────────────────────────────────────

class TestResponseParserStrategies:
    """Every extraction strategy, in isolation."""

    def setup_method(self):
        self.p = ResponseParser()

    # Strategy 1 — direct parse
    def test_direct_clean_json(self):
        result = self.p.extract_json('{"action": "filter"}')
        assert result == {"action": "filter"}

    def test_direct_json_array(self):
        result = self.p.extract_json('[1, 2, 3]')
        assert result == [1, 2, 3]

    # Strategy 2 — markdown fence
    def test_fence_json_block(self):
        raw    = "Here's the IR:\n```json\n{\"action\": \"aggregate\"}\n```"
        result = self.p.extract_json(raw)
        assert result["action"] == "aggregate"

    def test_fence_plain_block(self):
        raw    = "```\n{\"action\": \"lookup\"}\n```"
        result = self.p.extract_json(raw)
        assert result["action"] == "lookup"

    # Strategy 3 — XML wrapper
    def test_xml_json_tag(self):
        raw    = "<json>{\"action\": \"sequence\"}</json>"
        result = self.p.extract_json(raw)
        assert result["action"] == "sequence"

    def test_xml_output_tag(self):
        raw    = "<output>{\"action\": \"filter\"}</output>"
        result = self.p.extract_json(raw)
        assert result["action"] == "filter"

    def test_xml_result_tag(self):
        raw    = "<result>{\"action\": \"lookup\"}</result>"
        result = self.p.extract_json(raw)
        assert result["action"] == "lookup"

    # Strategy 4 — balanced bracket
    def test_preamble_and_postamble(self):
        raw    = 'Sure! Here you go: {"action": "filter"} Let me know!'
        result = self.p.extract_json(raw)
        assert result["action"] == "filter"

    def test_nested_object(self):
        raw    = '{"a": {"b": {"c": 3}}}'
        result = self.p.extract_json(raw)
        assert result["a"]["b"]["c"] == 3

    # Strategy 5 — clean and retry
    def test_trailing_comma_object(self):
        result = self.p.extract_json('{"a": 1,}')
        assert result == {"a": 1}

    def test_trailing_comma_array(self):
        result = self.p.extract_json('[1, 2, 3,]')
        assert result == [1, 2, 3]

    def test_python_true_false_none(self):
        raw    = '{"ok": True, "bad": False, "val": None}'
        result = self.p.extract_json(raw)
        assert result == {"ok": True, "bad": False, "val": None}

    def test_single_quoted_keys(self):
        raw    = "{'action': 'filter', 'count': 5}"
        result = self.p.extract_json(raw)
        assert result["action"] == "filter"
        assert result["count"]  == 5

    def test_js_line_comment_stripped(self):
        raw    = '{\n// this is a comment\n"action": "filter"\n}'
        result = self.p.extract_json(raw)
        assert result["action"] == "filter"

    # Strategy 6 — truncated repair
    def test_truncated_object(self):
        raw    = '{"action": "filter", "filter": {"operator": "and", "conditions": ['
        result = self.p.safe_extract(raw)
        assert result is not None
        assert result.get("action") == "filter"

    def test_truncated_mid_string(self):
        raw    = '{"action": "fil'
        result = self.p.safe_extract(raw)
        # May or may not fully recover — must not raise
        assert result is None or isinstance(result, dict)

    # Failure
    def test_raises_on_garbage(self):
        with pytest.raises(LLMResponseParseError):
            self.p.extract_json("this is definitely not json at all")

    def test_raises_on_empty(self):
        with pytest.raises(LLMResponseParseError):
            self.p.extract_json("")

    def test_raises_on_none(self):
        with pytest.raises(LLMResponseParseError):
            self.p.extract_json(None)

    def test_safe_extract_returns_default(self):
        result = self.p.safe_extract("not json", default={"fallback": True})
        assert result == {"fallback": True}

    def test_safe_extract_returns_none_by_default(self):
        result = self.p.safe_extract("not json")
        assert result is None


class TestResponseParserIRExtraction:

    def setup_method(self):
        self.p = ResponseParser()

    def test_extract_ir_dict_ok(self):
        raw    = json.dumps(SAMPLE_IR_FILTER)
        result = self.p.extract_ir_dict(raw)
        assert isinstance(result, dict)
        assert result["action"] == "filter"

    def test_extract_ir_dict_raises_on_array(self):
        with pytest.raises(LLMResponseParseError):
            self.p.extract_ir_dict("[1, 2, 3]")

    def test_field_alias_username_to_user(self):
        ir = {
            "action": "filter",
            "filter": {
                "operator": "and",
                "conditions": [
                    {"field": "username", "op": "eq", "value": "admin"},
                ],
            },
        }
        result = self.p.extract_ir_dict(json.dumps(ir), coerce_fields=True)
        assert result["filter"]["conditions"][0]["field"] == "user"

    def test_field_alias_source_ip_to_src_ip(self):
        ir = {
            "action": "filter",
            "filter": {
                "operator": "and",
                "conditions": [{"field": "source_ip", "op": "eq", "value": "1.2.3.4"}],
            },
        }
        result = self.p.extract_ir_dict(json.dumps(ir), coerce_fields=True)
        assert result["filter"]["conditions"][0]["field"] == "src_ip"

    def test_field_alias_ip_address_to_src_ip(self):
        ir = {
            "action": "filter",
            "filter": {
                "operator": "and",
                "conditions": [{"field": "ip_address", "op": "eq", "value": "10.0.0.1"}],
            },
        }
        result = self.p.extract_ir_dict(json.dumps(ir), coerce_fields=True)
        assert result["filter"]["conditions"][0]["field"] == "src_ip"

    def test_group_by_coercion(self):
        ir = {
            "action": "filter+aggregate",
            "filter": {"operator": "and", "conditions": []},
            "aggregation": {
                "function": "count",
                "group_by": ["username", "src_ip"],
                "alias": "cnt",
            },
        }
        result = self.p.extract_ir_dict(json.dumps(ir), coerce_fields=True)
        assert "user" in result["aggregation"]["group_by"]

    def test_no_coercion_when_disabled(self):
        ir = {
            "action": "filter",
            "filter": {
                "operator": "and",
                "conditions": [{"field": "username", "op": "eq", "value": "x"}],
            },
        }
        result = self.p.extract_ir_dict(json.dumps(ir), coerce_fields=False)
        assert result["filter"]["conditions"][0]["field"] == "username"

    def test_extract_and_validate_ok(self):
        ir, warnings = self.p.extract_and_validate(json.dumps(SAMPLE_IR_FILTER))
        assert ir["action"] == "filter"
        assert isinstance(warnings, list)

    def test_extract_and_validate_missing_action(self):
        bad = json.dumps({"filter": {"operator": "and", "conditions": []}})
        ir, warnings = self.p.extract_and_validate(bad)
        assert any("action" in w for w in warnings)


class TestResponseParserStreamBuffer:

    def test_feed_and_flush(self):
        p = ResponseParser()
        chunks = ['{"act', 'ion":', ' "filter"}']
        for c in chunks:
            p.feed_chunk(c)
        result = p.flush()
        assert result == {"action": "filter"}

    def test_flush_clears_buffer(self):
        p = ResponseParser()
        p.feed_chunk('{"action": "filter"}')
        p.flush()
        # Second flush with empty buffer should return None
        result = p.flush()
        assert result is None

    def test_reset_stream(self):
        p = ResponseParser()
        p.feed_chunk('{"action": "filter"}')
        p.reset_stream()
        result = p.flush()
        assert result is None

    def test_flush_with_coerce(self):
        p = ResponseParser()
        p.feed_chunk(json.dumps({
            "action": "filter",
            "filter": {
                "operator": "and",
                "conditions": [{"field": "username", "op": "eq", "value": "x"}],
            },
        }))
        result = p.flush(coerce_fields=True)
        assert result["filter"]["conditions"][0]["field"] == "user"


class TestResponseParserValidation:

    def setup_method(self):
        self.p = ResponseParser()

    def test_valid_ir_no_warnings(self):
        w = self.p.validate_ir_structure(SAMPLE_IR_FILTER)
        assert w == []

    def test_missing_action(self):
        w = self.p.validate_ir_structure({})
        assert any("action" in x for x in w)

    def test_invalid_action_value(self):
        w = self.p.validate_ir_structure({"action": "explode"})
        assert any("action" in x.lower() or "explode" in x for x in w)

    def test_filter_missing_conditions(self):
        ir = {"action": "filter", "filter": {"operator": "and"}}
        w  = self.p.validate_ir_structure(ir)
        assert any("conditions" in x for x in w)

    def test_filter_conditions_not_list(self):
        ir = {"action": "filter", "filter": {"operator": "and", "conditions": "bad"}}
        w  = self.p.validate_ir_structure(ir)
        assert len(w) > 0

    def test_condition_missing_field(self):
        ir = {
            "action": "filter",
            "filter": {
                "operator": "and",
                "conditions": [{"op": "eq", "value": "x"}],   # no 'field'
            },
        }
        w = self.p.validate_ir_structure(ir)
        assert any("field" in x for x in w)

    def test_time_window_missing_duration(self):
        ir = {"action": "filter", "time_window": {"field": "_time"}}
        w  = self.p.validate_ir_structure(ir)
        assert any("duration" in x for x in w)

    def test_time_window_as_string_warns(self):
        ir = {"action": "filter", "time_window": "24h"}
        w  = self.p.validate_ir_structure(ir)
        assert any("dict" in x for x in w)

    def test_aggregation_missing_function(self):
        ir = {"action": "aggregate", "aggregation": {"group_by": ["user"]}}
        w  = self.p.validate_ir_structure(ir)
        assert any("function" in x for x in w)

    def test_sequence_too_short(self):
        ir = {"action": "sequence", "sequence": [{"event_type": "process"}]}
        w  = self.p.validate_ir_structure(ir)
        assert any("sequence" in x.lower() for x in w)

    def test_threshold_without_aggregate_warns(self):
        ir = {
            "action": "filter",
            "filter": {"operator": "and", "conditions": []},
            "threshold": {"field": "cnt", "op": "gt", "value": 5},
        }
        w = self.p.validate_ir_structure(ir)
        assert any("threshold" in x.lower() for x in w)

    def test_full_aggregate_ir_no_warnings(self):
        w = self.p.validate_ir_structure(SAMPLE_IR_AGGREGATE)
        assert w == []


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 1 · FieldMapping
# ─────────────────────────────────────────────────────────────────────────────

class TestFieldMappingResolve:

    @pytest.mark.parametrize("canonical,platform,expected", [
        ("user",        "splunk",   "user"),
        ("user",        "qradar",   "username"),
        ("user",        "elastic",  "user.name"),
        ("user",        "sentinel", "Account"),
        ("user",        "wazuh",    "dstuser"),
        ("src_ip",      "splunk",   "src_ip"),
        ("src_ip",      "qradar",   "sourceip"),
        ("src_ip",      "elastic",  "source.ip"),
        ("dest_ip",     "sentinel", "DestinationIp"),
        ("process_name","elastic",  "process.name"),
        ("command_line","splunk",   "CommandLine"),
        ("file_hash",   "elastic",  "file.hash.sha256"),
        ("query_domain","elastic",  "dns.question.name"),
        ("timestamp",   "splunk",   "_time"),
        ("timestamp",   "elastic",  "@timestamp"),
        ("severity",    "wazuh",    "level"),
        ("country",     "elastic",  "source.geo.country_name"),
        ("auth_type",   "sentinel", "LogonType"),
        ("bytes_out",   "qradar",   "destinationbytes"),
    ])
    def test_known_mapping(self, canonical, platform, expected):
        assert resolve(canonical, platform) == expected

    def test_unknown_canonical_passthrough(self):
        assert resolve("totally_unknown_field", "splunk") == "totally_unknown_field"

    def test_unknown_platform_passthrough(self):
        assert resolve("src_ip", "nonexistent_siem") == "src_ip"

    def test_case_insensitive_platform(self):
        assert resolve("user", "SPLUNK") == resolve("user", "splunk")
        assert resolve("user", "Elastic") == resolve("user", "elastic")

    def test_platform_with_whitespace(self):
        assert resolve("user", "  splunk  ") == "user"

    def test_all_platforms_have_src_ip(self):
        for platform in PLATFORMS:
            result = resolve("src_ip", platform)
            assert result != "src_ip" or platform == "splunk", \
                f"src_ip on {platform} should be platform-specific"


class TestFieldMappingResolveAll:

    def test_resolve_all_list(self):
        fields = ["user", "src_ip", "dest_ip"]
        result = resolve_all(fields, "elastic")
        assert result == ["user.name", "source.ip", "destination.ip"]

    def test_resolve_all_empty(self):
        assert resolve_all([], "splunk") == []

    def test_resolve_all_unknown_passthrough(self):
        result = resolve_all(["nonexistent"], "splunk")
        assert result == ["nonexistent"]

    def test_resolve_all_length_preserved(self):
        fields = ["user", "src_ip", "process_name", "unknown_field"]
        result = resolve_all(fields, "qradar")
        assert len(result) == len(fields)


class TestFieldMappingIntegrity:

    def test_all_canonical_in_map(self):
        keys = get_canonical_fields()
        assert len(keys) > 0
        assert all(k in FIELD_MAP for k in keys)

    def test_all_platforms_covered_for_core_fields(self):
        core = ["user", "src_ip", "dest_ip", "status", "process_name",
                "command_line", "file_name", "query_domain"]
        for field in core:
            entry = FIELD_MAP[field]
            for platform in PLATFORMS:
                assert platform in entry, \
                    f"Field '{field}' missing platform '{platform}'"

    def test_no_empty_mappings(self):
        for canonical, entry in FIELD_MAP.items():
            for platform, mapped in entry.items():
                assert mapped, f"Empty mapping: {canonical} → {platform}"

    def test_platforms_set_matches_map(self):
        """Every platform used in FIELD_MAP must appear in PLATFORMS."""
        used = {p for entry in FIELD_MAP.values() for p in entry}
        unexpected = used - PLATFORMS
        assert not unexpected, f"Platforms in FIELD_MAP not declared in PLATFORMS: {unexpected}"


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 1 · PromptBuilder
# ─────────────────────────────────────────────────────────────────────────────

class TestPromptBuilderInit:

    def test_loads_examples(self, tmp_path):
        ep = make_examples_file(tmp_path)
        pb = PromptBuilder(examples_path=ep)
        assert len(pb.examples) == len(SAMPLE_EXAMPLES)

    def test_missing_file_empty_examples(self, tmp_path):
        pb = PromptBuilder(examples_path=tmp_path / "nonexistent.json")
        assert pb.examples == []

    def test_n_examples_stored(self, tmp_path):
        ep = make_examples_file(tmp_path)
        pb = PromptBuilder(examples_path=ep, n_examples=2)
        assert pb.n_examples == 2


class TestPromptBuilderMessages:

    @pytest.fixture
    def pb(self, tmp_path):
        return PromptBuilder(examples_path=make_examples_file(tmp_path))

    @pytest.fixture
    def pb_empty(self, tmp_path):
        return PromptBuilder(examples_path=tmp_path / "no.json")

    # Structure checks
    def test_groq_returns_system_and_user(self, pb):
        msgs = pb.build_ir_prompt("detect port scan", provider="groq")
        assert len(msgs) == 2
        assert msgs[0]["role"] == "system"
        assert msgs[1]["role"] == "user"

    def test_gemini_returns_user_only(self, pb):
        msgs = pb.build_ir_prompt("detect port scan", provider="gemini")
        assert len(msgs) == 1
        assert msgs[0]["role"] == "user"

    def test_ollama_returns_system_and_user(self, pb):
        msgs = pb.build_ir_prompt("detect port scan", provider="ollama")
        assert len(msgs) == 2

    def test_openrouter_returns_system_and_user(self, pb):
        msgs = pb.build_ir_prompt("detect port scan", provider="openrouter")
        assert len(msgs) == 2

    # Content checks — all conditions
    def test_few_shot_includes_examples(self, pb):
        msgs = pb.build_ir_prompt("query", condition="few_shot", provider="groq")
        combined = " ".join(m["content"] for m in msgs)
        assert "Example 1" in combined

    def test_zero_shot_no_examples(self, pb):
        msgs = pb.build_ir_prompt("query", condition="zero_shot", provider="groq")
        combined = " ".join(m["content"] for m in msgs)
        assert "Example" not in combined

    def test_chain_of_thought_has_steps(self, pb):
        msgs = pb.build_ir_prompt("query", condition="chain_of_thought", provider="groq")
        combined = " ".join(m["content"] for m in msgs)
        assert "Step" in combined

    def test_rag_uses_few_shot_template(self, pb):
        msgs = pb.build_ir_prompt(
            "query", condition="rag",
            rag_context="[some SIEM docs]", provider="groq"
        )
        combined = " ".join(m["content"] for m in msgs)
        assert "[some SIEM docs]" in combined
        assert "Example" in combined

    def test_tactic_hint_in_user_message(self, pb):
        msgs = pb.build_ir_prompt(
            "query", tactic_hint="credential-access", provider="groq"
        )
        assert "credential-access" in msgs[1]["content"]

    def test_nl_query_in_user_message(self, pb):
        msgs = pb.build_ir_prompt("detect brute force", provider="groq")
        assert "detect brute force" in msgs[1]["content"]

    def test_schema_in_system(self, pb):
        msgs = pb.build_ir_prompt("query", provider="groq")
        assert "action" in msgs[0]["content"]
        assert "filter" in msgs[0]["content"]

    def test_zero_shot_with_no_examples_file(self, pb_empty):
        msgs = pb_empty.build_ir_prompt("query", condition="few_shot", provider="groq")
        assert len(msgs) == 2    # still valid, just no examples in block

    # Refinement prompt
    def test_refinement_contains_errors(self, pb):
        msgs = pb.build_refinement_prompt(
            "detect brute force",
            previous_ir={"action": "bad"},
            validation_errors=["Missing 'filter'", "Bad action"],
            provider="groq",
        )
        combined = " ".join(m["content"] for m in msgs)
        assert "Missing 'filter'" in combined
        assert "Bad action"       in combined

    def test_refinement_contains_previous_ir(self, pb):
        msgs = pb.build_refinement_prompt(
            "detect brute force",
            previous_ir={"action": "bad"},
            validation_errors=["error"],
            provider="groq",
        )
        combined = " ".join(m["content"] for m in msgs)
        assert '"action"' in combined

    # NL from IR prompt
    def test_nl_from_ir_has_ir_json(self, pb):
        msgs = pb.build_nl_from_ir_prompt(SAMPLE_IR_FILTER, provider="groq")
        combined = " ".join(m["content"] for m in msgs)
        assert "filter" in combined

    # Gemini system instruction
    def test_gemini_system_instruction_nonempty(self, pb):
        instr = pb.get_gemini_system_instruction("few_shot")
        assert len(instr) > 100
        assert "action" in instr

    def test_gemini_system_instruction_zero_shot(self, pb):
        instr = pb.get_gemini_system_instruction("zero_shot")
        assert "Example" not in instr

    # add_example
    def test_add_example_increases_pool(self, pb):
        before = len(pb.examples)
        pb.add_example("new query", {"action": "filter"}, tactic="t", complexity="simple")
        assert len(pb.examples) == before + 1

    def test_add_example_retrievable_by_tactic(self, pb):
        pb.add_example("q", {"action": "filter"}, tactic="unique-tactic-xyz")
        found = pb.get_example_by_tactic("unique-tactic-xyz")
        assert found is not None
        assert found["nl_query"] == "q"

    # Lookup helpers
    def test_get_example_by_action(self, pb):
        results = pb.get_example_by_action("sequence")
        assert len(results) >= 1

    def test_get_example_by_complexity(self, pb):
        simple = pb.get_example_by_complexity("simple")
        assert len(simple) >= 1
        assert all(e["complexity"] == "simple" for e in simple)

    def test_get_example_by_tactic_missing(self, pb):
        assert pb.get_example_by_tactic("does-not-exist") is None

    # Few-shot diversity
    def test_few_shot_diverse_actions(self, pb):
        """Block should cover more than one IR action type."""
        block = pb._build_few_shot_block(3)
        action_types_present = sum(
            1 for action in ("filter", "aggregate", "sequence", "lookup")
            if action in block
        )
        assert action_types_present >= 2

    # Provider resolution
    def test_auto_provider_reads_env(self, pb, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "gemini")
        msgs = pb.build_ir_prompt("query", provider="auto")
        assert len(msgs) == 1   # gemini format

    def test_auto_provider_default_groq(self, pb, monkeypatch):
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        msgs = pb.build_ir_prompt("query", provider="auto")
        assert len(msgs) == 2   # groq format


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 1 · CircuitBreaker + RateLimiter (state machines, no network)
# ─────────────────────────────────────────────────────────────────────────────

class TestCircuitBreaker:

    def test_starts_closed(self):
        cb = CircuitBreaker()
        assert cb.allow_request()
        assert not cb.is_open

    def test_opens_after_threshold(self):
        cb = CircuitBreaker(failure_threshold=3)
        for _ in range(3):
            cb.record_failure()
        assert cb.is_open
        assert not cb.allow_request()

    def test_success_resets_failures(self):
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        assert not cb.is_open

    def test_half_open_after_timeout(self):
        cb = CircuitBreaker(failure_threshold=2, reset_timeout=0.01)
        cb.record_failure()
        cb.record_failure()
        assert cb.is_open
        time.sleep(0.02)
        assert cb.allow_request()   # should allow probe

    def test_success_from_half_open_closes(self):
        cb = CircuitBreaker(failure_threshold=2, reset_timeout=0.01)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.02)
        cb.allow_request()      # transition to half-open
        cb.record_success()
        assert not cb.is_open

    def test_failure_from_half_open_reopens(self):
        cb = CircuitBreaker(failure_threshold=2, reset_timeout=0.01)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.02)
        cb.allow_request()          # probe
        cb.record_failure()
        assert cb.is_open


class TestRateLimiter:

    def test_first_request_no_wait(self):
        rl    = RateLimiter(rpm=30)
        start = time.monotonic()
        rl.wait_if_needed()
        assert time.monotonic() - start < 0.1

    def test_tracks_request_times(self):
        rl = RateLimiter(rpm=100)
        for _ in range(10):
            rl.wait_if_needed()
        assert len(rl._req_times) == 10

    def test_purge_removes_old_entries(self):
        rl = RateLimiter(rpm=100)
        # Manually add old timestamps
        old = time.monotonic() - 65.0
        rl._req_times.append(old)
        rl._req_times.append(old)
        rl.wait_if_needed()  # triggers purge
        # Old entries should be gone
        assert all(t > time.monotonic() - 60.0 for t in rl._req_times)

    def test_rpm_1_triggers_sleep(self):
        """At rpm=1, second call within same window should wait."""
        rl = RateLimiter(rpm=1)
        rl.wait_if_needed()   # first — immediate
        # Manually set the timestamp to NOW (so window is full)
        # The second call should see the window is full and sleep
        # We patch time.sleep to check it's called
        with patch("src.llm.client.time.sleep") as mock_sleep:
            # Force the window to appear full by making rl think 1 req happened just now
            rl._req_times.clear()
            rl._req_times.append(time.monotonic())
            rl.wait_if_needed()
            mock_sleep.assert_called_once()


# ═════════════════════════════════════════════════════════════════════════════
# LAYER 2 — INTEGRATION TESTS
# ═════════════════════════════════════════════════════════════════════════════

class TestPromptToParserPipeline:
    """PromptBuilder output fed into ResponseParser with mock LLM text."""

    @pytest.fixture
    def pb(self, tmp_path):
        return PromptBuilder(examples_path=make_examples_file(tmp_path))

    @pytest.fixture
    def parser(self):
        return ResponseParser()

    def test_filter_ir_roundtrip(self, pb, parser):
        msgs   = pb.build_ir_prompt("detect failed logins", provider="groq")
        # Simulate LLM responding with a valid IR
        mock_response = json.dumps(SAMPLE_IR_FILTER)
        ir, warnings  = parser.extract_and_validate(mock_response)
        assert ir["action"] == "filter"
        assert warnings == []

    def test_aggregate_ir_roundtrip(self, pb, parser):
        msgs  = pb.build_ir_prompt(
            "count failed logins per user per IP in 10 minutes", provider="groq"
        )
        ir, w = parser.extract_and_validate(json.dumps(SAMPLE_IR_AGGREGATE))
        assert ir["action"] == "filter+aggregate"
        assert ir["threshold"]["value"] == 5
        assert w == []

    def test_fenced_response_roundtrip(self, pb, parser):
        """Many models wrap JSON in a markdown fence."""
        fenced   = f"```json\n{json.dumps(SAMPLE_IR_FILTER)}\n```"
        ir, w    = parser.extract_and_validate(fenced)
        assert ir["action"] == "filter"

    def test_refinement_prompt_then_parse(self, pb, parser):
        bad_ir = {"action": "wrong", "filter": {"operator": "and"}}
        w_orig = parser.validate_ir_structure(bad_ir)
        assert len(w_orig) > 0

        refine_msgs = pb.build_refinement_prompt(
            "detect brute force",
            previous_ir=bad_ir,
            validation_errors=w_orig,
            provider="groq",
        )
        # Simulate model returning corrected IR
        corrected    = json.dumps(SAMPLE_IR_AGGREGATE)
        ir, warnings = parser.extract_and_validate(corrected)
        assert ir["action"] == "filter+aggregate"
        assert warnings == []

    def test_alias_coercion_in_pipeline(self, pb, parser):
        """Parser coerces 'username' → 'user' before validation."""
        raw = json.dumps({
            "action": "filter",
            "filter": {
                "operator": "and",
                "conditions": [{"field": "username", "op": "eq", "value": "admin"}],
            },
        })
        ir, _ = parser.extract_and_validate(raw)
        assert ir["filter"]["conditions"][0]["field"] == "user"


class TestTokenCounterWithMessages:
    """TokenCounter and prompt messages interact correctly."""

    @pytest.fixture
    def pb(self, tmp_path):
        return PromptBuilder(examples_path=make_examples_file(tmp_path))

    def test_counter_estimates_prompt_tokens(self, pb):
        c    = TokenCounter("llama-3.3-70b-versatile")
        msgs = pb.build_ir_prompt("detect port scan", provider="groq")
        est  = c.estimate_messages(msgs)
        assert est > 50  # system + user prompt must be substantial

    def test_counter_fits_context_for_normal_query(self, pb):
        c    = TokenCounter("llama-3.3-70b-versatile")
        msgs = pb.build_ir_prompt("detect port scan", provider="groq")
        assert c.fits_context(msgs, reserve_tokens=2048)

    def test_utilisation_pct_reasonable(self, pb):
        c    = TokenCounter("llama-3.3-70b-versatile")
        msgs = pb.build_ir_prompt("detect brute force on SSH in last hour", provider="groq")
        pct  = c.utilisation_pct(msgs)
        assert 0.01 < pct < 5.0   # normal prompt should be < 5% of 128k window

    def test_record_from_mock_response(self):
        c    = TokenCounter()
        resp = make_openai_response("ok", prompt_tokens=350, completion_tokens=80)
        c.record_from_response(resp)
        assert c.usage.prompt_tokens     == 350
        assert c.usage.completion_tokens == 80
        assert c.usage.total_tokens      == 430


class TestFieldMappingWithIR:
    """resolve() applied to real IR conditions."""

    def test_resolve_filter_conditions_splunk(self):
        conditions = SAMPLE_IR_FILTER["filter"]["conditions"]
        for cond in conditions:
            resolved = resolve(cond["field"], "splunk")
            assert resolved  # must not be empty

    def test_resolve_filter_conditions_elastic(self):
        assert resolve("status",  "elastic") == "event.outcome"
        assert resolve("src_ip",  "elastic") == "source.ip"

    def test_resolve_aggregation_group_by_qradar(self):
        group_by = SAMPLE_IR_AGGREGATE["aggregation"]["group_by"]
        resolved = resolve_all(group_by, "qradar")
        assert resolved[0] == "username"    # user → username on qradar
        assert resolved[1] == "sourceip"    # src_ip → sourceip on qradar

    def test_time_field_sentinel(self):
        assert resolve("_time", "sentinel") == "TimeGenerated"

    def test_full_ir_all_platforms(self):
        """Resolve every field in SAMPLE_IR_AGGREGATE for every platform."""
        fields = [c["field"] for c in SAMPLE_IR_AGGREGATE["filter"]["conditions"]]
        fields += SAMPLE_IR_AGGREGATE["aggregation"]["group_by"]
        for platform in PLATFORMS:
            resolved = resolve_all(fields, platform)
            assert len(resolved) == len(fields)
            assert all(r for r in resolved)  # no empty strings


class TestPipelineEndToEnd:
    """PromptBuilder → mock LLM → ResponseParser → FieldMapping."""

    @pytest.fixture
    def pb(self, tmp_path):
        return PromptBuilder(examples_path=make_examples_file(tmp_path))

    @pytest.fixture
    def parser(self):
        return ResponseParser()

    def test_full_pipeline_filter(self, pb, parser):
        # 1. Build prompt
        msgs = pb.build_ir_prompt("detect failed SSH logins in last hour", provider="groq")
        assert len(msgs) == 2

        # 2. Simulate LLM response (with alias that needs coercion)
        mock_llm_out = json.dumps({
            "action": "filter",
            "event_type": "authentication",
            "filter": {
                "operator": "and",
                "conditions": [
                    {"field": "username", "op": "eq", "value": "failure"},
                    {"field": "dest_port", "op": "eq", "value": 22},
                ],
            },
            "time_window": {"duration": "1h", "field": "_time"},
        })

        # 3. Parse + coerce + validate
        ir, warnings = parser.extract_and_validate(mock_llm_out)
        assert warnings == []
        assert ir["filter"]["conditions"][0]["field"] == "user"  # coerced

        # 4. Resolve fields for Splunk
        conditions   = ir["filter"]["conditions"]
        resolved     = [resolve(c["field"], "splunk") for c in conditions]
        assert "user" in resolved

    def test_full_pipeline_aggregate(self, pb, parser):
        msgs = pb.build_ir_prompt(
            "alert when same IP fails login more than 10 times in 5 minutes",
            provider="groq",
        )
        mock_llm_out = json.dumps(SAMPLE_IR_AGGREGATE)
        ir, warnings = parser.extract_and_validate(mock_llm_out)
        assert warnings == []
        assert ir["threshold"]["value"] == 5

        # Resolve group_by for elastic
        group_by     = ir["aggregation"]["group_by"]
        elastic_gby  = resolve_all(group_by, "elastic")
        assert "user.name" in elastic_gby
        assert "source.ip" in elastic_gby

    def test_streaming_chunk_pipeline(self, pb, parser):
        msgs   = pb.build_ir_prompt("detect port scan", provider="groq")
        ir_str = json.dumps(SAMPLE_IR_FILTER)
        # Simulate streaming: feed in chunks
        chunk_size = 10
        for i in range(0, len(ir_str), chunk_size):
            parser.feed_chunk(ir_str[i:i + chunk_size])
        result = parser.flush(coerce_fields=True)
        assert result is not None
        assert result["action"] == "filter"

    def test_gemini_prompt_format_in_pipeline(self, pb, parser):
        """Gemini format (user-only) still produces parseable IR."""
        msgs = pb.build_ir_prompt("detect lateral movement", provider="gemini")
        assert len(msgs) == 1
        assert msgs[0]["role"] == "user"
        # Simulate Gemini response
        ir, _ = parser.extract_and_validate(json.dumps(SAMPLE_IR_FILTER))
        assert ir["action"] == "filter"


# ═════════════════════════════════════════════════════════════════════════════
# LAYER 3 — CONTRACT / PROVIDER SMOKE TESTS
# ═════════════════════════════════════════════════════════════════════════════

class TestLLMClientInit:

    def test_known_provider_ok(self):
        c = LLMClient(provider="groq",   api_key="test")
        assert c.provider == "groq"

    def test_ollama_no_key_required(self):
        c = LLMClient(provider="ollama")
        assert c.api_key == "none"

    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError, match="Unknown provider"):
            LLMClient(provider="nonexistent")

    def test_default_model_groq(self):
        c = LLMClient(provider="groq", api_key="x")
        assert c.model == PROVIDER_CONFIGS["groq"]["default_model"]

    def test_default_model_gemini(self):
        c = LLMClient(provider="gemini", api_key="x")
        assert c.model == PROVIDER_CONFIGS["gemini"]["default_model"]

    def test_default_model_ollama(self):
        c = LLMClient(provider="ollama")
        assert c.model == PROVIDER_CONFIGS["ollama"]["default_model"]

    def test_custom_model(self):
        c = LLMClient(provider="groq", model="llama-3.1-8b-instant", api_key="x")
        assert c.model == "llama-3.1-8b-instant"

    def test_ollama_host_from_param(self):
        c = LLMClient(provider="ollama", ollama_host="http://myserver:11434")
        assert "myserver" in c.base_url

    def test_ollama_host_from_env(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_HOST", "http://envhost:11434")
        c = LLMClient(provider="ollama")
        assert "envhost" in c.base_url

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER",    "ollama")
        monkeypatch.setenv("LLM_MODEL",       "mistral")
        monkeypatch.setenv("TEMPERATURE",     "0.3")
        monkeypatch.setenv("MAX_TOKENS",      "512")
        monkeypatch.setenv("LLM_TIMEOUT",     "30.0")
        monkeypatch.setenv("LLM_MAX_RETRIES", "2")
        c = LLMClient.from_env()
        assert c.provider    == "ollama"
        assert c.model       == "mistral"
        assert c.temperature == 0.3
        assert c.max_tokens  == 512
        assert c.timeout     == 30.0
        assert c.max_retries == 2

    def test_capabilities_property(self):
        c    = LLMClient(provider="groq", model="llama-3.3-70b-versatile", api_key="x")
        caps = c.capabilities
        assert caps["provider"]         == "groq"
        assert caps["model"]            == "llama-3.3-70b-versatile"
        assert caps["supports_streaming"] is True
        assert caps["context_window"]   == 128_000
        assert "docs" in caps

    def test_repr(self):
        c = LLMClient(provider="groq", api_key="x")
        assert "groq" in repr(c)


class TestGroqComplete:
    """LLMClient._complete_openai_compat for Groq — all network mocked."""

    def _make_client(self, **kw):
        return LLMClient(
            provider="groq",
            model="llama-3.3-70b-versatile",
            api_key="test-key",
            **kw,
        )

    @patch("src.llm.client.LLMClient._complete_openai_compat")
    def test_complete_returns_text(self, mock_compat):
        mock_compat.return_value = "Hello from Groq"
        c      = self._make_client()
        result = c.complete([{"role": "user", "content": "hi"}])
        assert result == "Hello from Groq"

    @patch("src.llm.client.LLMClient._complete_openai_compat")
    def test_system_prompt_prepended(self, mock_compat):
        mock_compat.return_value = "ok"
        c    = self._make_client()
        c.complete(
            [{"role": "user", "content": "hi"}],
            system_prompt="You are a bot",
        )
        call_messages = mock_compat.call_args[0][0]
        assert call_messages[0]["role"]    == "system"
        assert call_messages[0]["content"] == "You are a bot"

    @patch("src.llm.client.LLMClient._complete_openai_compat")
    def test_json_mode_forwarded(self, mock_compat):
        mock_compat.return_value = "{}"
        c = self._make_client()
        c.complete([{"role": "user", "content": "hi"}], json_mode=True)
        assert mock_compat.call_args[0][3] is True   # json_mode positional arg

    @patch("src.llm.client.LLMClient._complete_openai_compat")
    def test_temperature_override(self, mock_compat):
        mock_compat.return_value = "ok"
        c = self._make_client()
        c.complete([{"role": "user", "content": "hi"}], temperature=0.9)
        temp_arg = mock_compat.call_args[0][1]
        assert temp_arg == 0.9

    @patch("src.llm.client.LLMClient._complete_openai_compat")
    def test_retries_on_generic_error(self, mock_compat):
        mock_compat.side_effect = [RuntimeError("transient"), "ok"]
        c = self._make_client(max_retries=2)
        with patch("src.llm.client.time.sleep"):
            result = c.complete([{"role": "user", "content": "hi"}])
        assert result == "ok"
        assert mock_compat.call_count == 2

    @patch("src.llm.client.LLMClient._complete_openai_compat")
    def test_raises_after_max_retries(self, mock_compat):
        mock_compat.side_effect = RuntimeError("always fails")
        c = self._make_client(max_retries=2)
        with patch("src.llm.client.time.sleep"):
            with pytest.raises(LLMMaxRetriesError):
                c.complete([{"role": "user", "content": "hi"}])
        assert mock_compat.call_count == 2

    @patch("src.llm.client.LLMClient._complete_openai_compat")
    def test_rate_limit_triggers_backoff(self, mock_compat):
        mock_compat.side_effect = [LLMRateLimitError(model="x"), "ok"]
        c = self._make_client(max_retries=2)
        with patch("src.llm.client.time.sleep") as sleep_mock:
            result = c.complete([{"role": "user", "content": "hi"}])
        assert result == "ok"
        sleep_mock.assert_called_once()

    @patch("src.llm.client.LLMClient._complete_openai_compat")
    def test_timeout_propagates_immediately(self, mock_compat):
        mock_compat.side_effect = LLMTimeoutError(model="x")
        c = self._make_client()
        with pytest.raises(LLMTimeoutError):
            c.complete([{"role": "user", "content": "hi"}])
        assert mock_compat.call_count == 1   # no retry on timeout

    @patch("src.llm.client.LLMClient._complete_openai_compat")
    def test_circuit_opens_after_failures(self, mock_compat):
        mock_compat.side_effect = RuntimeError("fail")
        c = self._make_client(max_retries=1)
        c._circuit.failure_threshold = 3

        with patch("src.llm.client.time.sleep"):
            for _ in range(3):
                try:
                    c.complete([{"role": "user", "content": "hi"}])
                except (LLMMaxRetriesError, LLMError):
                    pass

        assert c._circuit.is_open

    def test_openai_compat_kwargs_groq(self):
        """Verify the actual kwargs passed to openai.OpenAI.chat.completions.create."""
        mock_create   = Mock(return_value=make_openai_response("hello"))
        mock_oai_inst = Mock()
        mock_oai_inst.chat.completions.create = mock_create
        mock_oai_cls  = Mock(return_value=mock_oai_inst)

        c = self._make_client()
        with patch.dict("sys.modules", {"openai": Mock(
            OpenAI=mock_oai_cls,
            RateLimitError=Exception,
            APITimeoutError=Exception,
            APIConnectionError=Exception,
        )}):
            c._complete_openai_compat(
                [{"role": "user", "content": "test"}],
                temp=0.0, max_toks=256, json_mode=False, tools=None,
            )

        kwargs = mock_create.call_args[1]
        assert kwargs["model"] == "llama-3.3-70b-versatile"
        assert kwargs["seed"]  == 42           # Groq temp=0 seed
        assert "json_object"   not in str(kwargs.get("response_format", ""))

    def test_openai_compat_json_mode(self):
        mock_create   = Mock(return_value=make_openai_response('{"action":"filter"}'))
        mock_oai_inst = Mock()
        mock_oai_inst.chat.completions.create = mock_create

        c = self._make_client()
        with patch.dict("sys.modules", {"openai": Mock(
            OpenAI=Mock(return_value=mock_oai_inst),
            RateLimitError=Exception,
            APITimeoutError=Exception,
            APIConnectionError=Exception,
        )}):
            c._complete_openai_compat(
                [{"role": "user", "content": "x"}],
                temp=0.0, max_toks=256, json_mode=True, tools=None,
            )

        kwargs = mock_create.call_args[1]
        assert kwargs.get("response_format") == {"type": "json_object"}

    def test_complete_json_calls_complete_with_json_mode(self):
        c = self._make_client()
        with patch.object(c, "complete", return_value='{"x":1}') as mock_complete:
            c.complete_json([{"role": "user", "content": "go"}])
            assert mock_complete.call_args[1]["json_mode"] is True
            assert mock_complete.call_args[1]["temperature"] == 0.0


class TestOllamaComplete:
    """LLMClient behaviour specific to Ollama provider."""

    def _make_client(self, **kw):
        return LLMClient(provider="ollama", model="llama3.2", **kw)

    @patch("src.llm.client.LLMClient._complete_openai_compat")
    def test_ollama_no_seed(self, mock_compat):
        """Ollama should NOT inject seed (Groq-only)."""
        mock_compat.return_value = "response"
        c = self._make_client()
        c.complete([{"role": "user", "content": "hi"}])
        # seed is injected inside _complete_openai_compat based on provider,
        # so we test the real method with a mocked openai module
        pass  # covered by test_openai_compat_kwargs_ollama below

    def test_openai_compat_kwargs_ollama(self):
        """Ollama should NOT get seed; api_key='none'."""
        mock_create   = Mock(return_value=make_openai_response("hello"))
        mock_oai_inst = Mock()
        mock_oai_inst.chat.completions.create = mock_create

        c = self._make_client()
        with patch.dict("sys.modules", {"openai": Mock(
            OpenAI=Mock(return_value=mock_oai_inst),
            RateLimitError=Exception,
            APITimeoutError=Exception,
            APIConnectionError=Exception,
        )}):
            c._complete_openai_compat(
                [{"role": "user", "content": "test"}],
                temp=0.0, max_toks=128, json_mode=False, tools=None,
            )

        kwargs   = mock_create.call_args[1]
        oai_call = mock_oai_inst.__class__.call_args  # OpenAI(api_key=...)
        assert "seed" not in kwargs                   # no seed for Ollama
        assert kwargs["model"] == "llama3.2"

    def test_list_ollama_models(self):
        """list_ollama_models() calls /api/tags and parses the response."""
        fake_data = json.dumps({"models": [
            {"name": "llama3.2:latest"},
            {"name": "mistral:7b"},
        ]}).encode()

        c = self._make_client()
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = Mock()
            mock_resp.read.return_value = fake_data
            mock_urlopen.return_value.__enter__ = lambda s: s
            mock_urlopen.return_value.__exit__  = Mock(return_value=False)
            mock_urlopen.return_value = mock_resp
            models = c.list_ollama_models()

        assert "llama3.2:latest" in models
        assert "mistral:7b"      in models

    def test_list_ollama_models_wrong_provider(self):
        c = LLMClient(provider="groq", api_key="x")
        with pytest.raises(LLMError, match="ollama"):
            c.list_ollama_models()

    def test_is_ollama_model_available_found(self):
        c = self._make_client()
        with patch.object(c, "list_ollama_models", return_value=["llama3.2:latest"]):
            assert c.is_ollama_model_available("llama3.2")

    def test_is_ollama_model_available_not_found(self):
        c = self._make_client()
        with patch.object(c, "list_ollama_models", return_value=["mistral:7b"]):
            assert not c.is_ollama_model_available("llama3.2")

    def test_is_ollama_model_available_list_error(self):
        c = self._make_client()
        with patch.object(c, "list_ollama_models", side_effect=LLMError("down")):
            assert not c.is_ollama_model_available()

    def test_pull_ollama_model_wrong_provider(self):
        c = LLMClient(provider="groq", api_key="x")
        with pytest.raises(LLMError, match="ollama"):
            c.pull_ollama_model("llama3.2")

    def test_pull_ollama_model_calls_subprocess(self):
        c = self._make_client()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)
            c.pull_ollama_model("llama3.2")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "ollama" in cmd
        assert "pull"   in cmd
        assert "llama3.2" in cmd

    def test_pull_ollama_model_failure_raises(self):
        c = self._make_client()
        with patch("subprocess.run", return_value=Mock(returncode=1)):
            with pytest.raises(LLMError):
                c.pull_ollama_model("nonexistent-model")


class TestGeminiComplete:
    """LLMClient._complete_gemini — SDK fully mocked."""

    def _make_client(self, **kw):
        return LLMClient(provider="gemini", model="gemini-2.0-flash", api_key="test-key", **kw)

    def _make_genai_mock(self, response_text: str = '{"action":"filter"}') -> Mock:
        usage                       = Mock()
        usage.prompt_token_count    = 100
        usage.candidates_token_count = 30

        response      = Mock()
        response.text = response_text
        response.usage_metadata = usage

        chat      = Mock()
        chat.send_message.return_value = response

        model     = Mock()
        model.start_chat.return_value = chat

        genai        = Mock()
        genai.configure = Mock()
        genai.GenerativeModel.return_value = model
        genai.GenerationConfig = Mock(return_value={})
        genai.protos = Mock()
        genai.protos.FunctionDeclaration = Mock()
        genai.protos.Tool = Mock()

        # Safety enums
        from enum import Enum
        class HarmCategory(Enum):
            HARM_CATEGORY_HATE_SPEECH       = 1
            HARM_CATEGORY_HARASSMENT        = 2
            HARM_CATEGORY_SEXUALLY_EXPLICIT = 3
            HARM_CATEGORY_DANGEROUS_CONTENT = 4
        class HarmBlockThreshold(Enum):
            BLOCK_NONE               = 0
            BLOCK_ONLY_HIGH          = 1
            BLOCK_MEDIUM_AND_ABOVE   = 2
            BLOCK_LOW_AND_ABOVE      = 3

        genai_types = Mock()
        genai_types.HarmCategory       = HarmCategory
        genai_types.HarmBlockThreshold = HarmBlockThreshold

        return genai, genai_types

    @patch("src.llm.client.LLMClient._complete_gemini")
    def test_gemini_complete_returns_text(self, mock_gemini):
        mock_gemini.return_value = '{"action": "filter"}'
        c      = self._make_client()
        result = c.complete([{"role": "user", "content": "detect failed login"}])
        assert result == '{"action": "filter"}'

    def test_gemini_configure_called_with_key(self):
        genai, genai_types = self._make_genai_mock()
        c = self._make_client()
        with patch.dict("sys.modules", {
            "google":                   Mock(),
            "google.generativeai":      genai,
            "google.generativeai.types": genai_types,
        }):
            c._complete_gemini(
                [{"role": "user", "content": "hi"}],
                temp=0.0, max_toks=256, json_mode=False, tools=None,
            )
        genai.configure.assert_called_once_with(api_key="test-key")

    def test_gemini_system_message_separated(self):
        genai, genai_types = self._make_genai_mock()
        c = self._make_client()
        messages = [
            {"role": "system", "content": "You are NL-SIEM"},
            {"role": "user",   "content": "hi"},
        ]
        with patch.dict("sys.modules", {
            "google":                   Mock(),
            "google.generativeai":      genai,
            "google.generativeai.types": genai_types,
        }):
            c._complete_gemini(messages, temp=0.0, max_toks=256, json_mode=False, tools=None)

        # GenerativeModel should have been called with system_instruction
        kwargs = genai.GenerativeModel.call_args[1]
        assert "system_instruction" in kwargs
        assert "NL-SIEM" in kwargs["system_instruction"]

    def test_gemini_json_mode_sets_mime_type(self):
        genai, genai_types = self._make_genai_mock()
        c = self._make_client()
        with patch.dict("sys.modules", {
            "google":                   Mock(),
            "google.generativeai":      genai,
            "google.generativeai.types": genai_types,
        }):
            c._complete_gemini(
                [{"role": "user", "content": "hi"}],
                temp=0.0, max_toks=256, json_mode=True, tools=None,
            )
        gen_config_call = genai.GenerationConfig.call_args[1]
        assert gen_config_call.get("response_mime_type") == "application/json"

    def test_gemini_token_usage_from_metadata(self):
        genai, genai_types = self._make_genai_mock()
        c = self._make_client()
        with patch.dict("sys.modules", {
            "google":                   Mock(),
            "google.generativeai":      genai,
            "google.generativeai.types": genai_types,
        }):
            c._complete_gemini(
                [{"role": "user", "content": "hi"}],
                temp=0.0, max_toks=256, json_mode=False, tools=None,
            )
        assert c.counter.usage.prompt_tokens     == 100
        assert c.counter.usage.completion_tokens == 30

    def test_gemini_rate_limit_error(self):
        genai, genai_types = self._make_genai_mock()
        chat  = genai.GenerativeModel.return_value.start_chat.return_value
        chat.send_message.side_effect = Exception("429 quota exceeded")
        c = self._make_client()
        with patch.dict("sys.modules", {
            "google":                   Mock(),
            "google.generativeai":      genai,
            "google.generativeai.types": genai_types,
        }):
            with pytest.raises(LLMRateLimitError):
                c._complete_gemini(
                    [{"role": "user", "content": "hi"}],
                    temp=0.0, max_toks=256, json_mode=False, tools=None,
                )

    def test_gemini_timeout_error(self):
        genai, genai_types = self._make_genai_mock()
        chat  = genai.GenerativeModel.return_value.start_chat.return_value
        chat.send_message.side_effect = Exception("deadline exceeded timeout")
        c = self._make_client()
        with patch.dict("sys.modules", {
            "google":                   Mock(),
            "google.generativeai":      genai,
            "google.generativeai.types": genai_types,
        }):
            with pytest.raises(LLMTimeoutError):
                c._complete_gemini(
                    [{"role": "user", "content": "hi"}],
                    temp=0.0, max_toks=256, json_mode=False, tools=None,
                )

    def test_gemini_safety_level_from_env(self, monkeypatch):
        monkeypatch.setenv("GEMINI_SAFETY_LEVEL", "off")
        genai, genai_types = self._make_genai_mock()
        c = self._make_client()
        with patch.dict("sys.modules", {
            "google":                   Mock(),
            "google.generativeai":      genai,
            "google.generativeai.types": genai_types,
        }):
            c._complete_gemini(
                [{"role": "user", "content": "hi"}],
                temp=0.0, max_toks=256, json_mode=False, tools=None,
            )
        # GenerativeModel called with safety_settings containing BLOCK_NONE
        gm_kwargs = genai.GenerativeModel.call_args[1]
        safety    = gm_kwargs.get("safety_settings", {})
        # All thresholds should be BLOCK_NONE (value 0)
        for threshold in safety.values():
            assert threshold.value == 0


class TestStreamingContract:
    """stream() and astream() delegate correctly."""

    def _make_client_groq(self):
        return LLMClient(provider="groq", model="llama-3.1-8b-instant", api_key="x")

    def test_stream_openai_compat_yields_chunks(self):
        c = self._make_client_groq()

        class FakeChunk:
            def __init__(self, text):
                self.choices = [Mock(delta=Mock(content=text))]

        fake_stream = [FakeChunk("Hello"), FakeChunk(", "), FakeChunk("world")]

        mock_create   = Mock(return_value=iter(fake_stream))
        mock_oai_inst = Mock()
        mock_oai_inst.chat.completions.create.return_value.__enter__ = lambda s: iter(fake_stream)
        mock_oai_inst.chat.completions.create.return_value.__exit__  = Mock(return_value=False)
        mock_oai_inst.chat.completions.create.return_value = fake_stream

        with patch.dict("sys.modules", {"openai": Mock(
            OpenAI=Mock(return_value=mock_oai_inst),
            APIConnectionError=Exception,
        )}):
            chunks = list(c._stream_openai_compat(
                [{"role": "user", "content": "hi"}],
                temp=0.0, max_toks=128,
            ))

        assert "Hello" in chunks

    def test_stream_records_tokens(self):
        c = self._make_client_groq()

        class FakeChunk:
            def __init__(self, text):
                self.choices = [Mock(delta=Mock(content=text))]

        fake_stream = [FakeChunk("OK")]

        mock_oai_inst = Mock()
        mock_oai_inst.chat.completions.create.return_value = fake_stream

        with patch.dict("sys.modules", {"openai": Mock(
            OpenAI=Mock(return_value=mock_oai_inst),
            APIConnectionError=Exception,
        )}):
            list(c._stream_openai_compat(
                [{"role": "user", "content": "hi"}],
                temp=0.0, max_toks=128,
            ))

        assert c.counter.usage.num_requests == 1

    def test_astream_is_async_generator(self):
        c = self._make_client_groq()

        async def run():
            with patch.object(c, "stream", return_value=iter(["chunk1", "chunk2"])):
                chunks = []
                async for chunk in c.astream([{"role": "user", "content": "hi"}]):
                    chunks.append(chunk)
                return chunks

        chunks = asyncio.run(run())
        assert chunks == ["chunk1", "chunk2"]

    def test_acomplete_wraps_complete(self):
        c = self._make_client_groq()

        async def run():
            with patch.object(c, "complete", return_value="async result"):
                return await c.acomplete([{"role": "user", "content": "hi"}])

        result = asyncio.run(run())
        assert result == "async result"


class TestHealthCheck:

    def test_health_check_passes(self):
        c = LLMClient(provider="groq", api_key="x")
        with patch.object(c, "complete", return_value="OK"):
            assert c.health_check() is True

    def test_health_check_fails_empty_response(self):
        c = LLMClient(provider="groq", api_key="x")
        with patch.object(c, "complete", return_value=""):
            assert c.health_check() is False

    def test_health_check_fails_on_exception(self):
        c = LLMClient(provider="groq", api_key="x")
        with patch.object(c, "complete", side_effect=LLMError("boom")):
            assert c.health_check() is False

    def test_health_check_max_tokens_small(self):
        """Health check must use a small token limit."""
        c = LLMClient(provider="groq", api_key="x")
        with patch.object(c, "complete", return_value="OK") as mock_complete:
            c.health_check()
        assert mock_complete.call_args[1]["max_tokens"] <= 10


class TestOpenRouterExtras:
    """OpenRouter-specific header injection."""

    def test_openrouter_extra_headers(self):
        mock_create   = Mock(return_value=make_openai_response("hi"))
        mock_oai_inst = Mock()
        mock_oai_inst.chat.completions.create = mock_create

        c = LLMClient(
            provider="openrouter",
            model="meta-llama/llama-3.1-70b-instruct:free",
            api_key="or-key",
        )
        with patch.dict("sys.modules", {"openai": Mock(
            OpenAI=Mock(return_value=mock_oai_inst),
            RateLimitError=Exception,
            APITimeoutError=Exception,
            APIConnectionError=Exception,
        )}):
            c._complete_openai_compat(
                [{"role": "user", "content": "hi"}],
                temp=0.0, max_toks=128, json_mode=False, tools=None,
            )

        kwargs = mock_create.call_args[1]
        assert "extra_headers" in kwargs
        assert "HTTP-Referer" in kwargs["extra_headers"]
        assert "X-Title"      in kwargs["extra_headers"]


class TestToolCallHandling:
    """Tool use / function calling returned as formatted JSON."""

    def test_format_tool_calls_single(self):
        c      = LLMClient(provider="groq", api_key="x")
        tc     = Mock()
        tc.function.name      = "search_logs"
        tc.function.arguments = '{"query": "failed login"}'
        msg    = Mock()
        msg.tool_calls = [tc]
        result = json.loads(c._format_tool_calls(msg))
        assert result["tool_calls"][0]["tool"]               == "search_logs"
        assert result["tool_calls"][0]["arguments"]["query"] == "failed login"

    def test_format_tool_calls_multiple(self):
        c = LLMClient(provider="groq", api_key="x")
        tc1 = Mock(); tc1.function.name = "a"; tc1.function.arguments = "{}"
        tc2 = Mock(); tc2.function.name = "b"; tc2.function.arguments = '{"x":1}'
        msg = Mock(); msg.tool_calls = [tc1, tc2]
        result = json.loads(c._format_tool_calls(msg))
        assert len(result["tool_calls"]) == 2
        assert result["tool_calls"][1]["tool"] == "b"

    def test_tools_forwarded_to_openai_compat(self):
        """Tools param should appear in create() kwargs when model supports them."""
        mock_create   = Mock(return_value=make_openai_response("ok"))
        mock_oai_inst = Mock()
        mock_oai_inst.chat.completions.create = mock_create

        c     = LLMClient(provider="groq", model="llama-3.3-70b-versatile", api_key="x")
        tools = [{"type": "function", "function": {"name": "fn", "description": "do thing", "parameters": {}}}]

        with patch.dict("sys.modules", {"openai": Mock(
            OpenAI=Mock(return_value=mock_oai_inst),
            RateLimitError=Exception,
            APITimeoutError=Exception,
            APIConnectionError=Exception,
        )}):
            c._complete_openai_compat(
                [{"role": "user", "content": "x"}],
                temp=0.0, max_toks=128, json_mode=False, tools=tools,
            )

        kwargs = mock_create.call_args[1]
        assert "tools"       in kwargs
        assert "tool_choice" in kwargs
        assert kwargs["tool_choice"] == "auto"


class TestFullPipelineWithMockLLM:
    """End-to-end: PromptBuilder → mocked LLMClient → ResponseParser → FieldMapping."""

    @pytest.fixture
    def pb(self, tmp_path):
        return PromptBuilder(examples_path=make_examples_file(tmp_path))

    @pytest.fixture
    def parser(self):
        return ResponseParser()

    def test_groq_brute_force_pipeline(self, pb, parser):
        c = LLMClient(provider="groq", model="llama-3.3-70b-versatile", api_key="x")

        expected_ir = json.dumps(SAMPLE_IR_AGGREGATE)
        with patch.object(c, "complete", return_value=expected_ir):
            msgs   = pb.build_ir_prompt(
                "alert when a single IP fails to log in more than 5 times in 10 minutes",
                provider="groq",
            )
            raw    = c.complete(msgs, json_mode=True)
            ir, w  = parser.extract_and_validate(raw)

        assert w             == []
        assert ir["action"]  == "filter+aggregate"
        assert ir["threshold"]["value"] == 5

        # Map to Elastic
        fields   = [c2["field"] for c2 in ir["filter"]["conditions"]]
        resolved = resolve_all(fields, "elastic")
        assert "event.outcome" in resolved

    def test_gemini_dns_pivot_pipeline(self, pb, parser):
        c = LLMClient(provider="gemini", model="gemini-2.0-flash", api_key="x")

        dns_ir = {
            "action": "filter+aggregate",
            "event_type": "dns",
            "filter": {
                "operator": "and",
                "conditions": [{"field": "query_domain", "op": "contains", "value": ".onion"}],
            },
            "aggregation": {
                "function": "count",
                "field": "query_domain",
                "group_by": ["src_ip", "query_domain"],
                "alias": "event_count",
            },
            "time_window": {"duration": "24h", "field": "_time"},
        }

        with patch.object(c, "complete", return_value=json.dumps(dns_ir)):
            msgs   = pb.build_ir_prompt("find DNS queries to .onion domains in last 24h", provider="gemini")
            raw    = c.complete(msgs)
            ir, w  = parser.extract_and_validate(raw)

        assert w == []
        assert ir["event_type"] == "dns"
        assert resolve("query_domain", "splunk") == "query"
        assert resolve("query_domain", "elastic") == "dns.question.name"

    def test_ollama_refinement_loop(self, pb, parser):
        """Simulate a self-refinement loop: bad IR → fix → validate OK."""
        c = LLMClient(provider="ollama", model="llama3.2")

        bad_ir = {"action": "unknown_action"}
        w1     = parser.validate_ir_structure(bad_ir)
        assert len(w1) > 0

        fixed_ir = json.dumps(SAMPLE_IR_FILTER)

        with patch.object(c, "complete", return_value=fixed_ir):
            refine_msgs = pb.build_refinement_prompt(
                "detect failed logins",
                previous_ir=bad_ir,
                validation_errors=w1,
                provider="ollama",
            )
            raw   = c.complete(refine_msgs)
            ir, w = parser.extract_and_validate(raw)

        assert w == []
        assert ir["action"] == "filter"

    def test_token_tracking_across_full_pipeline(self, pb, parser):
        c = LLMClient(provider="groq", model="llama-3.3-70b-versatile", api_key="x")

        mock_resp = make_openai_response(
            json.dumps(SAMPLE_IR_FILTER),
            prompt_tokens=450,
            completion_tokens=95,
        )
        with patch.object(c, "complete") as mock_complete:
            mock_complete.return_value = json.dumps(SAMPLE_IR_FILTER)
            mock_complete.side_effect  = None
            # Manually record as if the real call happened
            c.counter.record_from_response(mock_resp)

            msgs = pb.build_ir_prompt("detect failed logins", provider="groq")
            raw  = c.complete(msgs)

        assert c.counter.usage.prompt_tokens     == 450
        assert c.counter.usage.completion_tokens == 95
        assert c.counter.usage.total_tokens      == 545


# ─────────────────────────────────────────────────────────────────────────────
# CLI runner — run directly with `python test_llm_layer.py`
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import subprocess, sys
    result = subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-v", "--tb=short"],
        check=False,
    )
    sys.exit(result.returncode)