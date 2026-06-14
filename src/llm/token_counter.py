"""
Token Counter — estimates prompt token counts and tracks cost per run.

Works without any API call using tiktoken for estimation.
Supports Groq, Gemini, Ollama, and OpenRouter models.

Place at: src/llm/token_counter.py

Usage:
    from src.llm.token_counter import TokenCounter
    counter = TokenCounter()
    count = counter.estimate("your prompt text here")
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field  # dataclass still used for TokenUsage, RunCost
from pathlib import Path
from typing import Any

from src.utils.logger import get_logger

log = get_logger(__name__)


# ── Model context windows + pricing (cost_per_1m_tokens for budgeting) ────
class ModelSpec:
    """Immutable model capability spec."""
    __slots__ = (
        "context_window", "input_cost_per_1m", "output_cost_per_1m",
        "supports_vision", "supports_tools", "supports_json_mode",
    )

    def __init__(
        self,
        context_window:     int,
        input_cost_per_1m:  float = 0.0,
        output_cost_per_1m: float = 0.0,
        supports_vision:    bool  = False,
        supports_tools:     bool  = False,
        supports_json_mode: bool  = False,
    ) -> None:
        object.__setattr__(self, "context_window",     context_window)
        object.__setattr__(self, "input_cost_per_1m",  input_cost_per_1m)
        object.__setattr__(self, "output_cost_per_1m", output_cost_per_1m)
        object.__setattr__(self, "supports_vision",    supports_vision)
        object.__setattr__(self, "supports_tools",     supports_tools)
        object.__setattr__(self, "supports_json_mode", supports_json_mode)

    def __setattr__(self, name, value):
        raise AttributeError("ModelSpec is immutable")

    def __repr__(self) -> str:
        return (
            f"ModelSpec(ctx={self.context_window}, vision={self.supports_vision}, "
            f"tools={self.supports_tools}, json={self.supports_json_mode})"
        )


MODEL_REGISTRY: dict[str, ModelSpec] = {
    # ── Groq (free tier, fast inference) ──────────────────────────────────
    "llama-3.3-70b-versatile":       ModelSpec(128_000, supports_tools=True, supports_json_mode=True),
    "llama-3.1-70b-versatile":       ModelSpec(131_072, supports_tools=True, supports_json_mode=True),
    "llama-3.1-8b-instant":          ModelSpec(131_072, supports_tools=True, supports_json_mode=True),
    "llama3-70b-8192":               ModelSpec(8_192,   supports_json_mode=True),
    "llama3-8b-8192":                ModelSpec(8_192,   supports_json_mode=True),
    "mixtral-8x7b-32768":            ModelSpec(32_768,  supports_json_mode=True),
    "gemma2-9b-it":                  ModelSpec(8_192),
    "gemma-7b-it":                   ModelSpec(8_192),
    "llama-3.2-90b-vision-preview":  ModelSpec(8_192,   supports_vision=True, supports_tools=True),
    "llama-3.2-11b-vision-preview":  ModelSpec(8_192,   supports_vision=True),
    "llama-3.2-3b-preview":          ModelSpec(8_192,   supports_tools=True),
    "llama-3.2-1b-preview":          ModelSpec(8_192),
    "llama-guard-3-8b":              ModelSpec(8_192),
    "deepseek-r1-distill-llama-70b": ModelSpec(128_000, supports_json_mode=True),
    "qwen-qwq-32b":                  ModelSpec(131_072, supports_tools=True, supports_json_mode=True),
    "mistral-saba-24b":              ModelSpec(32_768,  supports_tools=True),
    "allam-2-7b":                    ModelSpec(4_096),

    # ── Gemini (Google AI Studio free tier) ───────────────────────────────
    "gemini-2.0-flash":              ModelSpec(1_048_576, supports_vision=True, supports_tools=True, supports_json_mode=True),
    "gemini-2.0-flash-lite":         ModelSpec(1_048_576, supports_vision=True),
    "gemini-2.0-flash-thinking-exp": ModelSpec(32_767,   supports_vision=True),
    "gemini-1.5-flash":              ModelSpec(1_048_576, supports_vision=True, supports_tools=True, supports_json_mode=True),
    "gemini-1.5-flash-8b":          ModelSpec(1_048_576, supports_vision=True),
    "gemini-1.5-pro":                ModelSpec(2_097_152, supports_vision=True, supports_tools=True, supports_json_mode=True),
    "gemini-1.0-pro":                ModelSpec(32_768,   supports_tools=True),

    # ── Ollama (local) ────────────────────────────────────────────────────
    "llama3.1":                      ModelSpec(131_072, supports_tools=True, supports_json_mode=True),
    "llama3.1:8b":                   ModelSpec(131_072, supports_tools=True, supports_json_mode=True),
    "llama3.1:70b":                  ModelSpec(131_072, supports_tools=True, supports_json_mode=True),
    "llama3.2":                      ModelSpec(131_072, supports_tools=True, supports_json_mode=True),
    "llama3.2:3b":                   ModelSpec(131_072, supports_tools=True),
    "llama3.3":                      ModelSpec(131_072, supports_tools=True, supports_json_mode=True),
    "mistral":                       ModelSpec(32_768,  supports_tools=True, supports_json_mode=True),
    "mistral:7b":                    ModelSpec(32_768,  supports_tools=True, supports_json_mode=True),
    "mixtral:8x7b":                  ModelSpec(32_768,  supports_tools=True),
    "qwen2:7b":                      ModelSpec(131_072, supports_tools=True, supports_json_mode=True),
    "qwen2.5":                       ModelSpec(131_072, supports_tools=True, supports_json_mode=True),
    "qwen2.5:7b":                    ModelSpec(131_072, supports_tools=True, supports_json_mode=True),
    "qwen2.5:72b":                   ModelSpec(131_072, supports_tools=True, supports_json_mode=True),
    "phi4":                          ModelSpec(16_384,  supports_tools=True),
    "deepseek-r1":                   ModelSpec(131_072, supports_json_mode=True),
    "deepseek-r1:7b":                ModelSpec(131_072),
    "deepseek-r1:70b":               ModelSpec(131_072),
    "llava":                         ModelSpec(4_096,   supports_vision=True),
    "llava:13b":                     ModelSpec(4_096,   supports_vision=True),
    "moondream":                     ModelSpec(2_048,   supports_vision=True),
    "gemma2":                        ModelSpec(8_192),
    "gemma2:9b":                     ModelSpec(8_192),
    "codellama":                     ModelSpec(16_384,  supports_json_mode=True),
    "nomic-embed-text":              ModelSpec(8_192),

    # ── OpenRouter free models ────────────────────────────────────────────
    "meta-llama/llama-3.1-70b-instruct:free":  ModelSpec(131_072, supports_tools=True, supports_json_mode=True),
    "meta-llama/llama-3.2-90b-vision:free":    ModelSpec(8_192,   supports_vision=True),
    "mistralai/mistral-7b-instruct:free":       ModelSpec(32_768,  supports_json_mode=True),
    "google/gemma-2-9b-it:free":               ModelSpec(8_192),
    "microsoft/phi-3-mini-128k-instruct:free": ModelSpec(128_000),
    "qwen/qwen-2-7b-instruct:free":            ModelSpec(131_072, supports_json_mode=True),
}

# Backward compat alias — keep old flat dict accessible
MODEL_CONTEXT_WINDOWS: dict[str, int] = {
    k: v.context_window for k, v in MODEL_REGISTRY.items()
}

# ── Approximate chars-per-token for fast estimation without tiktoken ──────
# FIX: Use 3 instead of 4 — a more conservative (safer) estimate.
# Real-world LLM tokenisers average ~3.5 chars/token for English prose but
# can drop to ~2 chars/token for highly repetitive or short-word content.
# Using 3 ensures fits_context() errs on the side of caution and correctly
# rejects inputs that are near or over the context limit.
CHARS_PER_TOKEN = 3


@dataclass
class RunCost:
    """Tracks USD cost estimates for a session (0.0 for free-tier models)."""
    input_cost:  float = 0.0
    output_cost: float = 0.0

    @property
    def total(self) -> float:
        return self.input_cost + self.output_cost

    def add(self, prompt_tokens: int, completion_tokens: int, spec: ModelSpec) -> None:
        self.input_cost  += (prompt_tokens     / 1_000_000) * spec.input_cost_per_1m
        self.output_cost += (completion_tokens / 1_000_000) * spec.output_cost_per_1m

    def summary(self) -> str:
        if self.total == 0.0:
            return "cost=free"
        return f"cost=${self.total:.6f} (in=${self.input_cost:.6f}, out=${self.output_cost:.6f})"


@dataclass
class TokenUsage:
    """Tracks token usage across a run."""
    prompt_tokens:     int = 0
    completion_tokens: int = 0
    total_tokens:      int = 0
    num_requests:      int = 0
    cost:              RunCost = field(default_factory=RunCost)

    def add(self, prompt: int, completion: int, spec: ModelSpec | None = None) -> None:
        self.prompt_tokens     += prompt
        self.completion_tokens += completion
        self.total_tokens      += prompt + completion
        self.num_requests      += 1
        if spec:
            self.cost.add(prompt, completion, spec)

    def to_dict(self) -> dict:
        return {
            "prompt_tokens":     self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens":      self.total_tokens,
            "num_requests":      self.num_requests,
            "cost_usd":          round(self.cost.total, 8),
        }

    def summary(self) -> str:
        return (
            f"requests={self.num_requests} | "
            f"prompt={self.prompt_tokens} | "
            f"completion={self.completion_tokens} | "
            f"total={self.total_tokens} | "
            f"{self.cost.summary()}"
        )


class TokenCounter:
    """
    Estimates token counts and tracks usage across a session.

    Uses tiktoken when available, falls back to char/3 estimation.
    Tracks cost estimates and model capability flags.
    """

    def __init__(self, model: str = "llama3.1"):
        self.model = model
        self.usage = TokenUsage()
        self._spec = MODEL_REGISTRY.get(model)
        self._enc  = self._load_encoder()

    # ── Capability shortcuts ───────────────────────────────────────────────

    @property
    def supports_vision(self) -> bool:
        return self._spec.supports_vision if self._spec else False

    @property
    def supports_tools(self) -> bool:
        return self._spec.supports_tools if self._spec else False

    @property
    def supports_json_mode(self) -> bool:
        return self._spec.supports_json_mode if self._spec else False

    @property
    def context_window(self) -> int:
        return self._spec.context_window if self._spec else 8_192

    # ── Encoding ──────────────────────────────────────────────────────────

    def _load_encoder(self):
        """Try to load tiktoken encoder; fall back to char estimation."""
        try:
            import tiktoken
            enc = tiktoken.get_encoding("cl100k_base")
            log.debug("tiktoken loaded", extra={"encoding": "cl100k_base"})
            return enc
        except ImportError:
            log.debug("tiktoken not installed, using char/3 estimation")
            return None

    def estimate(self, text: str) -> int:
        """
        Estimate token count for a string.

        Args:
            text: Input text.

        Returns:
            Estimated token count.
        """
        if not text:
            return 0
        if self._enc is not None:
            try:
                return len(self._enc.encode(text))
            except Exception:
                pass
        return max(1, len(text) // CHARS_PER_TOKEN)

    def estimate_messages(self, messages: list[dict]) -> int:
        """
        Estimate token count for a list of chat messages.

        Args:
            messages: List of {"role": ..., "content": ...} dicts.

        Returns:
            Estimated total token count including role overhead.
        """
        total = 0
        for msg in messages:
            total += 4  # per-message overhead
            content = msg.get("content", "")
            if isinstance(content, str):
                total += self.estimate(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict):
                        if "text" in part:
                            total += self.estimate(part["text"])
                        elif part.get("type") == "image_url":
                            total += 765  # ~85 tiles × 9 tokens, GPT-4V estimate
        return total

    def fits_context(self, messages: list[dict], reserve_tokens: int = 512) -> bool:
        """
        Check whether messages fit within the model's context window.

        Args:
            messages:       List of chat messages.
            reserve_tokens: Tokens to reserve for completion output.

        Returns:
            True if messages fit with reserved space.
        """
        used = self.estimate_messages(messages)
        fits = used + reserve_tokens <= self.context_window
        if not fits:
            log.warning(
                "Context window exceeded",
                extra={
                    "model":   self.model,
                    "used":    used,
                    "max":     self.context_window,
                    "reserve": reserve_tokens,
                    "over_by": used + reserve_tokens - self.context_window,
                },
            )
        return fits

    def utilisation_pct(self, messages: list[dict]) -> float:
        """
        Return fraction of context window used by messages (0.0 – 1.0).

        FIX: Previously returned a 0–100 percentage; corrected to return
        a 0.0–1.0 fraction so callers can format it themselves (e.g. f'{x:.1%}').
        client.py log format updated accordingly.
        """
        used = self.estimate_messages(messages)
        return round(used / self.context_window, 4)

    def record(self, prompt_tokens: int, completion_tokens: int) -> None:
        """
        Record actual token usage from an API response.

        Args:
            prompt_tokens:     Tokens used in the prompt.
            completion_tokens: Tokens in the completion.
        """
        self.usage.add(prompt_tokens, completion_tokens, self._spec)
        log.debug(
            "Token usage recorded",
            extra={
                "prompt":     prompt_tokens,
                "completion": completion_tokens,
                "session":    self.usage.summary(),
            },
        )

    def record_streaming(self, completion_text: str, prompt_messages: list[dict]) -> None:
        """
        Record token usage when only the completion text is available (streaming).
        Estimates prompt tokens from the message list.

        Args:
            completion_text: The full streamed completion string.
            prompt_messages: The messages sent to the model.
        """
        prompt_est     = self.estimate_messages(prompt_messages)
        completion_est = self.estimate(completion_text)
        self.record(prompt_est, completion_est)

    def record_from_response(self, response: Any) -> None:
        """
        Extract and record token usage from an OpenAI-compatible response object.

        Args:
            response: API response with .usage attribute.
        """
        try:
            usage = response.usage
            if usage:
                self.record(
                    prompt_tokens=getattr(usage, "prompt_tokens", 0),
                    completion_tokens=getattr(usage, "completion_tokens", 0),
                )
        except Exception as exc:
            log.debug("Could not extract token usage from response", extra={"error": str(exc)})

    def save(self, path: str | Path) -> None:
        """Save session usage to a JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "model":   self.model,
            "usage":   self.usage.to_dict(),
            "summary": self.usage.summary(),
            "capabilities": {
                "context_window":    self.context_window,
                "supports_vision":   self.supports_vision,
                "supports_tools":    self.supports_tools,
                "supports_json_mode": self.supports_json_mode,
            },
        }
        path.write_text(json.dumps(data, indent=2))
        log.info("Token usage saved", extra={"path": str(path)})

    def reset(self) -> None:
        """Reset session usage counters."""
        self.usage = TokenUsage()

    def __repr__(self) -> str:
        return f"TokenCounter(model={self.model!r}, {self.usage.summary()})"
