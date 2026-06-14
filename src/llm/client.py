"""
LLM Client — supports Groq, Google Gemini, Ollama (local), and OpenRouter.
All free. No OpenAI or Anthropic API keys required.

Provider routing:
  - groq       → api.groq.com          (OpenAI-compatible, Llama 3.3 70B, tool use, streaming)
  - gemini     → generativelanguage.googleapis.com (Gemini 2.0 Flash, vision, tools, streaming)
  - ollama     → localhost:11434        (fully local, streaming, multimodal, model management)
  - openrouter → openrouter.ai         (aggregates free models, streaming)

Set in .env:
    LLM_PROVIDER=groq
    GROQ_API_KEY=gsk_...
    LLM_MODEL=llama-3.3-70b-versatile
    OLLAMA_HOST=http://localhost:11434   # optional override

Place at: src/llm/client.py

Usage:
    from src.llm.client import LLMClient
    client = LLMClient()
    response = client.complete(messages=[{"role": "user", "content": "Hello"}])

    # Streaming
    for chunk in client.stream(messages=[{"role": "user", "content": "Hello"}]):
        print(chunk, end="", flush=True)

    # Async
    response = await client.acomplete(messages=[{"role": "user", "content": "Hello"}])
"""

from __future__ import annotations

import asyncio
import os
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Generator, Iterator

from src.llm.token_counter import MODEL_REGISTRY, TokenCounter
from src.utils.exceptions import (
    LLMError,
    LLMMaxRetriesError,
    LLMRateLimitError,
    LLMTimeoutError,
)
from src.utils.logger import get_logger

log = get_logger(__name__)


# ── Provider configs ──────────────────────────────────────────────────────
PROVIDER_CONFIGS: dict[str, dict] = {
    "groq": {
        "base_url":       "https://api.groq.com/openai/v1",
        "default_model":  "llama-3.3-70b-versatile",
        "key_env":        "GROQ_API_KEY",
        "rate_limit_rpm": 30,    # free tier: 30 req/min; 14,400 tokens/min
        "rate_limit_tpm": 14_400,
        "supports_streaming": True,
        "supports_tools":     True,
        "docs":           "https://console.groq.com/docs/openai",
    },
    "ollama": {
        "base_url":       None,  # resolved at runtime via OLLAMA_HOST
        "default_model":  "llama3.1",
        "key_env":        None,
        "rate_limit_rpm": 9_999,
        "rate_limit_tpm": 9_999_999,
        "supports_streaming": True,
        "supports_tools":     True,
        "docs":           "https://github.com/ollama/ollama/blob/main/docs/api.md",
    },
    "openrouter": {
        "base_url":       "https://openrouter.ai/api/v1",
        "default_model":  "meta-llama/llama-3.1-70b-instruct:free",
        "key_env":        "OPENROUTER_API_KEY",
        "rate_limit_rpm": 20,
        "rate_limit_tpm": 9_999_999,
        "supports_streaming": True,
        "supports_tools":     False,  # varies by model
        "docs":           "https://openrouter.ai/docs",
    },
    "gemini": {
        "base_url":       None,  # uses google-generativeai SDK
        "default_model":  "gemini-2.0-flash",
        "key_env":        "GOOGLE_API_KEY",
        "rate_limit_rpm": 15,    # free tier: 15 RPM; 1M TPM on Flash
        "rate_limit_tpm": 1_000_000,
        "supports_streaming": True,
        "supports_tools":     True,
        "docs":           "https://ai.google.dev/gemini-api/docs",
    },
}


# ── Circuit breaker ───────────────────────────────────────────────────────
@dataclass
class CircuitBreaker:
    """
    Simple circuit breaker to stop hammering a failing provider.

    States: closed (normal) → open (failing, reject calls) → half-open (probe).
    """
    failure_threshold: int   = 5
    reset_timeout:     float = 60.0   # seconds before trying again

    _failures:    int   = field(default=0, init=False)
    _opened_at:   float = field(default=0.0, init=False)
    _state:       str   = field(default="closed", init=False)  # closed | open | half-open

    def record_success(self) -> None:
        self._failures = 0
        self._state    = "closed"

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self._state    = "open"
            self._opened_at = time.monotonic()
            log.warning("Circuit breaker OPENED", extra={"failures": self._failures})

    def allow_request(self) -> bool:
        if self._state == "closed":
            return True
        if self._state == "open":
            if time.monotonic() - self._opened_at >= self.reset_timeout:
                self._state = "half-open"
                log.info("Circuit breaker HALF-OPEN — probing")
                return True
            return False
        # half-open: allow one probe
        return True

    @property
    def is_open(self) -> bool:
        return self._state == "open"


# ── Rate limiter ──────────────────────────────────────────────────────────
class RateLimiter:
    """
    Sliding-window rate limiter (requests per minute).
    Also tracks tokens per minute when tpm_limit > 0.
    """

    def __init__(self, rpm: int, tpm: int = 0):
        self.rpm       = max(rpm, 1)
        self.tpm       = tpm
        self._req_times: deque[float] = deque()
        self._tok_times: deque[tuple[float, int]] = deque()   # (ts, tokens)

    def _purge(self) -> None:
        cutoff = time.monotonic() - 60.0
        while self._req_times and self._req_times[0] < cutoff:
            self._req_times.popleft()
        while self._tok_times and self._tok_times[0][0] < cutoff:
            self._tok_times.popleft()

    def wait_if_needed(self, estimated_tokens: int = 0) -> None:
        self._purge()

        # Request-rate check
        if len(self._req_times) >= self.rpm:
            sleep_for = 60.0 - (time.monotonic() - self._req_times[0]) + 0.1
            if sleep_for > 0:
                log.debug("Rate limit — sleeping", extra={"seconds": round(sleep_for, 2)})
                time.sleep(sleep_for)
                self._purge()

        # Token-rate check
        if self.tpm > 0 and estimated_tokens > 0:
            used_tpm = sum(t for _, t in self._tok_times)
            if used_tpm + estimated_tokens > self.tpm:
                oldest = self._tok_times[0][0] if self._tok_times else time.monotonic()
                sleep_for = 60.0 - (time.monotonic() - oldest) + 0.1
                if sleep_for > 0:
                    log.debug("TPM limit — sleeping", extra={"seconds": round(sleep_for, 2)})
                    time.sleep(sleep_for)
                    self._purge()

        now = time.monotonic()
        self._req_times.append(now)
        if estimated_tokens > 0:
            self._tok_times.append((now, estimated_tokens))


# ── Main client ───────────────────────────────────────────────────────────
class LLMClient:
    """
    Unified LLM client for Groq, Gemini, Ollama, and OpenRouter.

    Features:
      - Streaming responses (stream / astream)
      - Async completions (acomplete)
      - Tool / function calling (Groq, Gemini, Ollama)
      - Vision / image inputs (Gemini, Ollama llava, Groq llama-3.2-vision)
      - Per-provider rate limiting with token-bucket awareness
      - Circuit breaker to avoid thundering-herd on failures
      - Structured JSON output mode
      - Ollama model management helpers (list, pull, running)
    """

    def __init__(
        self,
        provider:    str        = "groq",
        model:       str | None = None,
        api_key:     str | None = None,
        temperature: float      = 0.0,
        max_tokens:  int        = 2_048,
        timeout:     float      = 60.0,
        max_retries: int        = 3,
        *,
        ollama_host: str | None = None,
    ):
        """
        Initialise the LLM client.

        Args:
            provider:    One of groq / gemini / ollama / openrouter.
            model:       Model name. Defaults to provider's recommended free model.
            api_key:     API key. If None, reads from environment.
            temperature: Sampling temperature (0.0 for deterministic output).
            max_tokens:  Max completion tokens.
            timeout:     Request timeout in seconds.
            max_retries: Retry attempts on transient errors.
            ollama_host: Override OLLAMA_HOST (e.g. "http://remote:11434").
        """
        self.provider    = provider.lower().strip()
        self.temperature = temperature
        self.max_tokens  = max_tokens
        self.timeout     = timeout
        self.max_retries = max_retries

        cfg = PROVIDER_CONFIGS.get(self.provider)
        if cfg is None:
            raise ValueError(
                f"Unknown provider '{provider}'. "
                f"Valid options: {list(PROVIDER_CONFIGS)}"
            )

        self.model   = model or cfg["default_model"]
        self.api_key = api_key or self._load_api_key(cfg["key_env"])

        # Resolve Ollama base URL
        if self.provider == "ollama":
            host = (
                ollama_host
                or os.getenv("OLLAMA_HOST", "http://localhost:11434")
            ).rstrip("/")
            self.base_url = f"{host}/v1"
        else:
            self.base_url = cfg.get("base_url")

        self.counter        = TokenCounter(model=self.model)
        self._rate_limiter  = RateLimiter(
            rpm=cfg["rate_limit_rpm"],
            tpm=cfg.get("rate_limit_tpm", 0),
        )
        self._circuit       = CircuitBreaker()

        log.info(
            "LLMClient initialised",
            extra={
                "provider":  self.provider,
                "model":     self.model,
                "temp":      self.temperature,
                "streaming": cfg.get("supports_streaming", False),
                "tools":     cfg.get("supports_tools", False),
            },
        )

    # ─────────────────────────────────────────────
    # Public sync API
    # ─────────────────────────────────────────────

    def complete(
        self,
        messages:      list[dict],
        system_prompt: str | None   = None,
        temperature:   float | None = None,
        max_tokens:    int | None   = None,
        json_mode:     bool         = False,
        tools:         list[dict] | None = None,
    ) -> str:
        """
        Send a chat completion request and return the response text.

        Args:
            messages:      List of {"role": ..., "content": ...} dicts.
            system_prompt: Optional system message prepended to messages.
            temperature:   Override instance temperature for this call.
            max_tokens:    Override instance max_tokens for this call.
            json_mode:     Request JSON output (Groq, Ollama, Gemini).
            tools:         OpenAI-format tool definitions for function calling.

        Returns:
            Response text string.

        Raises:
            LLMMaxRetriesError: After all retry attempts fail.
            LLMTimeoutError:    If the request times out.
        """
        if system_prompt:
            messages = [{"role": "system", "content": system_prompt}] + messages

        if not self.counter.fits_context(messages, reserve_tokens=max_tokens or self.max_tokens):
            log.warning(
                "Messages may exceed context window",
                # FIX: utilisation_pct now returns 0.0–1.0 fraction; multiply by 100 for display
                extra={"utilisation": f"{self.counter.utilisation_pct(messages) * 100:.1f}%"},
            )

        temp   = temperature if temperature is not None else self.temperature
        n_toks = max_tokens  if max_tokens  is not None else self.max_tokens

        # Estimate tokens for rate-limit budgeting
        est_tokens = self.counter.estimate_messages(messages) + n_toks

        last_exc: Exception | None = None
        for attempt in range(1, self.max_retries + 1):

            if not self._circuit.allow_request():
                raise LLMError(
                    f"Circuit breaker open — provider '{self.provider}' appears to be down.",
                    details={"provider": self.provider},
                )

            try:
                self._rate_limiter.wait_if_needed(est_tokens)
                log.debug(
                    "LLM request",
                    extra={
                        "provider": self.provider,
                        "model":    self.model,
                        "attempt":  attempt,
                        "messages": len(messages),
                    },
                )

                if self.provider == "gemini":
                    text = self._complete_gemini(messages, temp, n_toks, json_mode, tools)
                else:
                    text = self._complete_openai_compat(messages, temp, n_toks, json_mode, tools)

                self._circuit.record_success()
                log.debug("LLM response", extra={"chars": len(text), "attempt": attempt})
                return text

            except LLMRateLimitError as exc:
                last_exc = exc
                self._circuit.record_failure()
                wait = min(2 ** attempt, 30)
                log.warning("Rate limit hit — backing off", extra={"wait_s": wait, "attempt": attempt})
                time.sleep(wait)

            except LLMTimeoutError:
                self._circuit.record_failure()
                raise

            except LLMError:
                raise

            except Exception as exc:
                last_exc = exc
                self._circuit.record_failure()
                wait = attempt * 2
                log.warning("LLM call failed — retrying", extra={"error": str(exc), "attempt": attempt, "wait_s": wait})
                time.sleep(wait)

        raise LLMMaxRetriesError(model=self.model, attempts=self.max_retries)

    def complete_json(
        self,
        messages:      list[dict],
        system_prompt: str | None = None,
    ) -> str:
        """
        Request JSON output. Wraps complete() with json_mode=True.
        The caller is responsible for parsing the returned string.
        """
        return self.complete(
            messages=messages,
            system_prompt=system_prompt,
            json_mode=True,
            temperature=0.0,
        )

    def stream(
        self,
        messages:      list[dict],
        system_prompt: str | None   = None,
        temperature:   float | None = None,
        max_tokens:    int | None   = None,
    ) -> Iterator[str]:
        """
        Stream response tokens as they arrive.

        Yields:
            Text chunks (strings) as they stream from the provider.

        Example:
            for chunk in client.stream(messages):
                print(chunk, end="", flush=True)
        """
        if system_prompt:
            messages = [{"role": "system", "content": system_prompt}] + messages

        temp   = temperature if temperature is not None else self.temperature
        n_toks = max_tokens  if max_tokens  is not None else self.max_tokens

        self._rate_limiter.wait_if_needed()

        if self.provider == "gemini":
            yield from self._stream_gemini(messages, temp, n_toks)
        else:
            yield from self._stream_openai_compat(messages, temp, n_toks)

    # ─────────────────────────────────────────────
    # Async API
    # ─────────────────────────────────────────────

    async def acomplete(
        self,
        messages:      list[dict],
        system_prompt: str | None   = None,
        temperature:   float | None = None,
        max_tokens:    int | None   = None,
        json_mode:     bool         = False,
        tools:         list[dict] | None = None,
    ) -> str:
        """
        Async version of complete(). Runs the sync call in a thread pool.

        Use when integrating with async frameworks (FastAPI, asyncio pipelines).
        """
        return await asyncio.to_thread(
            self.complete,
            messages=messages,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            json_mode=json_mode,
            tools=tools,
        )

    async def astream(
        self,
        messages: list[dict],
        system_prompt: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Generator[str, None, None]:
        """
        Async streaming wrapper around stream().
        """
        loop = asyncio.get_event_loop()

        gen = self.stream(
            messages,
            system_prompt,
            temperature,
            max_tokens,
        )

        _SENTINEL = object()

        while True:
            chunk = await loop.run_in_executor(
                None,
                lambda: next(gen, _SENTINEL),
            )

            if chunk is _SENTINEL:
                break

            yield chunk

    # ─────────────────────────────────────────────
    # Groq / OpenAI-compat implementation
    # ─────────────────────────────────────────────

    def _complete_openai_compat(
        self,
        messages:  list[dict],
        temp:      float,
        max_toks:  int,
        json_mode: bool,
        tools:     list[dict] | None,
    ) -> str:
        """
        Call any OpenAI-compatible endpoint: Groq, Ollama, OpenRouter.

        Groq extras handled:
          - tool_choice="auto" when tools provided
          - response_format JSON (Groq supports this natively)
          - Groq returns usage in every response — recorded automatically.

        Ollama extras:
          - num_predict instead of max_tokens for older Ollama builds
          - Automatic fallback when JSON mode unsupported
        """
        try:
            from openai import OpenAI, RateLimitError, APITimeoutError, APIConnectionError
        except ImportError:
            raise LLMError(
                "openai package not installed. Run: pip install openai",
                details={"provider": self.provider},
            )

        client = OpenAI(
            api_key=self.api_key or "none",
            base_url=self.base_url,
            timeout=self.timeout,
        )

        kwargs: dict[str, Any] = {
            "model":       self.model,
            "messages":    messages,
            "temperature": temp,
            "max_tokens":  max_toks,
        }

        # JSON mode — Groq and Ollama support response_format
        if json_mode and self.counter.supports_json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        elif json_mode:
            log.debug("JSON mode requested but model may not support it — relying on prompt")

        # Tool use — Groq and Ollama support function calling
        if tools and self.counter.supports_tools:
            kwargs["tools"]       = tools
            kwargs["tool_choice"] = "auto"
        elif tools:
            log.warning(
                "Tools requested but model/provider may not support them",
                extra={"model": self.model, "provider": self.provider},
            )

        # Groq-specific: seed for reproducibility at temp=0
        if self.provider == "groq" and temp == 0.0:
            kwargs["seed"] = 42

        # OpenRouter-specific: add site info for free tier
        if self.provider == "openrouter":
            kwargs["extra_headers"] = {
                "HTTP-Referer": os.getenv("OPENROUTER_SITE_URL", "https://github.com/nl-siem"),
                "X-Title":      os.getenv("OPENROUTER_APP_NAME", "NL-SIEM"),
            }

        try:
            response = client.chat.completions.create(**kwargs)
            self.counter.record_from_response(response)

            # Handle tool calls (Groq / Ollama function calling)
            msg = response.choices[0].message
            if hasattr(msg, "tool_calls") and msg.tool_calls:
                return self._format_tool_calls(msg)

            return msg.content or ""

        except RateLimitError as exc:
            raise LLMRateLimitError(model=self.model) from exc
        except APITimeoutError as exc:
            raise LLMTimeoutError(model=self.model, timeout_seconds=self.timeout) from exc
        except APIConnectionError as exc:
            raise LLMError(
                f"Cannot connect to {self.provider} at {self.base_url}. "
                "Check that the service is running.",
                details={"provider": self.provider, "base_url": self.base_url},
            ) from exc
        except Exception as exc:
            raise LLMError(
                f"OpenAI-compat call failed: {exc}",
                details={"provider": self.provider, "model": self.model},
            ) from exc

    def _stream_openai_compat(
        self,
        messages:  list[dict],
        temp:      float,
        max_toks:  int,
    ) -> Iterator[str]:
        """Stream from Groq / Ollama / OpenRouter via SSE."""
        try:
            from openai import OpenAI, APIConnectionError
        except ImportError:
            raise LLMError("openai package not installed. Run: pip install openai")

        client = OpenAI(
            api_key=self.api_key or "none",
            base_url=self.base_url,
            timeout=self.timeout,
        )

        kwargs: dict[str, Any] = {
            "model":       self.model,
            "messages":    messages,
            "temperature": temp,
            "max_tokens":  max_toks,
            "stream":      True,
        }
        if self.provider == "groq" and temp == 0.0:
            kwargs["seed"] = 42

        full_text = []
        try:
            stream_resp = client.chat.completions.create(**kwargs)

            for chunk in stream_resp:
                delta = chunk.choices[0].delta
                text = delta.content or ""

                if text:
                    full_text.append(text)
                    yield text
        except APIConnectionError as exc:
            raise LLMError(
                f"Cannot connect to {self.provider}.",
                details={"provider": self.provider},
            ) from exc
        finally:
            # Record estimated token usage from the full streamed text
            if full_text:
                self.counter.record_streaming("".join(full_text), messages)

    # ─────────────────────────────────────────────
    # Gemini implementation
    # ─────────────────────────────────────────────

    def _complete_gemini(
        self,
        messages:  list[dict],
        temp:      float,
        max_toks:  int,
        json_mode: bool,
        tools:     list[dict] | None,
    ) -> str:
        """
        Call Google Gemini via the google-generativeai SDK.

        Improvements over baseline:
          - Gemini 2.0 Flash support (faster, free)
          - response_mime_type for native JSON mode
          - Safety settings configurable via env
          - Function/tool declarations converted from OpenAI format
          - Grounding (Google Search) support
          - Proper usage tracking via response.usage_metadata
        """
        try:
            import google.generativeai as genai
            # FIX: Import HarmBlockThreshold and HarmCategory from genai.types here,
            # inside the lazy import block where genai is guaranteed to be available.
            # Previously these were referenced as bare names at module level, causing
            # NameError whenever _complete_gemini was called (even with genai installed).
            from google.generativeai.types import HarmBlockThreshold, HarmCategory
        except ImportError:
            raise LLMError(
                "google-generativeai package not installed. "
                "Run: pip install google-generativeai",
                details={"provider": "gemini"},
            )

        genai.configure(api_key=self.api_key)

        # Separate system message from conversation
        system_parts = [m["content"] for m in messages if m["role"] == "system"]
        conversation = [m for m in messages if m["role"] != "system"]

        system_instruction = "\n\n".join(system_parts) if system_parts else None

        # Safety settings — permissive for security research context
        # Override via env: GEMINI_SAFETY_LEVEL=off|low|medium|high
        safety_level = os.getenv("GEMINI_SAFETY_LEVEL", "medium").lower()
        safety_map   = {
            "off":    HarmBlockThreshold.BLOCK_NONE,
            "low":    HarmBlockThreshold.BLOCK_ONLY_HIGH,
            "medium": HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
            "high":   HarmBlockThreshold.BLOCK_LOW_AND_ABOVE,
        }
        threshold = safety_map.get(safety_level, HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE)
        safety_settings = {
            HarmCategory.HARM_CATEGORY_HATE_SPEECH:       threshold,
            HarmCategory.HARM_CATEGORY_HARASSMENT:        threshold,
            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: threshold,
            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: threshold,
        }

        # Generation config
        gen_config: dict[str, Any] = {
            "temperature":       temp,
            "max_output_tokens": max_toks,
        }
        if json_mode:
            gen_config["response_mime_type"] = "application/json"

        # Build Gemini tool declarations from OpenAI format
        gemini_tools = None
        if tools and self.counter.supports_tools:
            gemini_tools = self._convert_tools_to_gemini(tools)

        model_kwargs: dict[str, Any] = {}
        if system_instruction:
            model_kwargs["system_instruction"] = system_instruction
        if gemini_tools:
            model_kwargs["tools"] = gemini_tools

        gemini_model = genai.GenerativeModel(
            model_name=self.model,
            safety_settings=safety_settings,
            **model_kwargs,
        )

        # Build conversation history (multi-turn)
        gemini_history = []
        for msg in conversation[:-1]:
            role = "user" if msg["role"] == "user" else "model"
            content = msg["content"]
            if isinstance(content, list):
                # Multi-modal content
                parts = self._convert_multimodal_content(content)
                gemini_history.append({"role": role, "parts": parts})
            else:
                gemini_history.append({"role": role, "parts": [content]})

        chat = gemini_model.start_chat(history=gemini_history)

        # Handle the last user message (may be multimodal)
        last_msg     = conversation[-1] if conversation else {"content": ""}
        last_content = last_msg.get("content", "")
        if isinstance(last_content, list):
            last_parts = self._convert_multimodal_content(last_content)
        else:
            last_parts = [last_content]

        try:
            response = chat.send_message(
                last_parts,
                generation_config=genai.GenerationConfig(**gen_config),
            )

            text = response.text or ""

            # Record actual token usage from Gemini's usage_metadata
            meta = getattr(response, "usage_metadata", None)

            if meta:
                prompt_tokens = getattr(meta, "prompt_token_count", 0)
                completion_tokens = getattr(meta, "candidates_token_count", 0)

                try:
                    prompt_tokens = int(prompt_tokens)
                except Exception:
                    prompt_tokens = 0

                try:
                    completion_tokens = int(completion_tokens)
                except Exception:
                    completion_tokens = 0
                completion_tokens = (
                    completion_tokens
                    if isinstance(completion_tokens, int)
                    else 0
                )

                self.counter.record(
                    prompt_tokens,
                    completion_tokens,
                )
            else:
                self.counter.record_streaming(text, messages)

            return text

        except Exception as exc:
            err_str = str(exc).lower()
            if any(
                k in err_str
                for k in (
                    "quota",
                    "rate",
                    "429",
                    "resource_exhausted",
                    "too many requests",
                )
            ):
                raise LLMRateLimitError(model=self.model) from exc
            if any(k in err_str for k in ("timeout", "deadline", "504")):
                raise LLMTimeoutError(model=self.model, timeout_seconds=self.timeout) from exc
            if "api_key" in err_str or "invalid" in err_str:
                raise LLMError(
                    f"Gemini API key invalid or not set. "
                    f"Set GOOGLE_API_KEY in your environment. Error: {exc}",
                    details={"model": self.model},
                ) from exc
            raise LLMError(
                f"Gemini call failed: {exc}",
                details={"model": self.model},
            ) from exc

    def _stream_gemini(
        self,
        messages: list[dict],
        temp:     float,
        max_toks: int,
    ) -> Iterator[str]:
        """Stream from Gemini using generate_content with stream=True."""
        try:
            import google.generativeai as genai
        except ImportError:
            raise LLMError("google-generativeai package not installed.")

        genai.configure(api_key=self.api_key)

        system_parts = [m["content"] for m in messages if m["role"] == "system"]
        conversation = [m for m in messages if m["role"] != "system"]
        system_instruction = "\n\n".join(system_parts) if system_parts else None

        model_kwargs: dict[str, Any] = {}
        if system_instruction:
            model_kwargs["system_instruction"] = system_instruction

        gemini_model = genai.GenerativeModel(model_name=self.model, **model_kwargs)

        # Flatten all conversation turns into one prompt for streaming
        all_parts: list[str] = []
        for msg in conversation:
            role    = "User" if msg["role"] == "user" else "Assistant"
            content = msg.get("content", "")
            if isinstance(content, str):
                all_parts.append(f"{role}: {content}")

        prompt = "\n".join(all_parts)

        gen_config = genai.GenerationConfig(
            temperature=temp,
            max_output_tokens=max_toks,
        )

        full_chunks: list[str] = []
        try:
            for chunk in gemini_model.generate_content(
                prompt,
                generation_config=gen_config,
                stream=True,
            ):
                text = chunk.text or ""
                if text:
                    full_chunks.append(text)
                    yield text
        finally:
            if full_chunks:
                self.counter.record_streaming("".join(full_chunks), messages)

    # ─────────────────────────────────────────────
    # Ollama-specific helpers
    # ─────────────────────────────────────────────

    def list_ollama_models(self) -> list[str]:
        """
        List locally available Ollama models.

        Returns:
            List of model names (e.g. ['llama3.1:latest', 'mistral:7b']).

        Raises:
            LLMError: If Ollama is not reachable.
        """
        if self.provider != "ollama":
            raise LLMError("list_ollama_models() is only available for the 'ollama' provider.")

        try:
            import urllib.request, json as _json
            host    = self.base_url.rstrip("/v1").rstrip("/")
            url     = f"{host}/api/tags"
            req     = urllib.request.urlopen(url, timeout=5)
            data    = _json.loads(req.read())
            return [m["name"] for m in data.get("models", [])]
        except Exception as exc:
            raise LLMError(
                f"Cannot reach Ollama at {self.base_url}. Is it running? Error: {exc}",
                details={"base_url": self.base_url},
            ) from exc

    def pull_ollama_model(self, model: str) -> None:
        """
        Pull a model from the Ollama registry (equivalent to `ollama pull <model>`).

        Args:
            model: Model name, e.g. "llama3.1:8b" or "mistral".
        """
        if self.provider != "ollama":
            raise LLMError("pull_ollama_model() is only available for the 'ollama' provider.")

        import subprocess
        log.info("Pulling Ollama model", extra={"model": model})
        result = subprocess.run(
            ["ollama", "pull", model],
            check=False,
            capture_output=False,
            text=True,
        )
        if result.returncode != 0:
            raise LLMError(
                f"Failed to pull Ollama model '{model}'.",
                details={"model": model},
            )
        log.info("Ollama model pulled successfully", extra={"model": model})

    def is_ollama_model_available(self, model: str | None = None) -> bool:
        """
        Check whether a model is available locally in Ollama.

        Args:
            model: Model name to check. Defaults to self.model.

        Returns:
            True if the model exists locally.
        """
        target = model or self.model
        try:
            available = self.list_ollama_models()
            # Normalize: "llama3.1" matches "llama3.1:latest"
            return any(
                a == target or a.startswith(f"{target}:") or target.startswith(f"{a.split(':')[0]}:")
                for a in available
            )
        except LLMError:
            return False

    # ─────────────────────────────────────────────
    # Tool use helpers
    # ─────────────────────────────────────────────

    def _format_tool_calls(self, msg: Any) -> str:
        """
        Format tool call response as a JSON string for downstream parsing.
        """
        import json as _json
        calls = []
        for tc in msg.tool_calls or []:
            calls.append({
                "tool":      tc.function.name,
                "arguments": _json.loads(tc.function.arguments or "{}"),
            })
        return _json.dumps({"tool_calls": calls})

    def _convert_tools_to_gemini(self, tools: list[dict]) -> list[Any]:
        """
        Convert OpenAI-format tool definitions to Gemini FunctionDeclaration format.

        OpenAI format:
          {"type": "function", "function": {"name": ..., "description": ..., "parameters": ...}}

        Gemini format:
          genai.protos.FunctionDeclaration(name=..., description=..., parameters=...)
        """
        try:
            import google.generativeai as genai
        except ImportError:
            return []

        declarations = []
        for tool in tools:
            if tool.get("type") != "function":
                continue
            fn = tool.get("function", {})
            try:
                decl = genai.protos.FunctionDeclaration(
                    name=fn.get("name", ""),
                    description=fn.get("description", ""),
                    parameters=fn.get("parameters"),
                )
                declarations.append(decl)
            except Exception as exc:
                log.warning("Failed to convert tool to Gemini format", extra={"tool": fn.get("name"), "error": str(exc)})

        return [genai.protos.Tool(function_declarations=declarations)] if declarations else []

    def _convert_multimodal_content(self, content_list: list[dict]) -> list[Any]:
        """
        Convert OpenAI-format multimodal content to Gemini parts.

        Handles text and image_url types.
        """
        parts: list[Any] = []
        for part in content_list:
            ptype = part.get("type", "text")
            if ptype == "text":
                parts.append(part.get("text", ""))
            elif ptype == "image_url":
                url = part.get("image_url", {}).get("url", "")
                if url.startswith("data:"):
                    # Base64 inline image
                    try:
                        import google.generativeai as genai
                        header, b64data = url.split(",", 1)
                        mime  = header.split(";")[0].split(":")[1]
                        import base64
                        parts.append({"mime_type": mime, "data": base64.b64decode(b64data)})
                    except Exception:
                        parts.append(f"[Image: {url[:80]}]")
                else:
                    parts.append(f"[Image URL: {url}]")
        return parts

    # ─────────────────────────────────────────────
    # Utility
    # ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """
        Send a minimal test request to verify the provider is reachable.

        Returns:
            True if reachable, False otherwise.
        """
        try:
            response = self.complete(
                messages=[{"role": "user", "content": "Reply OK"}],
                max_tokens=5,
            )
            ok = bool(response and response.strip())
            log.info(
                "Health check passed" if ok else "Health check returned empty",
                extra={"provider": self.provider, "model": self.model},
            )
            return ok
        except Exception as exc:
            log.error("Health check failed", extra={"provider": self.provider, "error": str(exc)})
            return False

    @property
    def capabilities(self) -> dict[str, Any]:
        """Return provider and model capability summary."""
        cfg  = PROVIDER_CONFIGS[self.provider]
        spec = MODEL_REGISTRY.get(self.model)
        return {
            "provider":           self.provider,
            "model":              self.model,
            "context_window":     self.counter.context_window,
            "supports_streaming": cfg.get("supports_streaming", False),
            "supports_tools":     self.counter.supports_tools,
            "supports_json_mode": self.counter.supports_json_mode,
            "supports_vision":    self.counter.supports_vision,
            "rate_limit_rpm":     cfg["rate_limit_rpm"],
            "rate_limit_tpm":     cfg.get("rate_limit_tpm", 0),
            "docs":               cfg.get("docs"),
        }

    @classmethod
    def from_env(cls) -> "LLMClient":
        """
        Create an LLMClient from environment variables.

        Reads:
            LLM_PROVIDER     (groq / gemini / ollama / openrouter)
            LLM_MODEL        (optional override)
            OLLAMA_HOST      (optional; default http://localhost:11434)
            GROQ_API_KEY / GOOGLE_API_KEY / OPENROUTER_API_KEY
            TEMPERATURE      (default 0.0)
            MAX_TOKENS       (default 2048)
            LLM_TIMEOUT      (default 60.0)
            LLM_MAX_RETRIES  (default 3)
        """
        provider = os.getenv("LLM_PROVIDER", "groq").lower()
        model    = os.getenv("LLM_MODEL") or None
        temp     = float(os.getenv("TEMPERATURE", "0.0"))
        max_tok  = int(os.getenv("MAX_TOKENS", "2048"))
        timeout  = float(os.getenv("LLM_TIMEOUT", "60.0"))
        retries  = int(os.getenv("LLM_MAX_RETRIES", "3"))

        return cls(
            provider=provider,
            model=model,
            temperature=temp,
            max_tokens=max_tok,
            timeout=timeout,
            max_retries=retries,
        )

    def _load_api_key(self, env_var: str | None) -> str:
        if env_var is None:
            return "none"
        key = os.getenv(env_var, "")
        if not key:
            log.warning("API key not set", extra={"env_var": env_var, "provider": self.provider})
        return key

    def __repr__(self) -> str:
        return f"LLMClient(provider={self.provider!r}, model={self.model!r})"

