"""
LLM — language model interface layer.

Supports Groq, Google Gemini, Ollama (local), and OpenRouter.
All providers are free-tier compatible — no paid API keys required.

Quickstart
----------
    # Auto-detect provider from LLM_PROVIDER env var (default: groq)
    from src.llm import auto_client
    client = auto_client()
    reply  = client.complete([{"role": "user", "content": "Hello"}])

    # Explicit provider
    from src.llm import LLMClient
    client = LLMClient(provider="ollama", model="llama3.2")
    reply  = client.complete([{"role": "user", "content": "Hello"}])

    # Streaming
    for chunk in client.stream([{"role": "user", "content": "Count to 5"}]):
        print(chunk, end="", flush=True)

    # Async
    import asyncio
    reply = asyncio.run(client.acomplete([{"role": "user", "content": "Hello"}]))

    # NL → IR pipeline
    from src.llm import PromptBuilder, ResponseParser
    builder = PromptBuilder()
    parser  = ResponseParser()
    msgs    = builder.build_ir_prompt("Detect brute force on SSH in 1 hour")
    raw     = client.complete(msgs, json_mode=True)
    ir, warnings = parser.extract_and_validate(raw)

    # Token tracking
    from src.llm import TokenCounter
    counter = TokenCounter(model="llama-3.3-70b-versatile")
    print(counter.estimate("some text"))
    print(counter.supports_tools)   # True

Provider notes
--------------
  groq       Fast cloud inference. Free tier: 30 req/min, 14,400 tokens/min.
             Best models: llama-3.3-70b-versatile, deepseek-r1-distill-llama-70b
             Set GROQ_API_KEY in your environment.

  gemini     Google AI Studio free tier. 15 req/min, 1M tokens/min (Flash).
             Best models: gemini-2.0-flash, gemini-1.5-pro
             Set GOOGLE_API_KEY in your environment.

  ollama     Fully local. No API key. Unlimited throughput.
             Best models: llama3.2, qwen2.5:7b, mistral
             Requires: https://ollama.com — then `ollama pull llama3.2`
             Override host via OLLAMA_HOST env var.

  openrouter Aggregates many providers. Free models available.
             Set OPENROUTER_API_KEY in your environment.

Environment variables
---------------------
  LLM_PROVIDER     groq | gemini | ollama | openrouter  (default: groq)
  LLM_MODEL        override default model for the chosen provider
  GROQ_API_KEY     Groq API key
  GOOGLE_API_KEY   Gemini API key
  OPENROUTER_API_KEY
  OLLAMA_HOST      e.g. http://localhost:11434 (default)
  TEMPERATURE      float, default 0.0
  MAX_TOKENS       int, default 2048
  LLM_TIMEOUT      float seconds, default 60.0
  LLM_MAX_RETRIES  int, default 3
  GEMINI_SAFETY_LEVEL  off | low | medium | high (default: medium)
"""

from __future__ import annotations

import os
from typing import Literal

from src.llm.client import LLMClient, PROVIDER_CONFIGS
from src.llm.prompts import PromptBuilder, PromptCondition, ProviderHint
from src.llm.response_parser import ResponseParser
from src.llm.token_counter import (
    MODEL_CONTEXT_WINDOWS,
    MODEL_REGISTRY,
    ModelSpec,
    RunCost,
    TokenCounter,
    TokenUsage,
)

__all__ = [
    # ── Client ────────────────────────────────────────────────────────────
    "LLMClient",
    "PROVIDER_CONFIGS",
    # ── Prompts ───────────────────────────────────────────────────────────
    "PromptBuilder",
    "PromptCondition",
    "ProviderHint",
    # ── Parser ────────────────────────────────────────────────────────────
    "ResponseParser",
    # ── Token tracking ────────────────────────────────────────────────────
    "TokenCounter",
    "TokenUsage",
    "RunCost",
    "ModelSpec",
    "MODEL_REGISTRY",
    "MODEL_CONTEXT_WINDOWS",   # backward compat alias
    # ── Convenience factories ─────────────────────────────────────────────
    "auto_client",
    "groq_client",
    "gemini_client",
    "ollama_client",
    "openrouter_client",
]


# ── Convenience factories ─────────────────────────────────────────────────

def auto_client(**kwargs) -> LLMClient:
    """
    Create an LLMClient from environment variables.

    Reads LLM_PROVIDER (default: groq) and all other LLM_* env vars.
    Extra kwargs are passed through to LLMClient.

    Example:
        client = auto_client(temperature=0.2, max_tokens=1024)
    """
    base = LLMClient.from_env()
    # Allow overrides
    if kwargs:
        return LLMClient(
            provider=kwargs.pop("provider", base.provider),
            model=kwargs.pop("model", base.model),
            api_key=base.api_key,
            temperature=kwargs.pop("temperature", base.temperature),
            max_tokens=kwargs.pop("max_tokens", base.max_tokens),
            timeout=kwargs.pop("timeout", base.timeout),
            max_retries=kwargs.pop("max_retries", base.max_retries),
            **kwargs,
        )
    return base


def groq_client(
    model: str = "llama-3.3-70b-versatile",
    *,
    api_key:     str | None = None,
    temperature: float      = 0.0,
    max_tokens:  int        = 2_048,
) -> LLMClient:
    """
    Create a Groq client with sensible defaults.

    Best free models on Groq:
      - llama-3.3-70b-versatile     (128k ctx, tool use, JSON mode) ← default
      - deepseek-r1-distill-llama-70b (128k ctx, strong reasoning)
      - llama-3.1-8b-instant         (131k ctx, fastest)
      - qwen-qwq-32b                 (131k ctx, excellent reasoning)

    Requires GROQ_API_KEY in environment.
    """
    return LLMClient(
        provider="groq",
        model=model,
        api_key=api_key,
        temperature=temperature,
        max_tokens=max_tokens,
    )


def gemini_client(
    model: str = "gemini-2.0-flash",
    *,
    api_key:        str | None = None,
    temperature:    float      = 0.0,
    max_tokens:     int        = 2_048,
    safety_level:   Literal["off", "low", "medium", "high"] = "medium",
) -> LLMClient:
    """
    Create a Gemini client with sensible defaults.

    Best free models on Gemini:
      - gemini-2.0-flash        (1M ctx, vision, tools, fastest) ← default
      - gemini-1.5-pro          (2M ctx, most capable)
      - gemini-1.5-flash-8b    (1M ctx, most economical)

    Requires GOOGLE_API_KEY in environment.
    Safety level can be tuned via the safety_level arg or GEMINI_SAFETY_LEVEL env var.
    """
    if safety_level != "medium":
        os.environ["GEMINI_SAFETY_LEVEL"] = safety_level

    return LLMClient(
        provider="gemini",
        model=model,
        api_key=api_key,
        temperature=temperature,
        max_tokens=max_tokens,
    )


def ollama_client(
    model: str           = "llama3.2",
    *,
    host:        str | None = None,
    temperature: float      = 0.0,
    max_tokens:  int        = 2_048,
    auto_pull:   bool       = False,
) -> LLMClient:
    """
    Create an Ollama client for fully local inference.

    Best models for local use (pull with `ollama pull <name>`):
      - llama3.2           (fast, 128k ctx, tool use)  ← default
      - qwen2.5:7b         (128k ctx, strong coding/JSON)
      - mistral:7b         (32k ctx, reliable)
      - llama3.3           (128k ctx, best quality ~70B)
      - llava / moondream  (multimodal/vision)

    No API key needed. Requires Ollama to be running locally.
    Install: https://ollama.com

    Args:
        model:       Model name (must already be pulled, or set auto_pull=True).
        host:        Ollama host URL. Defaults to OLLAMA_HOST or localhost:11434.
        auto_pull:   If True and the model is not found locally, pull it automatically.
    """
    client = LLMClient(
        provider="ollama",
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        ollama_host=host,
    )

    if auto_pull:
        try:
            if not client.is_ollama_model_available():
                import warnings
                warnings.warn(
                    f"Ollama model '{model}' not found locally. Pulling now — this may take a while.",
                    stacklevel=2,
                )
                client.pull_ollama_model(model)
        except Exception:
            pass  # Let the first actual call surface the error

    return client


def openrouter_client(
    model: str = "meta-llama/llama-3.1-70b-instruct:free",
    *,
    api_key:     str | None = None,
    temperature: float      = 0.0,
    max_tokens:  int        = 2_048,
) -> LLMClient:
    """
    Create an OpenRouter client for aggregated free model access.

    Popular free models on OpenRouter:
      - meta-llama/llama-3.1-70b-instruct:free   ← default
      - mistralai/mistral-7b-instruct:free
      - google/gemma-2-9b-it:free
      - microsoft/phi-3-mini-128k-instruct:free

    Requires OPENROUTER_API_KEY in environment.
    """
    return LLMClient(
        provider="openrouter",
        model=model,
        api_key=api_key,
        temperature=temperature,
        max_tokens=max_tokens,
    )