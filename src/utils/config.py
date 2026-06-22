"""
Centralised configuration via pydantic-settings.
All env vars are read from .env or the shell environment.
Import the singleton `settings` anywhere in the codebase.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application-wide settings.
    Values are read from environment variables or a .env file.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── LLM provider keys ────────────────────────────────────────────────
    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")
    google_api_key: str = Field(default="", alias="GOOGLE_API_KEY")
    groq_api_key: str = Field(default="", alias="GROQ_API_KEY")
    # ── Model config ─────────────────────────────────────────────────────
    model_name: Literal[
        "gpt-4o",
        "gpt-4o-mini",
        "claude-opus-4-6",
        "claude-sonnet-4-6",
        "gemini-1.5-pro",
        "gemini-1.5-flash",
    ] = Field(default="gpt-4o", alias="MODEL_NAME")

    temperature: float = Field(default=0.0, ge=0.0, le=2.0, alias="TEMPERATURE")
    max_tokens: int = Field(default=2048, ge=256, le=8192, alias="MAX_TOKENS")
    llm_timeout: float = Field(default=60.0, alias="LLM_TIMEOUT")
    llm_max_retries: int = Field(default=3, alias="LLM_MAX_RETRIES")

    # ── Elasticsearch ─────────────────────────────────────────────────────
    es_host: str = Field(
    default="",
    alias="ELASTIC_HOST"
    )

    es_api_key: str = Field(
        default="",
        alias="ELASTIC_API_KEY"
    )

    
    # ── RAG config ────────────────────────────────────────────────────────
    embedding_model: str = Field(
        default="all-MiniLM-L6-v2", alias="EMBEDDING_MODEL"
    )
    faiss_index_path: Path = Field(
        default=Path("src/rag/faiss.index"), alias="FAISS_INDEX_PATH"
    )
    rag_top_k: int = Field(default=5, alias="RAG_TOP_K")
    chunk_size: int = Field(default=512, alias="CHUNK_SIZE")
    chunk_overlap: int = Field(default=64, alias="CHUNK_OVERLAP")

    # ── Paths ─────────────────────────────────────────────────────────────
    project_root: Path = Field(default=Path("."), alias="PROJECT_ROOT")
    knowledge_base_dir: Path = Field(
        default=Path("knowledge_base"), alias="KNOWLEDGE_BASE_DIR"
    )
    datasets_dir: Path = Field(default=Path("datasets"), alias="DATASETS_DIR")
    experiments_dir: Path = Field(
        default=Path("experiments"), alias="EXPERIMENTS_DIR"
    )

    # ── Logging ───────────────────────────────────────────────────────────
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO", alias="LOG_LEVEL"
    )
    log_file: Path | None = Field(default=None, alias="LOG_FILE")

    # ── Evaluation ────────────────────────────────────────────────────────
    siembench_path: Path = Field(
        default=Path("datasets/benchmark/siem_bench_v1.jsonl"),
        alias="SIEMBENCH_PATH",
    )
    results_dir: Path = Field(
        default=Path("experiments/results"), alias="RESULTS_DIR"
    )

    # ── Validators ────────────────────────────────────────────────────────
    @field_validator("temperature")
    @classmethod
    def check_temperature(cls, v: float) -> float:
        if not 0.0 <= v <= 2.0:
            raise ValueError("temperature must be between 0.0 and 2.0")
        return v

    @field_validator("faiss_index_path", "knowledge_base_dir", "datasets_dir", mode="before")
    @classmethod
    def coerce_path(cls, v: str | Path) -> Path:
        return Path(v)

    # ── Helpers ───────────────────────────────────────────────────────────
    @property
    def provider(self) -> str:
        """Infer provider from model name."""
        if self.model_name.startswith("gpt"):
            return "openai"
        if self.model_name.startswith("claude"):
            return "anthropic"
        if self.model_name.startswith("gemini"):
            return "google"
        return "unknown"

    @property
    def active_api_key(self) -> str:
        """Return the API key for the currently selected provider."""
        mapping = {
            "openai": self.openai_api_key,
            "anthropic": self.anthropic_api_key,
            "google": self.google_api_key,
        }
        return mapping.get(self.provider, "")

    def resolved(self, path: Path) -> Path:
        """Resolve a relative path against project_root."""
        if path.is_absolute():
            return path
        return self.project_root / path


# Singleton — import this everywhere
settings = Settings()