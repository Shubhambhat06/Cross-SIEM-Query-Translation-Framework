"""
Custom exception hierarchy for NL-SIEM.
All application errors inherit from NLSIEMError so callers can catch broadly or narrowly.
"""


class NLSIEMError(Exception):
    """Base exception for all NL-SIEM errors."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.message!r}, details={self.details})"


# ─────────────────────────────────────────────
# IR Exceptions
# ─────────────────────────────────────────────

class IRValidationError(NLSIEMError):
    """Raised when an IR dict fails schema validation."""


class IRCoercionError(NLSIEMError):
    """Raised when a field cannot be coerced to its expected type."""


class IRMissingFieldError(IRValidationError):
    """Raised when a required IR field is absent."""

    def __init__(self, field: str):
        super().__init__(
            f"Required IR field missing: '{field}'",
            details={"missing_field": field},
        )


class IRUnknownFieldError(IRValidationError):
    """Raised when an unrecognised field appears in the IR."""

    def __init__(self, field: str):
        super().__init__(
            f"Unknown IR field: '{field}'",
            details={"unknown_field": field},
        )


# ─────────────────────────────────────────────
# Translation Exceptions
# ─────────────────────────────────────────────

class TranslationError(NLSIEMError):
    """Raised when a SIEM translator fails to produce output."""

    def __init__(self, platform: str, reason: str, ir: dict | None = None):
        super().__init__(
            f"Translation failed for platform '{platform}': {reason}",
            details={"platform": platform, "reason": reason, "ir": ir},
        )
        self.platform = platform


class UnsupportedOperatorError(TranslationError):
    """Raised when the IR contains an operator not supported by a platform."""

    def __init__(self, platform: str, operator: str):
        super().__init__(
            platform=platform,
            reason=f"Operator '{operator}' is not supported",
        )
        self.operator = operator


class FieldMappingError(TranslationError):
    """Raised when a canonical field has no mapping for the target platform."""

    def __init__(self, platform: str, canonical_field: str):
        super().__init__(
            platform=platform,
            reason=f"No field mapping for '{canonical_field}'",
        )
        self.canonical_field = canonical_field


# ─────────────────────────────────────────────
# LLM Exceptions
# ─────────────────────────────────────────────

class LLMError(NLSIEMError):
    """Base class for LLM client errors."""


class LLMTimeoutError(LLMError):
    def __init__(
        self,
        model: str,
        timeout_seconds: float = 60.0,
    ):
        super().__init__(
            f"LLM call to '{model}' timed out after {timeout_seconds} seconds",
            details={"model": model, "timeout_seconds": timeout_seconds},
        )

class LLMRateLimitError(LLMError):
    """Raised when the LLM API returns a rate-limit response."""

    def __init__(self, model: str, retry_after: float | None = None):
        super().__init__(
            f"Rate limit hit for model '{model}'",
            details={"model": model, "retry_after": retry_after},
        )


class LLMResponseParseError(LLMError):
    """Raised when the LLM output cannot be parsed into expected structure."""

    def __init__(self, raw_output: str, reason: str):
        super().__init__(
            f"Failed to parse LLM response: {reason}",
            details={"raw_output": raw_output[:500], "reason": reason},
        )


class LLMMaxRetriesError(LLMError):
    """Raised when all retry attempts for an LLM call are exhausted."""

    def __init__(self, model: str, attempts: int):
        super().__init__(
            f"LLM call to '{model}' failed after {attempts} attempts",
            details={"model": model, "attempts": attempts},
        )


# ─────────────────────────────────────────────
# RAG Exceptions
# ─────────────────────────────────────────────

class RAGError(NLSIEMError):
    """Base class for RAG pipeline errors."""


class EmbeddingError(RAGError):
    """Raised when document embedding fails."""


class VectorStoreError(RAGError):
    """Raised when FAISS index operations fail."""

    def __init__(self, operation: str, reason: str):
        super().__init__(
            f"Vector store operation '{operation}' failed: {reason}",
            details={"operation": operation, "reason": reason},
        )


class KnowledgeBaseIngestError(RAGError):
    """Raised when ingestion of knowledge base documents fails."""

    def __init__(self, path: str, reason: str):
        super().__init__(
            f"Failed to ingest knowledge base at '{path}': {reason}",
            details={"path": path, "reason": reason},
        )


# ─────────────────────────────────────────────
# Evaluation Exceptions
# ─────────────────────────────────────────────

class EvaluationError(NLSIEMError):
    """Base class for evaluation pipeline errors."""


class SyntaxValidationError(EvaluationError):
    """Raised when a generated query fails syntactic validation."""

    def __init__(self, platform: str, query: str, reason: str):
        super().__init__(
            f"Syntax validation failed for '{platform}': {reason}",
            details={"platform": platform, "query": query[:300], "reason": reason},
        )


class ExecutionMatchError(EvaluationError):
    """Raised when query execution against the sandbox fails."""

    def __init__(self, platform: str, reason: str):
        super().__init__(
            f"Execution match failed for '{platform}': {reason}",
            details={"platform": platform, "reason": reason},
        )


class DatasetLoadError(EvaluationError):
    """Raised when the benchmark dataset cannot be loaded."""

    def __init__(self, path: str, reason: str):
        super().__init__(
            f"Failed to load dataset from '{path}': {reason}",
            details={"path": path, "reason": reason},
        )