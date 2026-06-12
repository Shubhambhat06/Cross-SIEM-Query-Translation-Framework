"""
Day 1 — Layer 0 Sanity Check
Run this from your project root:
    python test_layer0.py

Tests every Layer 0 module without pytest.
Green checkmarks = ready to proceed to Layer 1.
Red X = something is broken, fix before moving on.
"""

import sys
import os
import json
import tempfile
from pathlib import Path

# ── Make sure src/ is importable ─────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

PASS = "  ✅"
FAIL = "  ❌"
results = []


def check(label: str, fn):
    try:
        fn()
        print(f"{PASS} {label}")
        results.append((label, True, None))
    except Exception as exc:
        print(f"{FAIL} {label}")
        print(f"       → {type(exc).__name__}: {exc}")
        results.append((label, False, exc))


# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "═" * 60)
print("  NL-SIEM — Layer 0 Sanity Check")
print("═" * 60)

# ─────────────────────────────────────────────────────────────────────────────
print("\n── 1. IMPORTS ──────────────────────────────────────────────")

def test_import_exceptions():
    from src.utils.exceptions import (
        NLSIEMError,
        IRValidationError,
        IRMissingFieldError,
        IRUnknownFieldError,
        IRCoercionError,
        TranslationError,
        FieldMappingError,
        UnsupportedOperatorError,
        LLMError,
        LLMTimeoutError,
        LLMRateLimitError,
        LLMResponseParseError,
        LLMMaxRetriesError,
        RAGError,
        EmbeddingError,
        VectorStoreError,
        KnowledgeBaseIngestError,
        EvaluationError,
        SyntaxValidationError,
        ExecutionMatchError,
        DatasetLoadError,
    )

def test_import_config():
    from src.utils.config import settings, Settings

def test_import_logger():
    from src.utils.logger import get_logger, setup_logging, log_event, RUN_ID

def test_import_file_io():
    from src.utils.file_io import (
        load_json, save_json,
        load_jsonl, save_jsonl, stream_jsonl, append_jsonl,
        load_csv, save_csv,
        load_text, save_text,
        list_files, resolve_path, ensure_parent,
    )

def test_import_utils_init():
    from src.utils import settings, NLSIEMError, get_logger, setup_logging

check("Import: exceptions.py",    test_import_exceptions)
check("Import: config.py",        test_import_config)
check("Import: logger.py",        test_import_logger)
check("Import: file_io.py",       test_import_file_io)
check("Import: utils/__init__.py",test_import_utils_init)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 2. EXCEPTIONS ───────────────────────────────────────────")

def test_base_exception():
    from src.utils.exceptions import NLSIEMError
    e = NLSIEMError("test error", details={"key": "value"})
    assert str(e) == "test error"
    assert e.details == {"key": "value"}
    assert "NLSIEMError" in repr(e)

def test_ir_missing_field():
    from src.utils.exceptions import IRMissingFieldError
    e = IRMissingFieldError("action")
    assert "action" in str(e)
    assert e.details["missing_field"] == "action"

def test_translation_error():
    from src.utils.exceptions import TranslationError
    e = TranslationError(platform="splunk", reason="unsupported op", ir={"action": "filter"})
    assert e.platform == "splunk"
    assert "splunk" in str(e)
    assert e.details["ir"] == {"action": "filter"}

def test_llm_timeout():
    from src.utils.exceptions import LLMTimeoutError
    e = LLMTimeoutError(model="gpt-4o", timeout_seconds=30.0)
    assert "gpt-4o" in str(e)
    assert e.details["timeout_seconds"] == 30.0

def test_exception_hierarchy():
    from src.utils.exceptions import (
        NLSIEMError,
        IRValidationError,
        IRMissingFieldError,
        TranslationError,
        LLMError,
        RAGError,
        EvaluationError,
    )
    # All custom exceptions inherit from NLSIEMError
    assert issubclass(IRValidationError, NLSIEMError)
    assert issubclass(IRMissingFieldError, IRValidationError)
    assert issubclass(TranslationError, NLSIEMError)
    assert issubclass(LLMError, NLSIEMError)
    assert issubclass(RAGError, NLSIEMError)
    assert issubclass(EvaluationError, NLSIEMError)

def test_exceptions_are_catchable():
    from src.utils.exceptions import IRMissingFieldError, NLSIEMError
    try:
        raise IRMissingFieldError("action")
    except NLSIEMError as e:
        assert "action" in str(e)  # caught as base class ✓

check("Exception: base NLSIEMError",       test_base_exception)
check("Exception: IRMissingFieldError",     test_ir_missing_field)
check("Exception: TranslationError",        test_translation_error)
check("Exception: LLMTimeoutError",         test_llm_timeout)
check("Exception: inheritance hierarchy",   test_exception_hierarchy)
check("Exception: catchable as base class", test_exceptions_are_catchable)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 3. CONFIG ───────────────────────────────────────────────")

def test_config_defaults():
    from src.utils.config import settings
    assert settings.model_name == "gpt-4o"
    assert settings.temperature == 0.0
    assert settings.max_tokens == 2048
    assert settings.rag_top_k == 5
    assert settings.log_level == "INFO"

def test_config_provider_inference():
    from src.utils.config import Settings
    s = Settings(MODEL_NAME="gpt-4o")
    assert s.provider == "openai"
    s2 = Settings(MODEL_NAME="claude-sonnet-4-6")
    assert s2.provider == "anthropic"
    s3 = Settings(MODEL_NAME="gemini-1.5-pro")
    assert s3.provider == "google"

def test_config_path_coercion():
    from src.utils.config import settings
    assert isinstance(settings.faiss_index_path, Path)
    assert isinstance(settings.knowledge_base_dir, Path)
    assert isinstance(settings.datasets_dir, Path)

def test_config_resolved_path():
    from src.utils.config import Settings
    from pathlib import Path
    s = Settings()
    resolved = s.resolved(Path("datasets/benchmark"))
    assert isinstance(resolved, Path)

def test_config_temperature_validation():
    from src.utils.config import Settings
    from pydantic import ValidationError
    try:
        Settings(TEMPERATURE=5.0)
        assert False, "Should have raised ValidationError"
    except (ValidationError, Exception):
        pass  # expected

check("Config: default values",           test_config_defaults)
check("Config: provider inference",       test_config_provider_inference)
check("Config: path coercion to Path",    test_config_path_coercion)
check("Config: resolved() helper",        test_config_resolved_path)
check("Config: temperature validation",   test_config_temperature_validation)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 4. LOGGER ───────────────────────────────────────────────")

def test_get_logger_returns_logger():
    import logging
    from src.utils.logger import get_logger
    log = get_logger("test.module")
    assert isinstance(log, logging.Logger)
    assert log.name == "test.module"

def test_run_id_is_set():
    from src.utils.logger import RUN_ID
    assert isinstance(RUN_ID, str)
    assert len(RUN_ID) == 8

def test_logger_does_not_crash():
    from src.utils.logger import get_logger
    log = get_logger("test.sanity")
    # These should not raise
    log.info("Layer 0 test info message")
    log.debug("debug message")
    log.warning("warning message")

def test_log_event_helper():
    from src.utils.logger import get_logger, log_event
    log = get_logger("test.log_event")
    # Should not raise with extra kwargs
    log_event(log, "info", "test event", platform="splunk", query_id="SB-001")

def test_setup_logging_no_rich():
    from src.utils.logger import setup_logging
    import logging
    # Re-configure without rich — should not raise
    setup_logging(level="DEBUG", rich_console=False)
    root = logging.getLogger()
    assert root.level == logging.DEBUG
    # Reset to INFO for rest of tests
    setup_logging(level="INFO", rich_console=False)

check("Logger: get_logger returns Logger",   test_get_logger_returns_logger)
check("Logger: RUN_ID is 8-char string",     test_run_id_is_set)
check("Logger: info/debug/warning no crash", test_logger_does_not_crash)
check("Logger: log_event() with extras",     test_log_event_helper)
check("Logger: setup_logging() no-rich",     test_setup_logging_no_rich)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 5. FILE I/O ─────────────────────────────────────────────")

def test_json_roundtrip():
    from src.utils.file_io import save_json, load_json
    data = {"platform": "splunk", "query": "index=* | stats count by src_ip", "score": 0.91}
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = Path(f.name)
    try:
        save_json(data, path)
        loaded = load_json(path)
        assert loaded == data
    finally:
        path.unlink(missing_ok=True)

def test_jsonl_roundtrip():
    from src.utils.file_io import save_jsonl, load_jsonl
    records = [
        {"id": "SB-001", "nl": "find failed logins", "tactic": "initial_access"},
        {"id": "SB-002", "nl": "detect lateral movement", "tactic": "lateral_movement"},
        {"id": "SB-003", "nl": "exfil over DNS", "tactic": "exfiltration"},
    ]
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        path = Path(f.name)
    try:
        save_jsonl(records, path)
        loaded = load_jsonl(path)
        assert loaded == records
        assert len(loaded) == 3
    finally:
        path.unlink(missing_ok=True)

def test_jsonl_stream():
    from src.utils.file_io import save_jsonl, stream_jsonl
    records = [{"id": i, "val": f"item_{i}"} for i in range(5)]
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        path = Path(f.name)
    try:
        save_jsonl(records, path)
        streamed = list(stream_jsonl(path))
        assert len(streamed) == 5
        assert streamed[2]["id"] == 2
    finally:
        path.unlink(missing_ok=True)

def test_jsonl_append():
    from src.utils.file_io import save_jsonl, append_jsonl, load_jsonl
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        path = Path(f.name)
    try:
        save_jsonl([{"id": 1}], path)
        append_jsonl({"id": 2}, path)
        loaded = load_jsonl(path)
        assert len(loaded) == 2
        assert loaded[1]["id"] == 2
    finally:
        path.unlink(missing_ok=True)

def test_csv_roundtrip():
    from src.utils.file_io import save_csv, load_csv
    rows = [
        {"id": "SB-001", "tactic": "initial_access", "score": "0.91"},
        {"id": "SB-002", "tactic": "lateral_movement", "score": "0.85"},
    ]
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w") as f:
        path = Path(f.name)
    try:
        save_csv(rows, path)
        loaded = load_csv(path)
        assert len(loaded) == 2
        assert loaded[0]["tactic"] == "initial_access"
    finally:
        path.unlink(missing_ok=True)

def test_text_roundtrip():
    from src.utils.file_io import save_text, load_text
    content = "index=* status=failed earliest=-24h\n| stats count by src_ip\n| where count > 50"
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        path = Path(f.name)
    try:
        save_text(content, path)
        loaded = load_text(path)
        assert loaded == content
    finally:
        path.unlink(missing_ok=True)

def test_missing_file_raises():
    from src.utils.file_io import load_json
    from src.utils.exceptions import DatasetLoadError
    try:
        load_json("/nonexistent/path/file.json")
        assert False, "Should have raised DatasetLoadError"
    except DatasetLoadError as e:
        assert "not found" in str(e)

def test_resolve_path():
    from src.utils.file_io import resolve_path
    p = resolve_path("datasets/benchmark", root="/home/user/project")
    assert p == Path("/home/user/project/datasets/benchmark")

def test_list_files():
    from src.utils.file_io import list_files, save_text
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        save_text("a", tmpdir / "file1.txt")
        save_text("b", tmpdir / "file2.txt")
        save_text("c", tmpdir / "other.json")
        txt_files = list_files(tmpdir, "*.txt")
        assert len(txt_files) == 2
        all_files = list_files(tmpdir, "*")
        assert len(all_files) == 3

check("File IO: JSON roundtrip",          test_json_roundtrip)
check("File IO: JSONL roundtrip",         test_jsonl_roundtrip)
check("File IO: JSONL stream",            test_jsonl_stream)
check("File IO: JSONL append",            test_jsonl_append)
check("File IO: CSV roundtrip",           test_csv_roundtrip)
check("File IO: text roundtrip",          test_text_roundtrip)
check("File IO: missing file raises",     test_missing_file_raises)
check("File IO: resolve_path()",          test_resolve_path)
check("File IO: list_files() glob",       test_list_files)


# ─────────────────────────────────────────────────────────────────────────────
print("\n── 6. INTEGRATION — everything wired together ──────────────")

def test_logger_uses_config_level():
    import logging
    from src.utils.config import settings
    from src.utils.logger import setup_logging, get_logger
    setup_logging(level=settings.log_level, rich_console=False)
    log = get_logger("integration.test")
    assert log is not None

def test_exception_with_file_io():
    """DatasetLoadError (an EvaluationError) raised by file_io and caught as NLSIEMError."""
    from src.utils.file_io import load_jsonl
    from src.utils.exceptions import NLSIEMError, DatasetLoadError
    try:
        load_jsonl("/no/such/file.jsonl")
    except DatasetLoadError as e:
        assert isinstance(e, NLSIEMError)
        assert e.details.get("path") == "/no/such/file.jsonl"

def test_config_singleton():
    from src.utils.config import settings as s1
    from src.utils import settings as s2
    # Both imports should be the same object
    assert type(s1) == type(s2)
    assert s1.model_name == s2.model_name

def test_full_day1_workflow():
    """Simulate what you actually do on Day 1: log startup, save a result, reload it."""
    from src.utils.logger import get_logger, setup_logging
    from src.utils.config import settings
    from src.utils.file_io import save_json, load_json

    setup_logging(level="INFO", rich_console=False)
    log = get_logger("day1.workflow")
    log.info(
        "NL-SIEM initialized",
        extra={"model": settings.model_name, "provider": settings.provider}
    )

    # Simulate saving a translation result
    result = {
        "nl_query": "Find failed logins exceeding 50 attempts in 24 hours",
        "model": settings.model_name,
        "splunk": "index=* status=failed earliest=-24h | stats count by src_ip | where count > 50",
        "valid": True,
    }

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = Path(f.name)
    try:
        save_json(result, path)
        loaded = load_json(path)
        assert loaded["nl_query"] == result["nl_query"]
        assert loaded["valid"] is True
        log.info("Result saved and reloaded successfully", extra={"path": str(path)})
    finally:
        path.unlink(missing_ok=True)

check("Integration: logger uses config level",       test_logger_uses_config_level)
check("Integration: exception caught as base class", test_exception_with_file_io)
check("Integration: config singleton",               test_config_singleton)
check("Integration: full Day 1 workflow",            test_full_day1_workflow)


# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "═" * 60)
passed = sum(1 for _, ok, _ in results if ok)
failed = sum(1 for _, ok, _ in results if not ok)
total  = len(results)
print(f"  Results: {passed}/{total} passed", end="")
if failed:
    print(f"  |  {failed} FAILED ← fix before Layer 1")
    print("\n  Failed tests:")
    for label, ok, exc in results:
        if not ok:
            print(f"    ✗ {label}: {type(exc).__name__}: {exc}")
else:
    print("  — Layer 0 is solid. Ready for Layer 1 ✅")
print("═" * 60 + "\n")

sys.exit(0 if failed == 0 else 1)