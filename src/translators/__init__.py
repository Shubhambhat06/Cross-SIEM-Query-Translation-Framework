"""
Translators — per-SIEM IR output formatters.

Layer 2 of the NL-SIEM pipeline. Imports from Layer 1 (src.ir).

Usage:
    from src.translators import translate_all, SplunkTranslator

    results = translate_all(ir_query)
    # → {
    #     "splunk":   {"query": "...", "attck": [...], "error": None},
    #     "qradar":   {"query": "...", "attck": [...], "error": None},
    #     "elastic":  {"query": "...", "attck": [...], "error": None},
    #     "sentinel": {"query": "...", "attck": [...], "error": None},
    #     "wazuh":    {"query": "...", "attck": [...], "error": None},
    #   }
"""

from src.translators.splunk   import SplunkTranslator
from src.translators.qradar   import QRadarTranslator
from src.translators.elastic  import ElasticTranslator
from src.translators.sentinel import SentinelTranslator
from src.translators.wazuh    import WazuhTranslator
from src.translators.field_mapping import resolve, resolve_all, validate_mapping_completeness
from src.ir.schema import IRQuery
from src.utils.logger import get_logger

log = get_logger(__name__)

# ── Registry of all translators ───────────────────────────────────────────
_TRANSLATORS = {
    "splunk":   SplunkTranslator(),
    "qradar":   QRadarTranslator(),
    "elastic":  ElasticTranslator(),
    "sentinel": SentinelTranslator(),
    "wazuh":    WazuhTranslator(),
}


def translate_all(ir: IRQuery) -> dict[str, dict[str, object]]:
    """
    Translate a single IRQuery into all 5 SIEM query formats.

    Args:
        ir: Validated IRQuery from Layer 1.

    Returns:
        Dict mapping platform name → {"query": str | None, "attck": list[str],
        "error": str | None}. This shape is identical on success and
        failure — callers never need to type-check the value before use.
        (fixed) previously a failed translation returned a bare
        "ERROR: ..." string in place of the dict every successful
        translation returned, contradicting this function's own
        docstring and forcing every caller to branch on
        isinstance(result, dict) before touching it.
    """
    results: dict[str, dict[str, object]] = {}
    for platform, translator in _TRANSLATORS.items():
        try:
            results[platform] = {
                "query": translator.translate(ir),
                "attck": ir.attck_labels,
                "error": None,
            }
        except Exception as exc:
            log.error(
                "Translation failed",
                extra={"platform": platform, "error": str(exc)},
            )
            results[platform] = {
                "query": None,
                "attck": ir.attck_labels,
                "error": str(exc),
            }
    return results


def translate_one(ir: IRQuery, platform: str) -> str:
    """
    Translate an IRQuery to a single SIEM platform.

    Args:
        ir:       Validated IRQuery.
        platform: One of splunk / qradar / elastic / sentinel / wazuh.

    Returns:
        Platform-native query string.

    Raises:
        ValueError: If platform is not recognised.
        TranslationError: If translation fails for the given platform.
    """
    platform = platform.lower().strip()
    if platform not in _TRANSLATORS:
        raise ValueError(
            f"Unknown platform '{platform}'. "
            f"Valid options: {sorted(_TRANSLATORS.keys())}"
        )
    return _TRANSLATORS[platform].translate(ir)


__all__ = [
    "SplunkTranslator",
    "QRadarTranslator",
    "ElasticTranslator",
    "SentinelTranslator",
    "WazuhTranslator",
    "translate_all",
    "translate_one",
    "resolve",
    "resolve_all",
    "validate_mapping_completeness",
]