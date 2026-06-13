"""
Translators — per-SIEM IR output formatters.

Layer 2 of the NL-SIEM pipeline. Imports from Layer 1 (src.ir).

Usage:
    from src.translators import translate_all, SplunkTranslator

    results = translate_all(ir_query)
    # → {"splunk": "...", "qradar": "...", "elastic": "...", "sentinel": "...", "wazuh": "..."}
"""

from src.translators.splunk   import SplunkTranslator
from src.translators.qradar   import QRadarTranslator
from src.translators.elastic  import ElasticTranslator
from src.translators.sentinel import SentinelTranslator
from src.translators.wazuh    import WazuhTranslator
from src.translators.field_mapping import resolve, resolve_all
from src.ir.schema import IRQuery

# ── Registry of all translators ───────────────────────────────────────────
_TRANSLATORS = {
    "splunk":   SplunkTranslator(),
    "qradar":   QRadarTranslator(),
    "elastic":  ElasticTranslator(),
    "sentinel": SentinelTranslator(),
    "wazuh":    WazuhTranslator(),
}


def translate_all(ir: IRQuery) -> dict[str, str]:
    """
    Translate a single IRQuery into all 5 SIEM query formats.

    Args:
        ir: Validated IRQuery from Layer 1.

    Returns:
        Dict mapping platform name → query string.
        Failed translations return an error string prefixed with "ERROR:".
    """
    results: dict[str, str] = {}
    for platform, translator in _TRANSLATORS.items():
        try:
            results[platform] = translator.translate(ir)
        except Exception as exc:
            results[platform] = f"ERROR: {exc}"
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
]