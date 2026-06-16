"""
Agents — orchestration layer for NL-SIEM.
Layer 5 of the pipeline. Depends on Layers 1, 2, 3, 4.

Pipeline flow:
    ParserAgent → translate_all → ValidatorAgent → [RefinementAgent]
    all wired together by TranslationOrchestrator

Quickstart:
    from src.agents.translation_orchestrator import TranslationOrchestrator

    orc    = TranslationOrchestrator.from_env()
    result = orc.translate("Detect SSH brute force exceeding 50 attempts in 10 minutes")
    print(result.summary())
"""

from src.agents.parser_agent            import ParserAgent, ParseResult
from src.agents.validator_agent         import ValidatorAgent, ValidationReport, PlatformValidation
from src.agents.refinement_agent        import RefinementAgent, RefinementResult
from src.agents.translation_orchestrator import TranslationOrchestrator, TranslationResult

__all__ = [
    # Parser
    "ParserAgent",
    "ParseResult",
    # Validator
    "ValidatorAgent",
    "ValidationReport",
    "PlatformValidation",
    # Refinement
    "RefinementAgent",
    "RefinementResult",
    # Orchestrator
    "TranslationOrchestrator",
    "TranslationResult",
]