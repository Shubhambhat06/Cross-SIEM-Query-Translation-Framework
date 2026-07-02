import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from src.agents.translation_orchestrator import TranslationOrchestrator

orchestrator = TranslationOrchestrator.from_env()


def translate(query: str):
    try:
        result = orchestrator.translate(query)

        return {
            "success": True,
            "run_id": result.run_id,
            "ir": result.ir.to_dict(),
            "translations": result.translations,
            "pass_rate": result.pass_rate,
            "warnings": result.warnings,
            "elapsed_s": result.elapsed_s,
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }