#!/usr/bin/env python3
"""
scripts/translate_query.py
===========================
Interactive CLI demo: translate a natural-language SIEM query into all five
platform-specific query languages (Splunk SPL, IBM QRadar AQL, Elastic EQL,
Microsoft Sentinel KQL, Wazuh XML) using the full NL-SIEM pipeline.

Usage
-----
    # Interactive mode (prompts for query)
    python scripts/translate_query.py

    # One-shot mode
    python scripts/translate_query.py -q "Detect failed SSH logins from a single IP"

    # With specific platforms only
    python scripts/translate_query.py -q "Brute force detection" -p splunk elastic

    # With RAG context (requires ingested store)
    python scripts/translate_query.py -q "..." --rag

    # Disable refinement loop for speed
    python scripts/translate_query.py -q "..." --no-refine

    # Output to file
    python scripts/translate_query.py -q "..." --output results/my_query.json

    # Dry-run: show IR + prompt without calling LLM
    python scripts/translate_query.py -q "..." --dry-run

    # Verbose: show IR, RAG context, and token counts
    python scripts/translate_query.py -q "..." --verbose

Exit codes
----------
    0 — success (at least one platform translated)
    1 — partial success (some platforms failed)
    2 — fatal error
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.agents.parser_agent import ParserAgent
from src.llm.client import LLMClient
from src.utils.logger import get_logger

log = get_logger("translate_query")

PLATFORMS = ("splunk", "qradar", "elastic", "sentinel", "wazuh")

# ANSI colour codes (disabled on Windows without colorama)
try:
    import os
    _COLOUR = sys.stdout.isatty() and os.name != "nt"
except Exception:
    _COLOUR = False

def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOUR else text

CYAN   = "36"
GREEN  = "32"
YELLOW = "33"
RED    = "31"
BOLD   = "1"
DIM    = "2"


# ─────────────────────────────────────────────────────────────────────────────
# Display helpers
# ─────────────────────────────────────────────────────────────────────────────

def _print_header() -> None:
    print("\n" + _c("=" * 64, BOLD))
    print(_c("  NL-SIEM  |  Natural Language → SIEM Query Translator", BOLD))
    print(_c("=" * 64, BOLD))

def _print_ir(ir: dict) -> None:
    print(_c("\n── Intermediate Representation (IR) ──────────────────", DIM))
    print(json.dumps(ir, indent=2))

def _print_rag_context(context: str) -> None:
    if not context:
        return
    preview = context[:600] + ("…" if len(context) > 600 else "")
    print(_c("\n── RAG Context (truncated) ────────────────────────────", DIM))
    print(preview)

def _print_translations(translations: dict[str, str], validate: bool = True) -> None:
    print(_c("\n── Translations ───────────────────────────────────────", BOLD))
    for platform, query in translations.items():
        if not query:
            label = _c(f"[{platform.upper():>8}]", RED)
            print(f"{label}  (no output)")
            continue
        label = _c(f"[{platform.upper():>8}]", CYAN)
        print(f"\n{label}")
        print(query)

    if validate:
        _print_validation(translations)

def _print_validation(translations: dict[str, str]) -> None:
    try:
        from src.evaluation.syntax_validator import SyntaxValidator
        v = SyntaxValidator()
        print(_c("\n── Syntax Validation ──────────────────────────────────", DIM))
        all_valid = True
        for platform, query in translations.items():
            result = v.validate(platform, query or "")
            status = _c("PASS", GREEN) if result.is_valid else _c("FAIL", RED)
            detail = f"  [{result.error_type}]" if not result.is_valid else ""
            print(f"  {platform:<10} {status}{detail}")
            if not result.is_valid:
                all_valid = False
        return all_valid
    except ImportError:
        pass

def _print_timing(elapsed: float, tokens: int | None = None) -> None:
    token_str = f"  |  tokens: {tokens}" if tokens else ""
    print(_c(f"\n  ⏱  {elapsed:.2f}s{token_str}", DIM))

def _print_footer() -> None:
    print("\n" + _c("=" * 64, BOLD) + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# Core translate function
# ─────────────────────────────────────────────────────────────────────────────

def translate(
    nl_query:   str,
    platforms:  list[str],
    use_rag:    bool = True,
    refine:     bool = True,
    verbose:    bool = False,
    dry_run:    bool = False,
    store_path: Path | None = None,
) -> dict:
    """
    Run the full NL-SIEM pipeline for one natural-language query.

    Returns dict with keys:
        nl_query, ir, translations, elapsed_s
    """
    t0 = time.monotonic()

    condition = "rag" if use_rag else "few_shot"

    print(_c("\n[1/4]  Running NL-SIEM pipeline…", YELLOW))

    from src.agents.translation_orchestrator import TranslationOrchestrator

    orchestrator = TranslationOrchestrator.from_env(
        condition=condition,
        enable_rag=use_rag,
        enable_refinement=refine,
        store_path=str(store_path) if store_path else "src/rag/store",
    )

    if dry_run:
        print(_c("\n[DRY-RUN]  Pipeline construction successful.\n", YELLOW))
        return {
            "nl_query": nl_query,
            "translations": {},
            "dry_run": True,
        }

    result = orchestrator.translate(nl_query)

    if verbose:
        try:
            _print_ir(result.ir.to_dict())
        except Exception:
            pass

    print(_c("[2/4]  Parsing complete", GREEN))
    print(_c("[3/4]  Translation complete", GREEN))
    print(_c("[4/4]  Validation complete", GREEN))

    translations = result.translations

    # Filter requested platforms
    translations = {
        platform: query
        for platform, query in translations.items()
        if platform in platforms
    }

    elapsed = round(time.monotonic() - t0, 2)

    return {
        "nl_query": nl_query,
        "ir": result.ir.to_dict(),
        "translations": translations,
        "elapsed_s": elapsed,
        "tokens_used": None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Interactive REPL
# ─────────────────────────────────────────────────────────────────────────────

def _interactive_loop(args: argparse.Namespace) -> int:
    _print_header()
    print("  Type a natural-language SIEM query, or 'quit' to exit.\n")
    while True:
        try:
            nl_query = input(_c("  Query> ", CYAN)).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[BYE]")
            return 0
        if not nl_query:
            continue
        if nl_query.lower() in ("quit", "exit", "q"):
            return 0
        result = _run_one(nl_query, args)
        if result and args.output:
            _save(result, Path(args.output))


def _run_one(nl_query: str, args: argparse.Namespace) -> dict | None:
    try:
        result = translate(
            nl_query   = nl_query,
            platforms  = list(args.platforms),
            use_rag    = not args.no_rag,
            refine     = not args.no_refine,
            verbose    = args.verbose,
            dry_run    = args.dry_run,
            store_path = Path(args.store_path) if args.store_path else None,
        )
        _print_translations(result.get("translations", {}))
        _print_timing(result["elapsed_s"], result.get("tokens_used"))
        _print_footer()
        return result
    except Exception as exc:
        log.exception("Translation failed")
        print(_c(f"\n[ERROR]  {exc}\n", RED), file=sys.stderr)
        return None


def _save(result: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(_c(f"  Saved → {path}", DIM))


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Translate a natural-language SIEM query into all five platforms.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-q", "--query",      default=None,
                        help="NL query string. Omit for interactive mode.")
    parser.add_argument("-p", "--platforms",  nargs="+", default=list(PLATFORMS),
                        choices=PLATFORMS,
                        help="Platforms to translate into")
    parser.add_argument("--no-rag",           action="store_true",
                        help="Disable RAG retrieval")
    parser.add_argument("--no-refine",        action="store_true",
                        help="Skip self-critique refinement loop")
    parser.add_argument("--dry-run",          action="store_true",
                        help="Parse NL → IR only; no LLM call")
    parser.add_argument("--verbose", "-v",    action="store_true",
                        help="Show IR and RAG context")
    parser.add_argument("--output", "-o",     default=None,
                        help="Write JSON result to this file")
    parser.add_argument("--store-path",       default=None,
                        help="Override RAG store path")
    args = parser.parse_args()

    # Interactive mode
    if args.query is None:
        return _interactive_loop(args)

    # One-shot mode
    _print_header()
    print(f"  Query: {_c(args.query, BOLD)}\n")

    result = _run_one(args.query, args)
    if result is None:
        return 2

    if args.output:
        _save(result, Path(args.output))

    # Exit 1 if any platform produced no output
    translations = result.get("translations", {})
    missing = [p for p in args.platforms if not translations.get(p)]
    if missing:
        print(_c(f"[WARNING]  No output for: {missing}", YELLOW), file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())