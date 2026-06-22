#!/usr/bin/env python3
"""
scripts/run_evaluation.py
==========================
Full evaluation harness: translate all SIEMBench queries with the pipeline,
evaluate against ground truth using all Layer-6 metrics, and write results.

Pipeline
--------
    siembench.jsonl
         ↓  TranslationOrchestrator  — NL → 5-platform translations
         ↓  SyntaxValidator          — syntactic validity %
         ↓  SemanticScorer           — BLEU / ROUGE-L / field-F1
         ↓  ExecutionMatcher         — execution match (ES optional)
         ↓  ErrorAnalyzer            — failure taxonomy
         ↓  MetricsAggregator        — Table 2, Table 3
         ↓  write results/           — JSONL + JSON metrics

Usage
-----
    # Full evaluation (requires LLM keys + SIEMBench dataset)
    python scripts/run_evaluation.py

    # Custom paths
    python scripts/run_evaluation.py \\
        --dataset data/siembench.jsonl \\
        --output  results/eval_run_01/ \\
        --limit   50

    # Ablation study (conditions A, B, C)
    python scripts/run_evaluation.py --ablation

    # Skip LLM translation (evaluate existing results file)
    python scripts/run_evaluation.py --results-file results/existing_translations.jsonl

    # Disable execution matching (no ES instance required)
    python scripts/run_evaluation.py --no-exec

Exit codes: 0 success | 1 partial | 2 fatal
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

from src.utils.logger import get_logger
from src.utils.file_io import load_jsonl, save_jsonl

log = get_logger("run_evaluation")

PLATFORMS    = ("splunk", "qradar", "elastic", "sentinel", "wazuh")
DEFAULT_DS   = _ROOT / "data"   / "siembench.jsonl"
DEFAULT_OUT  = _ROOT / "results"


# ─────────────────────────────────────────────────────────────────────────────
# Translation
# ─────────────────────────────────────────────────────────────────────────────

def _translate_dataset(
    benchmark:  list[dict],
    use_rag:    bool,
    refine:     bool,
    store_path: Path | None,
) -> list[dict]:
    """
    Run the full pipeline on every benchmark record.
    Returns list of result dicts (nl_query + translations).
    """
    from src.agents.translation_orchestrator import TranslationOrchestrator

    orchestrator = TranslationOrchestrator.from_env(
    condition="rag" if use_rag else "few_shot",
    enable_rag=use_rag,
    enable_refinement=refine,
    store_path=str(store_path) if store_path else "src/rag/store",
    )

    results  = []
    total    = len(benchmark)
    t0       = time.monotonic()

    for i, record in enumerate(benchmark, start=1):
        nl_query = record["nl_query"]
        rid      = record.get("id", f"q{i:04d}")

        try:
            out          = orchestrator.translate(nl_query)
            translations = out.translations if hasattr(out, "translations") else out
            tokens       = getattr(out, "tokens_used", None)
        except Exception as exc:
            log.warning("Translation failed", extra={"id": rid, "error": str(exc)})
            translations = {p: "" for p in PLATFORMS}
            tokens       = None

        elapsed = round(time.monotonic() - t0, 2)
        results.append({
            "id":           rid,
            "nl_query":     nl_query,
            "translations": translations,
            "tokens_used":  tokens,
            "elapsed_s":    elapsed,
        })

        # Rolling progress
        pct = 100 * i / total
        print(f"\r  Translating [{i:>4}/{total}] {pct:5.1f}%  {nl_query[:40]:<40}", end="", flush=True)

    print()   # newline
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Evaluation
# ─────────────────────────────────────────────────────────────────────────────

def _run_evaluation(
    results:        list[dict],
    benchmark:      list[dict],
    use_exec:       bool,
    es_url:         str,
    run_ablation:   bool,
    output_dir:     Path,
) -> dict:
    """
    Run all Layer-6 evaluators and return aggregated metrics dict.
    """
    from src.evaluation.syntax_validator   import SyntaxValidator
    from src.evaluation.semantic_scorer    import SemanticScorer
    from src.evaluation.execution_match    import ExecutionMatcher
    from src.evaluation.error_analyzer     import ErrorAnalyzer
    from src.evaluation.metrics_aggregator import MetricsAggregator

    validator  = SyntaxValidator()
    scorer     = SemanticScorer(use_sacrebleu=True)
    matcher    = ExecutionMatcher(es_url=es_url) if use_exec else ExecutionMatcher()
    if not use_exec:
        matcher._available = False
    analyzer   = ErrorAnalyzer()
    aggregator = MetricsAggregator()

    print("\n  Running syntax validation…")
    syn_all  = validator.validate_dataset(results)

    print("  Running semantic scoring…")
    sem_all  = scorer.score_dataset(results, benchmark)

    print("  Running execution matching…")
    exec_all = matcher.match_dataset(results, benchmark)

    print("  Running error analysis…")
    err_all  = analyzer.analyze_dataset(
        results, benchmark,
        syntax_all=syn_all, semantic_all=sem_all, execution_all=exec_all,
    )

    # Aggregate metrics
    syn_metrics  = validator.compute_all_metrics(syn_all)
    sem_metrics  = {p: scorer.compute_metrics(sem_all[p], platform=p) for p in sem_all}
    exec_metrics = {p: matcher.compute_metrics(exec_all[p], platform=p) for p in exec_all}
    err_dists    = analyzer.compute_all_distributions(err_all)

    # Build tables
    t2 = aggregator.build_table2(syn_metrics, sem_metrics, exec_metrics)
    t3 = aggregator.build_table3(err_dists)

    # Ablation
    t4 = []
    if run_ablation:
        print("  Running ablation study (conditions A / B / C)…")
        from src.evaluation.ablation import AblationRunner
        from src.agents.translation_orchestrator import TranslationOrchestrator

        def _make_translate(condition):
            def _fn(nl_query, cond):
                orch = TranslationOrchestrator.from_env(
                condition=(
                    "zero_shot" if cond == "A"
                    else "few_shot" if cond == "B"
                    else "rag"
                ),
                enable_rag=(cond == "C"),
                enable_refinement=False,
            )
                out = orch.translate(nl_query)
                return out.translations if hasattr(out, "translations") else out
            return _fn

        runner       = AblationRunner(
            translate_fn     = _make_translate(None),
            syntax_validator = validator,
            semantic_scorer  = scorer,
            max_queries      = min(len(benchmark), 100),
        )
        abl_results = runner.run(benchmark, conditions=["A", "B", "C"])
        abl_table   = runner.build_table(abl_results)
        t4          = aggregator.build_table4(abl_table)

    # Save
    print(f"  Saving tables → {output_dir}")
    aggregator.print_tables(t2, t3, t4)
    file_paths = aggregator.save(t2, t3, t4, output_dir=output_dir)
    try:
        latex_paths = aggregator.save_latex(t2, t3, output_dir=output_dir)
        file_paths.update(latex_paths)
    except Exception as exc:
        log.warning("LaTeX save failed", extra={"error": str(exc)})

    # Per-platform summary dict for return
    summary: dict[str, dict] = {}
    for platform in PLATFORMS:
        sm = syn_metrics.get(platform)
        em = sem_metrics.get(platform)
        xm = exec_metrics.get(platform)
        summary[platform] = {
            "validity_pct":       getattr(sm, "validity_pct",       0.0),
            "avg_semantic_score": getattr(em, "avg_semantic_score", 0.0),
            "avg_bleu":           getattr(em, "avg_bleu",           0.0),
            "avg_rouge_l":        getattr(em, "avg_rouge_l",        0.0),
            "avg_field_f1":       getattr(em, "avg_field_f1",       0.0),
            "exact_match_pct":    getattr(xm, "exact_pct",          0.0),
        }

    return {
        "summary":   summary,
        "n_records": len(results),
        "file_paths": {k: str(v) for k, v in file_paths.items()},
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the full NL-SIEM evaluation pipeline.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--dataset",      type=Path, default=DEFAULT_DS,
                        help="SIEMBench JSONL file")
    parser.add_argument("--output",       type=Path, default=DEFAULT_OUT,
                        help="Output directory for results + tables")
    parser.add_argument("--results-file", type=Path, default=None,
                        help="Use pre-existing translations JSONL (skip LLM translation)")
    parser.add_argument("--limit",        type=int,  default=None,
                        help="Evaluate only first N records")
    parser.add_argument("--no-rag",       action="store_true",
                        help="Disable RAG retrieval during translation")
    parser.add_argument("--no-refine",    action="store_true",
                        help="Disable refinement loop")
    parser.add_argument("--no-exec",      action="store_true",
                        help="Disable Elasticsearch execution matching")
    parser.add_argument("--es-url",       default="http://localhost:9200",
                        help="Elasticsearch URL for execution matching")
    parser.add_argument("--ablation",     action="store_true",
                        help="Run ablation study (conditions A / B / C)")
    parser.add_argument("--store-path",   type=Path, default=None,
                        help="Override RAG store path")
    parser.add_argument("--quiet",        action="store_true")
    args = parser.parse_args()

    if not args.quiet:
        print("\n" + "=" * 64)
        print("  NL-SIEM  |  Full Evaluation Pipeline")
        print("=" * 64)

    # ── Load benchmark ─────────────────────────────────────────────────────
    if not args.dataset.exists():
        print(f"[ERROR]  Dataset not found: {args.dataset}\n"
              f"         Run: python scripts/generate_dataset.py", file=sys.stderr)
        return 2

    benchmark = load_jsonl(args.dataset)
    if args.limit:
        benchmark = benchmark[:args.limit]
    if not args.quiet:
        print(f"  Dataset : {args.dataset}  ({len(benchmark)} records)")

    # ── Translate (or load existing) ───────────────────────────────────────
    results_path = args.output / "translations.jsonl"
    if args.results_file and args.results_file.exists():
        print(f"  Loading existing translations from {args.results_file}")
        results = load_jsonl(args.results_file)
        if args.limit:
            results = results[:args.limit]
    else:
        if not args.quiet:
            print(f"\n  Translating {len(benchmark)} queries…")
        t0 = time.monotonic()
        results = _translate_dataset(
            benchmark  = benchmark,
            use_rag    = not args.no_rag,
            refine     = not args.no_refine,
            store_path = args.store_path,
        )
        elapsed = round(time.monotonic() - t0, 2)
        if not args.quiet:
            print(f"  Translation complete in {elapsed}s")

        args.output.mkdir(parents=True, exist_ok=True)
        save_jsonl(results, results_path)
        if not args.quiet:
            print(f"  Translations saved → {results_path}")

    # ── Evaluate ───────────────────────────────────────────────────────────
    if not args.quiet:
        print(f"\n  Evaluating {len(results)} result records…")
    t0 = time.monotonic()

    try:
        metrics = _run_evaluation(
            results      = results,
            benchmark    = benchmark,
            use_exec     = not args.no_exec,
            es_url       = args.es_url,
            run_ablation = args.ablation,
            output_dir   = args.output,
        )
    except KeyboardInterrupt:
        print("\n[INTERRUPTED]", file=sys.stderr)
        return 2
    except Exception as exc:
        log.exception("Evaluation failed")
        print(f"[ERROR]  {exc}", file=sys.stderr)
        return 2

    elapsed = round(time.monotonic() - t0, 2)

    # ── Print summary ──────────────────────────────────────────────────────
    if not args.quiet:
        print(f"\n── Summary  ({elapsed}s) ──────────────────────────────────────")
        header = f"  {'Platform':<12}  {'Valid%':>6}  {'Semantic':>9}  {'BLEU':>6}  {'Field-F1':>8}"
        print(header)
        print("  " + "-" * (len(header) - 2))
        for platform, m in metrics["summary"].items():
            print(
                f"  {platform:<12}  "
                f"{m['validity_pct']*100:>5.1f}%  "
                f"{m['avg_semantic_score']:>9.4f}  "
                f"{m['avg_bleu']:>6.4f}  "
                f"{m['avg_field_f1']:>8.4f}"
            )
        print("─" * 64)
        print(f"\n[OK]  Results written to: {args.output}\n")

    # Save summary JSON
    summary_path = args.output / "evaluation_summary.json"
    summary_path.write_text(json.dumps({
        **metrics,
        "elapsed_s":   elapsed,
        "dataset":     str(args.dataset),
        "n_evaluated": len(results),
        "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%S"),
    }, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())