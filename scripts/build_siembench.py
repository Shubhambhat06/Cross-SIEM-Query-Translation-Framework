#!/usr/bin/env python3
"""
build_siembench.py — Formal SIEMBench benchmark builder.

Takes natural-language seed queries (e.g. from generate_dataset.py, or a
hand-curated seed file), runs each through the full NL-SIEM pipeline to
collect five-platform ground truth, attaches a taxonomy-verified ATT&CK
tactic/technique/sub-technique label via ATTCKClassifierAgent, stratifies
the resulting records by complexity tier, and writes the final
train/dev/test JSONL splits consumed by the evaluation harness
(src/evaluation/ablation.py, metrics_aggregator.py).

Pipeline
--------
    seed NL queries (data/seeds/*.txt or --seeds-file)
        -> ParserAgent.parse()              (Layer 5)            -> base IRQuery
        -> ATTCKClassifierAgent.classify()  (this addition)       -> ClassificationResult
        -> AttckIRQuery.from_ir_query()                            -> AttckIRQuery
        -> translate_all()                  (Layer 2)             -> 5 platform queries
        -> stratified split (train/dev/test by complexity tier)
        -> data/siembench.{train,dev,test}.jsonl
        -> data/manifest.json, data/stats.json

Usage
-----
    python scripts/build_siembench.py \\
        --seeds-file data/seeds/nl_queries.txt \\
        --output-dir data \\
        --train-frac 0.7 --dev-frac 0.15

    # Resume / append to an existing benchmark rather than overwrite
    python scripts/build_siembench.py --seeds-file data/seeds/batch2.txt --append

Place at: scripts/build_siembench.py
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.agents.attck_classifier_agent import ATTCKClassifierAgent
from src.agents.translation_orchestrator import TranslationOrchestrator
from src.utils.exceptions import NLSIEMError
from src.utils.logger import get_logger, setup_logging

log = get_logger(__name__)


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="build_siembench.py",
        description="Build the SIEMBench train/dev/test benchmark with verified ATT&CK labels.",
    )
    parser.add_argument(
        "--seeds-file", required=True,
        help="Path to a plain-text file with one natural language query per line.",
    )
    parser.add_argument(
        "--output-dir", default="data",
        help="Directory to write siembench.{train,dev,test}.jsonl, manifest.json, stats.json (default: data)",
    )
    parser.add_argument("--train-frac", type=float, default=0.70)
    parser.add_argument("--dev-frac",   type=float, default=0.15)
    # test-frac is implied as the remainder
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for the stratified shuffle (default: 42, for reproducibility).",
    )
    parser.add_argument(
        "--append", action="store_true",
        help="Append new records to existing splits rather than overwriting them.",
    )
    parser.add_argument(
        "--condition", default="few_shot", choices=["zero_shot", "few_shot", "rag"],
        help="Prompting condition used to generate ground-truth translations (default: few_shot).",
    )
    parser.add_argument(
        "--delay-s", type=float, default=0.5,
        help="Delay between LLM calls to respect free-tier rate limits (default: 0.5s).",
    )
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def _infer_complexity(nl_query: str) -> str:
    """
    Heuristic complexity tier assignment based on surface cues, used only
    as a stratification key for the train/dev/test split — NOT as a
    scientific claim about query difficulty. Hand-authored seed sets
    should ideally pre-label complexity explicitly (one tier per line via
    a "<query>\\t<tier>" seed format); this fallback exists so a plain
    one-query-per-line seed file still produces a stratified split.
    """
    q = nl_query.lower()
    complex_markers   = ("sequence", "then", "followed by", "correlate", "across", "from one", "to a different")
    moderate_markers  = ("more than", "exceeding", "threshold", "aggregate", "group by", "count", "distinct")

    if any(m in q for m in complex_markers):
        return "complex"
    if any(m in q for m in moderate_markers):
        return "intermediate"
    return "simple"


def _read_seeds(path: Path) -> list[tuple[str, str | None]]:
    """
    Read seed queries. Supports two line formats:
        plain:        "<nl query>"
        tab-delimited: "<nl query>\\t<complexity_tier>"
    Returns list of (nl_query, complexity_or_None) tuples.
    """
    seeds: list[tuple[str, str | None]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" in line:
            q, tier = line.split("\t", 1)
            seeds.append((q.strip(), tier.strip().lower()))
        else:
            seeds.append((line, None))
    return seeds


def _stratified_split(
    records:    list[dict],
    train_frac: float,
    dev_frac:   float,
    seed:       int,
) -> tuple[list[dict], list[dict], list[dict]]:
    """
    Split records into train/dev/test, stratified by complexity tier so
    each split has a proportional mix of simple/intermediate/complex
    examples rather than a split that happens to dump all "complex"
    examples into test by chance of ordering.
    """
    rng = random.Random(seed)
    by_tier: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_tier[r.get("complexity", "simple")].append(r)

    train: list[dict] = []
    dev:   list[dict] = []
    test:  list[dict] = []

    for tier, tier_records in by_tier.items():
        shuffled = tier_records[:]
        rng.shuffle(shuffled)
        n = len(shuffled)
        n_train = round(n * train_frac)
        n_dev   = round(n * dev_frac)
        train.extend(shuffled[:n_train])
        dev.extend(shuffled[n_train:n_train + n_dev])
        test.extend(shuffled[n_train + n_dev:])

    # Final shuffle within each split so tier ordering isn't trivially
    # recoverable from record position.
    rng.shuffle(train)
    rng.shuffle(dev)
    rng.shuffle(test)

    return train, dev, test


def _load_existing_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


def _write_jsonl(records: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def main() -> int:
    args = _build_arg_parser().parse_args()
    setup_logging(level=args.log_level)

    seeds_path = Path(args.seeds_file)
    if not seeds_path.exists():
        print(f"[ERROR] Seeds file not found: {seeds_path}", file=sys.stderr)
        return 1

    seeds = _read_seeds(seeds_path)
    if not seeds:
        print(f"[ERROR] No seed queries found in {seeds_path}", file=sys.stderr)
        return 1

    log.info("Seeds loaded", extra={"count": len(seeds), "path": str(seeds_path)})

    # ── Build pipeline components ──────────────────────────────────────────
    orchestrator = TranslationOrchestrator.from_env(
        condition=args.condition,
        enable_refinement=True,
    )
    classifier = ATTCKClassifierAgent(client=orchestrator.parser_agent.client)

    # ── Process each seed ───────────────────────────────────────────────────
    records: list[dict] = []
    failures: list[dict] = []

    for i, (nl_query, declared_tier) in enumerate(seeds):
        t0 = time.monotonic()
        try:
            translation_result = orchestrator.translate(nl_query)

            classification = classifier.classify(nl_query)
            attck_ir = classifier.attach(translation_result.ir, classification)

            complexity = declared_tier or _infer_complexity(nl_query)

            record = {
                "id":            f"SB-{i + 1:04d}",
                "nl_query":      nl_query,
                "tactic":        attck_ir.tactic,
                "technique":     attck_ir.technique,
                "sub_technique": attck_ir.sub_technique,
                "attck_rationale": classification.rationale,
                "attck_confidence": classification.confidence,
                "complexity":    complexity,
                "ir":            attck_ir.to_dict(),
                "ground_truth": {
                    "splunk":   translation_result.splunk,
                    "qradar":   translation_result.qradar,
                    "elastic":  translation_result.elastic,
                    "sentinel": translation_result.sentinel,
                    "wazuh":    translation_result.wazuh,
                },
                "validation_pass_rate": translation_result.pass_rate,
                "condition":     args.condition,
            }
            records.append(record)

            log.info(
                "Seed processed",
                extra={
                    "index":        i + 1,
                    "total":        len(seeds),
                    "id":           record["id"],
                    "technique":    attck_ir.technique,
                    "pass_rate":    f"{translation_result.pass_rate:.0%}",
                    "elapsed_s":    round(time.monotonic() - t0, 2),
                },
            )

        except NLSIEMError as exc:
            log.error(
                "Seed processing failed",
                extra={"index": i + 1, "nl_query": nl_query[:80], "error": str(exc)},
            )
            failures.append({"index": i + 1, "nl_query": nl_query, "error": str(exc)})

        if args.delay_s > 0 and i < len(seeds) - 1:
            time.sleep(args.delay_s)

    if not records:
        print("[ERROR] No records were successfully built — see logs for failures.", file=sys.stderr)
        return 2

    # ── Split ───────────────────────────────────────────────────────────────
    train, dev, test = _stratified_split(
        records, train_frac=args.train_frac, dev_frac=args.dev_frac, seed=args.seed,
    )

    output_dir   = Path(args.output_dir)
    train_path   = output_dir / "siembench.train.jsonl"
    dev_path     = output_dir / "siembench.dev.jsonl"
    test_path    = output_dir / "siembench.test.jsonl"
    manifest_path = output_dir / "manifest.json"
    stats_path    = output_dir / "stats.json"

    if args.append:
        train = _load_existing_jsonl(train_path) + train
        dev   = _load_existing_jsonl(dev_path)   + dev
        test  = _load_existing_jsonl(test_path)  + test

    _write_jsonl(train, train_path)
    _write_jsonl(dev,   dev_path)
    _write_jsonl(test,  test_path)

    # ── Manifest + stats ────────────────────────────────────────────────────
    tier_counts: dict[str, int] = defaultdict(int)
    tactic_counts: dict[str, int] = defaultdict(int)
    for r in train + dev + test:
        tier_counts[r["complexity"]] += 1
        tactic_counts[r["tactic"]] += 1

    manifest = {
        "version":       "v1",
        "built_at_unix": time.time(),
        "total_records": len(train) + len(dev) + len(test),
        "splits": {
            "train": len(train),
            "dev":   len(dev),
            "test":  len(test),
        },
        "condition_used_for_ground_truth": args.condition,
        "seed":          args.seed,
        "failures":      len(failures),
    }
    stats = {
        "complexity_distribution": dict(tier_counts),
        "tactic_distribution":     dict(tactic_counts),
        "avg_validation_pass_rate": (
            sum(r["validation_pass_rate"] for r in train + dev + test) / (len(train) + len(dev) + len(test))
        ),
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2))
    stats_path.write_text(json.dumps(stats, indent=2))

    print("\n── SIEMBench Build Report ───────────────────────────────────")
    print(f"  Total records: {manifest['total_records']}")
    print(f"  Train / Dev / Test: {len(train)} / {len(dev)} / {len(test)}")
    print(f"  Failures: {len(failures)}")
    print(f"  Complexity distribution: {dict(tier_counts)}")
    print(f"  Avg validation pass rate: {stats['avg_validation_pass_rate']:.1%}")
    print(f"  Written to: {output_dir}/")
    print("──────────────────────────────────────────────────────────────")

    if failures:
        failures_path = output_dir / "build_failures.json"
        failures_path.write_text(json.dumps(failures, indent=2))
        print(f"\n[NOTICE] {len(failures)} seed(s) failed — see {failures_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())