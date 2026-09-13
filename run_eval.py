"""
run_eval.py

Production evaluation runner for NL-SIEM.

Pipeline

Dataset
    ↓
Sampler
    ↓
Cache
    ↓
Translation Orchestrator
    ↓
Evaluation Metrics
    ↓
CSV / JSON
    ↓
LaTeX
    ↓
Plots

Author: Shubham Bhat
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from tqdm import tqdm

from evaluations.cache import EvaluationCache
from evaluations.config import (
    EXPORT_JSON,
    EXPORT_CSV,
    EXPORT_LATEX,
    EXPORT_PLOTS,
    RAW_OUTPUT_DIR,
    REPORT_DIR,
)
from evaluations.metrics import MetricsCalculator
from evaluations.models import (
    EvaluationResult,
    RunSummary,
    to_json,
)
from evaluations.sampler import BenchmarkSampler

from src.agents.translation_orchestrator import (
    TranslationOrchestrator,
)

# ---------------------------------------------------------
# Logging
# ---------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

log = logging.getLogger("evaluation")


# ---------------------------------------------------------
# CLI
# ---------------------------------------------------------

def parse_args():

    parser = argparse.ArgumentParser(
        description="NL-SIEM Evaluation Runner"
    )

    parser.add_argument(
        "--sample-size",
        type=int,
        default=3,
    )

    parser.add_argument(
        "--random",
        action="store_true",
        help="Use random sampling instead of stratified.",
    )

    parser.add_argument(
        "--resume",
        action="store_true",
        help="Reuse cached evaluations.",
    )

    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute generated rules against connectors.",
    )

    parser.add_argument(
        "--condition",
        default="few_shot",
        choices=[
            "zero_shot",
            "few_shot",
            "rag",
        ],
    )

    parser.add_argument(
        "--output",
        default="evaluation_run",
    )

    return parser.parse_args()


# ---------------------------------------------------------
# Runner
# ---------------------------------------------------------

class EvaluationRunner:

    def __init__(self, args):

        self.args = args

        self.cache = EvaluationCache()

        self.metrics = MetricsCalculator()

        self.sampler = BenchmarkSampler()

        self.orchestrator = TranslationOrchestrator.from_env(
            condition=args.condition,
            enable_rag=args.condition == "rag",
        )

        self.results = []

        self.failed = []

        self.started = datetime.now()

        log.info(
            "Evaluation started (%s)",
            self.started.isoformat(),
        )

    # -----------------------------------------------------

    def load_samples(self):

        if self.args.random:

            samples = self.sampler.random_sample(
                self.args.sample_size
            )

        else:

            samples = self.sampler.stratified_sample(
                self.args.sample_size
            )

        log.info(
            "Loaded %d benchmark samples",
            len(samples),
        )

        return samples

    # -----------------------------------------------------

    def run(self):

        samples = self.load_samples()

        progress = tqdm(
            samples,
            desc="Evaluating",
            unit="query",
        )

        for sample in progress:

            try:

                result = self.evaluate_sample(sample)

                self.results.append(result)

                progress.set_postfix(
                    accuracy=len(self.results)
                )

            except Exception as exc:

                log.exception(exc)

                self.failed.append(
                    {
                        "sample": sample.sample_id,
                        "error": str(exc),
                    }
                )

        self.finish()

    # -----------------------------------------------------

        # -----------------------------------------------------

    def evaluate_sample(self, sample):
        """
        Evaluate a single benchmark sample.
        """

        cache_key = sample.nl_query

        # ---------------------------------------------
        # Cache
        # ---------------------------------------------

        if self.args.resume:

            cached = self.cache.get(cache_key)

            if cached is not None:

                log.info(
                    "Cache hit: %s",
                    sample.sample_id,
                )

                return EvaluationResult(
                    **cached
                )

        # ---------------------------------------------
        # Retry loop
        # ---------------------------------------------

        retries = 3

        last_exception = None

        translation = None

        for attempt in range(retries):

            try:

                translation = (
                    self.orchestrator.translate(
                        sample.nl_query,
                        execute=self.args.execute,
                    )
                )

                break

            except Exception as exc:

                last_exception = exc

                log.warning(
                    "Retry %d/%d for %s",
                    attempt + 1,
                    retries,
                    sample.sample_id,
                )

                time.sleep(2)

        if translation is None:

            raise RuntimeError(
                f"Evaluation failed after {retries} retries"
            ) from last_exception

        # ---------------------------------------------
        # Extract ATT&CK prediction
        # ---------------------------------------------

        predicted = []

        try:

            if translation.ir.technique_id:

                predicted.append(
                    translation.ir.technique_id
                )

            if translation.ir.sub_technique_id:

                predicted.append(
                    translation.ir.sub_technique_id
                )

        except Exception:

            pass

        ground_truth = sample.ground_truth

        attack_correct = (
            self.metrics.attack_match(
                predicted,
                ground_truth,
            )
        )

        drift = self.metrics.drift_score(
            predicted,
            ground_truth,
        )

        # ---------------------------------------------
        # Validation
        # ---------------------------------------------

        validation = translation.validation_report

        translation_success = (
            len(validation.valid_platforms) > 0
        )

        syntax_valid = validation.all_valid

        execution_success = True

        if translation.execution_results:

            execution_success = all(
                result.success
                for result
                in translation.execution_results.values()
            )

        # ---------------------------------------------
        # Token accounting
        # ---------------------------------------------

        prompt_tokens = 0
        completion_tokens = 0
        total_tokens = 0
        estimated_cost = 0.0

        if hasattr(
            translation.parse_result,
            "usage",
        ):

            usage = translation.parse_result.usage

            prompt_tokens = getattr(
                usage,
                "prompt_tokens",
                0,
            )

            completion_tokens = getattr(
                usage,
                "completion_tokens",
                0,
            )

            total_tokens = getattr(
                usage,
                "total_tokens",
                prompt_tokens
                + completion_tokens,
            )

            if hasattr(
                usage,
                "estimated_cost",
            ):

                estimated_cost = (
                    usage.estimated_cost
                )

        # ---------------------------------------------
        # Confidence
        # ---------------------------------------------

        confidence = 0.0

        try:

            if translation.ir.attck_mappings:

                confidence = (
                    translation.ir.attck_mappings[0]
                    .confidence
                )

        except Exception:

            pass

        # ---------------------------------------------
        # Platform outputs
        # ---------------------------------------------

        platform_results = {

            "splunk": translation.splunk,

            "qradar": translation.qradar,

            "elastic": translation.elastic,

            "sentinel": translation.sentinel,

            "wazuh": translation.wazuh,
        }

        # ---------------------------------------------
        # EvaluationResult
        # ---------------------------------------------

        result = EvaluationResult(

            sample_id=sample.sample_id,

            nl_query=sample.nl_query,

            predicted_attck=predicted,

            ground_truth_attck=ground_truth,

            attack_correct=attack_correct,

            ir_valid=True,

            translation_success=translation_success,

            syntax_valid=syntax_valid,

            execution_success=execution_success,

            latency_s=translation.elapsed_s,

            prompt_tokens=prompt_tokens,

            completion_tokens=completion_tokens,

            total_tokens=total_tokens,

            estimated_cost=estimated_cost,

            confidence=confidence,

            drift_score=drift,

            platform_results=platform_results,

            metadata={

                "warnings": translation.warnings,

                "provider": translation.provider,

                "model": translation.model,

                "condition": translation.condition,

                "run_id": translation.run_id,
            },
        )

        # ---------------------------------------------
        # Save raw TranslationResult
        # ---------------------------------------------

        raw_path = (
            RAW_OUTPUT_DIR
            /
            f"{sample.sample_id}.json"
        )

        with open(
            raw_path,
            "w",
            encoding="utf-8",
        ) as f:

            json.dump(
                translation.to_dict(),
                f,
                indent=2,
                ensure_ascii=False,
            )

        # ---------------------------------------------
        # Cache
        # ---------------------------------------------

        self.cache.save(
            cache_key,
            asdict(result),
        )

        return result
    # -----------------------------------------------------

       # -----------------------------------------------------

    def finish(self):
        """
        Finalize the evaluation run.

        Computes aggregate metrics and exports
        JSON, CSV and LaTeX reports.
        """

        finished = datetime.now()

        elapsed = (
            finished - self.started
        ).total_seconds()

        summary = self.metrics.summarize(
            self.results
        )

        run = RunSummary(

            model=self.orchestrator.model,

            provider=self.orchestrator.provider,

            dataset="SIEMBench",

            sample_size=len(self.results),

            started_at=self.started.isoformat(),

            finished_at=finished.isoformat(),

            elapsed_s=elapsed,

            metrics=summary,

            results=self.results,
        )

        # --------------------------------------------------
        # JSON
        # --------------------------------------------------

        if EXPORT_JSON:

            report = REPORT_DIR / (
                self.args.output + ".json"
            )

            with open(
                report,
                "w",
                encoding="utf-8",
            ) as f:

                f.write(
                    to_json(run)
                )

            log.info(
                "JSON report written to %s",
                report,
            )

        # --------------------------------------------------
        # CSV
        # --------------------------------------------------

        if EXPORT_CSV:

            csv_path = REPORT_DIR / (
                self.args.output + ".csv"
            )

            with open(
                csv_path,
                "w",
                newline="",
                encoding="utf-8",
            ) as f:

                writer = csv.writer(f)

                writer.writerow(
                    [
                        "sample_id",
                        "query",
                        "correct",
                        "predicted",
                        "ground_truth",
                        "latency",
                        "drift",
                        "confidence",
                        "translation_success",
                        "syntax_success",
                        "execution_success",
                    ]
                )

                for r in self.results:

                    writer.writerow(
                        [

                            r.sample_id,

                            r.nl_query,

                            r.attack_correct,

                            ";".join(
                                r.predicted_attck
                            ),

                            ";".join(
                                r.ground_truth_attck
                            ),

                            round(
                                r.latency_s,
                                3,
                            ),

                            round(
                                r.drift_score,
                                3,
                            ),

                            round(
                                r.confidence,
                                3,
                            ),

                            r.translation_success,

                            r.syntax_valid,

                            r.execution_success,
                        ]
                    )

            log.info(
                "CSV report written to %s",
                csv_path,
            )

        # --------------------------------------------------
        # LaTeX Table
        # --------------------------------------------------

        if EXPORT_LATEX:

            tex = REPORT_DIR / (
                self.args.output + ".tex"
            )

            with open(
                tex,
                "w",
                encoding="utf-8",
            ) as f:

                f.write("\\begin{table}[t]\n")
                f.write("\\centering\n")
                f.write("\\caption{NL-SIEM Evaluation Summary}\n")
                f.write("\\begin{tabular}{lr}\n")
                f.write("\\toprule\n")

                metrics = [

                    ("Queries", summary.total_queries),

                    (
                        "ATT\\&CK Accuracy",
                        f"{summary.attack_accuracy:.3f}",
                    ),

                    (
                        "Precision",
                        f"{summary.precision:.3f}",
                    ),

                    (
                        "Recall",
                        f"{summary.recall:.3f}",
                    ),

                    (
                        "F1",
                        f"{summary.f1:.3f}",
                    ),

                    (
                        "IR Success",
                        f"{summary.ir_success_rate:.3f}",
                    ),

                    (
                        "Translation Success",
                        f"{summary.translation_success_rate:.3f}",
                    ),

                    (
                        "Syntax Success",
                        f"{summary.syntax_success_rate:.3f}",
                    ),

                    (
                        "Execution Success",
                        f"{summary.execution_success_rate:.3f}",
                    ),

                    (
                        "Avg Latency (s)",
                        f"{summary.avg_latency:.3f}",
                    ),

                    (
                        "Avg Drift",
                        f"{summary.avg_drift:.3f}",
                    ),

                    (
                        "Prompt Tokens",
                        summary.total_prompt_tokens,
                    ),

                    (
                        "Completion Tokens",
                        summary.total_completion_tokens,
                    ),

                    (
                        "Total Tokens",
                        summary.total_tokens,
                    ),

                    (
                        "Estimated Cost ($)",
                        f"{summary.avg_cost:.5f}",
                    ),
                ]

                for key, value in metrics:

                    f.write(
                        f"{key} & {value} \\\\\n"
                    )

                f.write("\\bottomrule\n")
                f.write("\\end{tabular}\n")
                f.write("\\end{table}\n")

            log.info(
                "LaTeX table written to %s",
                tex,
            )

        # --------------------------------------------------
        # Plots
        # --------------------------------------------------

        if EXPORT_PLOTS:

            self.generate_plots()

        # --------------------------------------------------
        # Console summary
        # --------------------------------------------------

        print()

        print("=" * 70)

        print("NL-SIEM Evaluation Complete")

        print("=" * 70)

        print(
            f"Queries              : {summary.total_queries}"
        )

        print(
            f"ATT&CK Accuracy      : {summary.attack_accuracy:.3f}"
        )

        print(
            f"Precision            : {summary.precision:.3f}"
        )

        print(
            f"Recall               : {summary.recall:.3f}"
        )

        print(
            f"F1                   : {summary.f1:.3f}"
        )

        print(
            f"IR Success           : {summary.ir_success_rate:.3f}"
        )

        print(
            f"Translation Success  : {summary.translation_success_rate:.3f}"
        )

        print(
            f"Syntax Success       : {summary.syntax_success_rate:.3f}"
        )

        print(
            f"Execution Success    : {summary.execution_success_rate:.3f}"
        )

        print(
            f"Average Latency      : {summary.avg_latency:.3f}s"
        )

        print(
            f"Average Drift        : {summary.avg_drift:.3f}"
        )

        print(
            f"Total Tokens         : {summary.total_tokens}"
        )

        print(
            f"Average Cost         : ${summary.avg_cost:.6f}"
        )

        print(
            f"Failures             : {len(self.failed)}"
        )

        print(
            f"Elapsed              : {elapsed:.2f}s"
        )

        print("=" * 70)


    # ---------------------------------------------------------
    # Plot Generation
    # ---------------------------------------------------------

    def generate_plots(self):
        """
        Generate publication-ready plots.
        """

        try:

            import matplotlib.pyplot as plt

        except ImportError:

            log.warning(
                "matplotlib not installed. Skipping plots."
            )

            return

        self.plot_latency()
        self.plot_drift()
        self.plot_accuracy()

    # ---------------------------------------------------------

    def plot_latency(self):

        import matplotlib.pyplot as plt

        values = [
            r.latency_s
            for r in self.results
        ]

        plt.figure(figsize=(8, 4))

        plt.hist(
            values,
            bins=15,
        )

        plt.xlabel("Latency (seconds)")
        plt.ylabel("Queries")
        plt.title("Translation Latency")

        plt.tight_layout()

        plt.savefig(
            REPORT_DIR /
            "latency_histogram.png",
            dpi=300,
        )

        plt.close()

    # ---------------------------------------------------------

    def plot_drift(self):

        import matplotlib.pyplot as plt

        values = [
            r.drift_score
            for r in self.results
        ]

        plt.figure(figsize=(8, 4))

        plt.hist(
            values,
            bins=10,
        )

        plt.xlabel("Coverage Drift")

        plt.ylabel("Queries")

        plt.title("Coverage Drift Distribution")

        plt.tight_layout()

        plt.savefig(
            REPORT_DIR /
            "coverage_drift.png",
            dpi=300,
        )

        plt.close()

    # ---------------------------------------------------------

    def plot_accuracy(self):

        import matplotlib.pyplot as plt

        correct = sum(
            r.attack_correct
            for r in self.results
        )

        incorrect = (
            len(self.results)
            - correct
        )

        plt.figure(figsize=(5, 5))

        plt.pie(
            [
                correct,
                incorrect,
            ],
            labels=[
                "Correct",
                "Incorrect",
            ],
            autopct="%1.1f%%",
        )

        plt.title("ATT&CK Classification Accuracy")

        plt.savefig(
            REPORT_DIR /
            "accuracy_pie.png",
            dpi=300,
        )

        plt.close()

    # ---------------------------------------------------------
    # Optional Per-Tactic Report
    # ---------------------------------------------------------

    def tactic_breakdown(self):

        stats = {}

        for result in self.results:

            tactic = (
                result.metadata
                .get(
                    "ground_truth_tactic",
                    "unknown",
                )
            )

            if tactic not in stats:

                stats[tactic] = {

                    "total": 0,

                    "correct": 0,
                }

            stats[tactic]["total"] += 1

            if result.attack_correct:

                stats[tactic]["correct"] += 1

        return stats

    # ---------------------------------------------------------

    def print_tactic_breakdown(self):

        stats = self.tactic_breakdown()

        print("\nPer-Tactic Accuracy")

        print("-" * 60)

        for tactic, values in sorted(
            stats.items()
        ):

            acc = (
                values["correct"]
                /
                values["total"]
            )

            print(
                f"{tactic:20}"
                f"{values['correct']:3}"
                f"/"
                f"{values['total']:<3}"
                f"{acc:.2%}"
            )

    # ---------------------------------------------------------

    def save_failures(self):

        if not self.failed:

            return

        path = REPORT_DIR / "failed_queries.json"

        with open(
            path,
            "w",
            encoding="utf-8",
        ) as f:

            json.dump(
                self.failed,
                f,
                indent=2,
            )

        log.info(
            "Saved %d failures",
            len(self.failed),
        )
# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    args = parse_args()

    runner = EvaluationRunner(args)

    runner.run()


if __name__ == "__main__":
    main()