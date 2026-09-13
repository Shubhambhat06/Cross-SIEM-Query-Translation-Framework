"""
evaluation/metrics.py

Computes all evaluation metrics for NL-SIEM.

Includes

• ATT&CK Accuracy
• Precision
• Recall
• F1
• IR Success
• Translation Success
• Syntax Success
• Execution Success
• Average Latency
• Token Usage
• Estimated Cost
• ATT&CK Coverage Drift
"""

from __future__ import annotations

from statistics import mean

from evaluations.models import (
    EvaluationResult,
    MetricSummary,
)


class MetricsCalculator:

    def summarize(
        self,
        results: list[EvaluationResult],
    ) -> MetricSummary:

        summary = MetricSummary()

        if not results:
            return summary

        summary.total_queries = len(results)

        # --------------------------------------------------
        # Accuracy
        # --------------------------------------------------

        summary.attack_accuracy = mean(
            r.attack_correct
            for r in results
        )

        # --------------------------------------------------
        # Precision Recall F1
        # --------------------------------------------------

        tp = fp = fn = 0

        for r in results:

            pred = set(r.predicted_attck)

            gt = set(r.ground_truth_attck)

            tp += len(pred & gt)

            fp += len(pred - gt)

            fn += len(gt - pred)

        precision = (
            tp / (tp + fp)
            if tp + fp
            else 0
        )

        recall = (
            tp / (tp + fn)
            if tp + fn
            else 0
        )

        f1 = (
            (
                2
                * precision
                * recall
            )
            /
            (
                precision
                + recall
            )
            if precision + recall
            else 0
        )

        summary.precision = precision

        summary.recall = recall

        summary.f1 = f1

        # --------------------------------------------------
        # Success Rates
        # --------------------------------------------------

        summary.ir_success_rate = mean(
            r.ir_valid
            for r in results
        )

        summary.translation_success_rate = mean(
            r.translation_success
            for r in results
        )

        summary.syntax_success_rate = mean(
            r.syntax_valid
            for r in results
        )

        summary.execution_success_rate = mean(
            r.execution_success
            for r in results
        )

        # --------------------------------------------------
        # Latency
        # --------------------------------------------------

        summary.avg_latency = mean(
            r.latency_s
            for r in results
        )

        # --------------------------------------------------
        # Cost
        # --------------------------------------------------

        summary.avg_cost = mean(
            r.estimated_cost
            for r in results
        )

        # --------------------------------------------------
        # Drift
        # --------------------------------------------------

        summary.avg_drift = mean(
            r.drift_score
            for r in results
        )

        # --------------------------------------------------
        # Tokens
        # --------------------------------------------------

        summary.total_prompt_tokens = sum(
            r.prompt_tokens
            for r in results
        )

        summary.total_completion_tokens = sum(
            r.completion_tokens
            for r in results
        )

        summary.total_tokens = sum(
            r.total_tokens
            for r in results
        )

        return summary

    # ------------------------------------------------------
    # Coverage Drift
    # ------------------------------------------------------

    @staticmethod
    def drift_score(
        predicted: list[str],
        ground_truth: list[str],
    ) -> float:
        """
        Jaccard-based ATT&CK Coverage Drift.

        0.0 = identical

        1.0 = completely different
        """

        pred = set(predicted)

        gt = set(ground_truth)

        if not pred and not gt:
            return 0

        return 1 - (
            len(pred & gt)
            /
            len(pred | gt)
        )

    # ------------------------------------------------------
    # Exact Match
    # ------------------------------------------------------

    @staticmethod
    def attack_match(
        predicted: list[str],
        ground_truth: list[str],
    ) -> bool:

        return (
            set(predicted)
            ==
            set(ground_truth)
        )