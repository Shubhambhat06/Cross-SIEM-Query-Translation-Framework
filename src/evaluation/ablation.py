"""
Ablation — A/B/C condition runner for paper ablation study (Table 4).

Conditions:
  A — Baseline LLM only        (no RAG, no IR schema, no refinement)
  B — IR schema + LLM          (structured intermediate representation)
  C — Full system              (IR + RAG retrieval + refinement loop)

Place at: src/evaluation/ablation.py
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Literal

from src.utils.logger import get_logger

log = get_logger(__name__)

Condition = Literal["A", "B", "C"]

CONDITION_LABELS: dict[str, str] = {
    "A": "Baseline LLM",
    "B": "IR + LLM",
    "C": "Full System (IR + RAG + Refinement)",
}
PLATFORMS = ("splunk", "qradar", "elastic", "sentinel", "wazuh")


# ── Result dataclasses ─────────────────────────────────────────────────────────

@dataclass
class ConditionMetrics:
    """Aggregated evaluation metrics for one ablation condition on one platform."""
    condition:           Condition
    platform:            str
    n_queries:           int
    validity_pct:        float
    avg_semantic_score:  float
    avg_bleu:            float
    avg_rouge_l:         float
    avg_field_f1:        float
    avg_token_edit_sim:  float   # from optimised SemanticScorer
    avg_elapsed_s:       float

    def to_dict(self) -> dict:
        sign = "+" if True else ""  # placeholder; delta set in build_table
        return {
            "condition":          self.condition,
            "condition_label":    CONDITION_LABELS[self.condition],
            "platform":           self.platform,
            "n_queries":          self.n_queries,
            "validity_pct":       round(self.validity_pct,       4),
            "avg_semantic_score": round(self.avg_semantic_score, 4),
            "avg_bleu":           round(self.avg_bleu,           4),
            "avg_rouge_l":        round(self.avg_rouge_l,        4),
            "avg_field_f1":       round(self.avg_field_f1,       4),
            "avg_token_edit_sim": round(self.avg_token_edit_sim, 4),
            "avg_elapsed_s":      round(self.avg_elapsed_s,      4),
        }


@dataclass
class AblationRecord:
    """Per-query, per-platform result from one condition run."""
    condition:       Condition
    query_id:        str
    nl_query:        str
    platform:        str
    hypothesis:      str
    reference:       str
    is_valid:        bool
    semantic_score:  float
    bleu:            float
    rouge_l:         float
    field_f1:        float
    token_edit_sim:  float   # added — from optimised scorer
    elapsed_s:       float
    error:           str = ""

    def to_dict(self) -> dict:
        return {
            "condition":       self.condition,
            "query_id":        self.query_id,
            "nl_query":        self.nl_query[:80],
            "platform":        self.platform,
            "hypothesis":      self.hypothesis,
            "reference":       self.reference,
            "is_valid":        self.is_valid,
            "semantic_score":  round(self.semantic_score,  4),
            "bleu":            round(self.bleu,            4),
            "rouge_l":         round(self.rouge_l,         4),
            "field_f1":        round(self.field_f1,        4),
            "token_edit_sim":  round(self.token_edit_sim,  4),
            "elapsed_s":       round(self.elapsed_s,       4),
            "error":           self.error,
        }


@dataclass
class AblationResults:
    """Full results from running all conditions across the benchmark."""
    records: list[AblationRecord]                          = field(default_factory=list)
    metrics: dict[Condition, dict[str, ConditionMetrics]]  = field(default_factory=dict)
    # metrics structure: condition → platform → ConditionMetrics

    def get_metrics(self, condition: Condition, platform: str) -> ConditionMetrics | None:
        return self.metrics.get(condition, {}).get(platform)

    def all_conditions(self) -> list[Condition]:
        return list(self.metrics.keys())

    def to_table(self) -> list[dict]:
        """Flatten metrics to row-per-(condition, platform) for export."""
        return [
            m.to_dict()
            for condition, plat_map in self.metrics.items()
            for platform, m in plat_map.items()
        ]


# ── Ablation Runner ────────────────────────────────────────────────────────────

class AblationRunner:
    """
    Orchestrates ablation study by running the translation pipeline under
    three conditions and collecting structured metrics.

    Args:
        translate_fn:     Callable(nl_query, condition) → dict[platform, query].
                          Injected at construction to allow mocking in tests.
        syntax_validator: SyntaxValidator instance (lazy-init if None).
        semantic_scorer:  SemanticScorer instance (lazy-init if None).
        max_queries:      Cap on benchmark records (useful for fast dev runs).
    """

    def __init__(
        self,
        translate_fn:      Callable[[str, Condition], dict[str, str]] | None = None,
        syntax_validator   = None,
        semantic_scorer    = None,
        max_queries:       int = 10_000,
    ) -> None:
        self._translate_fn  = translate_fn or self._default_translate
        self._syntax        = syntax_validator
        self._semantic      = semantic_scorer
        self.max_queries    = max_queries

    # ─────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────

    def run(
        self,
        benchmark:  list[dict],
        conditions: list[Condition] = ("A", "B", "C"),
        platforms:  tuple[str, ...] = PLATFORMS,
    ) -> AblationResults:
        """
        Run ablation study across all conditions and benchmark records.

        Args:
            benchmark:  List of SIEMBench records (must have nl_query + ground_truth).
            conditions: Which conditions to run (default: all three).
            platforms:  Which platforms to evaluate.

        Returns:
            AblationResults with all per-record data and aggregated metrics.
        """
        validator  = self._get_syntax_validator()
        scorer     = self._get_semantic_scorer()
        subset     = benchmark[: self.max_queries]
        all_records: list[AblationRecord] = []

        for condition in conditions:
            log.info(
                "Running ablation condition",
                extra={"condition": condition, "label": CONDITION_LABELS[condition], "n": len(subset)},
            )
            for bench_rec in subset:
                query_id = bench_rec.get("id") or bench_rec.get("nl_query", "")[:40]
                nl_query = bench_rec.get("nl_query", "")
                gt       = bench_rec.get("ground_truth") or bench_rec.get("translations", {})

                t0 = time.monotonic()
                try:
                    translations = self._translate_fn(nl_query, condition)
                except Exception as exc:
                    log.warning(
                        "Translation failed",
                        extra={"condition": condition, "query": nl_query[:50], "error": str(exc)},
                    )
                    translations = {p: "" for p in platforms}
                elapsed = time.monotonic() - t0

                for platform in platforms:
                    hyp = translations.get(platform, "")
                    ref = gt.get(platform, "")
                    if not ref:
                        continue

                    is_valid       = False
                    semantic_score = 0.0
                    bleu           = 0.0
                    rouge_l        = 0.0
                    field_f1       = 0.0
                    token_edit_sim = 0.0
                    error          = ""

                    try:
                        syn_result = validator.validate(platform, hyp)
                        is_valid   = syn_result.is_valid
                    except Exception as exc:
                        error = f"syntax:{exc}"

                    try:
                        sem_result     = scorer.score(hyp, ref, platform=platform)
                        semantic_score = sem_result.semantic_score
                        bleu           = sem_result.bleu
                        rouge_l        = sem_result.rouge_l
                        field_f1       = sem_result.field_f1
                        # token_edit_sim is present in the optimised scorer
                        token_edit_sim = getattr(sem_result, "token_edit_sim", 0.0)
                    except Exception as exc:
                        error = error or f"semantic:{exc}"

                    all_records.append(AblationRecord(
                        condition      = condition,
                        query_id       = query_id,
                        nl_query       = nl_query,
                        platform       = platform,
                        hypothesis     = hyp,
                        reference      = ref,
                        is_valid       = is_valid,
                        semantic_score = semantic_score,
                        bleu           = bleu,
                        rouge_l        = rouge_l,
                        field_f1       = field_f1,
                        token_edit_sim = token_edit_sim,
                        elapsed_s      = elapsed / len(platforms),
                        error          = error,
                    ))

        metrics = self._aggregate(all_records, list(conditions), list(platforms))
        return AblationResults(records=all_records, metrics=metrics)

    def run_single_condition(
        self,
        benchmark:  list[dict],
        condition:  Condition,
        platforms:  tuple[str, ...] = PLATFORMS,
    ) -> dict[str, ConditionMetrics]:
        """
        Run a single ablation condition. Useful for incremental or parallel execution.

        Returns:
            platform → ConditionMetrics dict.
        """
        result = self.run(benchmark, conditions=[condition], platforms=platforms)
        return result.metrics.get(condition, {})

    def build_table(
        self,
        results:    AblationResults,
        conditions: list[Condition] = ("A", "B", "C"),
    ) -> list[dict]:
        """
        Build a flat table suitable for paper Table 4.

        Columns: condition_label, platform, validity_pct, avg_semantic_score,
        avg_bleu, avg_rouge_l, avg_field_f1, avg_token_edit_sim, delta_vs_A.

        Args:
            results:    AblationResults from run().
            conditions: Ordering of conditions in the output.

        Returns:
            List of row dicts, sorted by condition then platform.
        """
        rows = results.to_table()

        # Compute delta_vs_A per platform
        baseline: dict[str, float] = {
            row["platform"]: row["avg_semantic_score"]
            for row in rows
            if row["condition"] == "A"
        }
        for row in rows:
            base             = baseline.get(row["platform"], 0.0)
            row["delta_vs_A"] = round(row["avg_semantic_score"] - base, 4)

        cond_order = {c: i for i, c in enumerate(conditions)}
        plat_order = {p: i for i, p in enumerate(PLATFORMS)}
        rows.sort(key=lambda r: (
            cond_order.get(r["condition"], 99),
            plat_order.get(r["platform"],  99),
        ))
        return rows

    def latex_table(self, results: AblationResults) -> str:
        """Render Table 4 as a LaTeX booktabs table."""
        rows  = self.build_table(results)
        lines = [
            r"\begin{table}[t]",
            r"\centering",
            r"\caption{Ablation Study Results — Component Contribution}",
            r"\label{tab:ablation}",
            r"\begin{tabular}{llrrrrrr}",
            r"\toprule",
            r"Condition & Platform & Valid\% & Semantic & BLEU & ROUGE-L & Field-F1 & $\Delta$ vs A \\ \midrule",
        ]
        prev_cond = None
        for row in rows:
            if prev_cond and row["condition"] != prev_cond:
                lines.append(r"\midrule")
            sign = "+" if row["delta_vs_A"] >= 0 else ""
            lines.append(
                f"{CONDITION_LABELS[row['condition']]} & "
                f"{row['platform'].capitalize()} & "
                f"{row['validity_pct'] * 100:.1f} & "
                f"{row['avg_semantic_score']:.3f} & "
                f"{row['avg_bleu']:.3f} & "
                f"{row['avg_rouge_l']:.3f} & "
                f"{row['avg_field_f1']:.3f} & "
                f"{sign}{row['delta_vs_A']:.3f} \\\\"
            )
            prev_cond = row["condition"]
        lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
        return "\n".join(lines)

    # ─────────────────────────────────────────────
    # Aggregation
    # ─────────────────────────────────────────────

    @staticmethod
    def _aggregate(
        records:    list[AblationRecord],
        conditions: list[Condition],
        platforms:  list[str],
    ) -> dict[Condition, dict[str, ConditionMetrics]]:
        """Aggregate per-record data into per-(condition, platform) metrics."""
        buckets: dict[tuple, list[AblationRecord]] = defaultdict(list)
        for r in records:
            buckets[(r.condition, r.platform)].append(r)

        metrics: dict[Condition, dict[str, ConditionMetrics]] = {c: {} for c in conditions}

        for condition in conditions:
            for platform in platforms:
                recs = buckets.get((condition, platform), [])
                if not recs:
                    metrics[condition][platform] = ConditionMetrics(
                        condition=condition, platform=platform, n_queries=0,
                        validity_pct=0.0, avg_semantic_score=0.0, avg_bleu=0.0,
                        avg_rouge_l=0.0, avg_field_f1=0.0, avg_token_edit_sim=0.0,
                        avg_elapsed_s=0.0,
                    )
                    continue
                n = len(recs)
                metrics[condition][platform] = ConditionMetrics(
                    condition          = condition,
                    platform           = platform,
                    n_queries          = n,
                    validity_pct       = sum(1 for r in recs if r.is_valid) / n,
                    avg_semantic_score = sum(r.semantic_score  for r in recs) / n,
                    avg_bleu           = sum(r.bleu            for r in recs) / n,
                    avg_rouge_l        = sum(r.rouge_l         for r in recs) / n,
                    avg_field_f1       = sum(r.field_f1        for r in recs) / n,
                    avg_token_edit_sim = sum(r.token_edit_sim  for r in recs) / n,
                    avg_elapsed_s      = sum(r.elapsed_s       for r in recs) / n,
                )

        return metrics

    # ─────────────────────────────────────────────
    # Lazy init
    # ─────────────────────────────────────────────

    def _get_syntax_validator(self):
        if self._syntax is None:
            from src.evaluation.syntax_validator import SyntaxValidator
            self._syntax = SyntaxValidator()
        return self._syntax

    def _get_semantic_scorer(self):
        if self._semantic is None:
            from src.evaluation.semantic_scorer import SemanticScorer
            self._semantic = SemanticScorer()
        return self._semantic

    @staticmethod
    def _default_translate(nl_query: str, condition: Condition) -> dict[str, str]:
        """
        Stub used when no translate_fn is injected.
        Replace with real orchestrator in production:
            orc = TranslationOrchestrator(condition=condition)
            return orc.translate(nl_query).translations
        """
        log.warning(
            "AblationRunner: no translate_fn injected — returning empty translations. "
            "Inject a real orchestrator for actual evaluation."
        )
        return {p: "" for p in PLATFORMS}