"""
Metrics Aggregator — compiles all evaluation signals into paper Tables 2 & 3.

Consumes output from:
  - SyntaxValidator.compute_metrics()    → syntax validity %
  - SemanticScorer.compute_metrics()     → BLEU / ROUGE-L / field-F1
  - ExecutionMatcher.compute_metrics()   → execution match %
  - ErrorAnalyzer.compute_distribution() → error taxonomy
  - AblationRunner.build_table()         → ablation delta vs baseline

Produces:
  Table 2 — Main Results (per platform × metric)
  Table 3 — Error Analysis (per platform × error category)
  Table 4 — Ablation Study (condition × platform × metric)

Place at: src/evaluation/metrics_aggregator.py

Usage:
    from src.evaluation.metrics_aggregator import MetricsAggregator
    agg    = MetricsAggregator()
    table2 = agg.build_table2(syntax_metrics, semantic_metrics, execution_metrics)
    table3 = agg.build_table3(error_distributions)
    table4 = agg.build_table4(ablation_table)
    agg.print_tables(table2, table3, table4)
    agg.save(table2, table3, table4, output_dir="results/")
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from src.utils.logger import get_logger

log = get_logger(__name__)

PLATFORMS = ("splunk", "qradar", "elastic", "sentinel", "wazuh")


# ── Row dataclasses ────────────────────────────────────────────────────────

@dataclass
class Table2Row:
    """One row in paper Table 2 — Main Evaluation Results."""
    platform:         str
    n_queries:        int
    validity_pct:     float   # SyntaxValidator
    avg_bleu:         float   # SemanticScorer
    avg_rouge_l:      float   # SemanticScorer
    avg_field_f1:     float   # SemanticScorer
    avg_semantic:     float   # SemanticScorer combined
    exact_match_pct:  float   # ExecutionMatcher
    recall_match_pct: float   # ExecutionMatcher
    struct_match_pct: float   # ExecutionMatcher

    def to_dict(self) -> dict:
        return {
            "platform":         self.platform,
            "n_queries":        self.n_queries,
            "validity_%":       f"{self.validity_pct * 100:.1f}",
            "bleu":             f"{self.avg_bleu:.4f}",
            "rouge_l":          f"{self.avg_rouge_l:.4f}",
            "field_f1":         f"{self.avg_field_f1:.4f}",
            "semantic_score":   f"{self.avg_semantic:.4f}",
            "exact_match_%":    f"{self.exact_match_pct * 100:.1f}",
            "recall_match_%":   f"{self.recall_match_pct * 100:.1f}",
            "struct_match_%":   f"{self.struct_match_pct * 100:.1f}",
        }


@dataclass
class Table3Row:
    """One row in paper Table 3 — Error Analysis."""
    platform:          str
    total_queries:     int
    error_count:       int
    error_rate:        float
    syntax_errors:     int
    field_errors:      int
    operator_errors:   int
    logic_errors:      int
    temporal_errors:   int
    platform_errors:   int
    top_error:         str     # most common leaf error type

    def to_dict(self) -> dict:
        return {
            "platform":         self.platform,
            "total_queries":    self.total_queries,
            "errors":           self.error_count,
            "error_rate_%":     f"{self.error_rate * 100:.1f}",
            "syntax_errors":    self.syntax_errors,
            "field_errors":     self.field_errors,
            "operator_errors":  self.operator_errors,
            "logic_errors":     self.logic_errors,
            "temporal_errors":  self.temporal_errors,
            "platform_errors":  self.platform_errors,
            "top_error":        self.top_error,
        }


@dataclass
class Table4Row:
    """One row in paper Table 4 — Ablation Study."""
    condition:          str
    condition_label:    str
    platform:           str
    n_queries:          int
    validity_pct:       float
    avg_semantic:       float
    avg_bleu:           float
    avg_rouge_l:        float
    avg_field_f1:       float
    delta_vs_A:         float

    def to_dict(self) -> dict:
        sign = "+" if self.delta_vs_A >= 0 else ""
        return {
            "condition":       self.condition,
            "condition_label": self.condition_label,
            "platform":        self.platform,
            "n_queries":       self.n_queries,
            "validity_%":      f"{self.validity_pct * 100:.1f}",
            "semantic_score":  f"{self.avg_semantic:.4f}",
            "bleu":            f"{self.avg_bleu:.4f}",
            "rouge_l":         f"{self.avg_rouge_l:.4f}",
            "field_f1":        f"{self.avg_field_f1:.4f}",
            "delta_vs_A":      f"{sign}{self.delta_vs_A:.4f}",
        }


@dataclass
class AggregatedResults:
    """Container for all three paper tables."""
    table2: list[Table2Row]
    table3: list[Table3Row]
    table4: list[Table4Row]
    generated_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S"))

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at,
            "table2":       [r.to_dict() for r in self.table2],
            "table3":       [r.to_dict() for r in self.table3],
            "table4":       [r.to_dict() for r in self.table4],
        }


# ── Metrics Aggregator ─────────────────────────────────────────────────────

class MetricsAggregator:
    """
    Compiles evaluation signals into structured paper tables.

    All build_tableN() methods accept the output objects from their
    respective evaluator's compute_metrics() / compute_distribution() methods.
    Missing data is filled with zeros so partial-pipeline runs don't crash.
    """

    # ─────────────────────────────────────────────
    # Table 2 — Main Results
    # ─────────────────────────────────────────────

    def build_table2(
        self,
        syntax_metrics:    dict[str, Any],   # platform → SyntaxMetrics
        semantic_metrics:  dict[str, Any],   # platform → SemanticMetrics
        execution_metrics: dict[str, Any] | None = None,  # platform → ExecutionMetrics
    ) -> list[Table2Row]:
        """
        Build Table 2 — Main Evaluation Results.

        Args:
            syntax_metrics:    Output of SyntaxValidator.compute_all_metrics().
            semantic_metrics:  Output of SemanticScorer.compute_metrics() per platform.
            execution_metrics: Output of ExecutionMatcher.compute_metrics() per platform (optional).

        Returns:
            List of Table2Row, one per platform, ordered by PLATFORMS.
        """
        rows = []
        for platform in PLATFORMS:
            syn  = syntax_metrics.get(platform)
            sem  = semantic_metrics.get(platform)
            exe  = (execution_metrics or {}).get(platform)

            row = Table2Row(
                platform         = platform,
                n_queries        = getattr(syn,  "total",              0),
                validity_pct     = getattr(syn,  "validity_pct",       0.0),
                avg_bleu         = getattr(sem,  "avg_bleu",           0.0),
                avg_rouge_l      = getattr(sem,  "avg_rouge_l",        0.0),
                avg_field_f1     = getattr(sem,  "avg_field_f1",       0.0),
                avg_semantic     = getattr(sem,  "avg_semantic_score", 0.0),
                exact_match_pct  = getattr(exe,  "exact_pct",         0.0),
                recall_match_pct = getattr(exe,  "recall_pct",        0.0),
                struct_match_pct = getattr(exe,  "structural_pct",    0.0),
            )
            rows.append(row)

        # Append macro-average row
        if rows:
            rows.append(self._macro_avg_table2(rows))

        log.info("Built Table 2", extra={"rows": len(rows)})
        return rows

    def _macro_avg_table2(self, rows: list[Table2Row]) -> Table2Row:
        n = len(rows)
        return Table2Row(
            platform         = "MACRO-AVG",
            n_queries        = sum(r.n_queries        for r in rows),
            validity_pct     = sum(r.validity_pct     for r in rows) / n,
            avg_bleu         = sum(r.avg_bleu         for r in rows) / n,
            avg_rouge_l      = sum(r.avg_rouge_l      for r in rows) / n,
            avg_field_f1     = sum(r.avg_field_f1     for r in rows) / n,
            avg_semantic     = sum(r.avg_semantic     for r in rows) / n,
            exact_match_pct  = sum(r.exact_match_pct  for r in rows) / n,
            recall_match_pct = sum(r.recall_match_pct for r in rows) / n,
            struct_match_pct = sum(r.struct_match_pct for r in rows) / n,
        )

    # ─────────────────────────────────────────────
    # Table 3 — Error Analysis
    # ─────────────────────────────────────────────

    def build_table3(
        self,
        error_distributions: dict[str, Any],   # platform → ErrorDistribution
    ) -> list[Table3Row]:
        """
        Build Table 3 — Error Analysis.

        Args:
            error_distributions: Output of ErrorAnalyzer.compute_all_distributions().

        Returns:
            List of Table3Row, one per platform.
        """
        rows = []
        for platform in PLATFORMS:
            dist = error_distributions.get(platform)
            if dist is None:
                rows.append(Table3Row(
                    platform=platform, total_queries=0, error_count=0,
                    error_rate=0.0, syntax_errors=0, field_errors=0,
                    operator_errors=0, logic_errors=0, temporal_errors=0,
                    platform_errors=0, top_error="none",
                ))
                continue

            cats    = getattr(dist, "category_counts", {})
            leafs   = getattr(dist, "leaf_counts", {})
            top_err = dist.most_common_errors[0][0] if getattr(dist, "most_common_errors", []) else "none"

            rows.append(Table3Row(
                platform        = platform,
                total_queries   = getattr(dist, "total",       0),
                error_count     = getattr(dist, "error_count", 0),
                error_rate      = getattr(dist, "error_rate",  0.0),
                syntax_errors   = cats.get("SYNTAX_ERROR",    0),
                field_errors    = cats.get("FIELD_ERROR",      0),
                operator_errors = cats.get("OPERATOR_ERROR",   0),
                logic_errors    = cats.get("LOGIC_ERROR",      0),
                temporal_errors = cats.get("TEMPORAL_ERROR",   0),
                platform_errors = cats.get("PLATFORM_SPECIFIC",0),
                top_error       = top_err,
            ))

        log.info("Built Table 3", extra={"rows": len(rows)})
        return rows

    # ─────────────────────────────────────────────
    # Table 4 — Ablation Study
    # ─────────────────────────────────────────────

    def build_table4(
        self,
        ablation_table: list[dict],   # from AblationRunner.build_table()
    ) -> list[Table4Row]:
        """
        Build Table 4 — Ablation Study.

        Args:
            ablation_table: Output of AblationRunner.build_table() — list of dicts.

        Returns:
            List of Table4Row ordered by condition then platform.
        """
        rows = []
        for d in ablation_table:
            rows.append(Table4Row(
                condition       = d.get("condition",       "?"),
                condition_label = d.get("condition_label", "?"),
                platform        = d.get("platform",        "?"),
                n_queries       = d.get("n_queries",        0),
                validity_pct    = d.get("validity_pct",    0.0),
                avg_semantic    = d.get("avg_semantic_score", 0.0),
                avg_bleu        = d.get("avg_bleu",         0.0),
                avg_rouge_l     = d.get("avg_rouge_l",      0.0),
                avg_field_f1    = d.get("avg_field_f1",     0.0),
                delta_vs_A      = d.get("delta_vs_A",       0.0),
            ))

        log.info("Built Table 4", extra={"rows": len(rows)})
        return rows

    # ─────────────────────────────────────────────
    # Combined build
    # ─────────────────────────────────────────────

    def build_all(
        self,
        syntax_metrics:      dict[str, Any],
        semantic_metrics:    dict[str, Any],
        error_distributions: dict[str, Any],
        execution_metrics:   dict[str, Any] | None = None,
        ablation_table:      list[dict] | None     = None,
    ) -> AggregatedResults:
        """
        Build all three tables in one call.

        Args:
            syntax_metrics:      platform → SyntaxMetrics
            semantic_metrics:    platform → SemanticMetrics
            error_distributions: platform → ErrorDistribution
            execution_metrics:   platform → ExecutionMetrics (optional)
            ablation_table:      from AblationRunner.build_table() (optional)

        Returns:
            AggregatedResults container.
        """
        return AggregatedResults(
            table2 = self.build_table2(syntax_metrics, semantic_metrics, execution_metrics),
            table3 = self.build_table3(error_distributions),
            table4 = self.build_table4(ablation_table or []),
        )

    # ─────────────────────────────────────────────
    # Display
    # ─────────────────────────────────────────────

    def print_tables(
        self,
        table2: list[Table2Row],
        table3: list[Table3Row],
        table4: list[Table4Row],
    ) -> None:
        """Pretty-print all three tables to stdout."""
        self._print_table(
            "TABLE 2 — Main Evaluation Results",
            [r.to_dict() for r in table2],
        )
        self._print_table(
            "TABLE 3 — Error Analysis",
            [r.to_dict() for r in table3],
        )
        if table4:
            self._print_table(
                "TABLE 4 — Ablation Study",
                [r.to_dict() for r in table4],
            )

    @staticmethod
    def _print_table(title: str, rows: list[dict]) -> None:
        if not rows:
            print(f"\n{title}\n  (no data)\n")
            return
        cols  = list(rows[0].keys())
        widths = {c: max(len(c), max(len(str(r.get(c, ""))) for r in rows))
                  for c in cols}
        sep  = "+" + "+".join("-" * (w + 2) for w in widths.values()) + "+"
        hdr  = "|" + "|".join(f" {c:<{widths[c]}} " for c in cols) + "|"

        print(f"\n{title}")
        print(sep)
        print(hdr)
        print(sep)
        for row in rows:
            print("|" + "|".join(f" {str(row.get(c,'')):<{widths[c]}} " for c in cols) + "|")
        print(sep)

    # ─────────────────────────────────────────────
    # Persistence
    # ─────────────────────────────────────────────

    def save(
        self,
        table2:     list[Table2Row],
        table3:     list[Table3Row],
        table4:     list[Table4Row],
        output_dir: str | Path = "results",
    ) -> dict[str, Path]:
        """
        Save all three tables to JSON files.

        Args:
            table2, table3, table4: Built table rows.
            output_dir: Output directory (created if absent).

        Returns:
            Dict mapping table name → saved path.
        """
        out  = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts   = time.strftime("%Y%m%d_%H%M%S")

        paths = {}
        for name, rows, cls in [
            ("table2_main_results", table2, Table2Row),
            ("table3_error_analysis", table3, Table3Row),
            ("table4_ablation", table4, Table4Row),
        ]:
            p = out / f"{name}_{ts}.json"
            with open(p, "w", encoding="utf-8") as f:
                json.dump([r.to_dict() for r in rows], f, indent=2, ensure_ascii=False)
            paths[name] = p
            log.info("Saved table", extra={"table": name, "path": str(p), "rows": len(rows)})

        # Also save combined
        combined_path = out / f"all_tables_{ts}.json"
        with open(combined_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "generated_at": ts,
                    "table2": [r.to_dict() for r in table2],
                    "table3": [r.to_dict() for r in table3],
                    "table4": [r.to_dict() for r in table4],
                },
                f, indent=2, ensure_ascii=False,
            )
        paths["all_tables"] = combined_path
        log.info("Saved combined tables", extra={"path": str(combined_path)})

        return paths

    def save_latex(
        self,
        table2:     list[Table2Row],
        table3:     list[Table3Row],
        output_dir: str | Path = "results",
    ) -> dict[str, Path]:
        """
        Emit LaTeX booktabs tables for Table 2 and Table 3.

        Args:
            table2, table3: Built table rows.
            output_dir:     Output directory.

        Returns:
            Dict mapping 'table2_latex' / 'table3_latex' → saved path.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts  = time.strftime("%Y%m%d_%H%M%S")
        paths = {}

        # Table 2 LaTeX
        t2_path = out / f"table2_{ts}.tex"
        with open(t2_path, "w") as f:
            f.write(self._table2_latex(table2))
        paths["table2_latex"] = t2_path

        # Table 3 LaTeX
        t3_path = out / f"table3_{ts}.tex"
        with open(t3_path, "w") as f:
            f.write(self._table3_latex(table3))
        paths["table3_latex"] = t3_path

        log.info("Saved LaTeX tables", extra={"dir": str(out)})
        return paths

    # ─────────────────────────────────────────────
    # LaTeX helpers
    # ─────────────────────────────────────────────

    @staticmethod
    def _table2_latex(rows: list[Table2Row]) -> str:
        lines = [
            r"\begin{table}[t]",
            r"\centering",
            r"\caption{Main Evaluation Results — NL-SIEM Translation Quality}",
            r"\label{tab:main_results}",
            r"\begin{tabular}{lrrrrrrrrr}",
            r"\toprule",
            r"Platform & Valid\% & BLEU & ROUGE-L & Field-F1 & Semantic & Exact\% & Recall\% & Struct\% \\",
            r"\midrule",
        ]
        for r in rows:
            is_avg = r.platform == "MACRO-AVG"
            prefix = r"\midrule" + "\n" if is_avg else ""
            line = (
                f"{prefix}{r.platform} & "
                f"{r.validity_pct*100:.1f} & "
                f"{r.avg_bleu:.3f} & "
                f"{r.avg_rouge_l:.3f} & "
                f"{r.avg_field_f1:.3f} & "
                f"{r.avg_semantic:.3f} & "
                f"{r.exact_match_pct*100:.1f} & "
                f"{r.recall_match_pct*100:.1f} & "
                f"{r.struct_match_pct*100:.1f} \\\\"
            )
            lines.append(line)
        lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
        return "\n".join(lines)

    @staticmethod
    def _table3_latex(rows: list[Table3Row]) -> str:
        lines = [
            r"\begin{table}[t]",
            r"\centering",
            r"\caption{Error Analysis — Translation Failure Taxonomy}",
            r"\label{tab:error_analysis}",
            r"\begin{tabular}{lrrrrrrrr}",
            r"\toprule",
            r"Platform & Errors\% & Syntax & Field & Operator & Logic & Temporal & Platform & Top Error \\",
            r"\midrule",
        ]
        for r in rows:
            line = (
                f"{r.platform} & "
                f"{r.error_rate*100:.1f} & "
                f"{r.syntax_errors} & "
                f"{r.field_errors} & "
                f"{r.operator_errors} & "
                f"{r.logic_errors} & "
                f"{r.temporal_errors} & "
                f"{r.platform_errors} & "
                f"\\texttt{{{r.top_error}}} \\\\"
            )
            lines.append(line)
        lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
        return "\n".join(lines)

    # ─────────────────────────────────────────────
    # Convenience: build from raw evaluator outputs
    # ─────────────────────────────────────────────

    @classmethod
    def from_evaluators(
        cls,
        syntax_validator,
        semantic_scorer,
        error_analyzer,
        execution_matcher      = None,
        ablation_runner        = None,
        syntax_all_results:    dict[str, list] | None = None,
        semantic_all_results:  dict[str, list] | None = None,
        error_all_reports:     dict[str, list] | None = None,
        execution_all_results: dict[str, list] | None = None,
        ablation_results       = None,
    ) -> AggregatedResults:
        """
        Convenience class-method: build all tables directly from evaluator objects
        + pre-collected result lists.

        Args:
            syntax_validator:   SyntaxValidator instance.
            semantic_scorer:    SemanticScorer instance.
            error_analyzer:     ErrorAnalyzer instance.
            execution_matcher:  ExecutionMatcher instance (optional).
            ablation_runner:    AblationRunner instance (optional).
            *_all_results:      platform → list of result objects.
            ablation_results:   AblationResults from AblationRunner.run().

        Returns:
            AggregatedResults with all tables populated.
        """
        agg = cls()

        syntax_metrics = (
            syntax_validator.compute_all_metrics(syntax_all_results)
            if syntax_all_results else {}
        )
        semantic_metrics = {
            p: semantic_scorer.compute_metrics(results, platform=p)
            for p, results in (semantic_all_results or {}).items()
        }
        error_dists = (
            error_analyzer.compute_all_distributions(error_all_reports)
            if error_all_reports else {}
        )
        exec_metrics = {
            p: execution_matcher.compute_metrics(results, platform=p)
            for p, results in (execution_all_results or {}).items()
        } if (execution_matcher and execution_all_results) else None

        ablation_table = (
            ablation_runner.build_table(ablation_results)
            if (ablation_runner and ablation_results) else []
        )

        return agg.build_all(
            syntax_metrics      = syntax_metrics,
            semantic_metrics    = semantic_metrics,
            error_distributions = error_dists,
            execution_metrics   = exec_metrics,
            ablation_table      = ablation_table,
        )