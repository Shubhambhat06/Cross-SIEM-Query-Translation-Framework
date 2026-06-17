"""
Execution Match — Elasticsearch Docker sandbox runner for evaluation.

Measures execution-level equivalence: do hypothesis and reference queries
return the same result set when run against a live Elasticsearch instance?

Three match modes (defined in paper):
  1. exact_match    — identical hit counts + identical top-10 document IDs
  2. recall_match   — hypothesis retrieves ≥ 90% of ground-truth hits
  3. structural_match — same result *shape* (field presence, aggregation keys)

Mirrors Table 2 "Execution Match" column in the paper.

Place at: src/evaluation/execution_match.py

Usage:
    from src.evaluation.execution_match import ExecutionMatcher
    matcher = ExecutionMatcher(es_url="http://localhost:9200", index="siem-test-*")
    result  = matcher.match(
        hypothesis = 'event.category: "authentication" | stats count()',
        reference  = 'event.category: "authentication" | stats count()',
        platform   = "elastic",
    )
    print(result.exact_match, result.recall_score, result.structural_match)

Notes:
    - Requires a running Elasticsearch 8.x instance with test data loaded.
    - If ES is unavailable, all methods fall back gracefully (is_available=False).
    - For paper evaluation use Docker Compose: docker compose -f docker/es-sandbox.yml up
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

from src.utils.logger import get_logger

log = get_logger(__name__)

# Thresholds
_RECALL_THRESHOLD    = 0.90   # ≥ 90% of ground-truth hits required for recall_match
_TIMEOUT_SECONDS     = 10     # per-query ES timeout
_MAX_DOCS_COMPARED   = 1000   # cap for ID-set comparison


@dataclass
class ExecutionResult:
    """Raw result from executing one query against ES."""
    query:       str
    platform:    str
    hit_count:   int
    doc_ids:     list[str]   = field(default_factory=list)
    agg_keys:    set[str]    = field(default_factory=set)
    fields:      set[str]    = field(default_factory=set)
    error:       str         = ""
    elapsed_ms:  float       = 0.0

    @property
    def success(self) -> bool:
        return not self.error


@dataclass
class ExecutionMatchResult:
    """Execution match outcome for one hypothesis–reference pair."""
    platform:         str
    exact_match:      bool
    recall_match:     bool
    structural_match: bool
    recall_score:     float    # |hyp_ids ∩ ref_ids| / |ref_ids|
    hit_ratio:        float    # hyp_hit_count / ref_hit_count (or 0 if ref=0)
    hyp_hit_count:    int
    ref_hit_count:    int
    error:            str = ""

    @property
    def any_match(self) -> bool:
        return self.exact_match or self.recall_match or self.structural_match

    def to_dict(self) -> dict:
        return {
            "platform":         self.platform,
            "exact_match":      self.exact_match,
            "recall_match":     self.recall_match,
            "structural_match": self.structural_match,
            "recall_score":     round(self.recall_score, 4),
            "hit_ratio":        round(self.hit_ratio,    4),
            "hyp_hit_count":    self.hyp_hit_count,
            "ref_hit_count":    self.ref_hit_count,
            "error":            self.error,
        }


@dataclass
class ExecutionMetrics:
    """Aggregated execution match metrics across a dataset."""
    platform:            str
    total:               int
    exact_matches:       int
    recall_matches:      int
    structural_matches:  int
    any_matches:         int
    exact_pct:           float
    recall_pct:          float
    structural_pct:      float
    any_pct:             float
    avg_recall_score:    float
    errors:              int

    def to_dict(self) -> dict:
        return {
            "platform":           self.platform,
            "total":              self.total,
            "exact_matches":      self.exact_matches,
            "recall_matches":     self.recall_matches,
            "structural_matches": self.structural_matches,
            "any_matches":        self.any_matches,
            "exact_pct":          round(self.exact_pct,        4),
            "recall_pct":         round(self.recall_pct,       4),
            "structural_pct":     round(self.structural_pct,   4),
            "any_pct":            round(self.any_pct,          4),
            "avg_recall_score":   round(self.avg_recall_score, 4),
            "errors":             self.errors,
        }


class ExecutionMatcher:
    """
    Runs EQL/KQL queries against a live Elasticsearch sandbox and compares
    hypothesis vs reference result sets.

    Falls back to structural-only comparison when ES is unavailable.

    Args:
        es_url:  Elasticsearch base URL (default: http://localhost:9200).
        index:   Index pattern to search against (default: siem-test-*).
        api_key: Optional API key for ES auth.
        timeout: Per-query timeout in seconds.
    """

    def __init__(
        self,
        es_url:  str        = "http://localhost:9200",
        index:   str        = "siem-test-*",
        api_key: str | None = None,
        timeout: int        = _TIMEOUT_SECONDS,
    ) -> None:
        self.es_url  = es_url.rstrip("/")
        self.index   = index
        self.timeout = timeout
        self._headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            self._headers["Authorization"] = f"ApiKey {api_key}"

        self._available: bool | None = None   # lazy-checked

    # ─────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────

    @property
    def is_available(self) -> bool:
        """Check whether ES is reachable (cached after first call)."""
        if self._available is None:
            self._available = self._ping()
        return self._available

    def match(
        self,
        hypothesis: str,
        reference:  str,
        platform:   str = "elastic",
    ) -> ExecutionMatchResult:
        """
        Execute both queries and compute match metrics.

        If ES is unavailable, falls back to structural-only (no live execution).

        Args:
            hypothesis: Generated query.
            reference:  Ground-truth query.
            platform:   SIEM platform (only elastic queries are executed live).

        Returns:
            ExecutionMatchResult with match flags and scores.
        """
        if not self.is_available or platform != "elastic":
            return self._structural_only(hypothesis, reference, platform)

        hyp_result = self._execute(hypothesis, platform)
        ref_result = self._execute(reference,  platform)

        if not hyp_result.success or not ref_result.success:
            error = hyp_result.error or ref_result.error
            return ExecutionMatchResult(
                platform=platform,
                exact_match=False, recall_match=False, structural_match=False,
                recall_score=0.0, hit_ratio=0.0,
                hyp_hit_count=0, ref_hit_count=0,
                error=error,
            )

        return self._compare(hyp_result, ref_result, platform)

    def match_batch(
        self,
        hypotheses: dict[str, str],
        references: dict[str, str],
    ) -> dict[str, ExecutionMatchResult]:
        """
        Match all platforms in a translation batch.

        Args:
            hypotheses: platform → generated query.
            references: platform → ground-truth query.

        Returns:
            platform → ExecutionMatchResult.
        """
        return {
            platform: self.match(
                hypothesis = hypotheses.get(platform, ""),
                reference  = references.get(platform, ""),
                platform   = platform,
            )
            for platform in references
        }

    def match_dataset(
        self,
        results:   list[dict],
        benchmark: list[dict],
    ) -> dict[str, list[ExecutionMatchResult]]:
        """
        Match all records in a full dataset against SIEMBench ground truth.

        Args:
            results:   Generated results (from run_evaluation.py JSONL).
            benchmark: SIEMBench ground-truth records.

        Returns:
            platform → list of ExecutionMatchResult.
        """
        bench_by_id: dict[str, dict] = {}
        for rec in benchmark:
            rid = rec.get("id") or rec.get("nl_query", "")[:40]
            bench_by_id[rid] = rec

        all_results: dict[str, list[ExecutionMatchResult]] = {
            p: [] for p in ("splunk", "qradar", "elastic", "sentinel", "wazuh")
        }

        for result in results:
            rid       = result.get("id") or result.get("nl_query", "")[:40]
            bench_rec = bench_by_id.get(rid)
            if bench_rec is None:
                continue

            ground_truth = bench_rec.get("ground_truth", bench_rec.get("translations", {}))
            translations = result.get("translations", {})

            for platform in all_results:
                hyp = translations.get(platform, "")
                ref = ground_truth.get(platform, "")
                if ref:
                    all_results[platform].append(
                        self.match(hyp, ref, platform=platform)
                    )

        return all_results

    def compute_metrics(
        self,
        results: list[ExecutionMatchResult],
        platform: str = "",
    ) -> ExecutionMetrics:
        """Aggregate a list of ExecutionMatchResult into platform-level metrics."""
        if not results:
            return ExecutionMetrics(
                platform=platform, total=0,
                exact_matches=0, recall_matches=0, structural_matches=0, any_matches=0,
                exact_pct=0.0, recall_pct=0.0, structural_pct=0.0, any_pct=0.0,
                avg_recall_score=0.0, errors=0,
            )

        n                = len(results)
        exact_matches    = sum(1 for r in results if r.exact_match)
        recall_matches   = sum(1 for r in results if r.recall_match)
        structural_match = sum(1 for r in results if r.structural_match)
        any_matches      = sum(1 for r in results if r.any_match)
        errors           = sum(1 for r in results if r.error)
        avg_recall       = sum(r.recall_score for r in results) / n

        return ExecutionMetrics(
            platform           = platform or (results[0].platform if results else ""),
            total              = n,
            exact_matches      = exact_matches,
            recall_matches     = recall_matches,
            structural_matches = structural_match,
            any_matches        = any_matches,
            exact_pct          = exact_matches    / n,
            recall_pct         = recall_matches   / n,
            structural_pct     = structural_match / n,
            any_pct            = any_matches      / n,
            avg_recall_score   = avg_recall,
            errors             = errors,
        )

    # ─────────────────────────────────────────────
    # Execution
    # ─────────────────────────────────────────────

    def _execute(self, query: str, platform: str) -> ExecutionResult:
        """Run a single query against ES and return raw results."""
        t0 = time.monotonic()
        try:
            import urllib.request
            import urllib.error

            body = self._build_es_body(query)
            url  = f"{self.es_url}/{self.index}/_eql/search"

            req  = urllib.request.Request(
                url,
                data    = json.dumps(body).encode(),
                headers = self._headers,
                method  = "POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())

            elapsed = (time.monotonic() - t0) * 1000

            hits    = data.get("hits", {})
            events  = hits.get("events", [])
            total   = hits.get("total", {}).get("value", len(events))

            doc_ids = [
                str(e.get("_id", e.get("_source", {}).get("@timestamp", "")))
                for e in events[:_MAX_DOCS_COMPARED]
            ]
            fields   = set()
            agg_keys = set()

            for event in events[:10]:
                fields.update(self._flatten_keys(event.get("_source", {})))

            # EQL aggregations
            aggs = data.get("aggregations", {})
            agg_keys = set(aggs.keys())

            return ExecutionResult(
                query=query, platform=platform,
                hit_count=total, doc_ids=doc_ids,
                agg_keys=agg_keys, fields=fields,
                elapsed_ms=elapsed,
            )

        except Exception as exc:
            elapsed = (time.monotonic() - t0) * 1000
            log.debug("ES query failed", extra={"error": str(exc)})
            return ExecutionResult(
                query=query, platform=platform,
                hit_count=0, error=str(exc), elapsed_ms=elapsed,
            )

    def _build_es_body(self, query: str) -> dict:
        """Build the ES EQL search request body from a query string."""
        return {
            "query":      query,
            "size":       min(_MAX_DOCS_COMPARED, 100),
            "fetch_size": min(_MAX_DOCS_COMPARED, 100),
        }

    def _ping(self) -> bool:
        """Return True if ES is reachable."""
        try:
            import urllib.request
            req = urllib.request.Request(
                f"{self.es_url}/_cluster/health",
                headers=self._headers,
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read())
                return data.get("status") in ("green", "yellow")
        except Exception:
            return False

    # ─────────────────────────────────────────────
    # Comparison
    # ─────────────────────────────────────────────

    def _compare(
        self,
        hyp: ExecutionResult,
        ref: ExecutionResult,
        platform: str,
    ) -> ExecutionMatchResult:
        """Compare two execution results and compute match metrics."""
        # Recall: fraction of reference IDs also found in hypothesis
        ref_set  = set(ref.doc_ids)
        hyp_set  = set(hyp.doc_ids)
        overlap  = len(ref_set & hyp_set)
        recall   = overlap / len(ref_set) if ref_set else 1.0

        hit_ratio = (
            hyp.hit_count / ref.hit_count
            if ref.hit_count > 0 else (1.0 if hyp.hit_count == 0 else 0.0)
        )

        exact_match      = (hyp.hit_count == ref.hit_count) and (hyp_set == ref_set)
        recall_match     = recall >= _RECALL_THRESHOLD
        structural_match = self._structural_compare(hyp, ref)

        return ExecutionMatchResult(
            platform         = platform,
            exact_match      = exact_match,
            recall_match     = recall_match,
            structural_match = structural_match,
            recall_score     = recall,
            hit_ratio        = hit_ratio,
            hyp_hit_count    = hyp.hit_count,
            ref_hit_count    = ref.hit_count,
        )

    def _structural_compare(
        self,
        hyp: ExecutionResult,
        ref: ExecutionResult,
    ) -> bool:
        """
        True if hypothesis has same structural shape as reference:
          - Same aggregation bucket keys (if any)
          - Field coverage ≥ 80% of reference fields
        """
        # Aggregation key overlap (for aggregation queries)
        if ref.agg_keys:
            agg_overlap = len(hyp.agg_keys & ref.agg_keys) / len(ref.agg_keys)
            if agg_overlap < 0.8:
                return False

        # Field coverage
        if ref.fields:
            field_overlap = len(hyp.fields & ref.fields) / len(ref.fields)
            if field_overlap < 0.8:
                return False

        return True

    def _structural_only(
        self,
        hypothesis: str,
        reference:  str,
        platform:   str,
    ) -> ExecutionMatchResult:
        """
        Fallback when ES is unavailable: static structural comparison
        based on query text analysis (no live execution).
        """
        # Normalise both queries for comparison
        hyp_norm = self._normalise(hypothesis)
        ref_norm = self._normalise(reference)

        hyp_fields = set(re.findall(r"\b([a-z_\.]+)\s*[:=]", hyp_norm))
        ref_fields = set(re.findall(r"\b([a-z_\.]+)\s*[:=]", ref_norm))

        hyp_cmds = set(re.findall(r"[|\s]([a-z_]+)\s", hyp_norm))
        ref_cmds = set(re.findall(r"[|\s]([a-z_]+)\s", ref_norm))

        # Field coverage
        field_coverage = (
            len(hyp_fields & ref_fields) / len(ref_fields)
            if ref_fields else 1.0
        )
        cmd_coverage = (
            len(hyp_cmds & ref_cmds) / len(ref_cmds)
            if ref_cmds else 1.0
        )

        recall_score     = (field_coverage + cmd_coverage) / 2
        structural_match = field_coverage >= 0.8 and cmd_coverage >= 0.7
        recall_match     = recall_score >= _RECALL_THRESHOLD

        return ExecutionMatchResult(
            platform         = platform,
            exact_match      = (hyp_norm == ref_norm),
            recall_match     = recall_match,
            structural_match = structural_match,
            recall_score     = recall_score,
            hit_ratio        = 0.0,
            hyp_hit_count    = -1,   # sentinel: no live execution
            ref_hit_count    = -1,
            error            = "" if self.is_available else "ES unavailable — structural comparison only",
        )

    @staticmethod
    def _normalise(query: str) -> str:
        """Lowercase, collapse whitespace, strip comments."""
        q = re.sub(r"#.*$", "", query, flags=re.MULTILINE)
        q = re.sub(r"\s+", " ", q)
        return q.lower().strip()

    @staticmethod
    def _flatten_keys(d: dict, prefix: str = "") -> set[str]:
        """Recursively flatten nested dict keys into dot-notation set."""
        keys: set[str] = set()
        for k, v in d.items():
            full = f"{prefix}.{k}" if prefix else k
            keys.add(full)
            if isinstance(v, dict):
                keys.update(ExecutionMatcher._flatten_keys(v, full))
        return keys