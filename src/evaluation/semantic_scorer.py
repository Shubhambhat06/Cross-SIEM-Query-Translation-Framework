"""
Semantic Scorer — measures semantic equivalence between generated and ground-truth queries.

Four complementary metrics:
  1. BLEU-4         — n-gram precision (standard MT/code eval metric)
  2. ROUGE-L        — longest common subsequence recall
  3. Field-Match F1 — precision/recall on canonical field names extracted from queries
  4. Token-Edit Distance — normalised Levenshtein over query tokens (structural similarity)
  5. semantic_score — weighted combination of all four [0.0, 1.0]

These map directly to Table 2 in the paper (Semantic Equivalence columns).

References:
  - Papineni et al. (2002) BLEU: ACL 2002
  - Lin (2004) ROUGE: ACL Workshop
  - Levenshtein (1966) Binary codes capable of correcting deletions: SPD

Place at: src/evaluation/semantic_scorer.py

Usage:
    from src.evaluation.semantic_scorer import SemanticScorer

    scorer = SemanticScorer()

    # Score a single pair
    score = scorer.score(
        hypothesis = "index=* status=failed | stats count by src_ip | where count > 50",
        reference  = "index=* status=failed earliest=-24h | stats count as attempts by src_ip | where attempts > 50",
        platform   = "splunk",
    )
    print(score)       # rich __repr__
    print(score.bleu, score.rouge_l, score.field_f1, score.token_edit_sim, score.semantic_score)

    # Score a full 5-platform batch
    scores = scorer.score_batch(
        hypotheses = {"splunk": "...", "qradar": "...", ...},
        references = {"splunk": "...", "qradar": "...", ...},
    )

    # Aggregate across a dataset
    metrics = scorer.compute_metrics(scores["splunk"], platform="splunk")
    print(metrics.to_dict())

    # Score an entire dataset against SIEMBench ground truth
    all_scores = scorer.score_dataset(results_list, benchmark_list)
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from statistics import mean, stdev
from typing import Sequence

from src.utils.logger import get_logger

log = get_logger(__name__)


# ── Canonical field names (from field_mapping.py — all 5 platforms) ───────────
_CANONICAL_FIELDS: frozenset[str] = frozenset({
    # Network / connection
    "src_ip", "dest_ip", "src_port", "dest_port", "protocol", "direction",
    "bytes", "bytes_in", "bytes_out", "packets", "packets_in", "packets_out",
    "duration", "flow_id", "url", "uri_path", "uri_query", "http_method",
    "user_agent", "status_code", "response_time", "query_domain",
    # Authentication / identity
    "user", "username", "account", "domain", "auth_type",
    "session_id", "logon_type", "privilege",
    # Host / endpoint
    "host", "hostname", "computer", "dest", "src",
    "os", "os_version",
    # Process
    "process_name", "process_id", "parent_process", "parent_process_id",
    "command_line", "process_path", "process_hash", "integrity_level",
    # File
    "file_name", "file_path", "file_hash", "file_size", "file_extension",
    # Registry
    "registry_key", "registry_value", "registry_data",
    # DNS
    "dns_query", "dns_type", "dns_response", "dns_answer",
    # Threat / event metadata
    "event_id", "event_type", "event_category", "event_outcome", "event_action",
    "severity", "category", "action", "status", "reason", "result",
    "signature", "signature_id", "rule_name", "rule_id",
    # Time
    "timestamp", "_time", "timegenerated", "starttime", "@timestamp",
    # Aggregation outputs
    "count", "attempt_count", "event_count", "unique_targets",
    "total_bytes", "avg_bytes", "failure_count",
    # MITRE
    "mitre_technique", "mitre_tactic",
    # Platform-specific aliases (common in generated output)
    "sourceip", "destinationip", "source.ip", "destination.ip",
    "user.name", "event.outcome", "event.category", "event.action",
    "process.name", "process.pid", "process.command_line",
    "host.name", "network.direction", "network.bytes",
    "http.request.method", "http.response.status_code",
    "dns.question.name", "file.name", "file.path", "file.hash.sha256",
    "ipaddress", "computername",
})

# Canonical → per-platform aliases (used in both directions for normalisation)
_PLATFORM_FIELD_ALIASES: dict[str, dict[str, str]] = {
    "src_ip":         {"splunk": "src_ip",        "qradar": "sourceip",         "elastic": "source.ip",            "sentinel": "IpAddress",         "wazuh": "srcip"},
    "dest_ip":        {"splunk": "dest_ip",        "qradar": "destinationip",    "elastic": "destination.ip",       "sentinel": "DestinationIp",     "wazuh": "dstip"},
    "src_port":       {"splunk": "src_port",       "qradar": "sourceport",       "elastic": "source.port",          "sentinel": "SourcePort",        "wazuh": "srcport"},
    "dest_port":      {"splunk": "dest_port",      "qradar": "destinationport",  "elastic": "destination.port",     "sentinel": "DestinationPort",   "wazuh": "dstport"},
    "user":           {"splunk": "user",           "qradar": "username",         "elastic": "user.name",            "sentinel": "Account",           "wazuh": "dstuser"},
    "host":           {"splunk": "host",           "qradar": "logsourcename",    "elastic": "host.name",            "sentinel": "Computer",          "wazuh": "hostname"},
    "status":         {"splunk": "status",         "qradar": "eventdirection",   "elastic": "event.outcome",        "sentinel": "Status",            "wazuh": "status"},
    "action":         {"splunk": "action",         "qradar": "eventname",        "elastic": "event.action",         "sentinel": "Activity",          "wazuh": "action"},
    "event_id":       {"splunk": "EventCode",      "qradar": "eventid",          "elastic": "event.code",           "sentinel": "EventID",           "wazuh": "id"},
    "event_category": {"splunk": "sourcetype",     "qradar": "categoryname",     "elastic": "event.category",       "sentinel": "Category",          "wazuh": "group"},
    "process_name":   {"splunk": "process_name",   "qradar": "filename",         "elastic": "process.name",         "sentinel": "Process",           "wazuh": "program_name"},
    "process_id":     {"splunk": "process_id",     "qradar": "pid",              "elastic": "process.pid",          "sentinel": "ProcessId",         "wazuh": "pid"},
    "command_line":   {"splunk": "command_line",   "qradar": "command_line",     "elastic": "process.command_line", "sentinel": "CommandLine",       "wazuh": "command"},
    "parent_process": {"splunk": "parent_process", "qradar": "parent_process",   "elastic": "process.parent.name",  "sentinel": "ParentProcessName", "wazuh": "ppid"},
    "file_name":      {"splunk": "file_name",      "qradar": "filename",         "elastic": "file.name",            "sentinel": "FileName",          "wazuh": "file_name"},
    "file_path":      {"splunk": "file_path",      "qradar": "filepath",         "elastic": "file.path",            "sentinel": "FolderPath",        "wazuh": "file_path"},
    "file_hash":      {"splunk": "file_hash",      "qradar": "sha256hash",       "elastic": "file.hash.sha256",     "sentinel": "SHA256",            "wazuh": "md5"},
    "bytes_out":      {"splunk": "bytes_out",      "qradar": "bytes_sent",       "elastic": "source.bytes",         "sentinel": "SentBytes",         "wazuh": "bytes_out"},
    "bytes_in":       {"splunk": "bytes_in",       "qradar": "bytes_received",   "elastic": "destination.bytes",    "sentinel": "ReceivedBytes",     "wazuh": "bytes_in"},
    "protocol":       {"splunk": "protocol",       "qradar": "protocolname",     "elastic": "network.protocol",     "sentinel": "Protocol",          "wazuh": "protocol"},
    "timestamp":      {"splunk": "_time",          "qradar": "starttime",        "elastic": "@timestamp",           "sentinel": "TimeGenerated",     "wazuh": "timestamp"},
    "severity":       {"splunk": "severity",       "qradar": "severity",         "elastic": "event.severity",       "sentinel": "AlertSeverity",     "wazuh": "level"},
    "dns_query":      {"splunk": "query",          "qradar": "domainname",       "elastic": "dns.question.name",    "sentinel": "Name",              "wazuh": "dns.question.name"},
    "url":            {"splunk": "url",            "qradar": "url",              "elastic": "url.full",             "sentinel": "RequestURL",        "wazuh": "url"},
    "direction":      {"splunk": "direction",      "qradar": "flowdirection",    "elastic": "network.direction",    "sentinel": "CommunicationDirection", "wazuh": "direction"},
    "signature":      {"splunk": "signature",      "qradar": "rulename",         "elastic": "rule.name",            "sentinel": "AlertName",         "wazuh": "rule_description"},
}

# Build reverse lookup: lowercased alias → canonical name
_ALIAS_TO_CANONICAL: dict[str, str] = {}
for _canon, _aliases in _PLATFORM_FIELD_ALIASES.items():
    for _alias in _aliases.values():
        _ALIAS_TO_CANONICAL[_alias.lower()] = _canon

# Platform-specific operator / keyword sets (excluded from field extraction)
_PLATFORM_KEYWORDS: dict[str, frozenset[str]] = {
    "splunk": frozenset({
        "index", "sourcetype", "source", "host", "earliest", "latest",
        "stats", "where", "eval", "table", "sort", "head", "tail", "dedup",
        "rex", "lookup", "transaction", "timechart", "top", "rare", "fields",
        "rename", "join", "append", "union", "makeresults", "iplocation",
        "count", "sum", "avg", "min", "max", "dc", "values", "list", "by", "as",
        "and", "or", "not", "in", "like",
    }),
    "qradar": frozenset({
        "select", "from", "where", "group", "by", "having", "order",
        "limit", "last", "start", "stop", "hours", "days", "minutes",
        "count", "sum", "avg", "min", "max", "distinct", "and", "or", "not",
        "incidr", "like", "ilike", "between", "is", "null", "events", "flows",
        "dateformat", "logsourcename", "categoryname", "networkname",
    }),
    "elastic": frozenset({
        "where", "and", "or", "not", "by", "in", "like", "sequence",
        "with", "maxspan", "until", "sample", "any", "true", "false",
        "authentication", "network", "process", "file", "registry", "dns",
        "web", "head", "tail", "sort", "unique", "count", "filter",
        "from", "stats", "eval", "sort", "limit", "keep", "drop", "rename",
        "dissect", "grok", "enrich",
    }),
    "sentinel": frozenset({
        "where", "summarize", "project", "order", "sort", "top", "extend",
        "join", "union", "let", "render", "take", "limit", "count",
        "distinct", "evaluate", "parse", "make-series", "bin", "range",
        "by", "on", "asc", "desc", "and", "or", "not", "in", "has", "contains",
        "startswith", "endswith", "ago", "now", "bin", "between",
        "project-away", "project-rename", "mv-expand",
    }),
    "wazuh": frozenset({
        "rule", "description", "match", "regex", "if_sid", "same_source_ip",
        "frequency", "timeframe", "group", "mitre", "id", "level",
        "field", "name", "negate", "type",
    }),
}


# ── Score dataclass ────────────────────────────────────────────────────────────

@dataclass
class SemanticScore:
    """
    Full semantic equivalence score for one hypothesis–reference pair.

    Attributes:
        platform:         SIEM platform label.
        bleu:             BLEU-4 score [0, 1].
        rouge_l:          ROUGE-L F1 score [0, 1].
        field_f1:         Field-match F1 score [0, 1].
        field_precision:  Field-match precision [0, 1].
        field_recall:     Field-match recall [0, 1].
        token_edit_sim:   Normalised token edit-distance similarity [0, 1].
        semantic_score:   Weighted combination of all four metrics [0, 1].
        hypothesis_fields: Canonical fields extracted from hypothesis.
        reference_fields:  Canonical fields extracted from reference.
        matched_fields:    Fields present in both (for diagnostics).
        missing_fields:    Fields in reference but not hypothesis.
        extra_fields:      Fields in hypothesis but not reference.
    """

    platform:          str
    bleu:              float
    rouge_l:           float
    field_f1:          float
    field_precision:   float
    field_recall:      float
    token_edit_sim:    float
    semantic_score:    float

    # Diagnostic breakdowns
    hypothesis_fields: list[str] = field(default_factory=list)
    reference_fields:  list[str] = field(default_factory=list)
    matched_fields:    list[str] = field(default_factory=list)
    missing_fields:    list[str] = field(default_factory=list)   # in ref, not in hyp
    extra_fields:      list[str] = field(default_factory=list)   # in hyp, not in ref

    def to_dict(self) -> dict:
        return {
            "platform":          self.platform,
            "bleu":              round(self.bleu,           4),
            "rouge_l":           round(self.rouge_l,        4),
            "field_f1":          round(self.field_f1,       4),
            "field_precision":   round(self.field_precision,4),
            "field_recall":      round(self.field_recall,   4),
            "token_edit_sim":    round(self.token_edit_sim, 4),
            "semantic_score":    round(self.semantic_score, 4),
            "hypothesis_fields": self.hypothesis_fields,
            "reference_fields":  self.reference_fields,
            "matched_fields":    self.matched_fields,
            "missing_fields":    self.missing_fields,
            "extra_fields":      self.extra_fields,
        }

    def __repr__(self) -> str:
        return (
            f"SemanticScore(platform={self.platform!r}, "
            f"semantic={self.semantic_score:.3f}, "
            f"bleu={self.bleu:.3f}, rouge_l={self.rouge_l:.3f}, "
            f"field_f1={self.field_f1:.3f}, edit_sim={self.token_edit_sim:.3f})"
        )

    @property
    def grade(self) -> str:
        """Human-readable quality grade based on semantic_score."""
        s = self.semantic_score
        if s >= 0.85:  return "EXCELLENT"
        if s >= 0.70:  return "GOOD"
        if s >= 0.50:  return "PARTIAL"
        if s >= 0.25:  return "POOR"
        return "FAIL"


@dataclass
class SemanticMetrics:
    """
    Aggregated semantic metrics across a dataset for one platform.
    Directly populates Table 2 in the paper.
    """

    platform:            str
    total:               int
    avg_bleu:            float
    avg_rouge_l:         float
    avg_field_f1:        float
    avg_token_edit_sim:  float
    avg_semantic_score:  float
    std_semantic_score:  float    # standard deviation (for confidence intervals)
    pct_excellent:       float    # % scoring >= 0.85
    pct_good:            float    # % scoring >= 0.70
    pct_partial:         float    # % scoring >= 0.50

    def to_dict(self) -> dict:
        return {
            "platform":            self.platform,
            "total":               self.total,
            "avg_bleu":            round(self.avg_bleu,            4),
            "avg_rouge_l":         round(self.avg_rouge_l,         4),
            "avg_field_f1":        round(self.avg_field_f1,        4),
            "avg_token_edit_sim":  round(self.avg_token_edit_sim,  4),
            "avg_semantic_score":  round(self.avg_semantic_score,  4),
            "std_semantic_score":  round(self.std_semantic_score,  4),
            "pct_excellent":       round(self.pct_excellent,       4),
            "pct_good":            round(self.pct_good,            4),
            "pct_partial":         round(self.pct_partial,         4),
        }

    def to_latex_row(self) -> str:
        """Format as a LaTeX table row for the paper (Table 2)."""
        return (
            f"{self.platform.capitalize()} & "
            f"{self.avg_bleu:.3f} & "
            f"{self.avg_rouge_l:.3f} & "
            f"{self.avg_field_f1:.3f} & "
            f"{self.avg_token_edit_sim:.3f} & "
            f"{self.avg_semantic_score:.3f} \\\\"
        )

    def __repr__(self) -> str:
        return (
            f"SemanticMetrics(platform={self.platform!r}, n={self.total}, "
            f"semantic={self.avg_semantic_score:.3f}±{self.std_semantic_score:.3f}, "
            f"field_f1={self.avg_field_f1:.3f})"
        )


# ── Semantic Scorer ────────────────────────────────────────────────────────────

class SemanticScorer:
    """
    Computes semantic equivalence between generated and ground-truth SIEM queries.

    Metric weights (tuned for SIEM query evaluation, field coverage is most
    important because correct fields directly determine query correctness):

        Field-Match F1    :  50%   (field coverage — most critical)
        BLEU-4            :  25%   (n-gram surface form)
        ROUGE-L           :  15%   (sequence structure / recall)
        Token Edit Sim    :  10%   (structural similarity)

    Args:
        bleu_weight:         Weight for BLEU-4  (default 0.25).
        rouge_weight:        Weight for ROUGE-L (default 0.15).
        field_weight:        Weight for Field-F1 (default 0.50).
        edit_weight:         Weight for Token Edit Similarity (default 0.10).
        use_sacrebleu:       Use sacrebleu library if installed (default True).
        normalise_operators: Replace platform operators before tokenising so
                             ``count AS c`` and ``count() as c`` score equally (default True).
    """

    # ── Default metric weights ─────────────────────────────────────────────
    BLEU_WEIGHT   = 0.25
    ROUGE_WEIGHT  = 0.15
    FIELD_WEIGHT  = 0.50
    EDIT_WEIGHT   = 0.10

    def __init__(
        self,
        bleu_weight:          float = BLEU_WEIGHT,
        rouge_weight:         float = ROUGE_WEIGHT,
        field_weight:         float = FIELD_WEIGHT,
        edit_weight:          float = EDIT_WEIGHT,
        use_sacrebleu:        bool  = True,
        normalise_operators:  bool  = True,
    ) -> None:
        total = bleu_weight + rouge_weight + field_weight + edit_weight
        if not math.isclose(total, 1.0, abs_tol=1e-6):
            raise ValueError(
                f"Weights must sum to 1.0, got {total:.4f}. "
                f"(bleu={bleu_weight}, rouge={rouge_weight}, "
                f"field={field_weight}, edit={edit_weight})"
            )
        self.bleu_weight          = bleu_weight
        self.rouge_weight         = rouge_weight
        self.field_weight         = field_weight
        self.edit_weight          = edit_weight
        self.normalise_operators  = normalise_operators

        self._sacrebleu_available = False
        if use_sacrebleu:
            try:
                import sacrebleu  # noqa: F401
                self._sacrebleu_available = True
                log.debug("sacrebleu available — using library BLEU implementation")
            except ImportError:
                log.debug("sacrebleu not installed — using built-in BLEU")

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    def score(
        self,
        hypothesis: str,
        reference:  str,
        platform:   str = "",
    ) -> SemanticScore:
        """
        Compute the full semantic score for one hypothesis–reference pair.

        Args:
            hypothesis: Generated query string.
            reference:  Ground-truth query string.
            platform:   SIEM platform label (splunk / qradar / elastic / sentinel / wazuh).
                        Used for field alias resolution and operator normalisation.
                        Pass "" to use platform-agnostic defaults.

        Returns:
            SemanticScore with all four sub-metrics and the combined score.
        """
        if not reference:
            return SemanticScore(
                platform=platform,
                semantic_score=0.0,
                bleu=0.0,
                rouge_l=0.0,
                field_f1=0.0,
                field_precision=0.0,
                field_recall=0.0,
                token_edit_sim=0.0,
            )

        if not hypothesis:
            return SemanticScore(
                platform=platform, bleu=0.0, rouge_l=0.0, field_f1=0.0,
                field_precision=0.0, field_recall=0.0, token_edit_sim=0.0,
                semantic_score=0.0,
                hypothesis_fields=[], reference_fields=self._extract_canonical(reference, platform),
                missing_fields=self._extract_canonical(reference, platform),
            )

        bleu  = self.compute_bleu(hypothesis, reference, platform)
        rouge = self.compute_rouge_l(hypothesis, reference, platform)
        edit  = self.compute_token_edit_similarity(hypothesis, reference, platform)
        f1, precision, recall, hyp_fields, ref_fields, matched, missing, extra = \
            self.compute_field_match(hypothesis, reference, platform)

        combined = (
            self.bleu_weight  * bleu  +
            self.rouge_weight * rouge +
            self.field_weight * f1    +
            self.edit_weight  * edit
        )
        combined = round(min(1.0, max(0.0, combined)), 6)

        result = SemanticScore(
            platform          = platform,
            bleu              = bleu,
            rouge_l           = rouge,
            field_f1          = f1,
            field_precision   = precision,
            field_recall      = recall,
            token_edit_sim    = edit,
            semantic_score    = combined,
            hypothesis_fields = hyp_fields,
            reference_fields  = ref_fields,
            matched_fields    = matched,
            missing_fields    = missing,
            extra_fields      = extra,
        )
        log.debug(
            "Semantic score computed",
            extra={
                "platform": platform,
                "grade":    result.grade,
                "semantic": f"{combined:.3f}",
                "bleu":     f"{bleu:.3f}",
                "rouge_l":  f"{rouge:.3f}",
                "field_f1": f"{f1:.3f}",
                "edit_sim": f"{edit:.3f}",
            },
        )
        return result

    def score_batch(
        self,
        hypotheses: dict[str, str],
        references: dict[str, str],
    ) -> dict[str, SemanticScore]:
        """
        Score all platforms in a single translation batch.

        Args:
            hypotheses: platform → generated query.
            references: platform → ground-truth query.

        Returns:
            platform → SemanticScore (only platforms present in references).
        """
        scores = {}
        for platform, ref in references.items():
            hyp = hypotheses.get(platform, "")
            scores[platform] = self.score(hyp, ref, platform=platform)
        return scores

    def score_dataset(
        self,
        results:   list[dict],
        benchmark: list[dict],
    ) -> dict[str, list[SemanticScore]]:
        """
        Score all records in a results JSONL against SIEMBench ground truth.

        Aligns records by the 'id' field (falls back to first 40 chars of nl_query).

        Args:
            results:   List of dicts from run_evaluation.py output.
                       Each must have 'translations': {platform: query_str}.
            benchmark: SIEMBench records, each with either
                       'ground_truth' or 'translations': {platform: query_str}.

        Returns:
            Dict mapping platform → list[SemanticScore] (one per matched record).
        """
        platforms  = ("splunk", "qradar", "elastic", "sentinel", "wazuh")
        all_scores: dict[str, list[SemanticScore]] = {p: [] for p in platforms}

        # Build benchmark lookup
        bench_by_id: dict[str, dict] = {}
        for rec in benchmark:
            rid = rec.get("id") or rec.get("nl_query", "")[:40]
            bench_by_id[rid] = rec

        matched_count = 0
        for result in results:
            rid       = result.get("id") or result.get("nl_query", "")[:40]
            bench_rec = bench_by_id.get(rid)
            if bench_rec is None:
                log.warning("No benchmark record found", extra={"id": rid})
                continue

            matched_count += 1
            ground_truth  = bench_rec.get("ground_truth") or bench_rec.get("translations", {})
            translations  = result.get("translations", {})

            for platform in platforms:
                ref = ground_truth.get(platform, "")
                hyp = translations.get(platform, "")
                if ref:
                    all_scores[platform].append(self.score(hyp, ref, platform=platform))

        log.info(
            "Dataset scored",
            extra={
                "total_results": len(results),
                "matched":       matched_count,
                "platforms":     {p: len(all_scores[p]) for p in platforms},
            },
        )
        return all_scores

    def compute_metrics(
        self,
        scores:   list[SemanticScore],
        platform: str = "",
    ) -> SemanticMetrics:
        """
        Aggregate a list of SemanticScore objects into per-platform statistics.

        Includes standard deviation and grade-bucket percentages to directly
        populate Table 2 and Table 3 in the paper.

        Args:
            scores:   List of SemanticScore objects for one platform.
            platform: Platform label (inferred from scores[0] if omitted).

        Returns:
            SemanticMetrics with all aggregated statistics.
        """
        if not scores:
            plat = platform or ""
            return SemanticMetrics(
                platform=plat, total=0,
                avg_bleu=0.0, avg_rouge_l=0.0,
                avg_field_f1=0.0, avg_token_edit_sim=0.0,
                avg_semantic_score=0.0, std_semantic_score=0.0,
                pct_excellent=0.0, pct_good=0.0, pct_partial=0.0,
            )

        plat = platform or scores[0].platform
        n    = len(scores)

        sem_scores = [s.semantic_score for s in scores]
        std        = stdev(sem_scores) if n > 1 else 0.0

        return SemanticMetrics(
            platform            = plat,
            total               = n,
            avg_bleu            = mean(s.bleu           for s in scores),
            avg_rouge_l         = mean(s.rouge_l        for s in scores),
            avg_field_f1        = mean(s.field_f1       for s in scores),
            avg_token_edit_sim  = mean(s.token_edit_sim for s in scores),
            avg_semantic_score  = mean(sem_scores),
            std_semantic_score  = std,
            pct_excellent       = sum(1 for s in scores if s.semantic_score >= 0.85) / n,
            pct_good            = sum(1 for s in scores if s.semantic_score >= 0.70) / n,
            pct_partial         = sum(1 for s in scores if s.semantic_score >= 0.50) / n,
        )

    def compute_all_platform_metrics(
        self,
        all_scores: dict[str, list[SemanticScore]],
    ) -> dict[str, SemanticMetrics]:
        """
        Aggregate metrics across all platforms at once.

        Args:
            all_scores: Output of score_dataset().

        Returns:
            platform → SemanticMetrics for every platform.
        """
        return {
            platform: self.compute_metrics(scores, platform=platform)
            for platform, scores in all_scores.items()
        }

    def latex_table(
        self,
        metrics_by_platform: dict[str, SemanticMetrics],
        caption: str = "Semantic equivalence scores per platform (Table 2)",
        label:   str = "tab:semantic_scores",
    ) -> str:
        """
        Render a full LaTeX table from platform metrics.

        Args:
            metrics_by_platform: Output of compute_all_platform_metrics().
            caption:             Table caption.
            label:               Table label for \\ref{}.

        Returns:
            LaTeX table string, ready to paste into the paper.
        """
        platforms = ("splunk", "qradar", "elastic", "sentinel", "wazuh")
        lines     = [
            "\\begin{table}[h!]",
            "\\centering",
            "\\caption{" + caption + "}",
            "\\label{" + label + "}",
            "\\begin{tabular}{lrrrrr}",
            "\\hline",
            "Platform & BLEU-4 & ROUGE-L & Field-F1 & Token-Edit & Semantic \\\\ \\hline",
        ]
        for p in platforms:
            m = metrics_by_platform.get(p)
            if m:
                lines.append(m.to_latex_row())
        lines += [
            "\\hline",
            "\\end{tabular}",
            "\\end{table}",
        ]
        return "\n".join(lines)

    # ─────────────────────────────────────────────────────────────────────────
    # BLEU-4
    # ─────────────────────────────────────────────────────────────────────────

    def compute_bleu(
        self,
        hypothesis: str,
        reference:  str,
        platform:   str = "",
        max_n:      int = 4,
    ) -> float:
        """
        Compute BLEU-4 between hypothesis and reference.

        Uses sacrebleu if available; falls back to a pure-Python
        implementation that is correct for sentence-level evaluation.

        Args:
            hypothesis: Generated query.
            reference:  Ground-truth query.
            platform:   Used for operator normalisation.
            max_n:      Maximum n-gram order (default 4).

        Returns:
            BLEU score in [0.0, 1.0].
        """
        if not hypothesis or not reference:
            return 0.0
        if self._sacrebleu_available:
            return self._sacrebleu_score(hypothesis, reference)
        return self._builtin_bleu(hypothesis, reference, platform, max_n)

    def _sacrebleu_score(self, hypothesis: str, reference: str) -> float:
        try:
            from sacrebleu.metrics import BLEU
            bleu   = BLEU(effective_order=True)
            result = bleu.sentence_score(hypothesis, [reference])
            return min(1.0, result.score / 100.0)
        except Exception as exc:
            log.debug("sacrebleu failed, using built-in", extra={"error": str(exc)})
            return self._builtin_bleu(hypothesis, reference, "", 4)

    def _builtin_bleu(
        self,
        hypothesis: str,
        reference:  str,
        platform:   str,
        max_n:      int,
    ) -> float:
        hyp_tokens = self._tokenize(hypothesis, platform)
        ref_tokens = self._tokenize(reference,  platform)

        if not hyp_tokens or not ref_tokens:
            return 0.0

        # Brevity penalty
        bp = 1.0 if len(hyp_tokens) >= len(ref_tokens) else \
             math.exp(1 - len(ref_tokens) / len(hyp_tokens))

        log_prec = 0.0
        for n in range(1, min(max_n, len(hyp_tokens)) + 1):
            hyp_ngrams = self._get_ngrams(hyp_tokens, n)
            ref_ngrams = self._get_ngrams(ref_tokens,  n)

            clipped   = sum(min(cnt, ref_ngrams.get(ng, 0)) for ng, cnt in hyp_ngrams.items())
            total_hyp = sum(hyp_ngrams.values())

            if total_hyp == 0 or clipped == 0:
                return 0.0

            log_prec += (1.0 / max_n) * math.log(clipped / total_hyp)

        return round(min(1.0, bp * math.exp(log_prec)), 6)

    # ─────────────────────────────────────────────────────────────────────────
    # ROUGE-L
    # ─────────────────────────────────────────────────────────────────────────

    def compute_rouge_l(
        self,
        hypothesis: str,
        reference:  str,
        platform:   str = "",
    ) -> float:
        """
        Compute ROUGE-L F1 (longest common subsequence).

        Args:
            hypothesis: Generated query.
            reference:  Ground-truth query.
            platform:   Used for tokenisation.

        Returns:
            ROUGE-L F1 in [0.0, 1.0].
        """
        if not hypothesis or not reference:
            return 0.0

        hyp_tokens = self._tokenize(hypothesis, platform)
        ref_tokens = self._tokenize(reference,  platform)

        if not hyp_tokens or not ref_tokens:
            return 0.0

        lcs_len   = self._lcs_length(hyp_tokens, ref_tokens)
        precision = lcs_len / len(hyp_tokens)
        recall    = lcs_len / len(ref_tokens)

        denom = precision + recall
        return round((2 * precision * recall / denom) if denom > 0 else 0.0, 6)

    # ─────────────────────────────────────────────────────────────────────────
    # Token-level Edit Distance Similarity
    # ─────────────────────────────────────────────────────────────────────────

    def compute_token_edit_similarity(
        self,
        hypothesis: str,
        reference:  str,
        platform:   str = "",
    ) -> float:
        """
        Compute normalised token-level edit-distance similarity.

        Levenshtein distance at the token level, normalised to [0, 1]:
            similarity = 1 - (edit_distance / max(len(hyp), len(ref)))

        This captures structural differences that BLEU misses (e.g. a query
        with the correct fields but wrong clause order).

        Args:
            hypothesis: Generated query.
            reference:  Ground-truth query.
            platform:   Used for tokenisation.

        Returns:
            Similarity score in [0.0, 1.0].
        """
        if not hypothesis or not reference:
            return 0.0

        hyp_tokens = self._tokenize(hypothesis, platform)
        ref_tokens = self._tokenize(reference,  platform)

        if not hyp_tokens and not ref_tokens:
            return 1.0

        dist = self._token_edit_distance(hyp_tokens, ref_tokens)
        max_len = max(len(hyp_tokens), len(ref_tokens))
        return round(max(0.0, 1.0 - dist / max_len), 6)

    # ─────────────────────────────────────────────────────────────────────────
    # Field-Match F1
    # ─────────────────────────────────────────────────────────────────────────

    def compute_field_match(
        self,
        hypothesis: str,
        reference:  str,
        platform:   str = "",
    ) -> tuple[float, float, float, list[str], list[str], list[str], list[str], list[str]]:
        """
        Compute field-match precision, recall, and F1.

        Extracts canonical SIEM field names from both strings, normalises
        platform-specific aliases, then computes set overlap.

        Args:
            hypothesis: Generated query.
            reference:  Ground-truth query.
            platform:   SIEM platform (for alias resolution).

        Returns:
            Tuple of:
              (f1, precision, recall,
               hyp_fields, ref_fields,
               matched_fields, missing_fields, extra_fields)
        """
        hyp_canonical = set(self._extract_canonical(hypothesis, platform))
        ref_canonical = set(self._extract_canonical(reference,  platform))

        hyp_fields = sorted(hyp_canonical)
        ref_fields = sorted(ref_canonical)

        if not ref_canonical:
            # No fields in reference → cannot penalise hypothesis
            return (1.0, 1.0, 1.0, hyp_fields, ref_fields, hyp_fields, [], [])

        matched = sorted(hyp_canonical & ref_canonical)
        missing = sorted(ref_canonical - hyp_canonical)
        extra   = sorted(hyp_canonical - ref_canonical)

        tp        = len(matched)
        precision = tp / len(hyp_canonical) if hyp_canonical else 0.0
        recall    = tp / len(ref_canonical)
        denom     = precision + recall
        f1        = (2 * precision * recall / denom) if denom > 0 else 0.0

        return (
            round(f1, 6), round(precision, 6), round(recall, 6),
            hyp_fields, ref_fields, matched, missing, extra,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Field extraction
    # ─────────────────────────────────────────────────────────────────────────

    def _extract_canonical(self, query: str, platform: str) -> list[str]:
        """
        Extract and normalise SIEM field names from a query string.

        Steps:
        1. Extract candidates — known canonical fields, dot-notation fields,
           platform-specific aliases, XML attributes (Wazuh).
        2. Filter out stop-words and query keywords for the platform.
        3. Map aliases to canonical names via _ALIAS_TO_CANONICAL.
        4. Deduplicate while preserving order.

        Args:
            query:    Query string to extract from.
            platform: SIEM platform label (for keyword exclusion).

        Returns:
            Sorted list of unique canonical field name strings.
        """
        if not query:
            return []

        ql       = query.lower()
        found    = set()
        keywords = _PLATFORM_KEYWORDS.get(platform, frozenset())

        # ── 1a. Exact match against canonical set ──────────────────────────
        for cf in _CANONICAL_FIELDS:
            if re.search(r'\b' + re.escape(cf.lower()) + r'\b', ql):
                found.add(cf.lower())

        # ── 1b. Dot-notation fields (source.ip, user.name, etc.) ──────────
        for match in re.finditer(r'\b([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)+)\b', ql):
            candidate = match.group(1)
            if candidate not in keywords:
                found.add(candidate)

        # ── 1c. Splunk: fields before | that look like field=value ────────
        if platform == "splunk":
            for match in re.finditer(r'\b([a-z_][a-z0-9_]*)=', ql):
                candidate = match.group(1)
                if candidate not in keywords and len(candidate) > 1:
                    found.add(candidate)

        # ── 1d. QRadar: SELECT field list ─────────────────────────────────
        if platform == "qradar":
            sel_match = re.search(r'select\s+(.+?)\s+from', ql, re.DOTALL)
            if sel_match:
                for tok in re.split(r'[\s,]+', sel_match.group(1)):
                    tok = re.sub(r'\(.*\)', '', tok).strip()
                    if tok and tok not in keywords and len(tok) > 1:
                        found.add(tok)

        # ── 1e. Wazuh: field name="..." attributes ─────────────────────────
        if platform == "wazuh":
            for match in re.finditer(r'name="([^"]+)"', query):
                found.add(match.group(1).lower())

        # ── 2. Resolve aliases → canonical ────────────────────────────────
        canonical = set()
        for f in found:
            canonical.add(_ALIAS_TO_CANONICAL.get(f, f))

        # ── 3. Strip pure query keywords ──────────────────────────────────
        canonical = {f for f in canonical if f not in keywords and len(f) > 1}

        return sorted(canonical)

    # ─────────────────────────────────────────────────────────────────────────
    # Tokenisation
    # ─────────────────────────────────────────────────────────────────────────

    # Operator normalisation patterns:
    # Equalise things like  "count AS c" ↔ "count() as c"  for BLEU/ROUGE
    _OP_NORM: list[tuple[re.Pattern, str]] = [
        (re.compile(r'\bcount\s*\(\s*\*?\s*\)', re.I), "COUNT"),
        (re.compile(r'\bcount\s*\(\s*distinct\b', re.I), "COUNT_DISTINCT"),
        (re.compile(r'\bsum\s*\(', re.I),   "SUM("),
        (re.compile(r'\bavg\s*\(', re.I),   "AVG("),
        (re.compile(r'\bmin\s*\(', re.I),   "MIN("),
        (re.compile(r'\bmax\s*\(', re.I),   "MAX("),
        (re.compile(r'\bas\b', re.I),       "AS"),
        (re.compile(r'\bby\b', re.I),       "BY"),
        (re.compile(r'>='),                  "GTE"),
        (re.compile(r'<='),                  "LTE"),
        (re.compile(r'!='),                  "NEQ"),
        (re.compile(r'=='),                  "EQ"),
    ]

    def _tokenize(self, text: str, platform: str = "") -> list[str]:
        """
        Tokenise a query for n-gram / edit-distance computation.

        - Lowercases
        - Optionally normalises common operators for cross-platform fairness
        - Splits on whitespace and structural punctuation
        - Filters single-char noise tokens except meaningful operators

        Args:
            text:     Query string.
            platform: Platform label (unused here; reserved for future use).

        Returns:
            List of lowercase string tokens.
        """
        if not text:
            return []

        t = text

        if self.normalise_operators:
            for pattern, replacement in self._OP_NORM:
                t = pattern.sub(replacement, t)

        # Space out operators so they become separate tokens
        t = re.sub(r'([|=><!()\[\]{},;])', r' \1 ', t)
        t = t.lower()

        tokens = [tok for tok in t.split() if len(tok) > 0]
        return tokens

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _get_ngrams(tokens: list[str], n: int) -> Counter:
        """Return Counter of n-grams from a token list."""
        return Counter(
            tuple(tokens[i: i + n])
            for i in range(len(tokens) - n + 1)
        )

    @staticmethod
    def _lcs_length(a: Sequence, b: Sequence) -> int:
        """
        Compute LCS length using DP with O(min(m, n)) space.

        Ensures the shorter sequence is used as the column dimension
        to keep memory proportional to the shorter input.
        """
        m, n = len(a), len(b)
        if m > n:
            a, b = b, a
            m, n = n, m

        prev = [0] * (m + 1)
        for j in range(1, n + 1):
            curr = [0] * (m + 1)
            for i in range(1, m + 1):
                if a[i - 1] == b[j - 1]:
                    curr[i] = prev[i - 1] + 1
                else:
                    curr[i] = max(curr[i - 1], prev[i])
            prev = curr
        return prev[m]

    @staticmethod
    def _token_edit_distance(a: list[str], b: list[str]) -> int:
        """
        Compute token-level Levenshtein edit distance.

        Uses full DP matrix; inputs are expected to be short
        (tokenised SIEM queries, typically < 200 tokens).

        Args:
            a: Hypothesis token list.
            b: Reference token list.

        Returns:
            Minimum edit distance (insertions + deletions + substitutions).
        """
        m, n = len(a), len(b)
        # O(n) space optimised DP
        if m > n:
            a, b = b, a
            m, n = n, m

        prev = list(range(m + 1))
        for j in range(1, n + 1):
            curr = [j] + [0] * m
            for i in range(1, m + 1):
                if a[i - 1] == b[j - 1]:
                    curr[i] = prev[i - 1]
                else:
                    curr[i] = 1 + min(curr[i - 1], prev[i], prev[i - 1])
            prev = curr
        return prev[m]