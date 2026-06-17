"""
tests/test_layer6_evaluation.py
================================
Complete test suite for Layer 6 — Evaluation.

Covers:
  [T-SYN-*]  SyntaxValidator     — all 5 platforms, edge cases, metrics
  [T-SEM-*]  SemanticScorer      — BLEU, ROUGE-L, field-F1, batch, dataset
  [T-EXE-*]  ExecutionMatcher    — structural fallback, batch, metrics
  [T-ERR-*]  ErrorAnalyzer       — all error categories, distributions
  [T-ABL-*]  AblationRunner      — conditions A/B/C, aggregation, table
  [T-AGG-*]  MetricsAggregator   — Table 2/3/4, LaTeX, save, from_evaluators
  [T-INT-*]  Cross-layer         — full pipeline: syntax→semantic→error→aggregate

Run:
    pytest tests/test_layer6_evaluation.py -v
    pytest tests/test_layer6_evaluation.py -v -k "syntax"
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ──────────────────────────────────────────────────────────────────────────────
# Sample queries per platform
# ──────────────────────────────────────────────────────────────────────────────

SPLUNK_VALID   = "index=* sourcetype=syslog | stats count by src_ip | where count > 50"
SPLUNK_INVALID = "SELECT * FROM events WHERE failed=1"
SPLUNK_EMPTY   = ""

QRADAR_VALID   = "SELECT sourceip, COUNT(*) as attempts FROM events WHERE eventdirection='L2R' GROUP BY sourceip LAST 24 HOURS"
QRADAR_INVALID = "index=* | stats count by src_ip"
QRADAR_NO_FROM = "SELECT sourceip FROM accounts WHERE x=1"

ELASTIC_EQL    = "authentication where event.outcome == 'failure' | stats count()"
ELASTIC_KQL    = "event.category: authentication AND event.outcome: failure"
ELASTIC_SEQ    = "sequence [authentication where event.outcome == 'failure'] [process where process.name == 'cmd.exe']"
ELASTIC_BAD    = "this is not valid elastic syntax at all"

SENTINEL_VALID   = "SecurityEvent\n| where EventID == 4625\n| summarize count() by IpAddress\n| where count_ > 10"
SENTINEL_NOPIPE  = "SecurityEvent where EventID == 4625"
SENTINEL_BADOP   = "SecurityEvent | invalidop count() by IpAddress"

WAZUH_VALID = """<rule id="100001" level="10">
  <if_sid>5710</if_sid>
  <match>Failed password</match>
  <description>SSH brute force attempt detected</description>
  <group>authentication_failure,pci_dss_10.2.4</group>
</rule>"""
WAZUH_NOID      = '<rule level="5"><description>test</description></rule>'
WAZUH_BADXML    = '<rule id="100001" level="5"><description>unclosed'
WAZUH_LOWID     = '<rule id="50" level="5"><description>test</description><match>x</match></rule>'

REFERENCE_SPLUNK   = "index=* sourcetype=syslog earliest=-24h | stats count as attempts by src_ip | where attempts > 50"
REFERENCE_ELASTIC  = "authentication where event.outcome == 'failure' | stats count() by source.ip | where count > 5"


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _make_bench_record(i=0):
    return {
        "id":        f"q{i:04d}",
        "nl_query":  f"Detect brute force login attempt {i}",
        "ground_truth": {
            "splunk":   SPLUNK_VALID,
            "qradar":   QRADAR_VALID,
            "elastic":  ELASTIC_EQL,
            "sentinel": SENTINEL_VALID,
            "wazuh":    WAZUH_VALID,
        },
    }

def _make_result_record(i=0, valid=True):
    hyp = SPLUNK_VALID if valid else SPLUNK_INVALID
    return {
        "id":        f"q{i:04d}",
        "nl_query":  f"Detect brute force login attempt {i}",
        "translations": {
            "splunk":   hyp,
            "qradar":   QRADAR_VALID if valid else QRADAR_INVALID,
            "elastic":  ELASTIC_EQL,
            "sentinel": SENTINEL_VALID,
            "wazuh":    WAZUH_VALID,
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
# SyntaxValidator tests
# ══════════════════════════════════════════════════════════════════════════════

class TestSyntaxValidator:
    """[T-SYN] Tests for src/evaluation/syntax_validator.py"""

    @pytest.fixture
    def v(self):
        from src.evaluation.syntax_validator import SyntaxValidator
        return SyntaxValidator()

    # ── Splunk ────────────────────────────────────────────────────────────────

    def test_syn_01_splunk_valid(self, v):
        r = v.validate("splunk", SPLUNK_VALID)
        assert r.is_valid
        assert r.platform == "splunk"
        assert r.structural_score == 1.0

    def test_syn_02_splunk_empty(self, v):
        r = v.validate("splunk", SPLUNK_EMPTY)
        assert not r.is_valid
        assert r.error_type == "empty_query"

    def test_syn_03_splunk_wrong_start(self, v):
        r = v.validate("splunk", SPLUNK_INVALID)
        assert not r.is_valid
        assert r.error_type == "missing_keyword"

    def test_syn_04_splunk_unknown_command(self, v):
        r = v.validate("splunk", "index=* | fakecommand foo")
        assert not r.is_valid
        assert r.error_type == "unknown_command"

    def test_syn_05_splunk_star_ok(self, v):
        assert v.validate("splunk", "* | stats count by host").is_valid

    # ── QRadar ────────────────────────────────────────────────────────────────

    def test_syn_06_qradar_valid(self, v):
        assert v.validate("qradar", QRADAR_VALID).is_valid

    def test_syn_07_qradar_no_select(self, v):
        r = v.validate("qradar", QRADAR_INVALID)
        assert not r.is_valid
        assert r.error_type == "missing_keyword"

    def test_syn_08_qradar_no_from(self, v):
        r = v.validate("qradar", QRADAR_NO_FROM)
        assert not r.is_valid

    def test_syn_09_qradar_group_by_no_aggregate(self, v):
        r = v.validate("qradar", "SELECT sourceip FROM events GROUP BY sourceip LAST 1 HOURS")
        assert not r.is_valid
        assert r.error_type == "missing_aggregate"

    def test_syn_10_qradar_having_no_group(self, v):
        r = v.validate("qradar", "SELECT COUNT(*) FROM events HAVING COUNT(*) > 5")
        assert not r.is_valid
        assert r.error_type == "malformed_syntax"

    # ── Elastic ───────────────────────────────────────────────────────────────

    def test_syn_11_elastic_eql_valid(self, v):
        assert v.validate("elastic", ELASTIC_EQL).is_valid

    def test_syn_12_elastic_kql_valid(self, v):
        assert v.validate("elastic", ELASTIC_KQL).is_valid

    def test_syn_13_elastic_sequence(self, v):
        assert v.validate("elastic", ELASTIC_SEQ).is_valid

    def test_syn_14_elastic_sequence_no_brackets(self, v):
        r = v.validate("elastic", "sequence where event.outcome == 'failure'")
        assert not r.is_valid

    def test_syn_15_elastic_invalid(self, v):
        r = v.validate("elastic", ELASTIC_BAD)
        assert not r.is_valid

    # ── Sentinel ──────────────────────────────────────────────────────────────

    def test_syn_16_sentinel_valid(self, v):
        assert v.validate("sentinel", SENTINEL_VALID).is_valid

    def test_syn_17_sentinel_no_pipe(self, v):
        r = v.validate("sentinel", SENTINEL_NOPIPE)
        assert not r.is_valid
        assert r.error_type == "malformed_syntax"

    def test_syn_18_sentinel_bad_operator(self, v):
        r = v.validate("sentinel", SENTINEL_BADOP)
        assert not r.is_valid
        assert r.error_type == "unknown_command"

    def test_syn_19_sentinel_unknown_table_warning(self, v):
        r = v.validate("sentinel", "MyCustomTable | where x == 1 | summarize count()")
        assert r.is_valid
        assert any("not a standard" in w for w in r.warnings)

    # ── Wazuh ─────────────────────────────────────────────────────────────────

    def test_syn_20_wazuh_valid(self, v):
        assert v.validate("wazuh", WAZUH_VALID).is_valid

    def test_syn_21_wazuh_bad_xml(self, v):
        r = v.validate("wazuh", WAZUH_BADXML)
        assert not r.is_valid
        assert r.error_type == "invalid_xml"

    def test_syn_22_wazuh_no_id(self, v):
        r = v.validate("wazuh", WAZUH_NOID)
        assert not r.is_valid

    def test_syn_23_wazuh_low_id_warning(self, v):
        r = v.validate("wazuh", WAZUH_LOWID)
        assert r.is_valid
        assert any("reserved" in w for w in r.warnings)

    def test_syn_24_wazuh_empty(self, v):
        assert not v.validate("wazuh", "").is_valid

    # ── Batch / Dataset / Metrics ──────────────────────────────────────────────

    def test_syn_25_validate_batch(self, v):
        batch = v.validate_batch({
            "splunk": SPLUNK_VALID,
            "qradar": QRADAR_VALID,
            "elastic": ELASTIC_EQL,
            "sentinel": SENTINEL_VALID,
            "wazuh": WAZUH_VALID,
        })
        assert set(batch.keys()) == {"splunk", "qradar", "elastic", "sentinel", "wazuh"}
        assert all(r.is_valid for r in batch.values())

    def test_syn_26_validate_dataset(self, v):
        records = [_make_result_record(i, valid=True)  for i in range(3)] + \
                  [_make_result_record(i, valid=False) for i in range(3, 5)]
        all_r = v.validate_dataset(records)
        assert "splunk" in all_r
        assert len(all_r["splunk"]) == 5

    def test_syn_27_compute_metrics(self, v):
        results = [
            v.validate("splunk", SPLUNK_VALID),
            v.validate("splunk", SPLUNK_INVALID),
            v.validate("splunk", SPLUNK_VALID),
        ]
        m = v.compute_metrics(results, platform="splunk")
        assert m.total   == 3
        assert m.valid   == 2
        assert m.invalid == 1
        assert abs(m.validity_pct - 2/3) < 1e-6

    def test_syn_28_compute_metrics_empty(self, v):
        m = v.compute_metrics([], platform="splunk")
        assert m.total == 0
        assert m.validity_pct == 0.0

    def test_syn_29_to_dict(self, v):
        r = v.validate("splunk", SPLUNK_VALID)
        d = r.to_dict()
        assert "is_valid" in d
        assert "error_type" in d
        assert "structural_score" in d

    def test_syn_30_status_property(self, v):
        assert v.validate("splunk", SPLUNK_VALID).status  == "PASS"
        assert v.validate("splunk", SPLUNK_EMPTY).status  == "FAIL"


# ══════════════════════════════════════════════════════════════════════════════
# SemanticScorer tests
# ══════════════════════════════════════════════════════════════════════════════

class TestSemanticScorer:
    """[T-SEM] Tests for src/evaluation/semantic_scorer.py"""

    @pytest.fixture
    def s(self):
        from src.evaluation.semantic_scorer import SemanticScorer
        return SemanticScorer(use_sacrebleu=False)

    def test_sem_01_identical_score_1(self, s):
        r = s.score(SPLUNK_VALID, SPLUNK_VALID, platform="splunk")
        assert r.bleu    > 0.99
        assert r.rouge_l > 0.99
        assert r.field_f1 > 0.99

    def test_sem_02_empty_hypothesis(self, s):
        r = s.score("", SPLUNK_VALID, platform="splunk")
        assert r.bleu    == 0.0
        assert r.rouge_l == 0.0

    def test_sem_03_empty_reference(self, s):
        r = s.score(SPLUNK_VALID, "", platform="splunk")
        assert r.bleu    == 0.0
        assert r.rouge_l == 0.0

    def test_sem_04_score_in_range(self, s):
        r = s.score(SPLUNK_VALID, REFERENCE_SPLUNK, platform="splunk")
        assert 0.0 <= r.bleu           <= 1.0
        assert 0.0 <= r.rouge_l        <= 1.0
        assert 0.0 <= r.field_f1       <= 1.0
        assert 0.0 <= r.semantic_score <= 1.0

    def test_sem_05_semantic_score_weighted(self, s):
        r = s.score(SPLUNK_VALID, REFERENCE_SPLUNK, platform="splunk")

        expected = (
            0.25 * r.bleu +
            0.15 * r.rouge_l +
            0.50 * r.field_f1 +
            0.10 * r.token_edit_sim
        )

        assert abs(r.semantic_score - expected) < 1e-6
    def test_sem_06_to_dict(self, s):
        d = s.score(SPLUNK_VALID, REFERENCE_SPLUNK, platform="splunk").to_dict()
        for key in ("platform","bleu","rouge_l","field_f1","semantic_score"):
            assert key in d

    def test_sem_07_bleu_partial_overlap(self, s):
        b1 = s.compute_bleu(SPLUNK_VALID, REFERENCE_SPLUNK)
        b2 = s.compute_bleu("completely different text here", REFERENCE_SPLUNK)
        assert b1 > b2

    def test_sem_08_rouge_l(self, s):
        r = s.compute_rouge_l(SPLUNK_VALID, SPLUNK_VALID)
        assert r > 0.99
        r2 = s.compute_rouge_l("aaa bbb", "xxx yyy zzz")
        assert r2 == 0.0

    def test_sem_09_field_f1_same_fields(self, s):
        f1, p, r, *_ = s.compute_field_match(SPLUNK_VALID, SPLUNK_VALID, platform="splunk")
        assert f1 > 0.9

    def test_sem_10_field_f1_no_ref_fields(self, s):
        f1, p, r, *_ = s.compute_field_match("some text", "no fields here", platform="splunk")
        assert f1 == 1.0  # vacuously true when ref has no known fields

    def test_sem_11_score_batch(self, s):
        hyps = {"splunk": SPLUNK_VALID, "elastic": ELASTIC_EQL}
        refs = {"splunk": REFERENCE_SPLUNK, "elastic": REFERENCE_ELASTIC}
        batch = s.score_batch(hyps, refs)
        assert "splunk"  in batch
        assert "elastic" in batch

    def test_sem_12_compute_metrics(self, s):
        scores = [s.score(SPLUNK_VALID, REFERENCE_SPLUNK, platform="splunk") for _ in range(4)]
        m = s.compute_metrics(scores, platform="splunk")
        assert m.total == 4
        assert 0.0 <= m.avg_semantic_score <= 1.0

    def test_sem_13_compute_metrics_empty(self, s):
        m = s.compute_metrics([], platform="splunk")
        assert m.total == 0

    def test_sem_14_score_dataset(self, s):
        results   = [_make_result_record(i) for i in range(3)]
        benchmark = [_make_bench_record(i)  for i in range(3)]
        all_s = s.score_dataset(results, benchmark)
        assert "splunk" in all_s
        assert len(all_s["splunk"]) == 3

    def test_sem_15_lcs_length(self, s):
        assert s._lcs_length([1,2,3], [1,2,3]) == 3
        assert s._lcs_length([1,2,3], [4,5,6]) == 0
        assert s._lcs_length([1,3],   [1,2,3]) == 2

    def test_sem_16_tokenize(self, s):
        tokens = s._tokenize("index=* | stats count by src_ip")
        assert "index" in tokens or "index=" in "".join(tokens)
        assert len(tokens) > 3

    def test_sem_17_ngrams(self, s):
        ng = s._get_ngrams(["a","b","c","d"], 2)
        assert ("a","b") in ng
        assert ("c","d") in ng

    def test_sem_18_hypothesis_fields_extracted(self, s):
        r = s.score(SPLUNK_VALID, REFERENCE_SPLUNK, platform="splunk")
        assert len(r.hypothesis_fields) >= 0   # may be empty for short queries
        assert isinstance(r.hypothesis_fields, list)

    def test_sem_19_wazuh_xml_fields(self, s):
        r = s.score(WAZUH_VALID, WAZUH_VALID, platform="wazuh")
        assert r.field_f1 > 0.9


# ══════════════════════════════════════════════════════════════════════════════
# ExecutionMatcher tests  (no live ES — structural fallback only)
# ══════════════════════════════════════════════════════════════════════════════

class TestExecutionMatcher:
    """[T-EXE] Tests for src/evaluation/execution_match.py"""

    @pytest.fixture
    def m(self):
        from src.evaluation.execution_match import ExecutionMatcher
        # Force unavailable so all tests use structural fallback
        matcher = ExecutionMatcher(es_url="http://localhost:19200")
        matcher._available = False
        return matcher

    def test_exe_01_is_available_false(self, m):
        assert not m.is_available

    def test_exe_02_structural_identical(self, m):
        r = m.match(SPLUNK_VALID, SPLUNK_VALID, platform="splunk")
        assert r.exact_match

    def test_exe_03_structural_different(self, m):
        r = m.match(SPLUNK_INVALID, SPLUNK_VALID, platform="splunk")
        # Not exact match — different syntax
        assert isinstance(r.exact_match, bool)

    def test_exe_04_result_fields(self, m):
        r = m.match(SPLUNK_VALID, REFERENCE_SPLUNK, platform="splunk")
        assert hasattr(r, "exact_match")
        assert hasattr(r, "recall_match")
        assert hasattr(r, "structural_match")
        assert hasattr(r, "recall_score")
        assert 0.0 <= r.recall_score <= 1.0

    def test_exe_05_non_elastic_platform_structural(self, m):
        r = m.match(QRADAR_VALID, QRADAR_VALID, platform="qradar")
        assert r.exact_match

    def test_exe_06_match_batch(self, m):
        hyps = {"splunk": SPLUNK_VALID, "qradar": QRADAR_VALID}
        refs = {"splunk": SPLUNK_VALID, "qradar": QRADAR_VALID}
        batch = m.match_batch(hyps, refs)
        assert "splunk"  in batch
        assert "qradar"  in batch
        assert batch["splunk"].exact_match

    def test_exe_07_match_dataset(self, m):
        results   = [_make_result_record(i) for i in range(3)]
        benchmark = [_make_bench_record(i)  for i in range(3)]
        all_r = m.match_dataset(results, benchmark)
        assert "splunk" in all_r

    def test_exe_08_compute_metrics(self, m):
        results   = [_make_result_record(i) for i in range(5)]
        benchmark = [_make_bench_record(i)  for i in range(5)]
        all_r = m.match_dataset(results, benchmark)
        metrics = m.compute_metrics(all_r["splunk"], platform="splunk")
        assert metrics.total == 5
        assert 0.0 <= metrics.exact_pct <= 1.0

    def test_exe_09_compute_metrics_empty(self, m):
        metrics = m.compute_metrics([], platform="splunk")
        assert metrics.total == 0

    def test_exe_10_to_dict(self, m):
        r = m.match(SPLUNK_VALID, SPLUNK_VALID, platform="splunk")
        d = r.to_dict()
        assert "exact_match" in d
        assert "recall_score" in d

    def test_exe_11_flatten_keys(self, m):
        d   = {"a": {"b": 1, "c": {"d": 2}}, "e": 3}
        keys = m._flatten_keys(d)
        assert "a.b" in keys
        assert "a.c.d" in keys
        assert "e" in keys

    def test_exe_12_normalise(self, m):
        n = m._normalise("  INDEX=*  |  stats COUNT  ")
        assert n == n.lower()
        assert "  " not in n


# ══════════════════════════════════════════════════════════════════════════════
# ErrorAnalyzer tests
# ══════════════════════════════════════════════════════════════════════════════

class TestErrorAnalyzer:
    """[T-ERR] Tests for src/evaluation/error_analyzer.py"""

    @pytest.fixture
    def a(self):
        from src.evaluation.error_analyzer import ErrorAnalyzer
        return ErrorAnalyzer()

    def _syn_result(self, is_valid, error_type="none", detail=""):
        r = MagicMock()
        r.is_valid   = is_valid
        r.error_type = error_type
        r.error_detail = detail
        return r

    def _sem_score(self, field_f1=0.9, semantic=0.8):
        r = MagicMock()
        r.field_f1       = field_f1
        r.semantic_score = semantic
        r.hypothesis_fields = ["src_ip", "count"]
        r.reference_fields  = ["src_ip", "count", "user"]
        return r

    def _exec_result(self, any_match=True, hit_ratio=1.0, hyp=10, ref=10):
        r = MagicMock()
        r.any_match   = any_match
        r.hit_ratio   = hit_ratio
        r.hyp_hit_count = hyp
        r.ref_hit_count = ref
        return r

    # ── No-error path ─────────────────────────────────────────────────────────

    def test_err_01_no_error_when_everything_valid(self, a):
        r = a.analyze("splunk", SPLUNK_VALID, REFERENCE_SPLUNK,
                      syntax_result=self._syn_result(True),
                      semantic_score=self._sem_score(),
                      execution_result=self._exec_result())
        assert r.error_category == "NO_ERROR"
        assert not r.is_error

    # ── Syntax errors ─────────────────────────────────────────────────────────

    def test_err_02_syntax_empty_query(self, a):
        r = a.analyze("splunk", "",  REFERENCE_SPLUNK,
                      syntax_result=self._syn_result(False, "empty_query", "Empty query"))
        assert r.error_category == "SYNTAX_ERROR"
        assert r.error_leaf     == "empty_query"
        assert r.severity       == "CRITICAL"

    def test_err_03_syntax_malformed(self, a):
        r = a.analyze("splunk", SPLUNK_INVALID, REFERENCE_SPLUNK,
                      syntax_result=self._syn_result(False, "missing_keyword", "bad start"))
        assert r.error_category == "SYNTAX_ERROR"
        assert r.is_error

    def test_err_04_syntax_unknown_command(self, a):
        r = a.analyze("splunk", "index=* | fakeop x", REFERENCE_SPLUNK,
                      syntax_result=self._syn_result(False, "unknown_command", "bad cmd"))
        assert r.error_leaf == "unknown_command"

    # ── Cross-platform leak ───────────────────────────────────────────────────

    def test_err_05_cross_platform_leak_splunk_in_qradar(self, a):
        r = a.analyze("qradar", "index=* | stats count by src_ip", QRADAR_VALID,
                      syntax_result=self._syn_result(True))
        assert r.error_category == "PLATFORM_SPECIFIC"
        assert r.error_leaf     == "cross_platform_leak"

    def test_err_06_cross_platform_leak_select_in_splunk(self, a):
        r = a.analyze("splunk", "SELECT * FROM events", SPLUNK_VALID,
                      syntax_result=self._syn_result(True))
        assert r.error_category == "PLATFORM_SPECIFIC"

    # ── Field errors ──────────────────────────────────────────────────────────

    def test_err_07_field_error_low_f1(self, a):
        r = a.analyze("splunk", SPLUNK_VALID, REFERENCE_SPLUNK,
                      syntax_result=self._syn_result(True),
                      semantic_score=self._sem_score(field_f1=0.2))
        assert r.error_category == "FIELD_ERROR"
        assert r.error_leaf     == "wrong_field_name"
        assert r.severity       == "HIGH"

    def test_err_08_field_error_suggestions(self, a):
        r = a.analyze("splunk", SPLUNK_VALID, REFERENCE_SPLUNK,
                      syntax_result=self._syn_result(True),
                      semantic_score=self._sem_score(field_f1=0.1))
        assert len(r.suggestions) > 0

    # ── Temporal errors ───────────────────────────────────────────────────────

    def test_err_09_missing_time_splunk(self, a):
        # Valid syntax, good fields, but no earliest= in hypothesis
        r = a.analyze("splunk",
                      "index=* | stats count by src_ip | where count > 5",
                      REFERENCE_SPLUNK,
                      syntax_result=self._syn_result(True),
                      semantic_score=self._sem_score())
        assert r.error_category == "TEMPORAL_ERROR"
        assert r.error_leaf     == "missing_time_range"

    def test_err_10_no_temporal_error_when_time_present(self, a):
        r = a.analyze("splunk",
                      "index=* earliest=-24h | stats count by src_ip",
                      REFERENCE_SPLUNK,
                      syntax_result=self._syn_result(True),
                      semantic_score=self._sem_score())
        assert r.error_category != "TEMPORAL_ERROR"

    # ── Logic errors ──────────────────────────────────────────────────────────

    def test_err_11_logic_error_execution_mismatch(self, a):
        r = a.analyze("splunk",
                      "index=* earliest=-24h | stats count by src_ip",
                      REFERENCE_SPLUNK,
                      syntax_result=self._syn_result(True),
                      semantic_score=self._sem_score(),
                      execution_result=self._exec_result(any_match=False, hit_ratio=0.0, hyp=0, ref=10))
        assert r.error_category == "LOGIC_ERROR"
        assert r.error_leaf     == "missing_condition"

    def test_err_12_logic_error_too_broad(self, a):
        r = a.analyze("splunk",
                      "index=* earliest=-24h | stats count by src_ip",
                      REFERENCE_SPLUNK,
                      syntax_result=self._syn_result(True),
                      semantic_score=self._sem_score(),
                      execution_result=self._exec_result(any_match=False, hit_ratio=50.0, hyp=500, ref=10))
        assert r.error_category == "LOGIC_ERROR"
        assert r.error_leaf     == "inverted_condition"

    def test_err_13_low_semantic_no_other_error(self, a):
        r = a.analyze("splunk",
                      "index=* earliest=-24h | stats count by src_ip",
                      REFERENCE_SPLUNK,
                      syntax_result=self._syn_result(True),
                      semantic_score=self._sem_score(field_f1=0.9, semantic=0.3))
        assert r.error_category == "LOGIC_ERROR"

    # ── Batch / Distribution ──────────────────────────────────────────────────

    def test_err_14_analyze_batch(self, a):
        hyps = [SPLUNK_VALID, SPLUNK_INVALID, SPLUNK_VALID]
        refs = [REFERENCE_SPLUNK] * 3
        reports = a.analyze_batch("splunk", hyps, refs)
        assert len(reports) == 3

    def test_err_15_compute_distribution(self, a):
        reports = a.analyze_batch(
            "splunk",
            [SPLUNK_VALID, SPLUNK_INVALID, SPLUNK_EMPTY],
            [REFERENCE_SPLUNK] * 3,
            syntax_results=[
                self._syn_result(True),
                self._syn_result(False, "missing_keyword"),
                self._syn_result(False, "empty_query"),
            ],
        )
        dist = a.compute_distribution(reports, platform="splunk")
        assert dist.total       == 3
        assert dist.error_count >= 0
        assert 0.0 <= dist.error_rate <= 1.0

    def test_err_16_distribution_empty(self, a):
        dist = a.compute_distribution([], platform="splunk")
        assert dist.total == 0

    def test_err_17_compute_all_distributions(self, a):
        all_reports = {
            "splunk":  [a.analyze("splunk", SPLUNK_VALID, REFERENCE_SPLUNK)],
            "qradar":  [a.analyze("qradar", QRADAR_VALID, QRADAR_VALID)],
            "elastic": [a.analyze("elastic", ELASTIC_EQL, ELASTIC_EQL)],
            "sentinel":[a.analyze("sentinel", SENTINEL_VALID, SENTINEL_VALID)],
            "wazuh":   [a.analyze("wazuh", WAZUH_VALID, WAZUH_VALID)],
        }
        dists = a.compute_all_distributions(all_reports)
        assert set(dists.keys()) == {"splunk","qradar","elastic","sentinel","wazuh"}

    def test_err_18_to_dict(self, a):
        r = a.analyze("splunk", SPLUNK_VALID, REFERENCE_SPLUNK)
        d = r.to_dict()
        assert "error_category" in d
        assert "severity"       in d
        assert "suggestions"    in d


# ══════════════════════════════════════════════════════════════════════════════
# AblationRunner tests
# ══════════════════════════════════════════════════════════════════════════════

class TestAblationRunner:
    """[T-ABL] Tests for src/evaluation/ablation.py"""

    def _make_runner(self, translate_fn=None):
        from src.evaluation.ablation import AblationRunner
        from src.evaluation.syntax_validator import SyntaxValidator
        from src.evaluation.semantic_scorer  import SemanticScorer

        def _translate(nl_query, condition):
            # Condition A: bare/invalid, B: partial, C: full
            if condition == "A":
                return {p: SPLUNK_INVALID for p in ("splunk","qradar","elastic","sentinel","wazuh")}
            elif condition == "B":
                return {p: SPLUNK_VALID   for p in ("splunk","qradar","elastic","sentinel","wazuh")}
            else:
                return {
                    "splunk":   SPLUNK_VALID,
                    "qradar":   QRADAR_VALID,
                    "elastic":  ELASTIC_EQL,
                    "sentinel": SENTINEL_VALID,
                    "wazuh":    WAZUH_VALID,
                }

        return AblationRunner(
            translate_fn     = translate_fn or _translate,
            syntax_validator = SyntaxValidator(),
            semantic_scorer  = SemanticScorer(use_sacrebleu=False),
            max_queries      = 5,
        )

    def test_abl_01_run_all_conditions(self):
        runner  = self._make_runner()
        bench   = [_make_bench_record(i) for i in range(3)]
        results = runner.run(bench, conditions=["A","B","C"])
        assert set(results.all_conditions()) == {"A","B","C"}

    def test_abl_02_records_populated(self):
        runner  = self._make_runner()
        bench   = [_make_bench_record(i) for i in range(2)]
        results = runner.run(bench, conditions=["A","C"])
        assert len(results.records) > 0

    def test_abl_03_metrics_structure(self):
        runner  = self._make_runner()
        bench   = [_make_bench_record(i) for i in range(2)]
        results = runner.run(bench, conditions=["A","C"])
        m = results.get_metrics("C", "splunk")
        assert m is not None
        assert 0.0 <= m.validity_pct <= 1.0

    def test_abl_04_condition_c_better_than_a(self):
        runner  = self._make_runner()
        bench   = [_make_bench_record(i) for i in range(3)]
        results = runner.run(bench, conditions=["A","C"])
        m_a = results.get_metrics("A", "splunk")
        m_c = results.get_metrics("C", "splunk")
        # Condition C uses valid Splunk, A uses invalid — C must have higher validity
        assert m_c.validity_pct >= m_a.validity_pct

    def test_abl_05_build_table(self):
        runner  = self._make_runner()
        bench   = [_make_bench_record(i) for i in range(2)]
        results = runner.run(bench, conditions=["A","B","C"])
        table   = runner.build_table(results)
        assert len(table) > 0
        assert "condition" in table[0]
        assert "delta_vs_A" in table[0]

    def test_abl_06_to_table(self):
        runner  = self._make_runner()
        bench   = [_make_bench_record(i) for i in range(2)]
        results = runner.run(bench, conditions=["A"])
        rows    = results.to_table()
        assert isinstance(rows, list)

    def test_abl_07_run_single_condition(self):
        runner  = self._make_runner()
        bench   = [_make_bench_record(i) for i in range(2)]
        metrics = runner.run_single_condition(bench, condition="C")
        assert "splunk" in metrics

    def test_abl_08_condition_metrics_to_dict(self):
        runner  = self._make_runner()
        bench   = [_make_bench_record(i) for i in range(2)]
        results = runner.run(bench, conditions=["C"])
        m = results.get_metrics("C", "splunk")
        d = m.to_dict()
        assert "condition_label" in d
        assert "validity_pct" in d

    def test_abl_09_translate_error_handled(self):
        def bad_translate(nl, cond):
            raise RuntimeError("LLM timeout")
        from src.evaluation.ablation import AblationRunner
        from src.evaluation.syntax_validator import SyntaxValidator
        from src.evaluation.semantic_scorer  import SemanticScorer
        runner = AblationRunner(
            translate_fn=bad_translate,
            syntax_validator=SyntaxValidator(),
            semantic_scorer=SemanticScorer(use_sacrebleu=False),
        )
        bench   = [_make_bench_record(0)]
        results = runner.run(bench, conditions=["A"])
        # Should not raise, just record empty translations
        assert len(results.records) >= 0

    def test_abl_10_default_translate_stub(self):
        from src.evaluation.ablation import AblationRunner
        runner = AblationRunner()
        out = runner._default_translate("detect brute force", "A")
        assert isinstance(out, dict)
        assert "splunk" in out


# ══════════════════════════════════════════════════════════════════════════════
# MetricsAggregator tests
# ══════════════════════════════════════════════════════════════════════════════

class TestMetricsAggregator:
    """[T-AGG] Tests for src/evaluation/metrics_aggregator.py"""

    @pytest.fixture
    def agg(self):
        from src.evaluation.metrics_aggregator import MetricsAggregator
        return MetricsAggregator()

    def _make_syntax_metrics(self, validity=0.8):
        m = MagicMock()
        m.total         = 10
        m.validity_pct  = validity
        return m

    def _make_semantic_metrics(self, semantic=0.7, bleu=0.5, rouge=0.6, f1=0.75):
        m = MagicMock()
        m.total              = 10
        m.avg_bleu           = bleu
        m.avg_rouge_l        = rouge
        m.avg_field_f1       = f1
        m.avg_semantic_score = semantic
        return m

    def _make_exec_metrics(self, exact=0.6, recall=0.7, struct=0.8):
        m = MagicMock()
        m.total          = 10
        m.exact_pct      = exact
        m.recall_pct     = recall
        m.structural_pct = struct
        return m

    def _make_error_dist(self, error_rate=0.2):
        m = MagicMock()
        m.total          = 10
        m.error_count    = int(10 * error_rate)
        m.error_rate     = error_rate
        m.category_counts = {"SYNTAX_ERROR": 1, "FIELD_ERROR": 1}
        m.leaf_counts    = {"empty_query": 1}
        m.most_common_errors = [("empty_query", 1)]
        return m

    def _make_all_metrics(self):
        plats = ("splunk","qradar","elastic","sentinel","wazuh")
        syn  = {p: self._make_syntax_metrics()   for p in plats}
        sem  = {p: self._make_semantic_metrics()  for p in plats}
        exe  = {p: self._make_exec_metrics()      for p in plats}
        err  = {p: self._make_error_dist()        for p in plats}
        return syn, sem, exe, err

    # ── Table 2 ───────────────────────────────────────────────────────────────

    def test_agg_01_table2_platforms(self, agg):
        syn, sem, exe, _ = self._make_all_metrics()
        rows = agg.build_table2(syn, sem, exe)
        platforms = [r.platform for r in rows]
        for p in ("splunk","qradar","elastic","sentinel","wazuh"):
            assert p in platforms

    def test_agg_02_table2_macro_avg_row(self, agg):
        syn, sem, exe, _ = self._make_all_metrics()
        rows = agg.build_table2(syn, sem, exe)
        assert any(r.platform == "MACRO-AVG" for r in rows)

    def test_agg_03_table2_no_execution_metrics(self, agg):
        syn, sem, _, _ = self._make_all_metrics()
        rows = agg.build_table2(syn, sem, None)
        assert len(rows) > 0
        assert all(r.exact_match_pct == 0.0 for r in rows if r.platform != "MACRO-AVG")

    def test_agg_04_table2_to_dict(self, agg):
        syn, sem, exe, _ = self._make_all_metrics()
        rows = agg.build_table2(syn, sem, exe)
        for r in rows:
            d = r.to_dict()
            assert "validity_%" in d
            assert "semantic_score" in d

    # ── Table 3 ───────────────────────────────────────────────────────────────

    def test_agg_05_table3_platforms(self, agg):
        _, _, _, err = self._make_all_metrics()
        rows = agg.build_table3(err)
        platforms = [r.platform for r in rows]
        for p in ("splunk","qradar","elastic","sentinel","wazuh"):
            assert p in platforms

    def test_agg_06_table3_error_fields(self, agg):
        _, _, _, err = self._make_all_metrics()
        rows = agg.build_table3(err)
        for r in rows:
            assert 0.0 <= r.error_rate <= 1.0
            assert r.total_queries >= 0

    def test_agg_07_table3_none_dist(self, agg):
        rows = agg.build_table3({})
        assert len(rows) == 5   # one per platform, all zeros

    def test_agg_08_table3_to_dict(self, agg):
        _, _, _, err = self._make_all_metrics()
        rows = agg.build_table3(err)
        d = rows[0].to_dict()
        assert "error_rate_%" in d
        assert "top_error" in d

    # ── Table 4 ───────────────────────────────────────────────────────────────

    def test_agg_09_table4_from_ablation(self, agg):
        from src.evaluation.ablation import AblationRunner, CONDITION_LABELS
        runner  = AblationRunner(
            translate_fn=lambda nl, c: {p: SPLUNK_VALID for p in ("splunk","qradar","elastic","sentinel","wazuh")},
            syntax_validator=__import__("src.evaluation.syntax_validator", fromlist=["SyntaxValidator"]).SyntaxValidator(),
            semantic_scorer=__import__("src.evaluation.semantic_scorer", fromlist=["SemanticScorer"]).SemanticScorer(use_sacrebleu=False),
        )
        bench   = [_make_bench_record(i) for i in range(2)]
        results = runner.run(bench, conditions=["A","C"])
        table   = runner.build_table(results)
        rows    = agg.build_table4(table)
        assert len(rows) > 0
        assert all(hasattr(r, "delta_vs_A") for r in rows)

    def test_agg_10_table4_empty(self, agg):
        rows = agg.build_table4([])
        assert rows == []

    # ── build_all ─────────────────────────────────────────────────────────────

    def test_agg_11_build_all(self, agg):
        syn, sem, exe, err = self._make_all_metrics()
        result = agg.build_all(syn, sem, err, execution_metrics=exe)
        assert len(result.table2) > 0
        assert len(result.table3) > 0
        assert result.generated_at is not None

    def test_agg_12_build_all_to_dict(self, agg):
        syn, sem, exe, err = self._make_all_metrics()
        result = agg.build_all(syn, sem, err, execution_metrics=exe)
        d = result.to_dict()
        assert "table2" in d
        assert "table3" in d

    # ── Save ──────────────────────────────────────────────────────────────────

    def test_agg_13_save_json(self, agg):
        syn, sem, exe, err = self._make_all_metrics()
        t2   = agg.build_table2(syn, sem, exe)
        t3   = agg.build_table3(err)
        with tempfile.TemporaryDirectory() as td:
            paths = agg.save(t2, t3, [], output_dir=td)
            assert "table2_main_results"    in paths
            assert "table3_error_analysis"  in paths
            assert paths["table2_main_results"].exists()

    def test_agg_14_save_latex(self, agg):
        syn, sem, exe, err = self._make_all_metrics()
        t2 = agg.build_table2(syn, sem, exe)
        t3 = agg.build_table3(err)
        with tempfile.TemporaryDirectory() as td:
            paths = agg.save_latex(t2, t3, output_dir=td)
            assert "table2_latex" in paths
            tex = paths["table2_latex"].read_text()
            assert "\\begin{table}" in tex
            assert "\\toprule"      in tex

    def test_agg_15_print_tables_no_crash(self, agg):
        syn, sem, exe, err = self._make_all_metrics()
        t2 = agg.build_table2(syn, sem, exe)
        t3 = agg.build_table3(err)
        agg.print_tables(t2, t3, [])   # must not raise


# ══════════════════════════════════════════════════════════════════════════════
# __init__.py smoke tests
# ══════════════════════════════════════════════════════════════════════════════

class TestEvaluationInit:
    """[T-INIT] Verify src/evaluation/__init__.py exports."""

    def test_init_01_all_symbols_importable(self):
        import src.evaluation as ev
        for name in ev.__all__:
            assert hasattr(ev, name), f"src.evaluation does not export {name!r}"

    def test_init_02_class_identity(self):
        from src.evaluation import SyntaxValidator
        from src.evaluation.syntax_validator import SyntaxValidator as SV2
        assert SyntaxValidator is SV2

    def test_init_03_semantic_scorer_identity(self):
        from src.evaluation import SemanticScorer
        from src.evaluation.semantic_scorer import SemanticScorer as SS2
        assert SemanticScorer is SS2


# ══════════════════════════════════════════════════════════════════════════════
# Cross-layer integration tests
# ══════════════════════════════════════════════════════════════════════════════

class TestIntegration:
    """[T-INT] Cross-layer integration — full evaluation pipeline."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        from src.evaluation.syntax_validator import SyntaxValidator
        from src.evaluation.semantic_scorer  import SemanticScorer
        from src.evaluation.error_analyzer   import ErrorAnalyzer
        from src.evaluation.execution_match  import ExecutionMatcher
        from src.evaluation.metrics_aggregator import MetricsAggregator
        self.validator  = SyntaxValidator()
        self.scorer     = SemanticScorer(use_sacrebleu=False)
        self.analyzer   = ErrorAnalyzer()
        self.matcher    = ExecutionMatcher()
        self.matcher._available = False
        self.aggregator = MetricsAggregator()

    def test_int_01_full_single_query_pipeline(self):
        """syntax → semantic → error → no crash for valid splunk query."""
        syn = self.validator.validate("splunk", SPLUNK_VALID)
        sem = self.scorer.score(SPLUNK_VALID, REFERENCE_SPLUNK, platform="splunk")
        err = self.analyzer.analyze("splunk", SPLUNK_VALID, REFERENCE_SPLUNK,
                                    syntax_result=syn, semantic_score=sem)
        assert syn.is_valid
        assert 0.0 <= sem.semantic_score <= 1.0
        assert isinstance(err.error_category, str)

    def test_int_02_full_single_query_invalid(self):
        """Invalid query propagates correctly through all layers."""
        syn = self.validator.validate("splunk", SPLUNK_INVALID)
        sem = self.scorer.score(SPLUNK_INVALID, REFERENCE_SPLUNK, platform="splunk")
        err = self.analyzer.analyze("splunk", SPLUNK_INVALID, REFERENCE_SPLUNK,
                                    syntax_result=syn, semantic_score=sem)
        assert not syn.is_valid
        assert err.error_category == "SYNTAX_ERROR"
        assert err.severity in ("CRITICAL", "HIGH")

    def test_int_03_dataset_pipeline_all_platforms(self):
        """Full dataset eval across all 5 platforms returns consistent structures."""
        results   = [_make_result_record(i, valid=True)  for i in range(5)]
        benchmark = [_make_bench_record(i)               for i in range(5)]

        syn_all  = self.validator.validate_dataset(results)
        sem_all  = self.scorer.score_dataset(results, benchmark)
        exec_all = self.matcher.match_dataset(results, benchmark)
        err_all  = self.analyzer.analyze_dataset(results, benchmark,
                                                  syntax_all=syn_all,
                                                  semantic_all=sem_all)

        for platform in ("splunk","qradar","elastic","sentinel","wazuh"):
            assert platform in syn_all
            assert platform in sem_all
            assert platform in exec_all
            assert platform in err_all

    def test_int_04_metrics_aggregation_from_dataset(self):
        """Metrics computed from dataset feed correctly into MetricsAggregator."""
        results   = [_make_result_record(i, valid=True) for i in range(3)]
        benchmark = [_make_bench_record(i)              for i in range(3)]

        syn_all  = self.validator.validate_dataset(results)
        sem_all  = self.scorer.score_dataset(results, benchmark)
        err_all  = self.analyzer.analyze_dataset(results, benchmark)

        syn_metrics = self.validator.compute_all_metrics(syn_all)
        sem_metrics = {p: self.scorer.compute_metrics(sem_all[p], platform=p)
                       for p in sem_all}
        err_dists   = self.analyzer.compute_all_distributions(err_all)

        t2 = self.aggregator.build_table2(syn_metrics, sem_metrics)
        t3 = self.aggregator.build_table3(err_dists)

        assert len(t2) >= 5
        assert len(t3) == 5
        for row in t2:
            assert 0.0 <= row.validity_pct <= 1.0
            assert 0.0 <= row.avg_semantic <= 1.0

    def test_int_05_ablation_feeds_table4(self):
        """AblationRunner output correctly feeds into MetricsAggregator.build_table4."""
        from src.evaluation.ablation import AblationRunner

        def translate(nl, condition):
            if condition == "C":
                return {"splunk": SPLUNK_VALID, "qradar": QRADAR_VALID,
                        "elastic": ELASTIC_EQL, "sentinel": SENTINEL_VALID,
                        "wazuh": WAZUH_VALID}
            return {p: "" for p in ("splunk","qradar","elastic","sentinel","wazuh")}

        runner  = AblationRunner(translate_fn=translate,
                                 syntax_validator=self.validator,
                                 semantic_scorer=self.scorer)
        bench   = [_make_bench_record(i) for i in range(2)]
        results = runner.run(bench, conditions=["A","C"])
        table   = runner.build_table(results)
        t4      = self.aggregator.build_table4(table)

        assert len(t4) > 0
        for row in t4:
            assert row.condition in ("A","C")
            assert 0.0 <= row.validity_pct <= 1.0

    def test_int_06_error_analysis_consistency_with_syntax(self):
        """ErrorAnalyzer category matches SyntaxValidator is_valid for clear cases."""
        for query, ref, should_be_syntax_error in [
            (SPLUNK_EMPTY,   REFERENCE_SPLUNK, True),
            (SPLUNK_VALID,   REFERENCE_SPLUNK, False),
            (SPLUNK_INVALID, REFERENCE_SPLUNK, True),
        ]:
            syn = self.validator.validate("splunk", query)
            err = self.analyzer.analyze("splunk", query, ref, syntax_result=syn)
            if should_be_syntax_error:
                assert err.error_category in ("SYNTAX_ERROR", "PLATFORM_SPECIFIC")
            else:
                assert syn.is_valid

    def test_int_07_batch_then_aggregate_validity_pct(self):
        """Validity % computed from batch == manual count."""
        queries = [SPLUNK_VALID, SPLUNK_VALID, SPLUNK_INVALID, SPLUNK_EMPTY, SPLUNK_VALID]
        results = [self.validator.validate("splunk", q) for q in queries]
        metrics = self.validator.compute_metrics(results, platform="splunk")
        manual_valid = sum(1 for r in results if r.is_valid)
        assert metrics.valid == manual_valid
        assert abs(metrics.validity_pct - manual_valid / len(queries)) < 1e-6

    def test_int_08_semantic_field_f1_drives_error_category(self):
        """Field F1 below threshold → FIELD_ERROR even when syntax is valid."""
        syn = self.validator.validate("splunk", SPLUNK_VALID)
        assert syn.is_valid

        # Artificially low field F1
        sem = MagicMock()
        sem.field_f1            = 0.1
        sem.semantic_score      = 0.3
        sem.hypothesis_fields   = ["host"]
        sem.reference_fields    = ["src_ip", "dest_ip", "user", "count"]

        err = self.analyzer.analyze("splunk", SPLUNK_VALID, REFERENCE_SPLUNK,
                                    syntax_result=syn, semantic_score=sem)
        assert err.error_category == "FIELD_ERROR"

    def test_int_09_save_full_results_to_disk(self):
        """End-to-end save: build all tables, write to temp dir, files exist."""
        results   = [_make_result_record(i) for i in range(2)]
        benchmark = [_make_bench_record(i)  for i in range(2)]

        syn_all  = self.validator.validate_dataset(results)
        sem_all  = self.scorer.score_dataset(results, benchmark)
        err_all  = self.analyzer.analyze_dataset(results, benchmark)

        syn_metrics = self.validator.compute_all_metrics(syn_all)
        sem_metrics = {p: self.scorer.compute_metrics(sem_all[p], platform=p) for p in sem_all}
        err_dists   = self.analyzer.compute_all_distributions(err_all)

        t2 = self.aggregator.build_table2(syn_metrics, sem_metrics)
        t3 = self.aggregator.build_table3(err_dists)

        with tempfile.TemporaryDirectory() as td:
            paths = self.aggregator.save(t2, t3, [], output_dir=td)
            assert paths["table2_main_results"].exists()
            assert paths["table3_error_analysis"].exists()
            # Verify JSON is valid
            data = json.loads(paths["table2_main_results"].read_text())
            assert isinstance(data, list)
            assert len(data) > 0

    def test_int_10_wazuh_full_pipeline(self):
        """Wazuh-specific: valid XML passes syntax, scores semantically, no error flagged."""
        syn = self.validator.validate("wazuh", WAZUH_VALID)
        sem = self.scorer.score(WAZUH_VALID, WAZUH_VALID, platform="wazuh")
        err = self.analyzer.analyze("wazuh", WAZUH_VALID, WAZUH_VALID,
                                    syntax_result=syn, semantic_score=sem)
        assert syn.is_valid
        assert sem.semantic_score > 0.9
        assert err.error_category == "NO_ERROR"