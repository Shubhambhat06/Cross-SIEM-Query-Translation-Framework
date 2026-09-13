#!/usr/bin/env python3
"""
siembench_metrics.py
=====================
One combined, dependency-free script implementing every metric that the
NL-SIEM / ATT&CK-Coverage-Drift paper lists as TBD in Section VII
(Table "Evaluation Metrics with Formal Definitions") plus the two
supporting analyses described in the same section (Spearman correlation
against analyst ratings, and the multi-technique-threshold ROC/AUC).

Implemented metrics (paper equation/definition in parentheses):
  1.  ATT&CK classification accuracy
  2.  Precision / Recall / F1 over verified ATT&CK bindings
  3.  IR generation accuracy               (Definition: IR Consistency)
  4.  Translation similarity               (Eq. TS,  beta = 0.4 default)
  5.  Execution success rate
  6.  Coverage Preservation Score - CPS    (Eq. CPS)
  7.  Coverage Drift Score - delta          (Eq. Drift)
  8.  Semantic Fidelity Score - SFS        (Eq. SFS, alpha = 0.7 default)
  9.  Confidence-Weighted Coverage - CWC   (Eq. CWC, epsilon = 0.2 default)
  10. False positive / negative rate
  11. Token / API cost per record
  12. Per-stage and end-to-end latency
  13. Human acceptance rate (>= 4/5)
  14. Spearman's rho: analyst rating vs. computed Drift Score
  15. Error taxonomy distribution (the 6 fixed categories)
  16. ROC curve / AUC for the multi-technique inclusion threshold

No third-party packages are required (stdlib only), so this runs
anywhere Python 3.8+ runs.

------------------------------------------------------------------------
INPUT SHAPE
------------------------------------------------------------------------
Everything is computed from a list of "record" dicts, one per SIEMBench
query, shaped like this (all keys optional -- a metric simply skips a
record that doesn't carry what it needs):

{
  "id": "SB-CredAccess-01",
  "gold_techniques": ["T1110.001", "T1110.003"],   # gold label(s)
  "predicted_bindings": [                           # Stage-1 output
      {"technique": "T1110.001", "confidence": 0.83, "delta": 0.05},
      {"technique": "T1110.003", "confidence": 0.58, "delta": 0.31}
  ],
  "ir": { "attack": {"tactic": "credential-access",
                      "technique": "T1110",
                      "sub_technique": "T1110.001"},
          "action": "filter+aggregate",
          "event_type": "authentication", ... },     # Stage-2 output
  "translations": {
      "elastic": {
          "generated_query": "...",
          "ground_truth_query": "...",
          "execution_success": True,
          "provenance_ok": True,
          "R_D":  ["evt_1", "evt_2", ...],  # events the SOURCE rule fires on
          "R_Dp": ["evt_1", "evt_3", ...],  # events the TRANSLATED rule fires on
      },
      "wazuh": { ... }
  },
  "human_rating": 4,           # SOC analyst 1-5 score
  "cost_usd": 0.0031,
  "latency_s": {"classify": 0.8, "ir_build": 0.4, "translate": 0.9, "execute": 1.1},
  "error_category": None       # one of ERROR_CATEGORIES, or None if it succeeded
}

Run standalone for a worked demo built from the paper's own examples:
    python3 siembench_metrics.py

Or point it at a real SIEMBench-shaped JSON file:
    python3 siembench_metrics.py results.json
"""

import json
import math
import re
import sys
from collections import Counter, defaultdict

# ------------------------------------------------------------------ #
# small numeric helpers
# ------------------------------------------------------------------ #

def _mean(values):
    values = [v for v in values if v is not None]
    return sum(values) / len(values) if values else None


def _percentile(values, pct):
    values = [v for v in values if v is not None]
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * (pct / 100.0)
    f, c = math.floor(k), math.ceil(k)
    if f == c:
        return s[int(k)]
    return s[f] + (s[c] - s[f]) * (k - f)


# ------------------------------------------------------------------ #
# 1. ATT&CK classification accuracy
# ------------------------------------------------------------------ #

def classification_accuracy(records):
    """(1/N) * sum 1[T_hat_i == T_i*] -- top-ranked binding vs. primary gold."""
    scored = [r for r in records if r.get("gold_techniques") and r.get("predicted_bindings")]
    if not scored:
        return None
    correct = 0
    for r in scored:
        top = max(r["predicted_bindings"], key=lambda b: b.get("confidence", 0.0))
        if top.get("technique") == r["gold_techniques"][0]:
            correct += 1
    return correct / len(scored)


# ------------------------------------------------------------------ #
# 2. Precision / Recall / F1 over verified bindings (micro-averaged,
#    multi-label aware -- a record may have >1 gold and/or >1 prediction)
# ------------------------------------------------------------------ #

def precision_recall_f1(records):
    tp = fp = fn = 0
    for r in records:
        gold = set(r.get("gold_techniques", []) or [])
        pred = set(b["technique"] for b in r.get("predicted_bindings", []) or [])
        if not gold and not pred:
            continue
        tp += len(gold & pred)
        fp += len(pred - gold)
        fn += len(gold - pred)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn}


# ------------------------------------------------------------------ #
# 3. IR generation accuracy  (Definition: IR Consistency)
#    F_req = {tactic, technique_id, action, event_type}
# ------------------------------------------------------------------ #

REQUIRED_IR_FIELDS = ("tactic", "technique_id", "action", "event_type")


def validate_ir(ir):
    attack = (ir or {}).get("attack", {}) or {}
    flat = {
        "tactic": attack.get("tactic"),
        "technique_id": attack.get("technique"),
        "action": ir.get("action"),
        "event_type": ir.get("event_type"),
    }
    for field in REQUIRED_IR_FIELDS:
        v = flat.get(field)
        if v is None or (isinstance(v, str) and not v.strip()):
            return False, f"missing/empty required field: {field}"
    return True, None


def ir_generation_accuracy(records):
    total = valid = 0
    for r in records:
        if "ir" not in r:
            continue
        total += 1
        ok, _ = validate_ir(r["ir"])
        valid += int(ok)
    return valid / total if total else None


# ------------------------------------------------------------------ #
# 4. Translation similarity  (Eq. TS = beta*BLEU + (1-beta)*field_F1)
#    Self-contained BLEU-4 (add-one smoothed) + field/operator F1 that
#    ignores string literals, matching the paper's definition.
# ------------------------------------------------------------------ #

def _bleu(candidate, reference, max_n=4):
    cand, ref = candidate.split(), reference.split()
    if not cand or not ref:
        return 0.0
    precisions = []
    for n in range(1, max_n + 1):
        cand_ngrams = Counter(tuple(cand[i:i + n]) for i in range(len(cand) - n + 1))
        ref_ngrams = Counter(tuple(ref[i:i + n]) for i in range(len(ref) - n + 1))
        overlap = sum(min(c, ref_ngrams[g]) for g, c in cand_ngrams.items())
        total = max(sum(cand_ngrams.values()), 1)
        precisions.append((overlap + 1) / (total + 1))  # add-one smoothing
    geo_mean = math.exp(sum(math.log(p) for p in precisions) / max_n)
    bp = 1.0 if len(cand) > len(ref) else math.exp(1 - len(ref) / len(cand))
    return bp * geo_mean


def _strip_string_literals(text):
    return re.sub(r'"[^"]*"|\'[^\']*\'', " ", text)


def _field_op_tokens(text):
    text = _strip_string_literals(text)
    return re.findall(r"[A-Za-z_][A-Za-z0-9_.]*|==|!=|>=|<=|>|<|\|", text)


def _field_f1(candidate, reference):
    c, r = Counter(_field_op_tokens(candidate)), Counter(_field_op_tokens(reference))
    if not c or not r:
        return 0.0
    overlap = sum((c & r).values())
    precision = overlap / sum(c.values())
    recall = overlap / sum(r.values())
    return 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0


def translation_similarity(candidate, reference, beta=0.4):
    return beta * _bleu(candidate, reference) + (1 - beta) * _field_f1(candidate, reference)


def translation_similarity_report(records, beta=0.4):
    per_platform = defaultdict(list)
    for r in records:
        for plat, t in (r.get("translations") or {}).items():
            gen, gt = t.get("generated_query"), t.get("ground_truth_query")
            if gen and gt:
                per_platform[plat].append(translation_similarity(gen, gt, beta=beta))
    out = {plat: _mean(v) for plat, v in per_platform.items()}
    out["overall"] = _mean([s for v in per_platform.values() for s in v])
    return out


# ------------------------------------------------------------------ #
# 5. Execution success rate
# ------------------------------------------------------------------ #

def execution_success_rate(records, platforms=None):
    total = success = 0
    for r in records:
        for plat, t in (r.get("translations") or {}).items():
            if platforms and plat not in platforms:
                continue
            if "execution_success" not in t:
                continue
            total += 1
            success += int(bool(t["execution_success"]))
    return success / total if total else None


# ------------------------------------------------------------------ #
# 6-8. Coverage Preservation (CPS), Drift (delta), Semantic Fidelity (SFS)
#    all derived from R(D) / R(D') event-match sets per translation.
# ------------------------------------------------------------------ #

def coverage_metrics(records, alpha=0.7, platforms=None):
    deltas, cps_vals, sfs_vals = defaultdict(list), defaultdict(list), defaultdict(list)
    for r in records:
        for plat, t in (r.get("translations") or {}).items():
            if platforms and plat not in platforms:
                continue
            R_D, R_Dp = t.get("R_D"), t.get("R_Dp")
            if R_D is None or R_Dp is None:
                continue
            R_D, R_Dp = set(R_D), set(R_Dp)
            inter, union = R_D & R_Dp, R_D | R_Dp
            delta = 1 - len(inter) / len(R_D) if R_D else None
            cps = len(inter) / len(union) if union else None
            prov = 1.0 if t.get("provenance_ok", True) else 0.0
            sfs = alpha * cps + (1 - alpha) * prov if cps is not None else None
            if delta is not None:
                deltas[plat].append(delta)
            if cps is not None:
                cps_vals[plat].append(cps)
            if sfs is not None:
                sfs_vals[plat].append(sfs)

    platforms_seen = set(deltas) | set(cps_vals)
    result = {
        plat: {
            "mean_drift": _mean(deltas[plat]),
            "mean_cps": _mean(cps_vals[plat]),
            "mean_sfs": _mean(sfs_vals[plat]),
            "n": len(deltas[plat]),
        }
        for plat in platforms_seen
    }
    result["overall"] = {
        "mean_drift": _mean([d for v in deltas.values() for d in v]),
        "mean_cps": _mean([d for v in cps_vals.values() for d in v]),
        "mean_sfs": _mean([d for v in sfs_vals.values() for d in v]),
        "n": sum(len(v) for v in deltas.values()),
    }
    return result


# ------------------------------------------------------------------ #
# 9. Confidence-Weighted Coverage (Eq. CWC)
#    CWC(M) = sum_i c_i * 1[delta(D_Ti, D'_Ti) < epsilon]
# ------------------------------------------------------------------ #

def confidence_weighted_coverage(records, epsilon=0.2):
    per_record = []
    for r in records:
        bindings = r.get("predicted_bindings") or []
        if not bindings:
            continue
        cwc = 0.0
        for b in bindings:
            c = b.get("confidence", 0.0)
            delta = b.get("delta")  # per-binding drift if the caller has it
            if delta is None:
                # fall back to the record's mean drift across platforms
                deltas = []
                for t in (r.get("translations") or {}).values():
                    R_D, R_Dp = t.get("R_D"), t.get("R_Dp")
                    if R_D:
                        R_D, R_Dp = set(R_D), set(R_Dp or [])
                        deltas.append(1 - len(R_D & R_Dp) / len(R_D))
                delta = _mean(deltas) if deltas else 1.0
            cwc += c * (1.0 if delta < epsilon else 0.0)
        per_record.append(cwc)
    return _mean(per_record)


# ------------------------------------------------------------------ #
# 10. False positive / negative rate
#     FN rate = |R(D) - R(D')| / |R(D)|            (missed detections)
#     FP rate = |R(D') - R(D)| / denom              (spurious matches)
#     denom = corpus_size - |R(D)| if a reference corpus size is given,
#     else falls back to |R(D')|.
# ------------------------------------------------------------------ #

def fp_fn_rates(records, corpus_size=None):
    fn_rates, fp_rates = [], []
    for r in records:
        for t in (r.get("translations") or {}).values():
            R_D, R_Dp = t.get("R_D"), t.get("R_Dp")
            if R_D is None or R_Dp is None:
                continue
            R_D, R_Dp = set(R_D), set(R_Dp)
            missed, extra = R_D - R_Dp, R_Dp - R_D
            if R_D:
                fn_rates.append(len(missed) / len(R_D))
            denom = (corpus_size - len(R_D)) if corpus_size else (len(R_Dp) or 1)
            fp_rates.append(len(extra) / denom if denom else 0.0)
    return {"fn_rate": _mean(fn_rates), "fp_rate": _mean(fp_rates)}


# ------------------------------------------------------------------ #
# 11. Token / API cost per record
# ------------------------------------------------------------------ #

def cost_report(records):
    costs = [r["cost_usd"] for r in records if r.get("cost_usd") is not None]
    return {"mean_cost_usd": _mean(costs), "total_cost_usd": sum(costs) if costs else None, "n": len(costs)}


# ------------------------------------------------------------------ #
# 12. Per-stage and end-to-end latency
# ------------------------------------------------------------------ #

def latency_report(records):
    per_stage = defaultdict(list)
    totals = []
    for r in records:
        lat = r.get("latency_s") or {}
        if not lat:
            continue
        for stage, v in lat.items():
            per_stage[stage].append(v)
        totals.append(sum(lat.values()))
    report = {stage: {"mean": _mean(v), "p95": _percentile(v, 95)} for stage, v in per_stage.items()}
    report["total"] = {"mean": _mean(totals), "p95": _percentile(totals, 95)}
    return report


# ------------------------------------------------------------------ #
# 13. Human acceptance rate (rated >= threshold, default 4/5)
# ------------------------------------------------------------------ #

def human_acceptance_rate(records, threshold=4):
    ratings = [r["human_rating"] for r in records if r.get("human_rating") is not None]
    if not ratings:
        return None
    return sum(1 for x in ratings if x >= threshold) / len(ratings)


# ------------------------------------------------------------------ #
# 14. Spearman's rho: analyst rating vs. computed Drift Score
#     Pure-Python rank correlation (average ranks for ties) -- no scipy.
# ------------------------------------------------------------------ #

def _ranks(values):
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        avg_rank = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg_rank
        i = j + 1
    return ranks


def spearman_rho(x, y):
    if len(x) != len(y) or len(x) < 2:
        return None
    rx, ry = _ranks(x), _ranks(y)
    n = len(x)
    d2 = sum((rx[i] - ry[i]) ** 2 for i in range(n))
    return 1 - (6 * d2) / (n * (n ** 2 - 1))


def spearman_analyst_vs_drift(records):
    ratings, drifts = [], []
    for r in records:
        if r.get("human_rating") is None:
            continue
        rec_deltas = []
        for t in (r.get("translations") or {}).values():
            R_D, R_Dp = t.get("R_D"), t.get("R_Dp")
            if R_D:
                R_D, R_Dp = set(R_D), set(R_Dp or [])
                rec_deltas.append(1 - len(R_D & R_Dp) / len(R_D))
        if rec_deltas:
            ratings.append(r["human_rating"])
            drifts.append(_mean(rec_deltas))
    return spearman_rho(ratings, drifts)


# ------------------------------------------------------------------ #
# 15. Error taxonomy distribution (six categories fixed by the paper)
# ------------------------------------------------------------------ #

ERROR_CATEGORIES = (
    "attack_misclassification",
    "field_mapping_failure",
    "unsupported_construct",
    "llm_hallucination",
    "execution_failure",
    "nl_ambiguity",
)


def error_taxonomy(records):
    counts = Counter(r["error_category"] for r in records if r.get("error_category"))
    total = sum(counts.values())
    return {
        cat: {"count": counts.get(cat, 0), "pct": (100.0 * counts.get(cat, 0) / total) if total else 0.0}
        for cat in ERROR_CATEGORIES
    }


# ------------------------------------------------------------------ #
# 16. ROC curve / AUC for the multi-technique inclusion threshold
#     Input: list of (score, label) pairs, label in {0, 1}, independent
#     of the per-record structure above (this calibrates the classifier
#     acceptance threshold from Section "Stage One").
# ------------------------------------------------------------------ #

def roc_curve(pairs):
    pairs = sorted(pairs, key=lambda p: -p[0])
    P = sum(1 for _, l in pairs if l == 1)
    N = sum(1 for _, l in pairs if l == 0)
    tp = fp = 0
    points = [(0.0, 0.0)]
    for _, label in pairs:
        tp += int(label == 1)
        fp += int(label == 0)
        points.append((fp / N if N else 0.0, tp / P if P else 0.0))
    points.append((1.0, 1.0))
    return points


def auc(points):
    pts = sorted(set(points))
    return sum((x1 - x0) * (y0 + y1) / 2 for (x0, y0), (x1, y1) in zip(pts, pts[1:]))


# ------------------------------------------------------------------ #
# Orchestrator + pretty printer
# ------------------------------------------------------------------ #

def compute_all_metrics(records, roc_pairs=None, alpha=0.7, beta=0.4, epsilon=0.2,
                         human_threshold=4, corpus_size=None):
    return {
        "att&ck_classification_accuracy": classification_accuracy(records),
        "precision_recall_f1": precision_recall_f1(records),
        "ir_generation_accuracy": ir_generation_accuracy(records),
        "translation_similarity": translation_similarity_report(records, beta=beta),
        "execution_success_rate": execution_success_rate(records),
        "coverage_(cps_drift_sfs)": coverage_metrics(records, alpha=alpha),
        "confidence_weighted_coverage": confidence_weighted_coverage(records, epsilon=epsilon),
        "fp_fn_rates": fp_fn_rates(records, corpus_size=corpus_size),
        "cost": cost_report(records),
        "latency": latency_report(records),
        "human_acceptance_rate": human_acceptance_rate(records, threshold=human_threshold),
        "spearman_analyst_vs_drift": spearman_analyst_vs_drift(records),
        "error_taxonomy": error_taxonomy(records),
        "multi_technique_roc_auc": auc(roc_curve(roc_pairs)) if roc_pairs else None,
    }


def _fmt(v, pct=False, money=False):
    if v is None:
        return "TBD (no data)"
    if isinstance(v, float):
        if money:
            return f"${v:.4f}"
        return f"{v*100:.1f}%" if pct else f"{v:.3f}"
    return str(v)


def print_report(report):
    print("=" * 62)
    print("NL-SIEM / SIEMBench v1 -- Evaluation Metrics Report")
    print("=" * 62)

    print(f"\nATT&CK classification accuracy : {_fmt(report['att&ck_classification_accuracy'], pct=True)}")

    prf = report["precision_recall_f1"]
    print(f"Precision / Recall / F1        : "
          f"{_fmt(prf['precision'], pct=True)} / {_fmt(prf['recall'], pct=True)} / {_fmt(prf['f1'], pct=True)}"
          f"  (TP={prf['tp']}, FP={prf['fp']}, FN={prf['fn']})")

    print(f"IR generation accuracy         : {_fmt(report['ir_generation_accuracy'], pct=True)}")

    ts = report["translation_similarity"]
    print(f"Translation similarity (overall): {_fmt(ts.get('overall'), pct=True)}")
    for plat, v in ts.items():
        if plat != "overall":
            print(f"    - {plat:<10s}: {_fmt(v, pct=True)}")

    print(f"Execution success rate         : {_fmt(report['execution_success_rate'], pct=True)}")

    cov = report["coverage_(cps_drift_sfs)"]
    ov = cov.get("overall", {})
    print(f"Coverage Drift delta (overall)  : {_fmt(ov.get('mean_drift'))}")
    print(f"Coverage Preservation CPS       : {_fmt(ov.get('mean_cps'))}")
    print(f"Semantic Fidelity Score SFS     : {_fmt(ov.get('mean_sfs'))}")
    for plat, v in cov.items():
        if plat != "overall":
            print(f"    - {plat:<10s}: delta={_fmt(v['mean_drift'])}  CPS={_fmt(v['mean_cps'])}  SFS={_fmt(v['mean_sfs'])}  (n={v['n']})")

    print(f"Confidence-Weighted Coverage    : {_fmt(report['confidence_weighted_coverage'])}")

    fpfn = report["fp_fn_rates"]
    print(f"False positive / negative rate : {_fmt(fpfn['fp_rate'], pct=True)} / {_fmt(fpfn['fn_rate'], pct=True)}")

    cost = report["cost"]
    print(f"Token / API cost per record     : {_fmt(cost['mean_cost_usd'], money=True)}  (n={cost['n']})")

    lat = report["latency"]
    total = lat.pop("total", {})
    print(f"End-to-end latency (mean/p95)   : {_fmt(total.get('mean'))}s / {_fmt(total.get('p95'))}s")
    for stage, v in lat.items():
        print(f"    - {stage:<10s}: mean={_fmt(v['mean'])}s  p95={_fmt(v['p95'])}s")

    print(f"Human acceptance rate (>=4/5)  : {_fmt(report['human_acceptance_rate'], pct=True)}")
    print(f"Spearman rho (analyst vs delta) : {_fmt(report['spearman_analyst_vs_drift'])}")

    print("Error taxonomy:")
    for cat, v in report["error_taxonomy"].items():
        print(f"    - {cat:<28s}: {v['count']:>3d}  ({v['pct']:.1f}%)")

    print(f"Multi-technique threshold AUC   : {_fmt(report['multi_technique_roc_auc'])}")
    print("=" * 62)


# ------------------------------------------------------------------ #
# Demo: reconstructs the paper's own worked examples (T1110.001 /
# T1110.003 SSH brute-force / password-spraying, and SB-042
# exfiltration) with illustrative telemetry so every metric above has
# something to compute against. Replace with real pipeline output by
# passing a JSON file: `python3 siembench_metrics.py results.json`
# ------------------------------------------------------------------ #

def _demo_records():
    return [
        {
            "id": "SB-CredAccess-01",
            "gold_techniques": ["T1110.001", "T1110.003"],
            "predicted_bindings": [
                {"technique": "T1110.001", "confidence": 0.83},
                {"technique": "T1110.003", "confidence": 0.58},
            ],
            "ir": {
                "attack": {"tactic": "credential-access", "technique": "T1110",
                           "sub_technique": "T1110.001"},
                "action": "filter+aggregate", "event_type": "authentication",
            },
            "translations": {
                "elastic": {
                    "generated_query": "FROM logs-* | WHERE event.category == authentication AND event.outcome == failure AND @timestamp >= NOW() - 24 hours | STATS failed_count = COUNT() BY source.ip | WHERE failed_count > 50 | EVAL mitre_sub_technique = T1110.001",
                    "ground_truth_query": "FROM logs-* | WHERE event.category == authentication AND event.outcome == failure AND @timestamp >= NOW() - 24 hours | STATS failed_count = COUNT() BY source.ip | WHERE failed_count > 50 | EVAL mitre_sub_technique = T1110.001",
                    "execution_success": True, "provenance_ok": True,
                    "R_D": [f"evt_{i}" for i in range(60)],
                    "R_Dp": [f"evt_{i}" for i in range(55)],
                },
                "wazuh": {
                    "generated_query": "<rule><frequency>50</frequency><timeframe>86400</timeframe><mitre><id>T1110.001</id></mitre></rule>",
                    "ground_truth_query": "<rule><frequency>50</frequency><timeframe>86400</timeframe><mitre><id>T1110.001</id></mitre></rule>",
                    "execution_success": True, "provenance_ok": True,
                    "R_D": [f"evt_{i}" for i in range(60)],
                    "R_Dp": [f"evt_{i}" for i in range(58)],
                },
            },
            "human_rating": 5, "cost_usd": 0.0031,
            "latency_s": {"classify": 0.9, "ir_build": 0.5, "translate": 0.8, "execute": 1.0},
            "error_category": None,
        },
        {
            "id": "SB-042",
            "gold_techniques": ["T1048.003"],
            "predicted_bindings": [{"technique": "T1048.003", "confidence": 0.91}],
            "ir": {
                "attack": {"tactic": "exfiltration", "technique": "T1048",
                           "sub_technique": "T1048.003"},
                "action": "filter+aggregate", "event_type": "network",
            },
            "translations": {
                "elastic": {
                    "generated_query": "FROM logs-* | WHERE event.category == network AND destination.ip IN TI_IP_LIST | STATS c = COUNT() BY destination.ip | WHERE c > 1",
                    "ground_truth_query": "FROM logs-* | WHERE event.category == network AND destination.ip IN TI_IP_LIST | STATS c = COUNT() BY destination.ip | WHERE c > 1",
                    "execution_success": True, "provenance_ok": True,
                    "R_D": [f"net_{i}" for i in range(20)],
                    "R_Dp": [f"net_{i}" for i in range(20)],
                },
            },
            "human_rating": 4, "cost_usd": 0.0025,
            "latency_s": {"classify": 0.7, "ir_build": 0.4, "translate": 0.6, "execute": 0.9},
            "error_category": None,
        },
        {
            "id": "SB-Sequence-17",
            "gold_techniques": ["T1078.004"],
            "predicted_bindings": [{"technique": "T1078.002", "confidence": 0.61}],
            "ir": {"attack": {"tactic": "defense-evasion", "technique": "T1078"},
                   "action": "filter", "event_type": None},  # missing event_type -> IR invalid
            "translations": {
                "elastic": {"execution_success": False, "provenance_ok": False},
            },
            "human_rating": 2, "cost_usd": 0.0028,
            "latency_s": {"classify": 1.1, "ir_build": 0.3, "translate": 0.2, "execute": 0.1},
            "error_category": "unsupported_construct",
        },
    ]


def _demo_roc_pairs():
    # (classifier confidence score, gold-inclusion label) for the
    # multi-technique acceptance-threshold calibration of Fig. "roc"
    return [(0.91, 1), (0.83, 1), (0.61, 0), (0.58, 1), (0.40, 0), (0.22, 0)]


def load_records(path):
    """Load records from either JSON array or JSONL (newline-delimited JSON)."""
    with open(path, "r") as f:
        content = f.read().strip()
    
    # Try JSON array first
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    
    # Fall back to JSONL
    records = []
    for line in content.split("\n"):
        line = line.strip()
        if line:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"Warning: skipped unparseable line: {line[:50]}... ({e})")
    return records


if __name__ == "__main__":
    if len(sys.argv) > 1:
        recs = load_records(sys.argv[1])
        roc_pairs = None
    else:
        print("(no input file given -- running on the paper's own worked examples as a demo)\n")
        recs = _demo_records()
        roc_pairs = _demo_roc_pairs()

    report = compute_all_metrics(recs, roc_pairs=roc_pairs)
    print_report(report)