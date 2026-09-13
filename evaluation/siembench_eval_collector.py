#!/usr/bin/env python3
"""
siembench_eval_collector.py
============================
Works with your actual SIEMBench JSONL format (gold labels + confidence).
Shows you:
  1. What outputs you need to collect from your NL-SIEM pipeline
  2. Template structure for evaluation records
  3. Computes available metrics as you collect data

Run:
    python3 siembench_eval_collector.py /path/to/siembench_attck.jsonl
    python3 siembench_eval_collector.py /path/to/siembench_attck.jsonl --output eval_results.jsonl
"""

import json
import sys
import math
from collections import Counter, defaultdict
from pathlib import Path


def load_jsonl(path):
    """Load newline-delimited JSON."""
    records = []
    with open(path) as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"Warning: line {i} unparseable: {e}")
    return records


def show_data_inventory(records):
    """Show what fields exist and what's missing."""
    print("\n" + "=" * 70)
    print("DATA INVENTORY")
    print("=" * 70)
    print(f"Total records loaded: {len(records)}")
    
    # Check what fields each record has
    field_counts = Counter()
    for r in records:
        for field in r.keys():
            field_counts[field] += 1
    
    print(f"\nFields present in your data:")
    for field, count in sorted(field_counts.items(), key=lambda x: -x[1]):
        pct = 100 * count / len(records)
        print(f"  {field:<30s}: {count:>3d} / {len(records)} ({pct:>5.1f}%)")
    
    # Check what's needed but missing
    required_for_metrics = {
        "predicted_bindings": "Classifier output (technique + confidence)",
        "ir": "Intermediate representation",
        "translations": "Platform-specific translations (Elastic, Wazuh, etc.)",
        "human_rating": "Analyst 1-5 usefulness rating",
        "cost_usd": "Cost per record (USD)",
        "latency_s": "Timing per stage (dict with classify, ir_build, translate, execute)",
        "error_category": "Error type (if failure)",
    }
    
    missing = [f for f in required_for_metrics if f not in field_counts or field_counts[f] == 0]
    
    if missing:
        print(f"\nFields MISSING (needed for full evaluation):")
        for field in missing:
            print(f"  ❌ {field:<30s}: {required_for_metrics[field]}")
    else:
        print(f"\n✅ All required fields present!")


def show_evaluation_template(sample_record):
    """Show the structure of a complete evaluation record."""
    print("\n" + "=" * 70)
    print("EVALUATION RECORD TEMPLATE")
    print("=" * 70)
    
    template = {
        "id": sample_record.get("id", "GS-AUTH-001"),
        "gold_techniques": [
            f"{sample_record.get('attck', {}).get('technique', 'T1003')}."
            f"{sample_record.get('attck', {}).get('sub_technique', 'T1003.002').split('.')[-1]}"
        ],
        "predicted_bindings": [
            {
                "technique": "T1110.001",
                "confidence": 0.83,
                "delta": 0.05  # Optional: drift score if you have reference telemetry
            }
        ],
        "ir": {
            "attack": {
                "tactic": "credential-access",
                "technique": "T1110",
                "sub_technique": "T1110.001"
            },
            "action": "filter+aggregate",
            "event_type": "authentication",
            "filter": {"field": "status", "op": "eq", "value": "failed"},
            "group_by": ["user.name"],
            "time_window": "5m",
            "threshold": {"count": ">5"}
        },
        "translations": {
            "elastic": {
                "generated_query": "FROM logs-* | WHERE event.category == authentication ...",
                "ground_truth_query": "FROM logs-* | WHERE event.category == authentication ...",
                "execution_success": True,
                "provenance_ok": True,
                "R_D": ["evt_1", "evt_2", "evt_3"],  # Events SOURCE rule fires on
                "R_Dp": ["evt_1", "evt_2"],  # Events TRANSLATED rule fires on
            },
            "wazuh": {
                "generated_query": "<rule><frequency>5</frequency>...</rule>",
                "ground_truth_query": "<rule><frequency>5</frequency>...</rule>",
                "execution_success": True,
                "provenance_ok": True,
                "R_D": ["evt_1", "evt_2", "evt_3"],
                "R_Dp": ["evt_1", "evt_2", "evt_3"],  # Perfect match = delta ~0
            }
        },
        "human_rating": 4,  # 1-5 usefulness scale
        "cost_usd": 0.0031,
        "latency_s": {
            "classify": 0.9,
            "ir_build": 0.5,
            "translate": 0.8,
            "execute": 1.0
        },
        "error_category": None  # One of: attack_misclassification, field_mapping_failure, unsupported_construct, llm_hallucination, execution_failure, nl_ambiguity
    }
    
    print("\nMinimal evaluation record (JSON structure):")
    print(json.dumps(template, indent=2))


def compute_available_metrics(records):
    """Compute metrics on whatever fields are present."""
    print("\n" + "=" * 70)
    print("AVAILABLE METRICS (from current data)")
    print("=" * 70)
    
    # 1. ATT&CK classification accuracy (if predicted_bindings exist)
    records_with_predictions = [r for r in records if r.get("predicted_bindings")]
    if records_with_predictions:
        correct = 0
        for r in records_with_predictions:
            gold_tech = r.get("attck", {}).get("technique")
            pred = r["predicted_bindings"][0] if r["predicted_bindings"] else {}
            pred_tech = pred.get("technique")
            if gold_tech == pred_tech:
                correct += 1
        acc = 100 * correct / len(records_with_predictions)
        print(f"ATT&CK classification accuracy: {acc:.1f}% ({correct}/{len(records_with_predictions)})")
    else:
        print(f"ATT&CK classification accuracy: TBD (no predicted_bindings yet)")
    
    # 2. Confidence distribution (if confidence scores exist)
    confidence_scores = []
    for r in records:
        if r.get("attck", {}).get("confidence"):
            confidence_scores.append(r["attck"]["confidence"])
    
    if confidence_scores:
        print(f"Classifier confidence (gold labels):")
        print(f"  Mean: {sum(confidence_scores)/len(confidence_scores):.3f}")
        print(f"  Min:  {min(confidence_scores):.3f}")
        print(f"  Max:  {max(confidence_scores):.3f}")
    
    # 3. Coverage by complexity tier
    complexity_counts = Counter(r.get("complexity") for r in records)
    print(f"\nRecord distribution by complexity:")
    for c, count in sorted(complexity_counts.items()):
        pct = 100 * count / len(records)
        print(f"  {c:<10s}: {count:>3d} ({pct:>5.1f}%)")
    
    # 4. Coverage by category
    category_counts = Counter(r.get("category") for r in records)
    print(f"\nRecord distribution by category:")
    for cat, count in sorted(category_counts.items()):
        pct = 100 * count / len(records)
        print(f"  {cat:<20s}: {count:>3d} ({pct:>5.1f}%)")
    
    # 5. Drift scores (if available)
    records_with_drift = [r for r in records 
                          if r.get("translations") 
                          and any(t.get("R_D") for t in r["translations"].values())]
    if records_with_drift:
        print(f"\nDrift assessment available for: {len(records_with_drift)} records")
    else:
        print(f"\nDrift assessment: TBD (need translations with R_D/R_Dp event sets)")
    
    # 6. Cost & latency
    records_with_cost = [r for r in records if r.get("cost_usd")]
    records_with_latency = [r for r in records if r.get("latency_s")]
    
    if records_with_cost:
        costs = [r["cost_usd"] for r in records_with_cost]
        print(f"\nCost per record: ${sum(costs)/len(costs):.4f} (n={len(records_with_cost)})")
    else:
        print(f"\nCost per record: TBD")
    
    if records_with_latency:
        print(f"Latency data available: {len(records_with_latency)} records")
    else:
        print(f"Latency data: TBD")


def create_eval_template_file(input_path, output_path=None):
    """Create a template evaluation file from gold labels."""
    records = load_jsonl(input_path)
    
    if output_path is None:
        output_path = Path(input_path).stem + "_eval_template.jsonl"
    
    print(f"\nGenerating evaluation template → {output_path}")
    
    with open(output_path, "w") as f:
        for r in records:
            eval_record = {
                "id": r.get("id"),
                "gold_techniques": [
                    f"{r.get('attck', {}).get('technique', 'UNKNOWN')}"
                ],
                "predicted_bindings": [],  # FILL THIS IN from your classifier
                "ir": {},  # FILL THIS IN from IR construction
                "translations": {},  # FILL THIS IN from translation agents
                "human_rating": None,  # OPTIONAL: have SOC analysts rate
                "cost_usd": None,  # OPTIONAL: track execution cost
                "latency_s": {},  # OPTIONAL: track per-stage timing
                "error_category": None,  # OPTIONAL: categorize failures
            }
            f.write(json.dumps(eval_record) + "\n")
    
    print(f"✓ Template written: {output_path}")
    print(f"  → Fill in the empty fields with your pipeline outputs")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 siembench_eval_collector.py <path/to/siembench_attck.jsonl>")
        print("  python3 siembench_eval_collector.py <path> --output eval.jsonl")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = None
    
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        if idx + 1 < len(sys.argv):
            output_file = sys.argv[idx + 1]
    
    print(f"Loading {input_file}...")
    records = load_jsonl(input_file)
    
    show_data_inventory(records)
    show_evaluation_template(records[0] if records else {})
    compute_available_metrics(records)
    
    if output_file is None:
        output_file = Path(input_file).stem + "_eval_template.jsonl"
    
    create_eval_template_file(input_file, output_file)
    
    print("\n" + "=" * 70)
    print("NEXT STEPS")
    print("=" * 70)
    print("""
1. Run your NL-SIEM pipeline on each record (use nl_query as input)
2. Collect outputs:
   - predicted_bindings: [{"technique": "T1110.001", "confidence": 0.83}]
   - ir: {IR record from Stage 2}
   - translations: {platform -> generated_query, R_D, R_Dp event sets}
   - cost_usd, latency_s, human_rating (optional but recommended)
3. Fill the eval_template.jsonl with your pipeline outputs
4. Run the metrics script:
   
   python3 siembench_metrics.py eval_template.jsonl > report.txt
    """)


if __name__ == "__main__":
    main()