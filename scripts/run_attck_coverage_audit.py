#!/usr/bin/env python3
"""
run_attck_coverage_audit.py — CLI wrapper for ATTCKCoverageAuditor.

Run once against an existing/legacy rule set (the "pre-deployment"
baseline) and once against NL-SIEM-generated output (the "post-deployment"
set) to produce the coverage-lift figures reported in the paper
(experiments/results/attck_coverage/{pre,post}_deployment_audit.json).

Usage
-----
    # Pre-deployment baseline audit
    python scripts/run_attck_coverage_audit.py \\
        --rules data/legacy_rules.jsonl \\
        --label pre_deployment \\
        --output experiments/results/attck_coverage/pre_deployment_audit.json

    # Post-deployment audit
    python scripts/run_attck_coverage_audit.py \\
        --rules data/nlsiem_generated_rules.jsonl \\
        --label post_deployment \\
        --output experiments/results/attck_coverage/post_deployment_audit.json

    # Compute lift from two already-saved audits
    python scripts/run_attck_coverage_audit.py \\
        --compare-pre  experiments/results/attck_coverage/pre_deployment_audit.json \\
        --compare-post experiments/results/attck_coverage/post_deployment_audit.json

Input rule format (JSONL, one rule per line)
---------------------------------------------
    {"platform": "splunk", "technique": "T1110", "sub_technique": "T1110.001", "id": "rule-001"}

Place at: scripts/run_attck_coverage_audit.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.evaluation.attck_coverage_auditor import (
    ATTCKCoverageAuditor,
    CoverageAuditResult,
)
from src.utils.logger import get_logger, setup_logging

log = get_logger(__name__)


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_attck_coverage_audit.py",
        description="Audit ATT&CK technique coverage for a rule set, or compare two saved audits.",
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--rules",
        help="Path to a JSONL rule file to audit (single-audit mode).",
    )
    mode.add_argument(
        "--compare-pre",
        help="Path to a saved pre-deployment audit JSON (comparison mode, used with --compare-post).",
    )

    parser.add_argument(
        "--compare-post",
        help="Path to a saved post-deployment audit JSON (required with --compare-pre).",
    )
    parser.add_argument(
        "--label", default="audit",
        help="Label for a single-audit run (default: 'audit').",
    )
    parser.add_argument(
        "--output", default=None,
        help="Output path for the audit/lift JSON. If omitted, prints to stdout only.",
    )
    parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return parser


def _load_saved_audit(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main() -> int:
    args = _build_arg_parser().parse_args()
    setup_logging(level=args.log_level)

    auditor = ATTCKCoverageAuditor()

    # ── Comparison mode ────────────────────────────────────────────────────
    if args.compare_pre:
        if not args.compare_post:
            print("[ERROR] --compare-post is required when using --compare-pre", file=sys.stderr)
            return 1

        # Re-run audit() is not possible from saved JSON alone (it only
        # stores the aggregated report, not the raw rule list), so the
        # comparison path re-derives covered-ID sets directly from the
        # saved per-platform "covered" listings rather than calling
        # compute_lift() against reconstructed CoverageAuditResult objects.
        pre_data  = _load_saved_audit(args.compare_pre)
        post_data = _load_saved_audit(args.compare_post)

        pre_pct  = pre_data["aggregate_coverage_pct"]
        post_pct = post_data["aggregate_coverage_pct"]
        lift_pp  = (post_pct - pre_pct) * 100

        per_platform_lift = {}
        for platform in pre_data.get("per_platform", {}):
            pre_p  = pre_data["per_platform"].get(platform, {}).get("coverage_pct", 0.0)
            post_p = post_data.get("per_platform", {}).get(platform, {}).get("coverage_pct", 0.0)
            per_platform_lift[platform] = round((post_p - pre_p) * 100, 2)

        result = {
            "pre_label":          pre_data.get("label", "pre"),
            "post_label":         post_data.get("label", "post"),
            "pre_aggregate_pct":  round(pre_pct, 4),
            "post_aggregate_pct": round(post_pct, 4),
            "lift_pct_points":    round(lift_pp, 2),
            "per_platform_lift":  per_platform_lift,
        }

        print("\n── ATT&CK Coverage Lift ─────────────────────────────────────")
        print(f"  {result['pre_label']}: {result['pre_aggregate_pct']:.1%}")
        print(f"  {result['post_label']}: {result['post_aggregate_pct']:.1%}")
        print(f"  Lift: +{result['lift_pct_points']:.1f} percentage points")
        for platform, lift in per_platform_lift.items():
            print(f"    {platform:<10}: +{lift:.1f} pp")
        print("──────────────────────────────────────────────────────────────")

        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(result, indent=2))
            log.info("Lift comparison saved", extra={"path": str(out_path)})

        return 0

    # ── Single-audit mode ──────────────────────────────────────────────────
    rules_path = Path(args.rules)
    if not rules_path.exists():
        print(f"[ERROR] Rules file not found: {rules_path}", file=sys.stderr)
        return 1

    rules = auditor.load_rules_from_jsonl(rules_path)
    log.info("Loaded rules for audit", extra={"path": str(rules_path), "count": len(rules)})

    result: CoverageAuditResult = auditor.audit(rules, label=args.label)

    print(f"\n── ATT&CK Coverage Audit: {args.label} ────────────────────────")
    print(f"  Rules audited:        {result.total_rules_audited}")
    print(f"  Aggregate coverage:   {result.aggregate_coverage_pct:.1%} "
          f"({result.aggregate_covered_techniques}/{result.aggregate_total_techniques} techniques)")
    for platform, report in result.per_platform.items():
        print(f"  {platform:<10}: {report.coverage_pct:.1%} "
              f"({report.covered_techniques}/{report.total_techniques})")
    print("──────────────────────────────────────────────────────────────")

    if args.output:
        result.save(args.output)
        print(f"\nSaved to: {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())