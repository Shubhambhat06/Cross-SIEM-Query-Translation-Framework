"""
evaluation/models.py

Core dataclasses used throughout the evaluation framework.

These classes define the structure of:
- dataset samples
- per-query evaluation results
- aggregated metrics
- overall evaluation summary
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional
import json


# ==========================================================
# Dataset Sample
# ==========================================================

@dataclass(slots=True)
class Sample:
    """
    One benchmark sample.
    """

    sample_id: str

    nl_query: str

    ground_truth: list[str]

    tactic: str

    complexity: str

    metadata: dict = field(default_factory=dict)


# ==========================================================
# Per-query evaluation result
# ==========================================================

@dataclass(slots=True)
class EvaluationResult:
    """
    Stores the outcome of evaluating a single NL query.
    """

    sample_id: str

    nl_query: str

    predicted_attck: list[str]

    ground_truth_attck: list[str]

    attack_correct: bool

    ir_valid: bool

    translation_success: bool

    syntax_valid: bool

    execution_success: bool

    latency_s: float

    prompt_tokens: int

    completion_tokens: int

    total_tokens: int

    estimated_cost: float

    confidence: float

    drift_score: float

    platform_results: dict = field(default_factory=dict)

    metadata: dict = field(default_factory=dict)


# ==========================================================
# Aggregated metrics
# ==========================================================

@dataclass(slots=True)
class MetricSummary:

    total_queries: int = 0

    attack_accuracy: float = 0.0

    precision: float = 0.0

    recall: float = 0.0

    f1: float = 0.0

    avg_latency: float = 0.0

    avg_cost: float = 0.0

    avg_drift: float = 0.0

    ir_success_rate: float = 0.0

    translation_success_rate: float = 0.0

    syntax_success_rate: float = 0.0

    execution_success_rate: float = 0.0

    total_prompt_tokens: int = 0

    total_completion_tokens: int = 0

    total_tokens: int = 0


# ==========================================================
# Whole evaluation run
# ==========================================================

@dataclass(slots=True)
class RunSummary:

    model: str

    provider: str

    dataset: str

    sample_size: int

    started_at: str

    finished_at: str

    elapsed_s: float

    metrics: MetricSummary

    results: list[EvaluationResult]


# ==========================================================
# Serialization helpers
# ==========================================================

def to_dict(obj):
    """
    Convert any dataclass to a dictionary.
    """
    return asdict(obj)


def to_json(obj, indent: int = 2):
    """
    Convert dataclass to JSON.
    """
    return json.dumps(
        asdict(obj),
        indent=indent,
        ensure_ascii=False,
    )