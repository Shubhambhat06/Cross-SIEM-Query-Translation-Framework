"""
Evaluation — Layer 6 of the NL-SIEM pipeline.

Measures translation quality across five SIEM platforms:
  - Syntactic validity    (SyntaxValidator)
  - Semantic equivalence  (SemanticScorer: BLEU / ROUGE-L / field-F1)
  - Execution match       (ExecutionMatcher: ES Docker sandbox)
  - Error classification  (ErrorAnalyzer: failure taxonomy)
  - Ablation study        (AblationRunner: conditions A / B / C)
  - Table compilation     (MetricsAggregator: Table 2, 3, 4)

Dependencies: Layers 0 (utils), 1 (ir), 2 (translators), 5 (agents).

Quickstart
----------
    from src.evaluation import (
        SyntaxValidator, SemanticScorer,
        ExecutionMatcher, ErrorAnalyzer,
        AblationRunner, MetricsAggregator,
    )

    validator  = SyntaxValidator()
    scorer     = SemanticScorer()
    matcher    = ExecutionMatcher()   # needs ES; falls back to structural
    analyzer   = ErrorAnalyzer()
    ablation   = AblationRunner(translate_fn=my_translate)
    aggregator = MetricsAggregator()

    # Evaluate one query
    syn_result  = validator.validate("splunk", "index=* | stats count by src_ip")
    sem_result  = scorer.score(hypothesis, reference, platform="splunk")
    exec_result = matcher.match(hypothesis, reference, platform="elastic")
    error_rep   = analyzer.analyze("splunk", hypothesis, reference,
                                   syntax_result=syn_result,
                                   semantic_score=sem_result)
"""

from src.evaluation.ablation         import AblationRecord, AblationResults, AblationRunner, ConditionMetrics
from src.evaluation.error_analyzer   import ErrorAnalyzer, ErrorDistribution, ErrorReport
from src.evaluation.execution_match  import ExecutionMatchResult, ExecutionMatcher, ExecutionMetrics
from src.evaluation.metrics_aggregator import (
    AggregatedResults,
    MetricsAggregator,
    Table2Row,
    Table3Row,
    Table4Row,
)
from src.evaluation.semantic_scorer  import SemanticMetrics, SemanticScore, SemanticScorer
from src.evaluation.syntax_validator import SyntaxMetrics, SyntaxValidationResult, SyntaxValidator

__all__ = [
    # Syntax
    "SyntaxValidator",
    "SyntaxValidationResult",
    "SyntaxMetrics",
    # Semantic
    "SemanticScorer",
    "SemanticScore",
    "SemanticMetrics",
    # Execution
    "ExecutionMatcher",
    "ExecutionMatchResult",
    "ExecutionMetrics",
    # Error
    "ErrorAnalyzer",
    "ErrorReport",
    "ErrorDistribution",
    # Ablation
    "AblationRunner",
    "AblationResults",
    "AblationRecord",
    "ConditionMetrics",
    # Aggregation
    "MetricsAggregator",
    "AggregatedResults",
    "Table2Row",
    "Table3Row",
    "Table4Row",
]