"""
src/evaluation package
Reusable offline evaluation utilities for the NIDS project.
"""

from .offline_evaluator import (
    OfflineEvaluator,
    EvaluationReport,
    ClassMetrics,
    BinaryIntrusionMetrics,
)
from .offline_pipeline import (
    OfflineEvaluationPipeline,
    DataLeakageError,
    SchemaValidationError,
)

__all__ = [
    "OfflineEvaluator",
    "EvaluationReport",
    "ClassMetrics",
    "BinaryIntrusionMetrics",
    "OfflineEvaluationPipeline",
    "DataLeakageError",
    "SchemaValidationError",
]
