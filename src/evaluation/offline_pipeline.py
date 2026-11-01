"""
offline_pipeline.py
End-to-end reproducible offline evaluation pipeline for NIDS models.

Loads frozen XGBoost replacement models, validates input datasets against the canonical
63-feature schema, performs contamination/overlap checks, normalizes labels, runs
batch inference, and calculates comprehensive classification and intrusion metrics
using OfflineEvaluator.
"""

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union
import numpy as np
import pandas as pd
import xgboost as xgb

from .offline_evaluator import OfflineEvaluator, EvaluationReport

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_MODEL_PATH = REPO_ROOT / "models" / "replacement_v1" / "xgboost_nids_replacement_v1.json"
DEFAULT_FEATS_PATH = REPO_ROOT / "models" / "replacement_v1" / "selected_features.txt"
DEFAULT_LABELS_PATH = REPO_ROOT / "models" / "replacement_v1" / "label_mapping.json"
DEFAULT_PROD_DB = REPO_ROOT / "app_v2" / "data" / "nids.sqlite"


class DataLeakageError(ValueError):
    """Raised when an evaluation dataset overlaps with training partitions."""
    pass


class SchemaValidationError(ValueError):
    """Raised when an evaluation dataset violates feature schema or ordering."""
    pass


class OfflineEvaluationPipeline:
    """
    Executes reproducible, read-only offline evaluation on candidate datasets.
    """

    def __init__(
        self,
        model_path: Optional[Path] = None,
        features_path: Optional[Path] = None,
        label_mapping_path: Optional[Path] = None,
        output_dir: Optional[Path] = None,
    ):
        self.model_path = Path(model_path or DEFAULT_MODEL_PATH)
        self.features_path = Path(features_path or DEFAULT_FEATS_PATH)
        self.label_mapping_path = Path(label_mapping_path or DEFAULT_LABELS_PATH)
        self.output_dir = Path(output_dir or (REPO_ROOT / "reports" / "evaluation" / "stage4c1"))

        # Verify files exist
        if not self.model_path.is_file():
            raise FileNotFoundError(f"Model file not found: {self.model_path}")
        if not self.features_path.is_file():
            raise FileNotFoundError(f"Selected features file not found: {self.features_path}")
        if not self.label_mapping_path.is_file():
            raise FileNotFoundError(f"Label mapping file not found: {self.label_mapping_path}")

        # Load canonical features
        with open(self.features_path, "r", encoding="utf-8") as f:
            self.ordered_features = [line.strip() for line in f if line.strip()]

        if len(self.ordered_features) != 63:
            raise ValueError(f"Expected exactly 63 selected features, found {len(self.ordered_features)}.")

        # Load label mapping
        with open(self.label_mapping_path, "r", encoding="utf-8") as f:
            self.raw_mapping = json.load(f)

        self.evaluator = OfflineEvaluator(label_mapping=self.raw_mapping, benign_label="BENIGN")

        # Load frozen model booster in read-only mode
        self.booster = xgb.Booster()
        self.booster.load_model(str(self.model_path))

    def validate_schema(self, df: pd.DataFrame) -> None:
        """Validates that all 63 canonical features are present in the dataset."""
        missing = [f for f in self.ordered_features if f not in df.columns]
        if missing:
            raise SchemaValidationError(
                f"Evaluation dataset is missing {len(missing)} required features: {missing[:5]}..."
            )

    def sanitize_features(self, df: pd.DataFrame) -> np.ndarray:
        """
        Extracts the 63 canonical features in exact order, converts to float32,
        clamps all non-finite values (NaN, +Inf, -Inf) to 0.0, and clips negative values to 0.0.
        """
        matrix = df[self.ordered_features].to_numpy(dtype=np.float32, copy=True)
        np.nan_to_num(matrix, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
        np.clip(matrix, a_min=0.0, a_max=None, out=matrix)
        return matrix

    def validate_labels(self, raw_labels: Sequence[Any]) -> List[str]:
        """Normalizes and validates ground truth labels against the 15-class dictionary."""
        normalized = []
        for idx, lbl in enumerate(raw_labels):
            try:
                norm_name = self.evaluator._normalize_item(lbl)
                normalized.append(norm_name)
            except ValueError as exc:
                raise ValueError(f"Label at row {idx} is invalid or unsupported: '{lbl}'. Error: {exc}") from exc
        return normalized

    @staticmethod
    def compute_row_fingerprints(feature_matrix: np.ndarray) -> List[str]:
        """Computes deterministic 64-bit MD5 hashes of feature rows for overlap detection."""
        fingerprints = []
        for row in feature_matrix:
            # Hash bytes of float32 array
            row_bytes = row.tobytes()
            fp = hashlib.md5(row_bytes).hexdigest()
            fingerprints.append(fp)
        return fingerprints

    def evaluate_dataset(
        self,
        df: pd.DataFrame,
        label_column: str,
        training_fingerprints: Optional[Set[str]] = None,
        allow_training_overlap: bool = False,
    ) -> EvaluationReport:
        """
        Executes end-to-end offline evaluation.

        :param df: Candidate evaluation DataFrame.
        :param label_column: Column name containing ground truth labels.
        :param training_fingerprints: Optional set of MD5 hashes from training rows.
        :param allow_training_overlap: Strict flag; if False and overlap detected, raises DataLeakageError.
        :return: Comprehensive EvaluationReport.
        """
        # Safety Check: Assert we never touch the production database path
        if os.environ.get("NIDS_DB_PATH") == str(DEFAULT_PROD_DB):
            raise PermissionError("PROTECTION FAULT: Evaluation attempted while pointing to production DB!")

        if len(df) == 0:
            raise ValueError("Evaluation dataset cannot be empty (0 rows).")

        if label_column not in df.columns:
            raise KeyError(f"Label column '{label_column}' not found in dataset columns.")

        # 1. Validate Schema
        self.validate_schema(df)

        # 2. Extract and Sanitize Features
        feature_matrix = self.sanitize_features(df)

        # 3. Check for Contamination / Training Overlap
        if training_fingerprints is not None:
            candidate_fps = self.compute_row_fingerprints(feature_matrix)
            overlap_count = sum(1 for fp in candidate_fps if fp in training_fingerprints)
            overlap_pct = (overlap_count / len(candidate_fps)) * 100.0

            if overlap_count > 0 and not allow_training_overlap:
                raise DataLeakageError(
                    f"DATA LEAKAGE DETECTED: {overlap_count} / {len(candidate_fps)} rows ({overlap_pct:.2f}%) "
                    "overlap with training corpus. Independent evaluation cannot proceed on contaminated data."
                )

        # 4. Validate Ground-Truth Labels
        y_true = self.validate_labels(df[label_column].tolist())

        # 5. Execute Model Batch Inference
        dmatrix = xgb.DMatrix(feature_matrix, feature_names=self.ordered_features)
        raw_probs = self.booster.predict(dmatrix)  # shape (N, 15)
        pred_class_ids = raw_probs.argmax(axis=1)

        # Map predicted IDs to class names
        y_pred = [self.evaluator.id_to_name[int(cid)] for cid in pred_class_ids]

        # 6. Compute Comprehensive Metrics
        report = self.evaluator.evaluate(y_true, y_pred)

        # 7. Write Structured Outputs to Isolated Output Directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        cm_df = report.to_confusion_matrix_dataframe()
        cm_df.to_csv(self.output_dir / "confusion_matrix.csv")

        cls_df = report.to_classification_dataframe()
        cls_df.to_csv(self.output_dir / "classification_report.csv", index=False)

        with open(self.output_dir / "evaluation_summary.json", "w", encoding="utf-8") as f:
            f.write(report.to_json(indent=2))

        return report
