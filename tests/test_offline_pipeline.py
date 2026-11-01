"""
test_offline_pipeline.py
Unit tests for OfflineEvaluationPipeline.
Tests schema validation, label mapping, non-finite clamping, overlap detection,
deterministic inference, metric consistency, empty/invalid inputs, and production DB protection.
"""

import json
import os
from pathlib import Path
import unittest
import numpy as np
import pandas as pd

import sys
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.evaluation.offline_pipeline import (
    OfflineEvaluationPipeline,
    DataLeakageError,
    SchemaValidationError,
)


class TestOfflineEvaluationPipeline(unittest.TestCase):
    """Exhaustive test suite for OfflineEvaluationPipeline."""

    @classmethod
    def setUpClass(cls):
        cls.test_out_dir = REPO_ROOT / "reports" / "evaluation" / "stage4c1" / "test_scratch"
        cls.test_out_dir.mkdir(parents=True, exist_ok=True)
        cls.pipeline = OfflineEvaluationPipeline(output_dir=cls.test_out_dir)

    def _create_synthetic_fixture(self, n_rows: int = 10, label: str = "BENIGN") -> pd.DataFrame:
        """Creates a deterministic synthetic test DataFrame adhering to the 63-feature schema."""
        data = {}
        for feat in self.pipeline.ordered_features:
            data[feat] = [1.0 * (i + 1) for i in range(n_rows)]
        data["Label"] = [label] * n_rows
        return pd.DataFrame(data)

    # --------------------------------------------------------------------------
    # 1. Dataset Schema and Feature-Order Validation
    # --------------------------------------------------------------------------
    def test_01_schema_validation(self):
        df = self._create_synthetic_fixture(5)
        # Valid schema passes
        self.pipeline.validate_schema(df)

        # Drop one required column -> must raise SchemaValidationError
        bad_df = df.drop(columns=["Destination Port"])
        with self.assertRaises(SchemaValidationError) as ctx:
            self.pipeline.validate_schema(bad_df)
        self.assertIn("Destination Port", str(ctx.exception))

    # --------------------------------------------------------------------------
    # 2. Label Mapping and Unsupported Classes
    # --------------------------------------------------------------------------
    def test_02_label_mapping_and_unsupported_classes(self):
        df = self._create_synthetic_fixture(5, label="BENIGN")
        # Valid label passes
        norm = self.pipeline.validate_labels(df["Label"])
        self.assertEqual(norm, ["BENIGN"] * 5)

        # Unsupported class raises ValueError
        bad_df = self._create_synthetic_fixture(5, label="MaliciousRansomware")
        with self.assertRaises(ValueError) as ctx:
            self.pipeline.validate_labels(bad_df["Label"])
        self.assertIn("MaliciousRansomware", str(ctx.exception))

    # --------------------------------------------------------------------------
    # 3. Missing and Non-Finite Feature Handling
    # --------------------------------------------------------------------------
    def test_03_non_finite_feature_handling(self):
        df = self._create_synthetic_fixture(4)
        # Inject NaN, +Inf, -Inf, and negative value
        df.loc[0, "Flow Duration"] = np.nan
        df.loc[1, "Flow Duration"] = np.inf
        df.loc[2, "Flow Duration"] = -np.inf
        df.loc[3, "Flow Duration"] = -999.0

        sanitized = self.pipeline.sanitize_features(df)
        self.assertEqual(sanitized.shape, (4, 63))
        self.assertFalse(np.isnan(sanitized).any(), "NaN must be clamped to 0.0.")
        self.assertFalse(np.isinf(sanitized).any(), "Inf must be clamped to 0.0.")
        self.assertTrue((sanitized >= 0.0).all(), "Negative values must be clipped to 0.0.")
        # Verify clamped values
        col_idx = self.pipeline.ordered_features.index("Flow Duration")
        for i in range(4):
            self.assertEqual(sanitized[i, col_idx], 0.0)

    # --------------------------------------------------------------------------
    # 4. Duplicate and Overlap Checks (Data Leakage Detection)
    # --------------------------------------------------------------------------
    def test_04_overlap_and_leakage_detection(self):
        df = self._create_synthetic_fixture(5)
        matrix = self.pipeline.sanitize_features(df)
        fps = self.pipeline.compute_row_fingerprints(matrix)

        # Simulate training hash set containing fingerprint of row 0
        training_hashes = {fps[0]}

        # Evaluating with overlap check and allow_training_overlap=False -> DataLeakageError
        with self.assertRaises(DataLeakageError) as ctx:
            self.pipeline.evaluate_dataset(
                df,
                label_column="Label",
                training_fingerprints=training_hashes,
                allow_training_overlap=False,
            )
        self.assertIn("DATA LEAKAGE DETECTED", str(ctx.exception))

        # With allow_training_overlap=True, evaluation proceeds
        report = self.pipeline.evaluate_dataset(
            df,
            label_column="Label",
            training_fingerprints=training_hashes,
            allow_training_overlap=True,
        )
        self.assertEqual(report.total_samples, 5)

    # --------------------------------------------------------------------------
    # 5. Deterministic Predictions and Report Generation
    # --------------------------------------------------------------------------
    def test_05_deterministic_predictions_and_artifacts(self):
        df = self._create_synthetic_fixture(10, label="BENIGN")

        rep1 = self.pipeline.evaluate_dataset(df, label_column="Label")
        rep2 = self.pipeline.evaluate_dataset(df, label_column="Label")

        self.assertEqual(rep1.to_json(), rep2.to_json(), "Outputs must be bit-for-bit identical.")
        self.assertTrue((self.test_out_dir / "confusion_matrix.csv").is_file())
        self.assertTrue((self.test_out_dir / "classification_report.csv").is_file())
        self.assertTrue((self.test_out_dir / "evaluation_summary.json").is_file())

    # --------------------------------------------------------------------------
    # 6. Correct Metric Calculations and Confusion Matrix Totals
    # --------------------------------------------------------------------------
    def test_06_metric_calculations_and_totals(self):
        # 10 rows of BENIGN
        df = self._create_synthetic_fixture(10, label="BENIGN")
        report = self.pipeline.evaluate_dataset(df, label_column="Label")

        self.assertEqual(report.total_samples, 10)
        # Sum of confusion matrix elements must equal total_samples
        cm_total = sum(sum(row) for row in report.confusion_matrix)
        self.assertEqual(cm_total, 10)

        # Check binary intrusion metrics
        bm = report.binary_intrusion_metrics
        self.assertIsNotNone(bm)
        self.assertEqual(bm.benign_support, 10)
        self.assertEqual(bm.attack_support, 0)
        self.assertEqual(bm.missed_attack_rate, 0.0)

    # --------------------------------------------------------------------------
    # 7. Empty Datasets and Invalid Inputs
    # --------------------------------------------------------------------------
    def test_07_empty_and_invalid_inputs(self):
        empty_df = pd.DataFrame(columns=self.pipeline.ordered_features + ["Label"])
        with self.assertRaises(ValueError) as ctx:
            self.pipeline.evaluate_dataset(empty_df, label_column="Label")
        self.assertIn("cannot be empty", str(ctx.exception))

        # Missing label column
        df = self._create_synthetic_fixture(5)
        with self.assertRaises(KeyError) as ctx:
            self.pipeline.evaluate_dataset(df, label_column="NonExistentLabel")
        self.assertIn("NonExistentLabel", str(ctx.exception))

    # --------------------------------------------------------------------------
    # 8. Protection Against Accidental Production DB Writes
    # --------------------------------------------------------------------------
    def test_08_production_db_write_protection(self):
        prod_db = REPO_ROOT / "app_v2" / "data" / "nids.sqlite"
        old_env = os.environ.get("NIDS_DB_PATH")
        try:
            os.environ["NIDS_DB_PATH"] = str(prod_db)
            df = self._create_synthetic_fixture(5)
            with self.assertRaises(PermissionError) as ctx:
                self.pipeline.evaluate_dataset(df, label_column="Label")
            self.assertIn("PROTECTION FAULT", str(ctx.exception))
        finally:
            if old_env is not None:
                os.environ["NIDS_DB_PATH"] = old_env
            else:
                os.environ.pop("NIDS_DB_PATH", None)


if __name__ == "__main__":
    unittest.main()
