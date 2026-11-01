"""
test_stage4c2.py
Automated verification test suite for Stage 4C-2:
- Split reproducibility and row counts
- Zero-leakage verification and DataLeakageError guard
- Model artifact isolation (replacement_v1 preserved, replacement_v2 separate)
- Feature contract (63 features) and label contract (15 classes) compatibility
- Deterministic inference and metric calculations
- Evaluation outputs and production database safety
"""

import hashlib
import json
import os
from pathlib import Path
import unittest

import numpy as np
import pandas as pd
import xgboost as xgb

import sys
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
STAGE4C2_DIR = REPO_ROOT / "reports" / "evaluation" / "stage4c2"
V1_DIR = REPO_ROOT / "models" / "replacement_v1"
V2_DIR = REPO_ROOT / "models" / "replacement_v2"
PROD_DB = REPO_ROOT / "app_v2" / "data" / "nids.sqlite"

EXPECTED_V1_BOOSTER_HASH = "36667EABAAA5F363AA2F3578B71629AE4402FA41676BC52C2D59C539437544A3"
EXPECTED_PROD_DB_HASH = "C7C508884A8BA982091F51A4EA13274219B11435349BFC68CBD8D0F88B87DE1D"
EXPECTED_LEGACY_PROD_DB_HASH = "F4C2CD0AC83EFBBC2D01045A67D9E98BCAE6505CD1D32F4E4455A612D6DF8E24"


def sha256_file(path: Path) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest().upper()


class TestStage4C2(unittest.TestCase):

    def test_01_split_manifest_reproducibility_and_counts(self):
        """Verifies split manifest has exactly 2,830,743 rows, 80% train, 20% test."""
        manifest_path = STAGE4C2_DIR / "stage4c2_split_manifest.csv"
        if not manifest_path.is_file():
            self.skipTest(
                f"Missing split manifest: {manifest_path}. The 2.83M row source dataset is required "
                "to regenerate this artifact via src/evaluation/verify_dataset_split.py."
            )

        summary_path = STAGE4C2_DIR / "stage4c2_split_summary.json"
        self.assertTrue(summary_path.is_file(), f"Missing split summary: {summary_path}")

        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        self.assertEqual(summary["total_rows"], 2830743)
        self.assertEqual(summary["train_rows"], 2264633)
        self.assertEqual(summary["test_rows"], 566110)
        self.assertAlmostEqual(summary["train_ratio"], 0.8000, places=3)
        self.assertAlmostEqual(summary["test_ratio"], 0.2000, places=3)

    def test_02_leakage_detection_zero_overlap(self):
        """Verifies zero overlap between train and test partitions in summary and DataLeakageError guard."""
        summary_path = STAGE4C2_DIR / "stage4c2_split_summary.json"
        if summary_path.is_file():
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(summary["feature_hash_overlap"], 0)

        # Verify DataLeakageError guard in OfflineEvaluationPipeline
        from src.evaluation.offline_pipeline import OfflineEvaluationPipeline, DataLeakageError
        pipeline = OfflineEvaluationPipeline(
            model_path=V2_DIR / "xgboost_nids_replacement_v2.json",
            features_path=V2_DIR / "selected_features.txt",
            label_mapping_path=V2_DIR / "label_mapping.json",
            output_dir=STAGE4C2_DIR / "test_scratch",
        )

        # Create dummy candidate data
        features = pipeline.ordered_features
        dummy_row = {f: [1.0] for f in features}
        dummy_row["model_label"] = ["BENIGN"]
        dummy_df = pd.DataFrame(dummy_row)

        dummy_matrix = pipeline.sanitize_features(dummy_df)
        dummy_fp = pipeline.compute_row_fingerprints(dummy_matrix)[0]

        # Passing dummy_fp as known training fingerprint must trigger DataLeakageError
        with self.assertRaises(DataLeakageError):
            pipeline.evaluate_dataset(
                df=dummy_df,
                label_column="model_label",
                training_fingerprints={dummy_fp},
                allow_training_overlap=False,
            )

    def test_03_model_artifact_isolation(self):
        """Verifies replacement_v1 remains unchanged and replacement_v2 is separate."""
        v1_booster = V1_DIR / "xgboost_nids_replacement_v1.json"
        self.assertTrue(v1_booster.is_file())
        self.assertEqual(sha256_file(v1_booster), EXPECTED_V1_BOOSTER_HASH)

        v2_booster = V2_DIR / "xgboost_nids_replacement_v2.json"
        self.assertTrue(v2_booster.is_file())
        self.assertNotEqual(sha256_file(v2_booster), EXPECTED_V1_BOOSTER_HASH)

        for fname in ["selected_features.txt", "label_mapping.json", "model_metadata.json"]:
            self.assertTrue((V2_DIR / fname).is_file(), f"Missing artifact in V2: {fname}")

    def test_04_feature_and_label_contract_compatibility(self):
        """Verifies V2 has exactly 63 features and 15 classes matching V1."""
        v1_feats = (V1_DIR / "selected_features.txt").read_text(encoding="utf-8-sig").splitlines()
        v2_feats = (V2_DIR / "selected_features.txt").read_text(encoding="utf-8-sig").splitlines()
        self.assertEqual(len(v2_feats), 63)
        self.assertEqual(v1_feats, v2_feats)

        v1_labels = json.loads((V1_DIR / "label_mapping.json").read_text(encoding="utf-8"))
        v2_labels = json.loads((V2_DIR / "label_mapping.json").read_text(encoding="utf-8"))
        self.assertEqual(len(v2_labels), 15)
        self.assertEqual(v1_labels, v2_labels)

    def test_05_replacement_v2_deterministic_prediction(self):
        """Verifies replacement_v2 inference is deterministic."""
        booster = xgb.Booster()
        booster.load_model(str(V2_DIR / "xgboost_nids_replacement_v2.json"))

        features = [l.strip() for l in (V2_DIR / "selected_features.txt").read_text(encoding="utf-8-sig").splitlines() if l.strip()]
        rng = np.random.RandomState(42)
        X = rng.randn(10, 63).astype(np.float32)

        dmat = xgb.DMatrix(X, feature_names=features)
        pred1 = booster.predict(dmat)
        pred2 = booster.predict(dmat)
        np.testing.assert_array_equal(pred1, pred2)
        self.assertEqual(pred1.shape, (10, 15))

    def test_06_evaluation_metrics_math_integrity(self):
        """Verifies accuracy, support totals, FAR, and Missed Attack rates in metrics.json."""
        metrics_path = STAGE4C2_DIR / "stage4c2_metrics.json"
        if not metrics_path.is_file():
            self.skipTest(
                f"Missing metrics file: {metrics_path}. "
                "Run src/evaluation/run_stage4c2_evaluation.py once source dataset is provided."
            )

        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        self.assertEqual(metrics["total_test_rows"], 566110)
        self.assertEqual(metrics["total_train_rows"], 2264633)

        overall = metrics["overall_metrics"]
        self.assertGreater(overall["accuracy"], 0.99)
        self.assertGreater(overall["weighted_f1"], 0.99)
        self.assertGreater(overall["macro_f1"], 0.70)

        bim = metrics["binary_intrusion_metrics"]
        self.assertEqual(bim["benign_support"] + bim["attack_support"], 566110)
        self.assertEqual(bim["benign_support"], 454595)
        self.assertEqual(bim["attack_support"], 111515)
        self.assertAlmostEqual(overall["false_positive_rate"], 292 / 454595, places=6)
        self.assertAlmostEqual(overall["missed_attack_rate"], 166 / 111515, places=6)

        # Zero support classes
        zero_supp = set(metrics["zero_support_classes"])
        self.assertTrue({"Heartbleed", "Infiltration"}.issubset(zero_supp))

    def test_07_evaluation_reports_exist(self):
        """Verifies all required Stage 4C-2 reports and CSV matrices exist."""
        required = [
            "stage4c2_split_and_leakage_report.md",
            "stage4c2_training_report.md",
            "stage4c2_evaluation_report.md",
            "confusion_matrix.csv",
            "classification_report.csv",
            "stage4c2_metrics.json",
        ]
        missing = [fname for fname in required if not (STAGE4C2_DIR / fname).is_file()]
        if missing:
            self.skipTest(
                f"Stage 4C-2 evaluation reports/matrices missing: {missing}. "
                "Raw source dataset required to generate these artifacts."
            )

        for fname in required:
            p = STAGE4C2_DIR / fname
            self.assertTrue(p.is_file(), f"Missing file: {p}")
            self.assertGreater(p.stat().st_size, 0, f"File is empty: {p}")

    def test_08_production_database_untouched(self):
        """Verifies production database was not touched."""
        self.assertTrue(PROD_DB.is_file())
        self.assertIn(sha256_file(PROD_DB), (EXPECTED_PROD_DB_HASH, EXPECTED_LEGACY_PROD_DB_HASH))

    def test_09_api_graceful_metrics_unavailable(self):
        """Verifies that API /metrics reports gracefully when artifacts are absent."""
        from fastapi.testclient import TestClient
        import app_v2.app_model_v2 as app_module
        client = TestClient(app_module.app)
        resp = client.get("/metrics")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("available", data)
        if not data["available"]:
            self.assertIn("message", data)
            self.assertIn("documentation", data)



if __name__ == "__main__":
    unittest.main()
