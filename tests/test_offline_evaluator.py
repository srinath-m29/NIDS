"""
test_offline_evaluator.py
Comprehensive automated test suite for the OfflineEvaluator utility.
Validates metric accuracy, confusion matrix construction, edge case handling,
error reporting, and operational intrusion metrics.
"""

import json
from pathlib import Path
import unittest
import numpy as np
import pandas as pd

import sys
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.evaluation.offline_evaluator import (
    OfflineEvaluator,
    EvaluationReport,
    ClassMetrics,
    BinaryIntrusionMetrics,
)


class TestOfflineEvaluator(unittest.TestCase):
    """Exhaustive unit test suite for OfflineEvaluator."""

    def setUp(self):
        self.sample_mapping = {
            0: "BENIGN",
            1: "Bot",
            2: "DDoS",
            3: "PortScan"
        }
        self.evaluator = OfflineEvaluator(label_mapping=self.sample_mapping)

    # --------------------------------------------------------------------------
    # 1. Correct Confusion Matrix Construction
    # --------------------------------------------------------------------------
    def test_01_confusion_matrix_construction(self):
        # Actual:    [BENIGN, BENIGN, Bot,  DDoS, PortScan]
        # Predicted: [BENIGN, Bot,    Bot,  DDoS, BENIGN]
        y_true = [0, 0, 1, 2, 3]
        y_pred = [0, 1, 1, 2, 0]

        report = self.evaluator.evaluate(y_true, y_pred)
        self.assertEqual(report.total_samples, 5)
        self.assertEqual(report.accuracy, 3 / 5)

        # Class indices: 0: BENIGN, 1: Bot, 2: DDoS, 3: PortScan
        cm = report.confusion_matrix
        # Row 0 (Actual BENIGN): [1, 1, 0, 0]
        self.assertEqual(cm[0], [1, 1, 0, 0])
        # Row 1 (Actual Bot):    [0, 1, 0, 0]
        self.assertEqual(cm[1], [0, 1, 0, 0])
        # Row 2 (Actual DDoS):   [0, 0, 1, 0]
        self.assertEqual(cm[2], [0, 0, 1, 0])
        # Row 3 (Actual PortScan): [1, 0, 0, 0]
        self.assertEqual(cm[3], [1, 0, 0, 0])

        # Test conversion to DataFrame
        df_cm = report.to_confusion_matrix_dataframe()
        self.assertEqual(df_cm.shape, (4, 4))
        self.assertEqual(df_cm.loc["Actual_BENIGN", "Pred_BENIGN"], 1)
        self.assertEqual(df_cm.loc["Actual_BENIGN", "Pred_Bot"], 1)

    # --------------------------------------------------------------------------
    # 2. Per-Class Metric Calculations
    # --------------------------------------------------------------------------
    def test_02_per_class_metric_calculations(self):
        # 3 classes: A, B, C
        evaluator = OfflineEvaluator()
        y_true = ["A", "A", "A", "B", "B", "C"]
        y_pred = ["A", "A", "B", "B", "C", "C"]

        report = evaluator.evaluate(y_true, y_pred)
        m_a = report.per_class_metrics["A"]
        # Class A: TP=2, FP=0, FN=1, TN=3, Support=3
        self.assertEqual(m_a.true_positives, 2)
        self.assertEqual(m_a.false_positives, 0)
        self.assertEqual(m_a.false_negatives, 1)
        self.assertEqual(m_a.true_negatives, 3)
        self.assertEqual(m_a.support, 3)
        self.assertAlmostEqual(m_a.precision, 2 / 2, places=5)
        self.assertAlmostEqual(m_a.recall, 2 / 3, places=5)
        self.assertAlmostEqual(m_a.specificity, 3 / 3, places=5)
        self.assertAlmostEqual(m_a.f1_score, 2 * (1.0 * (2/3)) / (1.0 + (2/3)), places=5)

        # Class B: TP=1, FP=1, FN=1, TN=3, Support=2
        m_b = report.per_class_metrics["B"]
        self.assertEqual(m_b.true_positives, 1)
        self.assertEqual(m_b.false_positives, 1)
        self.assertEqual(m_b.false_negatives, 1)
        self.assertAlmostEqual(m_b.precision, 1 / 2, places=5)
        self.assertAlmostEqual(m_b.recall, 1 / 2, places=5)
        self.assertAlmostEqual(m_b.f1_score, 0.5, places=5)

    # --------------------------------------------------------------------------
    # 3. Missing or Invalid Labels
    # --------------------------------------------------------------------------
    def test_03_missing_or_invalid_labels(self):
        # None or invalid type in labels
        with self.assertRaises(ValueError):
            self.evaluator.evaluate([0, None], [0, 1])

        with self.assertRaises(ValueError):
            self.evaluator.evaluate([0, 1], [0, 3.14])  # float not supported as label

    # --------------------------------------------------------------------------
    # 4. Predictions Containing Unsupported Classes
    # --------------------------------------------------------------------------
    def test_04_unsupported_classes(self):
        # ID 99 is not in sample_mapping (0..3)
        with self.assertRaises(ValueError) as ctx:
            self.evaluator.evaluate([0, 1], [0, 99])
        self.assertIn("Unsupported class ID: 99", str(ctx.exception))

        # String label 'UnknownAttack' not in sample_mapping
        with self.assertRaises(ValueError) as ctx:
            self.evaluator.evaluate(["BENIGN", "UnknownAttack"], ["BENIGN", "Bot"])
        self.assertIn("Unsupported class name: 'UnknownAttack'", str(ctx.exception))

    # --------------------------------------------------------------------------
    # 5. Zero-Denominator Metric Cases
    # --------------------------------------------------------------------------
    def test_05_zero_denominator_cases(self):
        # Class PortScan (ID 3) is never predicted and never present in y_true
        # Class DDoS (ID 2) is present in y_true but never predicted (FP=0, TP=0 -> Precision denominator is 0)
        y_true = [0, 0, 1, 2]
        y_pred = [0, 0, 1, 0]

        report = self.evaluator.evaluate(y_true, y_pred)
        m_ddos = report.per_class_metrics["DDoS"]
        # DDoS was never predicted -> TP=0, FP=0 -> Precision must safely be 0.0
        self.assertEqual(m_ddos.precision, 0.0)
        self.assertEqual(m_ddos.recall, 0.0)
        self.assertEqual(m_ddos.f1_score, 0.0)

        # PortScan was never in true or pred -> TP=0, FP=0, FN=0 -> Support=0, Precision=0, Recall=0
        m_ps = report.per_class_metrics["PortScan"]
        self.assertEqual(m_ps.support, 0)
        self.assertEqual(m_ps.precision, 0.0)
        self.assertEqual(m_ps.recall, 0.0)
        self.assertEqual(m_ps.f1_score, 0.0)
        self.assertEqual(m_ps.specificity, 1.0)  # TN / (TN + FP) = 4 / 4 = 1.0

    # --------------------------------------------------------------------------
    # 6. Empty Input and Mismatched Input Lengths
    # --------------------------------------------------------------------------
    def test_06_empty_and_mismatched_inputs(self):
        # Empty arrays
        with self.assertRaises(ValueError) as ctx:
            self.evaluator.evaluate([], [])
        self.assertIn("cannot be empty", str(ctx.exception))

        # Mismatched lengths
        with self.assertRaises(ValueError) as ctx:
            self.evaluator.evaluate([0, 1, 2], [0, 1])
        self.assertIn("Mismatched input lengths", str(ctx.exception))

    # --------------------------------------------------------------------------
    # 7. Reproducible Output for Identical Inputs
    # --------------------------------------------------------------------------
    def test_07_reproducibility(self):
        y_true = [0, 1, 2, 3, 0, 1, 2, 3] * 10
        y_pred = [0, 1, 0, 3, 0, 2, 2, 3] * 10

        rep1 = self.evaluator.evaluate(y_true, y_pred)
        rep2 = self.evaluator.evaluate(y_true, y_pred)

        self.assertEqual(rep1.to_json(), rep2.to_json(), "Outputs must be bit-for-bit identical.")
        self.assertEqual(rep1.accuracy, rep2.accuracy)
        self.assertEqual(rep1.confusion_matrix, rep2.confusion_matrix)

    # --------------------------------------------------------------------------
    # 8. Binary Intrusion Detection Metrics (False Alarm & Missed Attack Rates)
    # --------------------------------------------------------------------------
    def test_08_binary_intrusion_metrics(self):
        # BENIGN = 0, Attack = 1 (Bot) or 2 (DDoS)
        # Sample:
        # 1. True: BENIGN, Pred: BENIGN (True Negative for Attack)
        # 2. True: BENIGN, Pred: BENIGN (True Negative for Attack)
        # 3. True: BENIGN, Pred: Bot    (False Positive for Attack = False Alarm)
        # 4. True: Bot,    Pred: Bot    (True Positive for Attack)
        # 5. True: DDoS,   Pred: DDoS   (True Positive for Attack)
        # 6. True: Bot,    Pred: BENIGN (False Negative for Attack = Missed Attack)
        y_true = [0, 0, 0, 1, 2, 1]
        y_pred = [0, 0, 1, 1, 2, 0]

        report = self.evaluator.evaluate(y_true, y_pred)
        bm = report.binary_intrusion_metrics
        self.assertIsNotNone(bm)

        self.assertEqual(bm.benign_support, 3)
        self.assertEqual(bm.attack_support, 3)
        self.assertEqual(bm.false_positives, 1, "Exactly 1 benign flow misclassified as attack.")
        self.assertEqual(bm.false_negatives, 1, "Exactly 1 attack flow misclassified as benign.")
        self.assertEqual(bm.benign_correct, 2)
        self.assertEqual(bm.attack_correct, 2)

        # False Positive Rate = FP / Benign Support = 1 / 3 = 0.33333
        self.assertAlmostEqual(bm.false_positive_rate, 1 / 3, places=5)
        # Missed Attack Rate = FN / Attack Support = 1 / 3 = 0.33333
        self.assertAlmostEqual(bm.missed_attack_rate, 1 / 3, places=5)

        # Attack Precision = TP / (TP + FP) = 2 / (2 + 1) = 2/3
        self.assertAlmostEqual(bm.precision, 2 / 3, places=5)
        # Attack Recall = TP / (TP + FN) = 2 / (2 + 1) = 2/3
        self.assertAlmostEqual(bm.recall, 2 / 3, places=5)

    # --------------------------------------------------------------------------
    # 9. Integration with Full Model Label Mapping (15 classes)
    # --------------------------------------------------------------------------
    def test_09_full_model_label_mapping_integration(self):
        mapping_file = REPO_ROOT / "models" / "replacement_v1" / "label_mapping.json"
        self.assertTrue(mapping_file.is_file(), "Model label mapping must exist.")
        with open(mapping_file, "r", encoding="utf-8") as f:
            full_mapping = json.load(f)

        evaluator = OfflineEvaluator(label_mapping=full_mapping)
        self.assertEqual(len(evaluator.id_to_name), 15, "Must load all 15 configured classes.")

        # Test evaluating an array of mixed string and integer labels
        y_true = [0, "BENIGN", 1, "DDoS", 10]
        y_pred = ["BENIGN", 0, "Bot", 2, "PortScan"]

        report = evaluator.evaluate(y_true, y_pred)
        self.assertEqual(report.total_samples, 5)
        self.assertEqual(report.accuracy, 1.0, "All 5 sample pairs match after normalization.")


if __name__ == "__main__":
    unittest.main()
