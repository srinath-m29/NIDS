"""
run_stage4c2_evaluation.py
Executes the Stage 4C-2 offline evaluation pipeline on the certified held-out test set
(566,110 rows) using the newly trained models/replacement_v2 model.
"""

import gc
import json
import os
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

sys.stdout.reconfigure(encoding="utf-8")

SPLIT_MANIFEST = ROOT / "reports" / "evaluation" / "stage4c2" / "stage4c2_split_manifest.csv"
DATA_DIR = ROOT / "data" / "processed" / "feature_cleaned_v2"
MODEL_DIR = ROOT / "models" / "replacement_v2"
OUT_DIR = ROOT / "reports" / "evaluation" / "stage4c2"

from src.evaluation.offline_pipeline import OfflineEvaluationPipeline


def run_evaluation():
    print("=== STAGE 4C-2 OFFLINE HELD-OUT EVALUATION ===", flush=True)
    start_total = time.time()

    if not SPLIT_MANIFEST.is_file():
        raise FileNotFoundError(f"Split manifest not found: {SPLIT_MANIFEST}")

    manifest = pd.read_csv(SPLIT_MANIFEST)
    test_mask = (manifest["split"] == "TEST").values
    train_mask = (manifest["split"] == "TRAIN").values
    n_test = test_mask.sum()
    print(f"Total manifest rows: {len(manifest):,}")
    print(f"Test rows to evaluate: {n_test:,} ({n_test / len(manifest) * 100:.2f}%)")

    features_path = MODEL_DIR / "selected_features.txt"
    features = [l.strip() for l in features_path.read_text(encoding="utf-8-sig").splitlines() if l.strip()]

    files = sorted(DATA_DIR.glob("*.csv"))
    frames = []
    usecols = features + ["model_label"]
    dtypes = {col: np.float32 for col in features}
    dtypes["model_label"] = "string"

    offset = 0
    total_loaded = 0
    for i, path in enumerate(files, 1):
        n_file_rows = pd.read_csv(path, usecols=["model_label"]).shape[0]
        file_test_mask = test_mask[offset : offset + n_file_rows]
        offset += n_file_rows

        if not file_test_mask.any():
            continue

        print(f"[{i}/{len(files)}] Loading TEST slice from {path.name} ({file_test_mask.sum():,} rows)...", flush=True)
        full_df = pd.read_csv(path, usecols=usecols, dtype=dtypes, low_memory=False)
        test_slice = full_df[file_test_mask].copy()
        del full_df
        frames.append(test_slice)
        total_loaded += len(test_slice)
        gc.collect()

    print(f"Combining {len(frames)} test slices (total {total_loaded:,} rows)...", flush=True)
    test_df = pd.concat(frames, ignore_index=True, copy=False)
    del frames
    gc.collect()

    if len(test_df) != n_test:
        raise ValueError(f"Expected {n_test} test rows, loaded {len(test_df)}")

    # Instantiate pipeline
    pipeline = OfflineEvaluationPipeline(
        model_path=MODEL_DIR / "xgboost_nids_replacement_v2.json",
        features_path=MODEL_DIR / "selected_features.txt",
        label_mapping_path=MODEL_DIR / "label_mapping.json",
        output_dir=OUT_DIR,
    )

    print("Running evaluation inference through OfflineEvaluationPipeline...", flush=True)
    eval_start = time.time()
    report = pipeline.evaluate_dataset(
        df=test_df,
        label_column="model_label",
    )
    eval_duration = time.time() - eval_start
    print(f"Inference and metric calculation completed in {eval_duration:.2f} seconds.", flush=True)

    # Save stage4c2_metrics.json
    metrics_data = {
        "evaluation_stage": "STAGE_4C-2",
        "model_version": "replacement_v2",
        "model_path": str(MODEL_DIR / "xgboost_nids_replacement_v2.json"),
        "split_manifest": str(SPLIT_MANIFEST),
        "total_test_rows": len(test_df),
        "total_train_rows": int(train_mask.sum()),
        "evaluation_seconds": round(eval_duration, 2),
        "overall_metrics": {
            "accuracy": report.accuracy,
            "macro_f1": report.macro_f1,
            "weighted_f1": report.weighted_f1,
            "false_positive_rate": report.binary_intrusion_metrics.false_positive_rate if report.binary_intrusion_metrics else 0.0,
            "missed_attack_rate": report.binary_intrusion_metrics.missed_attack_rate if report.binary_intrusion_metrics else 0.0,
        },
        "binary_intrusion_metrics": {
            "benign_support": report.binary_intrusion_metrics.benign_support if report.binary_intrusion_metrics else 0,
            "attack_support": report.binary_intrusion_metrics.attack_support if report.binary_intrusion_metrics else 0,
            "false_alarms": report.binary_intrusion_metrics.false_positives if report.binary_intrusion_metrics else 0,
            "missed_attacks": report.binary_intrusion_metrics.false_negatives if report.binary_intrusion_metrics else 0,
            "false_positive_rate": report.binary_intrusion_metrics.false_positive_rate if report.binary_intrusion_metrics else 0.0,
            "missed_attack_rate": report.binary_intrusion_metrics.missed_attack_rate if report.binary_intrusion_metrics else 0.0,
            "precision": report.binary_intrusion_metrics.precision if report.binary_intrusion_metrics else 0.0,
            "recall": report.binary_intrusion_metrics.recall if report.binary_intrusion_metrics else 0.0,
            "f1_score": report.binary_intrusion_metrics.f1_score if report.binary_intrusion_metrics else 0.0,
        },
        "per_class_metrics": {
            name: {
                "precision": m.precision,
                "recall": m.recall,
                "specificity": m.specificity,
                "f1_score": m.f1_score,
                "support": m.support,
                "tp": m.true_positives,
                "fp": m.false_positives,
                "fn": m.false_negatives,
                "tn": m.true_negatives,
            }
            for name, m in report.per_class_metrics.items()
        },
        "zero_support_classes": [name for name, m in report.per_class_metrics.items() if m.support == 0],
        "confusion_matrix": {
            "classes": report.class_names,
            "matrix": report.confusion_matrix if isinstance(report.confusion_matrix, list) else report.confusion_matrix.tolist(),
        },
    }

    metrics_file = OUT_DIR / "stage4c2_metrics.json"
    metrics_file.write_text(json.dumps(metrics_data, indent=2), encoding="utf-8")
    print(f"Metrics successfully written to: {metrics_file}", flush=True)

    fpr = report.binary_intrusion_metrics.false_positive_rate if report.binary_intrusion_metrics else 0.0
    mar = report.binary_intrusion_metrics.missed_attack_rate if report.binary_intrusion_metrics else 0.0
    zero_supp = [name for name, m in report.per_class_metrics.items() if m.support == 0]

    print("\n=== SUMMARY METRICS ===", flush=True)
    print(f"Accuracy: {report.accuracy * 100:.2f}%")
    print(f"Macro F1: {report.macro_f1:.4f}")
    print(f"Weighted F1: {report.weighted_f1:.4f}")
    print(f"Benign False Positive Rate (FPR): {fpr * 100:.4f}%")
    print(f"Attack Missed Detection Rate: {mar * 100:.4f}%")
    print(f"Zero support classes: {zero_supp}")
    print(f"Total execution elapsed: {time.time() - start_total:.2f} seconds.")


if __name__ == "__main__":
    run_evaluation()
