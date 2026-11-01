"""Stage 3B: XGBoost Five-Fold Out-of-Fold Baseline Diagnostic Error Analysis.

Evaluates out-of-fold predictions from the 5-fold baseline, computes confusion matrices,
per-class classification metrics, top misclassification pairs, minority-class breakdowns
(XSS, SQL Injection, Bot, Heartbleed, Infiltration), fold-level stability, and validates
full coverage (2,830,743 rows) against baseline metrics.
"""

import csv
import json
import os
import sys
import time
from pathlib import Path
import gc

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.preprocessing import LabelEncoder


def main():
    start_total_time = time.time()
    print("=" * 70)
    print("STARTING STAGE 3B: XGBOOST OUT-OF-FOLD DIAGNOSTIC ERROR ANALYSIS")
    print("=" * 70)

    root = Path(__file__).resolve().parent.parent.parent
    data_dir = root / "data/processed/feature_cleaned_v2"
    fold_map_path = root / "reports/evaluation/row_fold_map_v1.csv"
    baseline_metrics_path = root / "reports/evaluation/xgboost_baseline_v1/metrics.json"
    out_dir = root / "reports/evaluation/xgboost_error_analysis_v1"

    EXPECTED_ROWS = 2_830_743
    N_FOLDS = 5
    META = {
        "raw_label", "Label", "model_label", "label_quality_status",
        "source_file", "source_row"
    }

    # Verify prerequisites
    if not baseline_metrics_path.is_file():
        raise SystemExit(f"FAIL: Baseline metrics missing: {baseline_metrics_path}")
    if not fold_map_path.is_file():
        raise SystemExit(f"FAIL: Fold map missing: {fold_map_path}")
    if not data_dir.is_dir():
        raise SystemExit(f"FAIL: Data directory missing: {data_dir}")

    out_dir.mkdir(parents=True, exist_ok=True)

    # Load baseline metrics for comparison
    with baseline_metrics_path.open("r", encoding="utf-8") as f:
        baseline_metrics = json.load(f)

    # Step 1: Check existing OOF predictions
    oof_artifact_path = out_dir / "oof_predictions.npz"
    can_reuse_oof = False
    if oof_artifact_path.is_file():
        print(f"Found existing OOF predictions at {oof_artifact_path}. Checking validity...")
        try:
            data = np.load(oof_artifact_path)
            if "oof" in data and "y_true" in data and "fold_ids" in data:
                oof = data["oof"]
                y = data["y_true"]
                fold_ids = data["fold_ids"]
                classes = list(data["classes"])
                if len(oof) == EXPECTED_ROWS and not (oof < 0).any():
                    print("Reusing existing OOF predictions artifact.")
                    can_reuse_oof = True
        except Exception as e:
            print(f"Failed to load existing OOF artifact: {e}. Will re-run experiment.")

    cuda_device_info = {}
    total_training_seconds = 0.0
    fold_training_results = []

    if not can_reuse_oof:
        print("No existing OOF prediction array found. Re-running 5-fold baseline...")

        # Record CUDA device info
        try:
            import subprocess
            smi_output = subprocess.check_output(
                ["nvidia-smi", "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader"],
                text=True
            ).strip()
            cuda_device_info["nvidia_smi"] = smi_output
            print(f"CUDA Device: {smi_output}")
        except Exception as e:
            cuda_device_info["nvidia_smi_error"] = str(e)

        # 1. Read fold assignments
        print("Reading row fold map...", flush=True)
        fold_rows = {}
        last_row = {}
        with fold_map_path.open(newline="", encoding="utf-8-sig") as f:
            for r in csv.DictReader(f):
                name = r["source_file"]
                row_num = int(r["source_row"])
                fold_id = int(r["fold_id"])
                expected_next = last_row.get(name, 1) + 1
                if row_num != expected_next:
                    raise SystemExit(f"FAIL: Non-sequential source rows in fold map: {name}, {row_num}")
                if fold_id not in range(N_FOLDS):
                    raise SystemExit(f"FAIL: Invalid fold ID {fold_id}")
                fold_rows.setdefault(name, []).append(fold_id)
                last_row[name] = row_num

        # 2. Get features
        files = sorted(data_dir.glob("*.csv"))
        if len(files) != 8:
            raise SystemExit(f"FAIL: Expected 8 cleaned CSVs, found {len(files)}")

        with files[0].open("r", newline="", encoding="utf-8-sig") as f:
            header = next(csv.reader(f))
        features = [c for c in header if c not in META]

        if len(features) != 63:
            raise SystemExit(f"FAIL: Expected 63 features, found {len(features)}")

        # 3. Load dataset
        X = np.empty((EXPECTED_ROWS, len(features)), dtype=np.float32)
        y_text = np.empty(EXPECTED_ROWS, dtype=object)
        fold_ids = np.empty(EXPECTED_ROWS, dtype=np.int8)
        offset = 0

        for path in files:
            print(f"Loading {path.name}...", flush=True)
            df = pd.read_csv(
                path,
                usecols=features + ["model_label", "source_file", "source_row"],
                dtype={c: np.float32 for c in features},
            )

            if df.empty:
                raise SystemExit(f"FAIL: Empty data file: {path.name}")

            source_names = df["source_file"].astype(str)
            unique_names = source_names.unique()
            if len(unique_names) != 1:
                raise SystemExit(f"FAIL: Mixed source_file values in {path.name}")

            source_name = unique_names[0]
            if source_name not in fold_rows:
                raise SystemExit(f"FAIL: No fold mapping for {source_name}")

            row_numbers = df["source_row"].to_numpy(dtype=np.int64)
            expected_rows = np.arange(2, len(df) + 2, dtype=np.int64)
            mapped = fold_rows[source_name]

            if len(mapped) != len(df) or not np.array_equal(row_numbers, expected_rows):
                raise SystemExit(f"FAIL: Row alignment mismatch in {path.name}")

            end = offset + len(df)
            if end > EXPECTED_ROWS:
                raise SystemExit("FAIL: More rows than expected")

            X[offset:end] = df[features].to_numpy(dtype=np.float32)
            y_text[offset:end] = df["model_label"].astype(str).to_numpy(dtype=object)
            fold_ids[offset:end] = np.asarray(mapped, dtype=np.int8)
            offset = end
            del df
            gc.collect()

        if offset != EXPECTED_ROWS:
            raise SystemExit(f"FAIL: Loaded {offset} rows, expected {EXPECTED_ROWS}")

        if not np.isfinite(X[~np.isnan(X)]).all():
            raise SystemExit("FAIL: Invalid feature values detected")

        encoder = LabelEncoder()
        y = encoder.fit_transform(y_text).astype(np.int32)
        classes = [str(c) for c in encoder.classes_]
        del y_text
        gc.collect()

        if len(classes) != 15:
            raise SystemExit(f"FAIL: Expected 15 classes, found {len(classes)}")

        print(f"\nDataset loaded: {X.shape[0]:,} rows, {X.shape[1]} features, {len(classes)} classes")

        # 4. Out-of-fold training and prediction
        oof = np.full(EXPECTED_ROWS, -1, dtype=np.int32)
        start_train_all = time.time()

        for fold in range(N_FOLDS):
            test_idx = np.flatnonzero(fold_ids == fold)
            train_idx = np.flatnonzero(fold_ids != fold)

            print(f"\nTraining Fold {fold + 1}/{N_FOLDS}: train={len(train_idx):,}, test={len(test_idx):,}...", flush=True)

            model = xgb.XGBClassifier(
                objective="multi:softprob",
                num_class=len(classes),
                eval_metric="mlogloss",
                n_estimators=100,
                max_depth=8,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                tree_method="hist",
                device="cuda",
                max_bin=128,
                random_state=42,
                n_jobs=8,
            )

            fold_start = time.time()
            model.fit(X[train_idx], y[train_idx], verbose=False)
            pred = model.predict(X[test_idx]).astype(np.int32)
            oof[test_idx] = pred
            fold_dur = round(time.time() - fold_start, 2)

            fold_acc = float(accuracy_score(y[test_idx], pred))
            fold_bal_acc = float(balanced_accuracy_score(y[test_idx], pred))
            fold_macro_f1 = float(f1_score(y[test_idx], pred, average="macro", zero_division=0))
            fold_weighted_f1 = float(f1_score(y[test_idx], pred, average="weighted", zero_division=0))

            fold_res = {
                "fold_id": fold,
                "train_rows": int(len(train_idx)),
                "test_rows": int(len(test_idx)),
                "accuracy": fold_acc,
                "balanced_accuracy": fold_bal_acc,
                "macro_f1": fold_macro_f1,
                "weighted_f1": fold_weighted_f1,
                "seconds": fold_dur,
            }
            fold_training_results.append(fold_res)
            print(f"Fold {fold} finished in {fold_dur}s | Acc: {fold_acc:.6f} | Macro F1: {fold_macro_f1:.6f}")

            del model, train_idx, test_idx, pred
            gc.collect()

        total_training_seconds = round(time.time() - start_train_all, 2)
        print(f"\nAll folds completed in {total_training_seconds} seconds.")

        # Save OOF predictions for reuse
        print(f"Saving OOF predictions to {oof_artifact_path}...")
        np.savez_compressed(
            oof_artifact_path,
            oof=oof,
            y_true=y,
            fold_ids=fold_ids,
            classes=np.array(classes, dtype=object),
        )
        del X
        gc.collect()

    else:
        # If reusing, pull fold results from baseline metrics
        fold_training_results = baseline_metrics.get("fold_results", [])
        total_training_seconds = baseline_metrics.get("total_training_seconds", 0.0)

    # Validation 1: Coverage
    print("\nValidating row coverage...")
    if len(oof) != EXPECTED_ROWS:
        raise SystemExit(f"FAIL: Row count is {len(oof)}, expected {EXPECTED_ROWS}")
    if (oof < 0).any():
        num_unpredicted = int((oof < 0).sum())
        raise SystemExit(f"FAIL: {num_unpredicted} rows have no out-of-fold prediction!")
    print(f"PASS: All {EXPECTED_ROWS:,} rows covered exactly once by out-of-fold predictions.")

    # Validation 2: Numerical agreement with baseline metrics
    print("\nValidating numerical agreement with baseline...")
    current_acc = float(accuracy_score(y, oof))
    current_bal_acc = float(balanced_accuracy_score(y, oof))
    current_macro_f1 = float(f1_score(y, oof, average="macro", zero_division=0))
    current_weighted_f1 = float(f1_score(y, oof, average="weighted", zero_division=0))

    base_acc = baseline_metrics["overall_oof"]["accuracy"]
    base_bal_acc = baseline_metrics["overall_oof"]["balanced_accuracy"]
    base_macro_f1 = baseline_metrics["overall_oof"]["macro_f1"]
    base_weighted_f1 = baseline_metrics["overall_oof"]["weighted_f1"]

    acc_diff = abs(current_acc - base_acc)
    bal_acc_diff = abs(current_bal_acc - base_bal_acc)
    macro_f1_diff = abs(current_macro_f1 - base_macro_f1)
    weighted_f1_diff = abs(current_weighted_f1 - base_weighted_f1)

    print(f"Accuracy:         Current={current_acc:.8f}, Baseline={base_acc:.8f}, Diff={acc_diff:.2e}")
    print(f"Balanced Acc:     Current={current_bal_acc:.8f}, Baseline={base_bal_acc:.8f}, Diff={bal_acc_diff:.2e}")
    print(f"Macro F1:         Current={current_macro_f1:.8f}, Baseline={base_macro_f1:.8f}, Diff={macro_f1_diff:.2e}")
    print(f"Weighted F1:      Current={current_weighted_f1:.8f}, Baseline={base_weighted_f1:.8f}, Diff={weighted_f1_diff:.2e}")

    tolerance = 1e-4
    if max(acc_diff, bal_acc_diff, macro_f1_diff, weighted_f1_diff) > tolerance:
        print(f"WARNING: Metric difference exceeds tolerance {tolerance}!")
    else:
        print(f"PASS: Reported metrics agree with baseline within tolerance {tolerance}.")

    # Step 3A: Compute 15x15 Confusion Matrix
    print("\nComputing 15x15 Confusion Matrix...")
    cm = confusion_matrix(y, oof, labels=np.arange(len(classes)))
    cm_df = pd.DataFrame(cm, index=classes, columns=classes)
    cm_df.index.name = "True Class"

    cm_csv_path = out_dir / "confusion_matrix.csv"
    cm_df.to_csv(cm_csv_path, encoding="utf-8-sig")

    cm_json_path = out_dir / "confusion_matrix.json"
    cm_json_dict = {
        "classes": classes,
        "matrix": cm.tolist(),
        "labeled_matrix": {
            true_cls: {pred_cls: int(cm[i, j]) for j, pred_cls in enumerate(classes)}
            for i, true_cls in enumerate(classes)
        }
    }
    with cm_json_path.open("w", encoding="utf-8") as f:
        json.dump(cm_json_dict, f, indent=2)

    # Step 3B: Per-Class Classification Report
    print("Computing Per-Class Metrics...")
    report_dict = classification_report(
        y,
        oof,
        labels=np.arange(len(classes)),
        target_names=classes,
        output_dict=True,
        zero_division=0,
    )

    per_class_rows = []
    for cls_name in classes:
        metrics = report_dict[cls_name]
        per_class_rows.append({
            "class": cls_name,
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1_score": metrics["f1-score"],
            "support": int(metrics["support"]),
        })

    per_class_df = pd.DataFrame(per_class_rows)
    per_class_csv_path = out_dir / "classification_report.csv"
    per_class_df.to_csv(per_class_csv_path, index=False, encoding="utf-8-sig")

    class_report_json_path = out_dir / "classification_report.json"
    with class_report_json_path.open("w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2)

    # Step 3C: Most Frequent Incorrect Class Predictions
    print("Extracting Most Frequent Incorrect Class Predictions...")
    misclass_list = []
    total_errors = int((y != oof).sum())

    for i, true_cls in enumerate(classes):
        true_support = int(cm[i].sum())
        for j, pred_cls in enumerate(classes):
            if i != j and cm[i, j] > 0:
                count = int(cm[i, j])
                pct_of_true = (count / true_support * 100) if true_support > 0 else 0.0
                pct_of_all_errors = (count / total_errors * 100) if total_errors > 0 else 0.0
                misclass_list.append({
                    "true_class": true_cls,
                    "predicted_class": pred_cls,
                    "count": count,
                    "pct_of_true_class": round(pct_of_true, 4),
                    "pct_of_total_errors": round(pct_of_all_errors, 4),
                })

    misclass_list.sort(key=lambda x: x["count"], reverse=True)

    misclass_df = pd.DataFrame(misclass_list)
    misclass_csv_path = out_dir / "most_frequent_misclassifications.csv"
    misclass_df.to_csv(misclass_csv_path, index=False, encoding="utf-8-sig")

    misclass_json_path = out_dir / "most_frequent_misclassifications.json"
    with misclass_json_path.open("w", encoding="utf-8") as f:
        json.dump({
            "total_samples": EXPECTED_ROWS,
            "total_errors": total_errors,
            "overall_error_rate_pct": round(total_errors / EXPECTED_ROWS * 100, 4),
            "misclassifications": misclass_list,
        }, f, indent=2)

    # Step 3D: Specific Error Analysis for Target Minority Classes
    # Target classes: XSS, SQL injection, Bot, Heartbleed, Infiltration
    target_minority_names = [
        "Web Attack \ufffd XSS",
        "Web Attack \ufffd Sql Injection",
        "Bot",
        "Heartbleed",
        "Infiltration"
    ]

    print("\nComputing Detailed Minority-Class Error Analysis...")
    minority_analysis = {}

    for target_name in target_minority_names:
        if target_name not in classes:
            # Check for alternative naming if encoding differs
            match = [c for c in classes if target_name.split()[-1] in c]
            if match:
                cls_idx = classes.index(match[0])
                cls_key = match[0]
            else:
                continue
        else:
            cls_idx = classes.index(target_name)
            cls_key = target_name

        support = int(cm[cls_idx].sum())
        tp = int(cm[cls_idx, cls_idx])
        fn = support - tp
        fp = int(cm[:, cls_idx].sum() - tp)
        tn = EXPECTED_ROWS - tp - fn - fp

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / support if support > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        # False negatives breakdown: what did the model predict when true was this class?
        fn_breakdown = {}
        for j, pred_name in enumerate(classes):
            if j != cls_idx and cm[cls_idx, j] > 0:
                fn_breakdown[pred_name] = {
                    "count": int(cm[cls_idx, j]),
                    "pct_of_true_class": round(float(cm[cls_idx, j]) / support * 100, 2),
                }

        # Sort fn_breakdown by count descending
        fn_breakdown = dict(sorted(fn_breakdown.items(), key=lambda item: item[1]["count"], reverse=True))

        # False positives breakdown: what true classes were falsely flagged as this class?
        fp_breakdown = {}
        for i, true_name in enumerate(classes):
            if i != cls_idx and cm[i, cls_idx] > 0:
                fp_breakdown[true_name] = {
                    "count": int(cm[i, cls_idx]),
                    "pct_of_all_false_positives": round(float(cm[i, cls_idx]) / fp * 100, 2) if fp > 0 else 0.0,
                }
        fp_breakdown = dict(sorted(fp_breakdown.items(), key=lambda item: item[1]["count"], reverse=True))

        # Fold-wise performance for this class
        fold_metrics = []
        for f_id in range(N_FOLDS):
            mask = (fold_ids == f_id)
            y_fold = y[mask]
            oof_fold = oof[mask]

            fold_support = int((y_fold == cls_idx).sum())
            fold_tp = int(((y_fold == cls_idx) & (oof_fold == cls_idx)).sum())
            fold_fn = fold_support - fold_tp
            fold_fp = int(((y_fold != cls_idx) & (oof_fold == cls_idx)).sum())

            f_prec = fold_tp / (fold_tp + fold_fp) if (fold_tp + fold_fp) > 0 else 0.0
            f_rec = fold_tp / fold_support if fold_support > 0 else 0.0
            f_f1 = 2 * f_prec * f_rec / (f_prec + f_rec) if (f_prec + f_rec) > 0 else 0.0

            fold_metrics.append({
                "fold_id": f_id,
                "support": fold_support,
                "true_positives": fold_tp,
                "false_negatives": fold_fn,
                "false_positives": fold_fp,
                "precision": round(f_prec, 6),
                "recall": round(f_rec, 6),
                "f1_score": round(f_f1, 6),
            })

        # Summary statistics across folds
        recalls = [m["recall"] for m in fold_metrics]
        precisions = [m["precision"] for m in fold_metrics]
        f1s = [m["f1_score"] for m in fold_metrics]

        minority_analysis[cls_key] = {
            "class_index": cls_idx,
            "overall": {
                "support": support,
                "true_positives": tp,
                "false_negatives": fn,
                "false_positives": fp,
                "precision": round(precision, 6),
                "recall": round(recall, 6),
                "f1_score": round(f1, 6),
            },
            "false_negatives_confusion_breakdown": fn_breakdown,
            "false_positives_confusion_breakdown": fp_breakdown,
            "fold_wise": fold_metrics,
            "fold_summary": {
                "recall_mean": round(float(np.mean(recalls)), 6),
                "recall_std": round(float(np.std(recalls)), 6),
                "recall_min": round(float(np.min(recalls)), 6),
                "recall_max": round(float(np.max(recalls)), 6),
                "f1_mean": round(float(np.mean(f1s)), 6),
                "f1_std": round(float(np.std(f1s)), 6),
            }
        }

    minority_json_path = out_dir / "minority_class_analysis.json"
    with minority_json_path.open("w", encoding="utf-8") as f:
        json.dump(minority_analysis, f, indent=2)

    # Step 3E: Fold-Wise Performance for All Classes
    print("Computing Fold-Wise Performance Table for All Classes...")
    fold_class_rows = []
    for f_id in range(N_FOLDS):
        mask = (fold_ids == f_id)
        y_fold = y[mask]
        oof_fold = oof[mask]

        for cls_idx, cls_name in enumerate(classes):
            f_supp = int((y_fold == cls_idx).sum())
            f_tp = int(((y_fold == cls_idx) & (oof_fold == cls_idx)).sum())
            f_fn = f_supp - f_tp
            f_fp = int(((y_fold != cls_idx) & (oof_fold == cls_idx)).sum())

            f_prec = f_tp / (f_tp + f_fp) if (f_tp + f_fp) > 0 else 0.0
            f_rec = f_tp / f_supp if f_supp > 0 else 0.0
            f_f1 = 2 * f_prec * f_rec / (f_prec + f_rec) if (f_prec + f_rec) > 0 else 0.0

            fold_class_rows.append({
                "fold_id": f_id,
                "class": cls_name,
                "support": f_supp,
                "true_positives": f_tp,
                "false_negatives": f_fn,
                "false_positives": f_fp,
                "precision": round(f_prec, 6),
                "recall": round(f_rec, 6),
                "f1_score": round(f_f1, 6),
            })

    fold_class_df = pd.DataFrame(fold_class_rows)
    fold_class_csv_path = out_dir / "fold_class_performance.csv"
    fold_class_df.to_csv(fold_class_csv_path, index=False, encoding="utf-8-sig")

    # Step 4: Executive Error Analysis Summary
    print("Writing Executive Summary...")
    total_pipeline_seconds = round(time.time() - start_total_time, 2)

    summary_report = {
        "status": "PASS",
        "stage": "3B",
        "objective": "Diagnostic Error Analysis of Baseline XGBoost Five-Fold OOF Predictions",
        "total_rows": EXPECTED_ROWS,
        "features": len(features),
        "classes": classes,
        "artifacts_generated": {
            "confusion_matrix_csv": str(cm_csv_path),
            "confusion_matrix_json": str(cm_json_path),
            "classification_report_csv": str(per_class_csv_path),
            "classification_report_json": str(class_report_json_path),
            "most_frequent_misclassifications_csv": str(misclass_csv_path),
            "most_frequent_misclassifications_json": str(misclass_json_path),
            "minority_class_analysis_json": str(minority_json_path),
            "fold_class_performance_csv": str(fold_class_csv_path),
            "oof_predictions_npz": str(oof_artifact_path),
        },
        "validation": {
            "row_count_expected": EXPECTED_ROWS,
            "row_count_actual": len(oof),
            "all_rows_covered_once": bool(len(oof) == EXPECTED_ROWS and not (oof < 0).any()),
            "agreement_with_baseline": {
                "baseline_accuracy": base_acc,
                "current_accuracy": current_acc,
                "accuracy_diff": acc_diff,
                "baseline_macro_f1": base_macro_f1,
                "current_macro_f1": current_macro_f1,
                "macro_f1_diff": macro_f1_diff,
                "baseline_balanced_accuracy": base_bal_acc,
                "current_balanced_accuracy": current_bal_acc,
                "balanced_accuracy_diff": bal_acc_diff,
                "baseline_weighted_f1": base_weighted_f1,
                "current_weighted_f1": current_weighted_f1,
                "weighted_f1_diff": weighted_f1_diff,
                "passed_within_tolerance": bool(max(acc_diff, bal_acc_diff, macro_f1_diff, weighted_f1_diff) <= tolerance),
            }
        },
        "overall_oof_metrics": {
            "accuracy": current_acc,
            "balanced_accuracy": current_bal_acc,
            "macro_f1": current_macro_f1,
            "weighted_f1": current_weighted_f1,
            "total_misclassifications": total_errors,
            "misclassification_rate_pct": round(total_errors / EXPECTED_ROWS * 100, 4),
        },
        "timing": {
            "total_pipeline_seconds": total_pipeline_seconds,
            "total_training_seconds": total_training_seconds,
            "fold_training_results": fold_training_results,
        },
        "device_info": cuda_device_info,
        "key_findings": {
            "top_3_misclassifications": misclass_list[:3],
            "minority_class_summary": {
                name: {
                    "support": minority_analysis[name]["overall"]["support"],
                    "recall": minority_analysis[name]["overall"]["recall"],
                    "precision": minority_analysis[name]["overall"]["precision"],
                    "f1_score": minority_analysis[name]["overall"]["f1_score"],
                    "primary_confusion": list(minority_analysis[name]["false_negatives_confusion_breakdown"].items())[0] if minority_analysis[name]["false_negatives_confusion_breakdown"] else None
                }
                for name in minority_analysis
            }
        }
    }

    summary_json_path = out_dir / "error_analysis_summary.json"
    with summary_json_path.open("w", encoding="utf-8") as f:
        json.dump(summary_report, f, indent=2)

    print(f"\nDiagnostic Error Analysis completed successfully in {total_pipeline_seconds}s!")
    print(f"Summary saved to: {summary_json_path}")


if __name__ == "__main__":
    main()
