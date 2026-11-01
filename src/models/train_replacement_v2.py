"""
Stage 4C-2: Train Replacement Model V2 on Certified Held-Out Split

This script trains models/replacement_v2/xgboost_nids_replacement_v2.json
strictly on the 2,264,633 rows designated as TRAIN in stage4c2_split_manifest.csv.
The 566,110 TEST rows are strictly held out and untouched.
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
DATA_DIR = ROOT / "data" / "processed" / "feature_cleaned_v2"
SPLIT_MANIFEST = ROOT / "reports" / "evaluation" / "stage4c2" / "stage4c2_split_manifest.csv"
V1_DIR = ROOT / "models" / "replacement_v1"
OUT_DIR = ROOT / "models" / "replacement_v2"
MIN_FREE_GIB = 2.5


def free_ram_gib() -> float:
    import ctypes

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    status = MEMORYSTATUSEX()
    status.dwLength = ctypes.sizeof(status)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise RuntimeError("Unable to determine free system RAM.")
    return status.ullAvailPhys / (1024 ** 3)


def train_replacement_v2():
    print("=== PRE-TRAINING RESOURCE AND INVARIANT CHECK ===", flush=True)
    free = free_ram_gib()
    print(f"Available RAM: {free:.2f} GiB", flush=True)
    if free < MIN_FREE_GIB:
        raise RuntimeError(f"Training aborted: free RAM {free:.2f} GiB is below {MIN_FREE_GIB:.1f} GiB.")

    if not SPLIT_MANIFEST.is_file():
        raise FileNotFoundError(f"Split manifest not found: {SPLIT_MANIFEST}")

    # Verify V1 contract
    v1_features_path = V1_DIR / "selected_features.txt"
    v1_labels_path = V1_DIR / "label_mapping.json"
    features = [line.strip() for line in v1_features_path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    label_mapping = json.loads(v1_labels_path.read_text(encoding="utf-8"))

    if len(features) != 63:
        raise ValueError(f"Expected 63 features, found {len(features)}")
    if len(label_mapping) != 15:
        raise ValueError(f"Expected 15 classes, found {len(label_mapping)}")

    # Invert mapping name -> int id
    name_to_id = {v: int(k) for k, v in label_mapping.items()}

    print(f"XGBoost version: {xgb.__version__}", flush=True)
    print(f"Loading split manifest: {SPLIT_MANIFEST.name}", flush=True)
    manifest = pd.read_csv(SPLIT_MANIFEST)

    train_mask = (manifest["split"] == "TRAIN").values
    test_mask = (manifest["split"] == "TEST").values
    print(f"Total manifest rows: {len(manifest):,}")
    print(f"Training rows to ingest: {train_mask.sum():,} ({train_mask.sum()/len(manifest)*100:.2f}%)")
    print(f"Test rows reserved/untouched: {test_mask.sum():,} ({test_mask.sum()/len(manifest)*100:.2f}%)")

    # Ingest data
    files = sorted(DATA_DIR.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files found in {DATA_DIR}")

    frames = []
    usecols = features + ["model_label"]
    dtypes = {feat: np.float32 for feat in features}
    dtypes["model_label"] = "string"

    offset = 0
    total_loaded = 0
    for i, path in enumerate(files, 1):
        n_file_rows = pd.read_csv(path, usecols=["model_label"]).shape[0]
        file_train_mask = train_mask[offset : offset + n_file_rows]
        offset += n_file_rows

        if not file_train_mask.any():
            continue

        print(f"[{i}/{len(files)}] Loading TRAIN slice from {path.name} ({file_train_mask.sum():,} rows)...", flush=True)
        # Read file with chunking or filtering
        full_df = pd.read_csv(path, usecols=usecols, dtype=dtypes, low_memory=False)
        train_df = full_df[file_train_mask].copy()
        del full_df
        frames.append(train_df)
        total_loaded += len(train_df)
        gc.collect()

    print(f"Combining {len(frames)} training slices (total {total_loaded:,} rows)...", flush=True)
    train_data = pd.concat(frames, ignore_index=True, copy=False)
    del frames
    gc.collect()

    # Map labels to integer IDs
    y_labels = train_data["model_label"].str.strip().values
    y = np.array([name_to_id[lbl] for lbl in y_labels], dtype=np.int32)

    X = train_data[features].to_numpy(dtype=np.float32, copy=True)
    del train_data
    gc.collect()

    # Sanitize NaN/inf and clip negative
    np.nan_to_num(X, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    np.clip(X, a_min=0.0, a_max=None, out=X)

    print(f"Training matrix ready: {X.shape}, dtype={X.dtype}", flush=True)
    print(f"Free RAM before model fit: {free_ram_gib():.2f} GiB", flush=True)

    model = xgb.XGBClassifier(
        objective="multi:softprob",
        num_class=15,
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        tree_method="hist",
        device="cuda",
        max_bin=64,
        random_state=42,
        n_jobs=4,
        verbosity=1,
    )

    print("Fitting XGBoost replacement_v2 model on GPU...", flush=True)
    start_time = time.time()
    model.fit(X, y, verbose=False)
    training_duration = time.time() - start_time
    print(f"Training completed in {training_duration:.2f} seconds.", flush=True)

    # Save artifacts into models/replacement_v2/
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    model_path = OUT_DIR / "xgboost_nids_replacement_v2.json"
    model.save_model(model_path)
    print(f"Saved model to: {model_path}", flush=True)

    (OUT_DIR / "selected_features.txt").write_text("\n".join(features) + "\n", encoding="utf-8")
    (OUT_DIR / "label_mapping.json").write_text(json.dumps(label_mapping, indent=2, ensure_ascii=False), encoding="utf-8")

    # Compute per-class training support
    unique_ids, counts = np.unique(y, return_counts=True)
    support_dict = {label_mapping[str(uid)]: int(cnt) for uid, cnt in zip(unique_ids, counts)}

    metadata = {
        "model_version": "replacement_v2",
        "algorithm": "XGBoost XGBClassifier",
        "xgboost_version": xgb.__version__,
        "training_rows": int(len(y)),
        "held_out_test_rows": int(test_mask.sum()),
        "total_source_rows": len(manifest),
        "split_manifest": str(SPLIT_MANIFEST),
        "feature_count": len(features),
        "class_count": len(label_mapping),
        "classes": [label_mapping[str(i)] for i in range(15)],
        "training_seconds": round(training_duration, 2),
        "device_requested": "cuda",
        "evaluation_performed": False,
        "cross_validation_performed": False,
        "training_scope": "Certified 80% partition (2,264,633 rows) from stage4c2_split_manifest.csv; 566,110 rows strictly held out.",
        "training_support_per_class": support_dict,
        "limitations": [
            "Trained strictly on 80% partition; zero rows from TEST partition entered training.",
            "Minority classes with < 100 total rows (Heartbleed: 11, Infiltration: 36, SQL Injection: 21) are present in training but have 0 test support.",
            "Certified for offline held-out evaluation on the 566,110 reserved test rows."
        ]
    }
    (OUT_DIR / "model_metadata.json").write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
    print("Metadata written successfully.", flush=True)
    print(f"\n=== REPLACEMENT V2 TRAINING COMPLETE ({training_duration:.2f}s) ===", flush=True)


if __name__ == "__main__":
    train_replacement_v2()
