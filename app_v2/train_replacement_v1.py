import gc
import json
import os
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.preprocessing import LabelEncoder

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data" / "processed" / "feature_cleaned_v2"
FEATURE_FILE = ROOT / "dataset" / "processed" / "selected_features.txt"
OUT_DIR = ROOT / "models" / "replacement_v1"
MIN_FREE_GIB = 2.5

def free_ram_gib():
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

def main():
    print("=== PRE-TRAINING RESOURCE CHECK ===", flush=True)
    free = free_ram_gib()
    print(f"Available RAM: {free:.2f} GiB", flush=True)
    if free < MIN_FREE_GIB:
        raise RuntimeError(
            f"Training aborted: free RAM {free:.2f} GiB is below "
            f"{MIN_FREE_GIB:.1f} GiB."
        )

    if OUT_DIR.exists():
        raise RuntimeError(
            f"Output directory already exists; refusing to overwrite: {OUT_DIR}"
        )
    if not FEATURE_FILE.is_file():
        raise FileNotFoundError(FEATURE_FILE)

    features = [
        line.strip()
        for line in FEATURE_FILE.read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    ]
    if len(features) != 63 or len(set(features)) != len(features):
        raise RuntimeError(f"Expected 63 unique features, got {len(features)}.")

    files = sorted(DATA_DIR.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files in {DATA_DIR}")

    print(f"XGBoost version: {xgb.__version__}", flush=True)
    print(f"CSV files: {len(files)}", flush=True)
    print(f"Selected features: {len(features)}", flush=True)
    print("Reading prepared data; no evaluation split will be run.", flush=True)

    frames = []
    usecols = features + ["model_label"]
    dtypes = {name: np.float32 for name in features}
    dtypes["model_label"] = "string"

    for i, path in enumerate(files, 1):
        print(f"[{i}/{len(files)}] Loading {path.name}", flush=True)
        frame = pd.read_csv(
            path,
            usecols=usecols,
            dtype=dtypes,
            low_memory=False,
        )
        missing = [name for name in usecols if name not in frame.columns]
        if missing:
            raise RuntimeError(f"{path.name} is missing columns: {missing}")
        frames.append(frame)

    print("Combining prepared data...", flush=True)
    data = pd.concat(frames, ignore_index=True, copy=False)
    del frames
    gc.collect()

    data["model_label"] = data["model_label"].str.strip()
    data = data.dropna(subset=["model_label"])
    data = data[data["model_label"] != ""]
    if data.empty:
        raise RuntimeError("No rows with usable model_label values.")

    labels = LabelEncoder()
    y = labels.fit_transform(data["model_label"].to_numpy())
    if len(labels.classes_) < 2:
        raise RuntimeError("At least two distinct classes are required.")

    print(f"Rows for training: {len(data):,}", flush=True)
    print(f"Classes: {len(labels.classes_)}", flush=True)
    print(f"Free RAM before matrix creation: {free_ram_gib():.2f} GiB", flush=True)

    if free_ram_gib() < MIN_FREE_GIB:
        raise RuntimeError("Training aborted: free RAM dropped below 2.5 GiB.")

    X = data[features].to_numpy(dtype=np.float32, copy=True)
    del data
    gc.collect()
    np.nan_to_num(X, copy=False, nan=0.0, posinf=0.0, neginf=0.0)

    print(f"Training matrix: {X.shape}, dtype={X.dtype}", flush=True)
    print(f"Free RAM before training: {free_ram_gib():.2f} GiB", flush=True)
    if free_ram_gib() < MIN_FREE_GIB:
        raise RuntimeError("Training aborted: free RAM dropped below 2.5 GiB.")

    model = xgb.XGBClassifier(
        objective="multi:softprob",
        num_class=len(labels.classes_),
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

    started = time.time()
    print("Starting the single replacement-model training run...", flush=True)
    model.fit(X, y, verbose=False)
    elapsed = time.time() - started

    OUT_DIR.mkdir(parents=True, exist_ok=False)
    model_path = OUT_DIR / "xgboost_nids_replacement_v1.json"
    model.save_model(model_path)

    (OUT_DIR / "label_mapping.json").write_text(
        json.dumps(
            {str(i): str(name) for i, name in enumerate(labels.classes_)},
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (OUT_DIR / "selected_features.txt").write_text(
        "\n".join(features) + "\n",
        encoding="utf-8",
    )
    metadata = {
        "model_version": "replacement_v1",
        "algorithm": "XGBoost XGBClassifier",
        "xgboost_version": xgb.__version__,
        "training_rows": int(len(y)),
        "feature_count": len(features),
        "class_count": len(labels.classes_),
        "classes": [str(name) for name in labels.classes_],
        "training_seconds": round(elapsed, 2),
        "device_requested": "cuda",
        "evaluation_performed": False,
        "cross_validation_performed": False,
        "training_scope": "All usable rows in the prepared CSV files; no holdout evaluation.",
        "limitations": [
            "No independent performance evaluation was run.",
            "Reported historical metrics are not results for this replacement model.",
            "Training on all prepared rows means this model has no untouched test set.",
            "Dataset replay only; not live packet capture or automatic blocking.",
        ],
    }
    (OUT_DIR / "model_metadata.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("\n=== TRAINING COMPLETE ===", flush=True)
    print(f"Model: {model_path}", flush=True)
    print(f"Rows used: {len(y):,}", flush=True)
    print(f"Classes: {len(labels.classes_)}", flush=True)
    print(f"Elapsed training time: {elapsed:.1f} seconds", flush=True)
    print("Evaluation performed: No", flush=True)
    print("Cross-validation performed: No", flush=True)
    print(f"Artifacts saved in: {OUT_DIR}", flush=True)

if __name__ == "__main__":
    main()
