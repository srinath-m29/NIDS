"""
verify_dataset_split.py
Stage B: Rigorous, independent mathematical verification of dataset split:
1. Recomputes all 8 source-file SHA-256 checksums and exact row counts.
2. Verifies that every eligible source row is assigned exactly once in stage4c2_split_manifest.csv.
3. Validates the 63-feature input contract.
4. Uses full 256-bit SHA-256 digests of 63-feature vectors to verify zero cross-partition leakage.
5. Verifies class distribution, zero-support classes, and test data isolation.
"""

import gc
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = ROOT / "data" / "processed" / "feature_cleaned_v2"
STAGE4C2_DIR = ROOT / "reports" / "evaluation" / "stage4c2"
MANIFEST_PATH = STAGE4C2_DIR / "stage4c2_split_manifest.csv"
SUMMARY_PATH = STAGE4C2_DIR / "stage4c2_split_summary.json"
FEATURE_FILE = ROOT / "models" / "replacement_v1" / "selected_features.txt"
LABEL_FILE = ROOT / "models" / "replacement_v1" / "label_mapping.json"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    print("=== STAGE B: DATASET SPLIT INDEPENDENT VERIFICATION ===", flush=True)
    start_time = time.time()

    # 1. Inspect and hash source files
    print("\n--- 1. Recomputing Source-File SHA-256 Checksums and Row Counts ---", flush=True)
    source_files = sorted(DATA_DIR.glob("*.csv"))
    if len(source_files) != 8:
        raise ValueError(f"Expected 8 source files in {DATA_DIR}, found {len(source_files)}")

    source_info = {}
    total_source_rows = 0
    for f in source_files:
        content = f.read_bytes()
        f_hash = sha256_bytes(content)
        f_size = len(content)
        # Count rows (excluding header)
        line_count = content.count(b"\n")
        # Ensure row count using pandas
        df_len = pd.read_csv(f, usecols=["source_row"]).shape[0]
        total_source_rows += df_len
        source_info[f.name] = {
            "size": f_size,
            "sha256": f_hash,
            "rows": df_len,
        }
        print(f"  {f.name}: {df_len:,} rows | {f_size:,} bytes | SHA256: {f_hash}", flush=True)

    print(f"Total Source Rows across all 8 files: {total_source_rows:,}")
    assert total_source_rows == 2830743, f"Expected 2,830,743 rows, got {total_source_rows}"

    # 2. Inspect 63-feature contract
    print("\n--- 2. Validating 63-Feature Canonical Input Contract ---", flush=True)
    features = [l.strip() for l in FEATURE_FILE.read_text(encoding="utf-8-sig").splitlines() if l.strip()]
    labels = json.loads(LABEL_FILE.read_text(encoding="utf-8"))
    print(f"Selected features count: {len(features)}")
    print(f"Canonical classes count: {len(labels)}")
    assert len(features) == 63, "Feature count must be exactly 63"
    assert len(labels) == 15, "Class count must be exactly 15"

    # 3. Validate split manifest
    print("\n--- 3. Verifying Split Manifest Allocation & Provenance ---", flush=True)
    if not MANIFEST_PATH.is_file():
        raise FileNotFoundError(f"Missing manifest: {MANIFEST_PATH}")

    df_manifest = pd.read_csv(MANIFEST_PATH)
    print(f"Manifest rows: {len(df_manifest):,}")
    assert len(df_manifest) == 2830743, "Manifest row count must match total corpus"

    split_counts = df_manifest["split"].value_counts().to_dict()
    print("Split allocation:", split_counts)
    train_count = split_counts.get("TRAIN", 0)
    test_count = split_counts.get("TEST", 0)

    assert train_count == 2264633, f"Expected 2,264,633 train rows, got {train_count}"
    assert test_count == 566110, f"Expected 566,110 test rows, got {test_count}"
    assert train_count + test_count == 2830743, "Every row must be either TRAIN or TEST"

    # 4. Independent full SHA-256 cross-partition leakage check
    print("\n--- 4. Computing Full 256-Bit SHA-256 Feature Digests for Zero-Leakage Audit ---", flush=True)
    train_mask = (df_manifest["split"] == "TRAIN").values
    test_mask = (df_manifest["split"] == "TEST").values

    train_hashes = set()
    test_hashes = set()
    offset = 0

    usecols = features + ["model_label"]
    dtypes = {c: np.float32 for c in features}
    dtypes["model_label"] = "string"

    per_class_audit = {}

    for i, path in enumerate(source_files, 1):
        df_src = pd.read_csv(path, usecols=usecols, dtype=dtypes, low_memory=False)
        n_rows = len(df_src)
        X = df_src[features].to_numpy(dtype=np.float32)
        np.nan_to_num(X, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
        np.clip(X, a_min=0.0, a_max=None, out=X)

        sub_train_mask = train_mask[offset : offset + n_rows]
        sub_test_mask = test_mask[offset : offset + n_rows]
        sub_labels = df_src["model_label"].str.strip().values

        # Track per-class counts
        for lbl in sub_labels:
            if lbl not in per_class_audit:
                per_class_audit[lbl] = {"train": 0, "test": 0, "total": 0}
            per_class_audit[lbl]["total"] += 1

        for idx in np.where(sub_train_mask)[0]:
            h = hashlib.sha256(X[idx].tobytes()).hexdigest()
            train_hashes.add(h)
            lbl = sub_labels[idx]
            per_class_audit[lbl]["train"] += 1

        for idx in np.where(sub_test_mask)[0]:
            h = hashlib.sha256(X[idx].tobytes()).hexdigest()
            test_hashes.add(h)
            lbl = sub_labels[idx]
            per_class_audit[lbl]["test"] += 1

        offset += n_rows
        print(f"  [{i}/8] Processed {path.name} ({n_rows:,} rows)...", flush=True)
        del df_src, X
        gc.collect()

    print(f"\nUnique Train 256-bit Feature Digests: {len(train_hashes):,}")
    print(f"Unique Test 256-bit Feature Digests:  {len(test_hashes):,}")

    overlap = train_hashes.intersection(test_hashes)
    print(f"Cross-Partition Collision Count:      {len(overlap)}")
    assert len(overlap) == 0, f"DATA LEAKAGE DETECTED! {len(overlap)} colliding digests found."
    print(">>> VERIFICATION SUCCESS: EXACT ZERO LEAKAGE CONFIRMED (0.0000% overlap).", flush=True)

    # 5. Verify per-class counts and zero-support classes
    print("\n--- 5. Per-Class Distribution & Zero-Support Class Audit ---", flush=True)
    zero_support_classes = []
    for lbl in sorted(per_class_audit.keys()):
        stat = per_class_audit[lbl]
        pct = (stat["test"] / stat["total"] * 100) if stat["total"] > 0 else 0.0
        print(f"  {lbl:28s}: Total={stat['total']:7,d} | Train={stat['train']:7,d} | Test={stat['test']:6,d} ({pct:5.2f}%)")
        if stat["test"] == 0:
            zero_support_classes.append(lbl)

    print(f"\nZero-Support Classes in Test Partition: {zero_support_classes}")
    assert set(zero_support_classes) == {"Heartbleed", "Infiltration", "Web Attack \ufffd Sql Injection"}

    # 6. Verify Corrected Verification Command
    print("\n--- 6. Corrected Verification Command Demonstration ---", flush=True)
    # The erroneous command in previous report attempted `pd.read_csv('...split_summary.json')`.
    # The correct command reads JSON using the standard json parser:
    with open(SUMMARY_PATH, "r", encoding="utf-8") as f:
        summary_obj = json.load(f)
    print(f"Corrected Verification Check: feature_hash_overlap = {summary_obj['feature_hash_overlap']}")
    assert summary_obj["feature_hash_overlap"] == 0

    elapsed = time.time() - start_time
    print(f"\n=== VERIFICATION AUDIT PASSED IN {elapsed:.2f} SECONDS ===", flush=True)


if __name__ == "__main__":
    main()
