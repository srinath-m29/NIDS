"""
generate_final_integrity_manifest.py
Audits SHA-256 checksums of all protected assets and new stage deliverables,
verifying 100% integrity and producing the final integrity manifest.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

PROTECTED_ASSETS = {
    "models/replacement_v1/xgboost_nids_replacement_v1.json": "36667EABAAA5F363AA2F3578B71629AE4402FA41676BC52C2D59C539437544A3",
    "models/replacement_v1/selected_features.txt": "7A2CA037B3341EBF64E8252A8F1BCDBB2A1A9F14C66FE0ED2DA47AF3FDE4C6F2",
    "models/replacement_v1/label_mapping.json": "8A1EDFEA81ED7E10A394EA51E30962E93F7391DEA03699C928AB497E05CEED5A",
    "models/replacement_v1/model_metadata.json": "2B7F71D2878967E773403ABE499FA17BDAB57EC891A3F48C07285EF6F0CFDCB4",
    "app_v2/data/nids.sqlite": "C7C508884A8BA982091F51A4EA13274219B11435349BFC68CBD8D0F88B87DE1D",
    "app_v2/data/nids.sqlite.bak_baseline": "C7C508884A8BA982091F51A4EA13274219B11435349BFC68CBD8D0F88B87DE1D",
}

DELIVERABLE_ASSETS = [
    "models/replacement_v2/xgboost_nids_replacement_v2.json",
    "models/replacement_v2/selected_features.txt",
    "models/replacement_v2/label_mapping.json",
    "models/replacement_v2/model_metadata.json",
    "reports/requirements_traceability_matrix.md",
    "reports/evaluation/stage4c2/stage4c2_verification_report.md",
    "reports/evaluation/stage4c2/stage4c2_split_and_leakage_report.md",
    "reports/evaluation/stage4c2/stage4c2_training_report.md",
    "reports/evaluation/stage4c2/stage4c2_evaluation_report.md",
    "reports/evaluation/stage4c2/stage4c2_metrics.json",
    "reports/evaluation/stage4c2/confusion_matrix.csv",
    "reports/evaluation/stage4c2/confusion_matrix_text.txt",
    "reports/evaluation/stage4c2/performance_verification.json",
    "reports/final/final_gate_corrections_changelog.md",
    "reports/final/read_only_evidence_audit_report.md",
    "reports/final/reproducibility_manifest.json",
    "reports/final/near_duplicate_audit_results.json",
    "app_v2/app_model_v2.py",
    "app_v2/static/index_v2.html",
    "tests/test_api_v2.py",
    "tests/test_stage4b.py",
    "tests/test_stage4c2.py",
    "README.md",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().upper()


def audit():
    manifest = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "protected_assets_audit": [],
        "deliverables_audit": [],
        "protected_assets_match_all": True,
    }

    print("=== AUDITING PROTECTED ASSETS ===")
    for rel_path, expected_hash in PROTECTED_ASSETS.items():
        full_path = REPO_ROOT / rel_path
        if not full_path.is_file():
            print(f"[FAIL] Missing protected asset: {rel_path}")
            manifest["protected_assets_match_all"] = False
            continue
        actual_hash = sha256_file(full_path)
        match = (actual_hash == expected_hash)
        if not match:
            manifest["protected_assets_match_all"] = False
            print(f"[MISMATCH] {rel_path}: expected {expected_hash}, got {actual_hash}")
        else:
            print(f"[OK] {rel_path}: 100% MATCH")
        manifest["protected_assets_audit"].append({
            "path": rel_path,
            "expected_sha256": expected_hash,
            "actual_sha256": actual_hash,
            "matches": match,
            "size_bytes": full_path.stat().st_size,
        })

    print("\n=== AUDITING DELIVERABLE ARTIFACTS ===")
    for rel_path in DELIVERABLE_ASSETS:
        full_path = REPO_ROOT / rel_path
        if not full_path.is_file():
            print(f"[WARN] Deliverable not found: {rel_path}")
            continue
        act_hash = sha256_file(full_path)
        print(f"[DELIVERABLE] {rel_path}: {act_hash}")
        manifest["deliverables_audit"].append({
            "path": rel_path,
            "sha256": act_hash,
            "size_bytes": full_path.stat().st_size,
        })

    # Save manifests
    out_c2 = REPO_ROOT / "reports" / "evaluation" / "stage4c2" / "stage4c2_integrity_manifest.json"
    out_final = REPO_ROOT / "reports" / "final" / "final_integrity_manifest.json"
    out_final.parent.mkdir(parents=True, exist_ok=True)

    c2_json = json.dumps(manifest, indent=2)
    out_c2.write_text(c2_json, encoding="utf-8")
    out_final.write_text(c2_json, encoding="utf-8")
    print(f"\n[+] Manifests saved to {out_c2} and {out_final}")
    return manifest


if __name__ == "__main__":
    audit()
