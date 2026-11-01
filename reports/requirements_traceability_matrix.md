# NIDS REQUIREMENTS TRACEABILITY MATRIX

**Project:** Network Traffic Classification and Automated Intrusion Detection System (NIDS)  
**Repository:** `C:\Projects\NIDS`  
**Platform:** Windows 11 Pro (Build 26100), Python 3.12.8, XGBoost 3.4.1  
**Executive Authority:** ChatGPT  
**Independent Reviewer:** Claude  
**Primary Worker:** Antigravity  
**Execution Timestamp:** 2026-10-12 15:15 IST (09:45 UTC)  
**Status:** **ACTIVE TRACEABILITY MATRIX**  

---

## 1. Traceability Overview

This matrix maps every functional, security, machine learning, operational, and testing requirement specified in the **Master Executive Execution Order** to its implementation in the codebase, associated test suites, and current verification status.

---

## 2. Core Operational Capabilities (Section 2)

| Requirement ID | Requirement Description | Implementation Files | Test Evidence | Status |
| :--- | :--- | :--- | :--- | :---: |
| **REQ-CORE-01** | Offline network-traffic dataset analysis | `src/evaluation/offline_evaluator.py`, `offline_pipeline.py` | `tests/test_offline_evaluator.py`, `test_offline_pipeline.py` | **VERIFIED** |
| **REQ-CORE-02** | CSV-based traffic analysis and replay | `app_v2/app_model_v2.py` (`/score`), `static/index_v2.html` | `tests/test_stage4b.py`, `test_app_v2.py` | **VERIFIED** |
| **REQ-CORE-03** | Network-flow validation and 63-feature extraction | `app_v2/capture/feature_extractor.py`, `packet_dissector.py` | `tests/test_stage4b.py`, `test_feature_parity.py` | **VERIFIED** |
| **REQ-CORE-04** | Multiclass ML traffic classification (15 classes) | `models/replacement_v2/`, `src/evaluation/offline_pipeline.py` | `tests/test_stage4c2.py` | **VERIFIED** |
| **REQ-CORE-05** | Authorized live packet capture (loopback default) | `app_v2/capture/live_capture_worker.py` (Scapy AsyncSniffer) | `tests/test_stage4b.py` | **VERIFIED** |
| **REQ-CORE-06** | Live flow construction and tracking | `app_v2/capture/flow_tracker.py` | `tests/test_stage4b.py` | **VERIFIED** |
| **REQ-CORE-07** | Automated inference on completed flows | `app_v2/capture/live_capture_worker.py`, `app_model_v2.py` | `tests/test_stage4b.py`, `test_stage4c2.py` | **VERIFIED** |
| **REQ-CORE-08** | Live monitoring and detection-event presentation | `app_v2/static/index_v2.html`, `app_v2/app_model_v2.py` | `tests/test_app_v2.py` | **IMPLEMENTED** |
| **REQ-CORE-09** | Prediction and event persistence (SQLite) | `app_v2/app_model_v2.py`, `capture/live_capture_worker.py` | `tests/test_stage4b.py`, `test_stage4c2.py` | **VERIFIED** |
| **REQ-CORE-10** | Searchable traffic and prediction history | `app_v2/app_model_v2.py` (`/flows`, `/runs`, `/events`) | `tests/test_app_v2.py` | **IMPLEMENTED** |
| **REQ-CORE-11** | Dashboard statistics and visualizations | `app_v2/static/index_v2.html`, `/summary`, `/capture/stats` | `tests/test_app_v2.py` | **IMPLEMENTED** |
| **REQ-CORE-12** | Model and capture-system health monitoring | `app_v2/app_model_v2.py` (`/health`, `/ready`, `/capture/status`) | `tests/test_stage4b.py`, `test_app_v2.py` | **VERIFIED** |
| **REQ-CORE-13** | Reproducible model training and held-out evaluation | `src/models/train_replacement_v2.py`, `run_stage4c2_evaluation.py` | `tests/test_stage4c2.py` | **VERIFIED** |
| **REQ-CORE-14** | Automated testing, security checks, and integrity verification | `tests/`, `reports/evaluation/stage4c2/` manifests | Full test discovery suite (40+ tests) | **VERIFIED** |

---

## 3. Security Boundaries & Protected Assets (Section 3)

| Requirement ID | Requirement Description | Implementation / Guard | Verification Evidence | Status |
| :--- | :--- | :--- | :--- | :---: |
| **REQ-SEC-01** | Zero unauthorized scanning / injection / blocking | Strict passive capture worker; no active socket send | Code audit of `live_capture_worker.py` | **ENFORCED** |
| **REQ-SEC-02** | Default non-promiscuous loopback capture | `resolve_adapter_name()`, bound to `127.0.0.1` | `test_stage4b.py` | **ENFORCED** |
| **REQ-SEC-03** | No raw packet payload persistence | Payload discarded; only 63 flow features saved | `app_v2/capture/flow_tracker.py` | **ENFORCED** |
| **REQ-SEC-04** | Protected asset `replacement_v1` booster preserved | Read-only; hash checked against reference `3666...44A3` | `test_stage4c2.py` (test 03) | **VERIFIED** |
| **REQ-SEC-05** | Protected asset `selected_features.txt` preserved | Read-only; hash checked against reference `7A2C...46F2` | `test_stage4c2.py` | **VERIFIED** |
| **REQ-SEC-06** | Protected asset `label_mapping.json` preserved | Read-only; hash checked against reference `8A1E...ED5A` | `test_stage4c2.py` | **VERIFIED** |
| **REQ-SEC-07** | Protected asset `model_metadata.json` preserved | Read-only; hash checked against reference `2B7F...DCB4` | Stage 4C-2 baseline check | **VERIFIED** |
| **REQ-SEC-08** | Production database `nids.sqlite` untouched | Read-only in tests; hash checked against `F4C2...8E24` | `test_stage4c2.py` (test 08) | **VERIFIED** |
| **REQ-SEC-09** | Database baseline backup preserved | Hash checked against reference `C7C5...DE1D` | Hash check verification | **VERIFIED** |
| **REQ-SEC-10** | Isolated test databases for automated test execution | `nids_test_live_4b.sqlite`, `test_scratch/` | `tests/test_stage4b.py`, `test_stage4c2.py` | **ENFORCED** |

---

## 4. Dataset Split & Machine Learning (Sections 6 & 7)

| Requirement ID | Requirement Description | Implementation Files | Test Evidence | Status |
| :--- | :--- | :--- | :--- | :---: |
| **REQ-ML-01** | Source dataset provenance ($2,830,743$ rows in 8 files) | `data/processed/feature_cleaned_v2/*.csv` | `stage4c2_split_and_leakage_report.md` | **VERIFIED** |
| **REQ-ML-02** | Group-aware leakage-resistant split (80% train / 20% test) | `reports/evaluation/stage4c2/stage4c2_split_manifest.csv` | `tests/test_stage4c2.py` (test 01) | **VERIFIED** |
| **REQ-ML-03** | Exact zero feature-vector overlap (0.0000% leakage) | `reports/evaluation/stage4c2/stage4c2_split_summary.json` | `tests/test_stage4c2.py` (test 02) | **VERIFIED** |
| **REQ-ML-04** | Disclose zero-support classes (< 100 corpus rows) | `stage4c2_evaluation_report.md` (Heartbleed, Infilt, SQL Inj) | `tests/test_stage4c2.py` (test 06) | **VERIFIED** |
| **REQ-ML-05** | Train separate model `models/replacement_v2` | `src/models/train_replacement_v2.py` | `models/replacement_v2/model_metadata.json` | **VERIFIED** |
| **REQ-ML-06** | Evaluate `replacement_v2` on locked test set ($566,110$ rows) | `src/evaluation/run_stage4c2_evaluation.py` | `stage4c2_metrics.json` | **VERIFIED** |
| **REQ-ML-07** | Compute Confusion Matrix, Macro/Weighted F1, FPR, FNR | `src/evaluation/offline_evaluator.py` | `tests/test_offline_evaluator.py` | **VERIFIED** |

---

## 5. Flow Feature Extraction (Section 8)

| Requirement ID | Requirement Description | Implementation Files | Test Evidence | Status |
| :--- | :--- | :--- | :--- | :---: |
| **REQ-FE-01** | Exact 63 canonical feature order and names | `app_v2/capture/feature_extractor.py`, `models/selected_features.txt` | `tests/test_stage4b.py`, `test_stage4c2.py` | **VERIFIED** |
| **REQ-FE-02** | Non-finite / NaN clamping and non-negative clipping | `src/evaluation/offline_pipeline.py`, `feature_extractor.py` | `tests/test_offline_pipeline.py` | **VERIFIED** |
| **REQ-FE-03** | Bidirectional TCP/UDP packet and byte aggregation | `app_v2/capture/flow_tracker.py` | `tests/test_stage4b.py` | **VERIFIED** |
| **REQ-FE-04** | Flow timeout, FIN/RST finalization, and pending flush | `app_v2/capture/flow_tracker.py`, `live_capture_worker.py` | `tests/test_stage4b.py` | **VERIFIED** |
| **REQ-FE-05** | Mark live extractor `EXPERIMENTAL / NOT OPERATIONALLY VALIDATED` | `feature_extractor.py`, metadata headers | Audit of extractor docstrings | **ENFORCED** |

---

## 6. FastAPI Backend & Persistence (Sections 9 & 14)

| Requirement ID | Endpoint / Capability | Target Functionality | Status |
| :--- | :--- | :--- | :---: |
| **REQ-API-01** | `GET /health` | Health status, version, mode | **VERIFIED** |
| **REQ-API-02** | `GET /ready` | Readiness check (model loaded, DB connected) | **IMPLEMENTED** |
| **REQ-API-03** | `GET /model/info` | Active model metadata, features, classes, available versions | **IMPLEMENTED** |
| **REQ-API-04** | `POST /predict/flow` | Single-flow 63-feature JSON prediction | **IMPLEMENTED** |
| **REQ-API-05** | `POST /predict/batch` | Bounded batch JSON prediction | **IMPLEMENTED** |
| **REQ-API-06** | `POST /score` | Upload CSV, validate schema, batch predict, persist | **VERIFIED** |
| **REQ-API-07** | `GET /summary` | Aggregated runs, rows scored, class distribution | **VERIFIED** |
| **REQ-API-08** | `GET /flows` | Paginated flow records with filtering and search | **VERIFIED** |
| **REQ-API-09** | `GET /flows/{flow_id}` | Detailed 63-feature inspection of individual flow | **IMPLEMENTED** |
| **REQ-API-10** | `GET /runs` | Paginated batch execution history | **VERIFIED** |
| **REQ-API-11** | `GET /capture/interfaces` | Enumerate local Scapy/Npcap network adapters | **IMPLEMENTED** |
| **REQ-API-12** | `GET /capture/status` | Current worker state, packets, flows, errors | **IMPLEMENTED** |
| **REQ-API-13** | `POST /capture/start` | Start live capture worker with explicit interface selection | **IMPLEMENTED** |
| **REQ-API-14** | `POST /capture/stop` | Coordinate clean capture worker shutdown and flush | **IMPLEMENTED** |
| **REQ-API-15** | `GET /capture/flows` | Retrieve recent live completed flows | **IMPLEMENTED** |
| **REQ-API-16** | `GET /capture/stats` | Real-time live monitoring counters (packets, flows, attacks) | **IMPLEMENTED** |
| **REQ-API-17** | `GET /events` | Detection event feed (Model-Classified Attack alerts) | **IMPLEMENTED** |
| **REQ-API-18** | `GET /capture/stream` | Server-Sent Events (SSE) streaming live flow events | **IMPLEMENTED** |
| **REQ-API-19** | Thread-safe DB operations | Safe SQLite connection handling, parameterized queries, indexes | **ENFORCED** |
| **REQ-API-20** | Error handling & HTTP status codes | Standardized error schemas (400, 404, 413, 422, 500) | **ENFORCED** |

---

## 7. Live Dashboard & Frontend (Sections 12 & 16)

| Requirement ID | Frontend Element / Interaction | Implementation Path | Verification Status |
| :--- | :--- | :--- | :---: |
| **REQ-FE-01** | Capture Controls (Start/Stop/Interface select) | `app_v2/static/index_v2.html` Live Monitoring tab | **VERIFIED** |
| **REQ-FE-02** | Real-time counter cards (Packets, Flows, Alerts) | `app_v2/static/index_v2.html` Metrics row | **VERIFIED** |
| **REQ-FE-03** | Live flows table with pagination and filtering | `app_v2/static/index_v2.html` Flows data table | **VERIFIED** |
| **REQ-FE-04** | Detection events alert panel ("Model-Classified Attack") | `app_v2/static/index_v2.html` Alert feed | **VERIFIED** |
| **REQ-FE-05** | CSV analysis and replay tab | `app_v2/static/index_v2.html` File upload panel | **VERIFIED** |
| **REQ-FE-06** | Model inspection tab (V1 vs V2, 63 features, metrics) | `app_v2/static/index_v2.html` Diagnostic modal | **VERIFIED** |
| **REQ-FE-07** | Bounded polling / SSE updates | `app_v2/static/index_v2.html` JavaScript event loop | **VERIFIED** |
| **REQ-FE-08** | Error states and disconnect handling | `app_v2/static/index_v2.html` Banner notification system | **VERIFIED** |

---

## 8. Verification Status Legend
- **VERIFIED:** Fully implemented, exercised by automated regression tests, and passing.
- **IMPLEMENTED:** Implemented in code and verified during stage integration.
- **ENFORCED:** Security invariant or constraint enforced programmatically by defensive assertions.
