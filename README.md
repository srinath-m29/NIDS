# Network Traffic Classification and Automated Intrusion Detection System (NIDS)

Automated Network Flow Analysis, Multiclass XGBoost Threat Classification, and Real-Time Diagnostic Dashboard for Windows 11.

---

## 1. Executive Summary & Mission

The Network Traffic Classification and Automated Intrusion Detection System (NIDS) automates network flow analysis, feature extraction, and threat detection that would otherwise require intensive manual analysis by a security operations center (SOC) analyst or network administrator.

The system ingests network packets or flow records, performs bidirectional flow aggregation, extracts a strict 63-feature contract, and classifies traffic into 15 categories (BENIGN traffic plus 14 distinct attack classes) using an optimized XGBoost gradient-boosted decision tree ensemble.

### System Capabilities
1. **Offline Dataset Replay & CSV Batch Analysis:** Validates and scores network traffic flow CSVs adhering to the cleaned CIC-IDS-2017 schema.
2. **Authorized Live Packet Capture:** Ingests raw network packets via Windows Npcap (defaulting strictly to loopback `127.0.0.1` / `\Device\NPF_Loopback`) in non-promiscuous mode.
3. **Pure-Python Flow Construction:** Performs stateful bidirectional flow tracking, TCP state tracking, inter-arrival time calculation, and flow lifecycle timeout management.
4. **Automated ML Classification:** Performs real-time inference on completed flows using either the verified `replacement_v2` model or historical `replacement_v1`.
5. **Detection Alerting & Persistence:** Automatically logs "Model-Classified Attack" events with full 5-tuple context into an isolated or production SQLite database.
6. **Unified Web Dashboard:** Serves a responsive, dark-mode single-page application (FastAPI backend + Vanilla CSS/JS) featuring live telemetry, event feeds, and flow inspection.
7. **Rigorous Held-Out Evaluation:** Built upon an independently verified exact-duplicate-free 80/20 train/test split with **0 exact feature-vector collisions** across 2,830,743 rows (in-distribution benchmark estimate).

---

## 2. Technology Stack & Platform

| Component | Technology | Version | Purpose |
|---|---|---|---|
| **Host OS** | Windows 11 Pro | 10.0.26100 | Operating environment |
| **Runtime** | Python | 3.12.8 (64-bit) | Backend & capture runtime |
| **ML Engine** | XGBoost | 3.4.1 | Histogram booster ensemble |
| **Backend API** | FastAPI / Uvicorn | 0.128.0 / 0.41.0 | Asynchronous REST & SSE streaming |
| **Data Engine** | Pandas / NumPy | 2.2.3 / 2.2.3 | Vectorized batch operations |
| **Capture Driver** | Npcap / Scapy | 1.80+ / 2.6.1 | Windows loopback packet capture |
| **Storage** | SQLite | 3.x | Thread-safe transaction persistence |
| **Frontend UI** | HTML5 / CSS3 / Vanilla JS | ES2022 | Single-page monitoring dashboard |

---

## 3. Architecture & Data Flow

```
                           [ NETWORK TRAFFIC INGESTION ]
                                         │
             ┌───────────────────────────┴───────────────────────────┐
             ▼                                                       ▼
   [ Authorized Live Capture ]                             [ CSV Dataset Replay ]
  - Npcap Loopback (\Device\NPF_Loopback)                  - 63 Canonical Features
  - Non-promiscuous, local only                           - Up to 50k rows / 100MB
             │                                                       │
             ▼                                                       │
  [ Pure-Python Packet Dissector ]                                   │
  - Layer 2/3/4 decoding (Ethernet/IP/TCP/UDP)                       │
  - 3.65 µs per packet                                               │
             │                                                       │
             ▼                                                       │
  [ Stateful Bidirectional Flow Tracker ]                            │
  - 5-tuple grouping: (src_ip, dst_ip, src_p, dst_p, proto)          │
  - Forward / Backward packet & byte accumulation                    │
  - Inactivity timeout (120s) & TCP teardown (FIN/RST)               │
             │                                                       │
             ▼                                                       │
  [ 63-Feature Canonical Extractor ]                                 │
  - Inter-arrival times, packet length statistics                    │
  - TCP flags, flow duration, transfer rates                         │
  - 20.96 µs per flow                                                │
             │                                                       │
             └───────────────────────────┬───────────────────────────┘
                                         ▼
                      [ XGBoost Multi-Class Hist Booster ]
                       - Active Model: replacement_v2
                       - Input Contract: Exactly 63 features
                       - Inference: 0.38 ms / flow (274k flows/sec)
                                         │
                                         ▼
                    ┌────────────────────┴────────────────────┐
                    ▼                                         ▼
         [ BENIGN Classification ]               [ Model-Classified Attack ]
        - Logged as normal traffic              - Triggers Intrusion Event
        - Telemetry counter updated             - Injected into /events feed
                    │                                         │
                    └────────────────────┬────────────────────┘
                                         ▼
                             [ SQLite Persistence ]
                 - runs, flows, detection_events, capture_sessions
                 - Production protected; isolated for test capture
                                         │
                                         ▼
                         [ FastAPI REST API & SSE Stream ]
                                         │
                                         ▼
                   [ Web Monitoring & Diagnostic Dashboard ]
```

---

## 4. Model Provenance & Evaluation (Stage 4C-2)

### 4.1 Dataset Partitioning & Exact-Duplicate-Free Split Verification
The model was trained on the cleaned CIC-IDS-2017 benchmark dataset comprising **2,830,743 processed rows** across 8 source CSV files:
- **Training Partition (80%):** 2,264,633 rows ($1,998,602$ unique SHA-256 feature digests)
- **Locked Held-Out Test Partition (20%):** 566,110 rows ($500,189$ unique SHA-256 feature digests)
- **Exact-Duplicate-Free Verification:** Full 256-bit SHA-256 hash comparison verified **0 identical 63-feature vector collisions** across the train/test boundary.
  - *Boundary Disclosure:* Claims are strictly designated as an **exact-duplicate-free split** (no identical feature vectors across partitions). This eliminates memorization of repeated flows but represents an in-distribution estimate from a single benchmark dataset; it does not eliminate all forms of correlation (such as temporal session proximity or shared capture-environment characteristics inherent to CIC-IDS-2017).
- **Disposition of 698 Conflicting-Label Groups (7,020 Rows):**
  - In `reports/evaluation/fold_validation_v1.json`, exactly **698 feature-vector groups** totaling **7,020 rows** were documented where identical 63-feature vectors carry differing ground-truth labels across capture sessions.
  - In the underlying 5-fold stratification, Folds 0–3 contained **555 groups (3,039 rows)**, and Fold 4 contained **143 groups (3,981 rows)**.
  - In Stage 4C-2, Folds 0–3 formed the training set (2,264,633 rows) and Fold 4 formed the candidate test set (566,110 rows).
  - During collision resolution, the 25 colliding test rows moved to training as complete hash clusters.
  - **Audit Disposition Result:** All 555 conflicting groups (3,039 rows) reside entirely in the Training partition. All 143 conflicting groups (3,981 rows) reside entirely in the Test partition. **Exactly 0 conflicting-label groups cross the train/test boundary**.
- **Single Evaluation Protocol:** The locked test partition was evaluated **exactly once** after training was finalized and the model was frozen. No model architecture decisions, feature selections, or hyperparameter tunings were made using test set results.

### 4.2 Per-Class Held-Out Performance (Primary Evidence)
Evaluated on the locked 566,110-row test partition (preserving original class order):

| Class Index & Name | Train Support | Test Support | Precision | Recall | F1-Score | Operational Finding |
|---|---|---|---|---|---|---|
| `[ 0] BENIGN` | 1,818,502 | 454,595 | 0.999635 | 0.999358 | 0.999496 | Baseline normal traffic |
| `[ 1] Bot` | 1,573 | 393 | 0.910653 | 0.674300 | 0.774854 | Ares botnet C2 traffic mimicry |
| `[ 2] DDoS` | 102,421 | 25,606 | 0.999961 | 0.999531 | 0.999746 | High-volume attack |
| `[ 3] DoS GoldenEye` | 8,234 | 2,059 | 0.999509 | 0.988830 | 0.994141 | Application DoS |
| `[ 4] DoS Hulk` | 184,858 | 46,215 | 0.998272 | 0.999892 | 0.999081 | High-volume DoS |
| `[ 5] DoS Slowhttptest` | 4,399 | 1,100 | 0.987342 | 0.992727 | 0.990027 | Low-rate DoS |
| `[ 6] DoS slowloris` | 4,637 | 1,159 | 0.996534 | 0.992235 | 0.994380 | Low-rate DoS |
| `[ 7] FTP-Patator` | 6,351 | 1,587 | 1.000000 | 1.000000 | 1.000000 | Brute force authentication |
| `[ 8] Heartbleed` | 11 | 0 | N/A | N/A | N/A | **Unevaluated (0 test support)** |
| `[ 9] Infiltration` | 36 | 0 | N/A | N/A | N/A | **Unevaluated (0 test support)** |
| `[10] PortScan` | 127,144 | 31,786 | 0.993807 | 0.999654 | 0.996722 | High-volume reconnaissance |
| `[11] SSH-Patator` | 4,718 | 1,179 | 1.000000 | 0.999152 | 0.999576 | Brute force authentication |
| `[12] Web Attack  Brute Force` | 1,206 | 301 | 0.712895 | 0.973422 | 0.823034 | Web application attack |
| `[13] Web Attack  Sql Injection` | 21 | 0 | N/A | N/A | N/A | **Unevaluated (0 test support)** |
| `[14] Web Attack  XSS` | 522 | 130 | 0.736842 | 0.107692 | 0.187919 | Low individual recall; 112/130 flagged as Brute Force |

### 4.3 Summary Metrics & Aggregate Disclosures

| Metric | Measured Value | Basis / Explicit Denominator |
|---|---|---|
| **Macro-F1 (12 Supported Classes)** | **0.8966** | Denominator = 12 (unweighted mean of evaluated classes) |
| **Macro-F1 (All 15 Classes)** | **0.7173** | Denominator = 15 (assigning 0.0 to 3 unevaluated classes) |
| **Overall Accuracy** | **99.8917%** | 565,497 / 566,110 correct (diagonal sum of 15x15 matrix) |
| **Benign False Alarm Rate (FPR)** | **0.0642%** | 292 / 454,595 benign flows misclassified as attack |
| **Attack Missed-Detection Rate** | **0.1489%** | 166 / 111,515 attack flows misclassified as benign |
| **Weighted F1 Score** | **0.9988** | Class-distribution weighted harmonic mean |
| **Aggregate Attack Recall (Qualified)** | **99.8511%** | 111,349 / 111,515 attacks detected across pooled attack flows |

> [!WARNING]
> **Crucial Qualification on Aggregate Attack Recall:**  
> This aggregate figure is dominated by massive-volume DoS and PortScan attacks (DoS Hulk: 46,215, PortScan: 31,786, DDoS: 25,606), which together comprise **92.9%** ($103,607 / 111,515$) of all attack test flows.  
> In stark contrast, low-volume attacks experience substantial failure rates:  
> - `Web Attack XSS`: Individual recall is only **10.77%** (14 / 130). However, 112/130 are grouped as Web Attack Brute Force, yielding **96.92%** detection as a general web attack.  
> - `Bot`: Recall is **67.43%** (265 / 393) due to Ares botnet C2 HTTP/IRC traffic mimicry of normal user traffic.  
> - `Heartbleed`, `Infiltration`, and `SQL Injection`: **0 test support and completely unevaluated**.  
> Therefore, aggregate attack recall must NOT be cited as a standalone headline metric or used to imply uniform threat coverage.

### 4.4 Mandatory Operational Disclosures
1. **Live Capture is EXPERIMENTAL:** The pure-Python live packet capture and flow extraction pipeline is **EXPERIMENTAL / NOT OPERATIONALLY VALIDATED** for physical perimeter defense. It defaults safely to loopback (`127.0.0.1`).
2. **In-Distribution Estimate from One Split:** Reported `replacement_v2` metrics represent an in-distribution performance estimate derived from a single 80/20 partition of the CIC-IDS-2017 dataset; they do not establish out-of-distribution generalization to external network environments.
3. **Unevaluated Minority Classes:** `Heartbleed` (11 train rows), `Infiltration` (36 train rows), and `Web Attack Sql Injection` (21 train rows) have zero test rows in the held-out partition and are completely unevaluated.
4. **Baseline Model v1 Status:** `replacement_v1` is unevaluated by the v2 test results and was trained on historical overlapping data.
5. **Uncalibrated Model Confidence:** Output probabilities from XGBoost softmax are uncalibrated model scores and do not establish empirical correctness or true likelihood of intrusion.

---

## 5. Security Boundaries & Protected Assets

### 5.1 Operating Boundaries
- **Strictly Passive Monitoring:** The system only inspects traffic. It performs zero packet injection, active port scans, counterattacks, or automated firewall blocking.
- **Default Loopback:** Physical capture adapters require explicit user selection. Loopback (`127.0.0.1`) is the default.
- **Payload Privacy:** Raw packet payloads are discarded immediately after dissection; only statistical flow metadata is retained.

### 5.2 Protected Assets Baseline (SHA-256)
The following reference files must never be modified or overwritten:

| Asset | Path | Reference SHA-256 Hash |
|---|---|---|
| `replacement_v1` Model | `models/replacement_v1/xgboost_nids_replacement_v1.json` | `36667EABAAA5F363AA2F3578B71629AE4402FA41676BC52C2D59C539437544A3` |
| `replacement_v1` Features | `models/replacement_v1/selected_features.txt` | `7A2CA037B3341EBF64E8252A8F1BCDBB2A1A9F14C66FE0ED2DA47AF3FDE4C6F2` |
| `replacement_v1` Labels | `models/replacement_v1/label_mapping.json` | `8A1EDFEA81ED7E10A394EA51E30962E93F7391DEA03699C928AB497E05CEED5A` |
| `replacement_v1` Metadata | `models/replacement_v1/model_metadata.json` | `2B7F71D2878967E773403ABE499FA17BDAB57EC891A3F48C07285EF6F0CFDCB4` |
| Production Database | `app_v2/data/nids.sqlite` | `F4C2CD0AC83EFBBC2D01045A67D9E98BCAE6505CD1D32F4E4455A612D6DF8E24` |
| Database Baseline Backup | `app_v2/data/nids.sqlite.bak_baseline` | `C7C508884A8BA982091F51A4EA13274219B11435349BFC68CBD8D0F88B87DE1D` |

---

## 6. Installation & Quickstart

### Prerequisites
- Windows 10/11 (Administrator privileges required if running live packet capture via Npcap).
- Python 3.12 (64-bit).
- Optional for live network capture: [Npcap](https://npcap.com/) installed with "WinPcap API-compatible Mode" enabled (loopback adapter required for local live traffic).

### Setup Steps
```powershell
# 1. Clone repository and navigate to project root:
cd <path-to-nids-root>

# 2. Create and activate virtual environment:
python -m venv app_v2\.venv
.\app_v2\.venv\Scripts\Activate.ps1

# 3. Install consolidated dependencies:
pip install -r requirements.txt

# 4. Launch FastAPI active v2 backend and interactive dashboard:
python -m uvicorn app_v2.app_model_v2:app --host 127.0.0.1 --port 8000
```

Access the dashboard at: **http://127.0.0.1:8000**

> [!NOTE]
> `app_v2/app_model_v2.py` is the designated active v2 entry point. `app_v2/app.py` and `app_v2/app_model_v1.py` are deprecated legacy prototypes preserved for historical reference.

---

## 7. API Reference

The backend provides over 30 REST and streaming endpoints:

### Core & Health
- `GET /` — Serves the NIDS Interactive Diagnostic Dashboard (`static/index_v2.html`).
- `GET /health` — Service health, active model version, class counts, capture status.
- `GET /ready` — Readiness check verifying database connectivity and model contracts.
- `GET /features` — Returns the canonical 63-feature contract in exact model order.
- `GET /metrics` — Held-out evaluation metrics from Stage 4C-2. If artifacts are not generated from raw data, returns `{"available": false}` with documentation guidance.

### Model Management
- `GET /model/info` — Active model metadata, architecture specs, and class list.
- `POST /model/select` — Hot-swaps the active classifier (`replacement_v1` or `replacement_v2`) with thread-safe locking.

### Prediction & Classification
- `POST /predict/flow` — Classifies a single flow dictionary against the 63-feature contract.
- `POST /predict/batch` — Classifies a batch of flows (bounded up to 1,000 flows).
- `POST /score` — Safely ingests a flow CSV file, validates feature columns, runs model inference, reports coerced columns, and returns a summary plus sample flows.

### Live Packet Capture & Streaming
- `GET /capture/interfaces` — Discovers network adapters, identifying loopback and authorization status.
- `POST /capture/start` — Starts asynchronous background packet capture (Npcap loopback).
- `POST /capture/stop` — Cleanly halts capture and flushes pending flows.
- `GET /capture/status` — Current capture lifecycle status, elapsed time, and packet counts.
- `GET /capture/stats` — Detailed live telemetry (packets captured, active flows, classified, alerts, IPv6, unsupported).
- `GET /capture/flows` — Retrieves recent live-constructed flows with classification results.
- `GET /capture/sessions` — Retrieves historical capture session records.
- `GET /capture/stream` — Real-time Server-Sent Events (SSE) telemetry stream (asynchronous generator with clean disconnect detection).

### Detection Events & Database
- `GET /events` — Retrieves model-classified attack alerts with filtering.
- `POST /events/{event_id}/ack` — Acknowledges an intrusion event.
- `GET /summary` — Database summary statistics (total flows, scored rows, class counts).
- `GET /runs` — Ingestion run history with pagination.
- `GET /flows` — Flow records query with filtering and pagination.
- `GET /flows/{flow_id}` — Detailed 5-tuple and feature metadata for a specific flow.

---

## 8. Verification & Test Commands

Execute the test suites using the isolated virtual environment:

```powershell
# Run full regression suite from project root:
.\app_v2\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py"

# Or execute individual test modules:
# 1. API v2 Unit & Lifecycle Tests
.\app_v2\.venv\Scripts\python.exe -m unittest tests/test_api_v2.py

# 2. Stage 4B Live Capture & Flow Extraction Tests
.\app_v2\.venv\Scripts\python.exe -m unittest tests/test_stage4b.py

# 3. Stage 4C-2 Split Verification & Model Evaluation Tests
.\app_v2\.venv\Scripts\python.exe -m unittest tests/test_stage4c2.py

# 4. Offline Pipeline & Evaluator Tests
.\app_v2\.venv\Scripts\python.exe -m unittest tests/test_offline_evaluator.py tests/test_offline_pipeline.py

# 5. Remediation Suite (Portability, Concurrency, Safety)
.\app_v2\.venv\Scripts\python.exe -m unittest tests/test_remediation.py

# 6. Run Stage O Performance Benchmark
.\app_v2\.venv\Scripts\python.exe src/evaluation/benchmark_performance.py
```


---

## 9. Performance Benchmark Summary

Empirically measured on Windows 11 Pro:
- **Single-Flow Inference:** Mean **0.41 ms** (p50: 0.38 ms, p95: 0.61 ms, p99: 0.72 ms).
- **Batch Throughput:** **339,532 flows/second** at batch size 10,000.
- **Packet Dissection:** **3.65 µs** per packet (~274,000 packets/sec).
- **Feature Extraction:** **20.96 µs** per flow (~47,700 flows/sec).
- **Memory Footprint:** Baseline RSS ~145 MB with bounded flow and event caches.

---

## 10. Repository File Structure

```
<project-root>/
├── app_v2/
│   ├── app_model_v2.py              # Main FastAPI application (30+ routes)
│   ├── run_live_capture.py          # Standalone loopback capture runner
│   ├── capture/
│   │   ├── feature_extractor.py     # 63 canonical feature extractor
│   │   ├── flow_tracker.py          # Bidirectional stateful flow tracking
│   │   ├── live_capture_worker.py   # Scapy AsyncSniffer capture worker
│   │   └── packet_dissector.py      # Layer 2/3/4 packet dissector
│   ├── data/
│   │   ├── nids.sqlite              # Protected production SQLite DB
│   │   ├── nids.sqlite.bak_baseline # Protected baseline database backup
│   │   └── test/                    # Isolated test databases
│   └── static/
│       └── index_v2.html            # Complete diagnostic dashboard UI
├── models/
│   ├── replacement_v1/              # Protected baseline XGBoost model
│   └── replacement_v2/              # Certified holdout-evaluated XGBoost model
├── reports/
│   ├── evaluation/stage4c2/         # Stage 4C-2 split, metrics, and training reports
│   └── requirements_traceability_matrix.md
├── src/
│   └── evaluation/
│       ├── benchmark_performance.py # Stage O empirical latency/throughput benchmark
│       ├── evaluate_model_holdout.py# Holdout evaluation script
│       ├── train_replacement_v2.py  # Model replacement_v2 training script
│       └── verify_dataset_split.py  # 2.83M row split & leakage verifier
└── tests/
    ├── test_api_v2.py               # REST API & capture lifecycle unit tests
    ├── test_stage4b.py              # Live capture, packet parsing, & DB isolation
    └── test_stage4c2.py             # Split integrity & holdout metric tests
```
