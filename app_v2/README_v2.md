# NIDS Application v2 - Architecture, Setup, and Operational Guide

## 1. Project Overview & Active Entry Point

This package contains the active v2 implementation of the Network Intrusion Detection System (NIDS), featuring:
- **Active Production Entry Point:** `app_v2/app_model_v2.py`
- Multi-class threat classification using XGBoost (`replacement_v2` certified model and `replacement_v1` baseline).
- Strict 63-feature canonical contract validation.
- Live network packet capture via Npcap (defaulting strictly to loopback `127.0.0.1` / `\Device\NPF_Loopback`).
- Stateful bidirectional flow tracking and feature extraction.
- Asynchronous Server-Sent Events (SSE) telemetry stream (`/capture/stream`).
- Thread-safe model selection and inference locking.
- Secure-by-default CORS policy.
- Interactive diagnostic web dashboard (`static/index_v2.html`).

> [!WARNING]
> Legacy entry points `app_v2/app.py` and `app_v2/app_model_v1.py` are deprecated and preserved only for historical reference. Always use `app_v2/app_model_v2.py`.

---

## 2. Quickstart & Execution

### Setup Environment
```powershell
# From the repository root:
python -m venv app_v2\.venv
.\app_v2\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Launch Active v2 Application
```powershell
# From the repository root:
python -m uvicorn app_v2.app_model_v2:app --host 127.0.0.1 --port 8000
```

Access the dashboard at: **http://127.0.0.1:8000**

---

## 3. Key Endpoints

- **Dashboard:** `http://127.0.0.1:8000/`
- **Health & Readiness:** `GET /health`, `GET /ready`
- **Model Info & Switching:** `GET /model/info`, `POST /model/select`
- **Single & Batch Inference:** `POST /predict/flow`, `POST /predict/batch`
- **CSV Replay & Ingestion:** `POST /score` (bounded memory, file size checks, coerced column reporting)
- **Live Capture Control:** `GET /capture/interfaces`, `POST /capture/start`, `POST /capture/stop`, `GET /capture/status`, `GET /capture/stats`
- **SSE Telemetry Stream:** `GET /capture/stream` (asynchronous, non-blocking, clean disconnect detection)
- **Database & Alerts:** `GET /events`, `POST /events/{event_id}/ack`, `GET /runs`, `GET /flows`, `GET /summary`
- **Evaluation Metrics:** `GET /metrics`

---

## 4. Evaluation Metrics Artifacts & Dataset Notice

The offline evaluation metrics for Stage 4C-2 are designed to be computed across 566,110 held-out test rows from the 2.83M row processed CIC-IDS-2017 dataset.

Because the multi-gigabyte source dataset CSVs are external to this git repository:
- When `reports/evaluation/stage4c2/stage4c2_metrics.json` is present, `/metrics` returns the verified held-out evaluation metrics.
- When the artifact is not present, `/metrics` gracefully returns `{"available": false}` with documentation on how to regenerate them once the raw dataset is provisioned.
- Evaluation metrics are never fabricated.

To generate the evaluation artifacts after placing the processed dataset into `data/processed/feature_cleaned_v2/`:
```powershell
python src/evaluation/verify_dataset_split.py
python src/evaluation/run_stage4c2_evaluation.py
```

---

## 5. Security & Operational Disclosures

1. **Passive Monitoring Only:** The system does not alter packets, perform active network scans, or conduct automated counterattacks.
2. **Experimental Live Capture:** The pure-Python packet dissector and flow tracker are experimental and intended for local loopback demonstration. They are not certified for perimeter security enforcement on high-throughput physical links without measured line-rate validation.
3. **Protected Baseline Assets:** The baseline SQLite database (`app_v2/data/nids.sqlite.bak_baseline`) and trained model weights (`models/replacement_v1/`, `models/replacement_v2/`) are strictly protected assets.
