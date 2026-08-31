# TrustAI Sentinel - Phase 1

Phase 1 is the working prototype for evaluating whether an encrypted traffic classifier model is safe enough to deploy.

## What Phase 1 Builds

- Model upload / registration for `.joblib` and `.pkl` scikit-learn models
- Model verification using file type, SHA-256 hash, metadata matching, and unsafe-format warnings
- Dependency scanner using `requirements.txt` parsing plus `pip-audit` when network access is available
- Encrypted traffic classifier evaluation using CSV flow metadata and weighted accuracy/precision/recall/F1
- Trust score engine combining verification, dependency safety, and classifier performance
- SQLite registry for model records and scan history
- Better dashboard with Overview, Classifier, Findings, Registry, and Report tabs
- FastAPI backend for health checks, model registry, scan history, latest report, and upload-based scans

## Activate Environment

```powershell
cd "C:\Users\glady\Mini project"
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, run:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

## Install Requirements

```powershell
pip install -r requirements.txt
```

## Generate Demo Encrypted Traffic Classifier

```powershell
python scripts\seed_demo_data.py
```

This creates:

- `data\sample_models\traffic_rf_v1.joblib`
- `data\processed\encrypted_traffic_train.csv`
- `data\processed\encrypted_traffic_test.csv`
- `data\metadata\traffic_rf_v1_metadata.json`
- `data\sample_requirements\requirements_demo.txt`

## Run One Phase 1 Scan From CMD

```powershell
python scripts\run_phase1_scan.py
```

The generated trust report is saved at:

```text
reports\trust_reports\traffic_rf_v1_phase1_trust_report.json
```

## Start Dashboard

```powershell
streamlit run dashboard\app.py --server.port 8501
```

Open:

```text
http://localhost:8501
```

Dashboard usage:

1. Choose **Use demo artifacts** to test the built-in Random Forest encrypted traffic classifier.
2. Or choose **Upload files** to upload your own `.joblib` / `.pkl` model, CSV test dataset, `requirements.txt`, and optional metadata JSON.
3. Click **Run Phase 1 Trust Scan**.
4. Review the trust score, classifier metrics, findings, registry, scan history, and downloadable JSON report.

## Start FastAPI Backend

```powershell
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

Open API docs:

```text
http://localhost:8000/docs
```

Useful endpoints:

- `GET /health`
- `GET /models`
- `GET /scans`
- `GET /scans/latest`
- `POST /scan/phase1`

## Upload File Format

Model:

- `.joblib` or `.pkl`
- Should be a scikit-learn-compatible classifier with `.predict()`

Dataset:

- CSV file
- Must include a target column named `label` by default
- Feature columns should match the columns used while training the model

Optional metadata JSON:

```json
{
  "model_name": "traffic_rf_v1",
  "version": "1.0",
  "algorithm": "Random Forest",
  "framework": "scikit-learn",
  "task": "Encrypted Traffic Classification",
  "target_column": "label",
  "expected_features": [
    "flow_duration",
    "packet_count",
    "avg_packet_size",
    "bytes_sent",
    "bytes_received",
    "iat_mean",
    "iat_std",
    "flow_bytes_per_second"
  ]
}
```

## Current Verified Demo Result

Latest verified demo scan:

- Trust score: `95.0 / 100`
- Model verification: pass
- Dependency scanner: pass, with a low warning if `pip-audit` cannot reach vulnerability data
- Classifier evaluation: pass
- Demo weighted F1 score: `1.0`

