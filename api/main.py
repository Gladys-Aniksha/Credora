from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from core.config import DATA_DIR
from core.db import (
    acknowledge_runtime_alert,
    init_db,
    latest_scan,
    list_drift_windows,
    list_integrity_checks,
    list_models,
    list_runtime_alerts,
    list_scans,
)
from core.model_package import ModelPackageError, verify_model_package
from modules.phase3_operations.m6_runtime_integrity.scheduler import run_integrity_cycle
from modules.phase3_operations.m7_flow_ingestion.collector import ingest_flow_file
from modules.phase3_operations.m8_production_monitoring.monitor import monitor_rolling_windows
from scripts.run_phase1_scan import run_phase1_scan

app = FastAPI(title="TrustAI Sentinel API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = DATA_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "TrustAI Sentinel API"}


@app.get("/models")
def models() -> list[dict]:
    return list_models()


@app.get("/scans")
def scans() -> list[dict]:
    return list_scans()


@app.get("/scans/latest")
def scan_latest() -> dict | None:
    return latest_scan()


def save_upload(upload: UploadFile, subdir: str) -> Path:
    folder = UPLOAD_DIR / subdir
    folder.mkdir(parents=True, exist_ok=True)
    safe_name = Path(upload.filename or "upload.bin").name
    path = folder / f"{uuid4().hex}-{safe_name}"
    path.write_bytes(upload.file.read())
    return path


@app.post("/scan/phase1")
def scan_phase1(
    model: UploadFile = File(...),
    dataset: UploadFile = File(...),
    requirements: UploadFile = File(...),
    metadata: UploadFile | None = File(None),
) -> dict:
    model_path = save_upload(model, "models")
    dataset_path = save_upload(dataset, "datasets")
    requirements_path = save_upload(requirements, "requirements")
    metadata_path = save_upload(metadata, "metadata") if metadata else None
    report = run_phase1_scan(model_path, dataset_path, requirements_path, metadata_path)
    return report.to_dict()


@app.get("/alerts")
def alerts(status: str | None = None, limit: int = 100) -> list[dict]:
    return list_runtime_alerts(limit=min(max(limit, 1), 500), status=status)


@app.post("/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int) -> dict[str, bool]:
    if not acknowledge_runtime_alert(alert_id):
        raise HTTPException(status_code=404, detail="Open alert not found")
    return {"acknowledged": True}


@app.get("/monitoring/drift-windows")
def drift_windows(model_name: str | None = None, limit: int = 100) -> list[dict]:
    return list_drift_windows(model_name=model_name, limit=min(max(limit, 1), 500))


@app.get("/monitoring/integrity-checks")
def integrity_checks(model_name: str | None = None, limit: int = 100) -> list[dict]:
    return list_integrity_checks(model_name=model_name, limit=min(max(limit, 1), 500))


@app.post("/flows/ingest")
def ingest_flows(
    capture: UploadFile = File(...),
    source_format: str = Form("auto"),
    default_label: str | None = Form(None),
) -> dict:
    source_path = save_upload(capture, "captures")
    output_path = UPLOAD_DIR / "canonical_flows" / f"{source_path.stem}.csv"
    try:
        return asdict(ingest_flow_file(source_path, output_path, source_format, default_label))
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/monitoring/integrity-check")
def integrity_check(model: UploadFile = File(...), metadata: UploadFile = File(...)) -> dict:
    model_path = save_upload(model, "runtime_models")
    metadata_path = save_upload(metadata, "runtime_metadata")
    try:
        return asdict(run_integrity_cycle(model_path, metadata_path))
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/monitoring/drift")
def monitor_drift(
    captured_flows: UploadFile = File(...),
    baseline: UploadFile = File(...),
    model_name: str = Form(...),
    window_size: int = Form(250),
) -> list[dict]:
    captured_path = save_upload(captured_flows, "monitoring")
    baseline_path = save_upload(baseline, "monitoring_baselines")
    try:
        results = monitor_rolling_windows(
            model_name=model_name,
            captured_csv_path=captured_path,
            baseline_path=baseline_path,
            output_dir=DATA_DIR / "production_windows" / model_name,
            window_size=window_size,
        )
        return [asdict(result) for result in results]
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/packages/verify")
def verify_package(package: UploadFile = File(...), trust_key: UploadFile = File(...)) -> dict:
    package_path = save_upload(package, "packages")
    key_path = save_upload(trust_key, "trust_keys")
    extract_dir = UPLOAD_DIR / "verified_packages" / package_path.stem
    try:
        verified = verify_model_package(package_path, key_path, extract_dir)
        return {
            "verified": True,
            "manifest": verified.manifest,
            "model_path": str(verified.model_path),
            "metadata_path": str(verified.metadata_path),
            "requirements_path": str(verified.requirements_path),
        }
    except (ModelPackageError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
