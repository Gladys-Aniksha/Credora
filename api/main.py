from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import time
from uuid import uuid4

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware

from core.config import API_KEY, DATA_DIR, MAX_UPLOAD_BYTES, TRUSTED_ORIGINS
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
from core.security import ensure_within_directory, slugify_filename
from modules.phase3_operations.m6_runtime_integrity.scheduler import run_integrity_cycle
from modules.phase3_operations.m7_flow_ingestion.collector import ingest_flow_file
from modules.phase3_operations.m8_production_monitoring.monitor import monitor_rolling_windows
from scripts.run_phase1_scan import run_phase1_scan

app = FastAPI(title="Credora API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=TRUSTED_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = DATA_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 20
_rate_limit_buckets: dict[str, list[float]] = {}


@app.middleware("http")
async def reject_oversized_requests(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Upload exceeds Credora size limit.")
    return await call_next(request)


def require_api_key(x_credora_api_key: str | None = Header(default=None)) -> None:
    if x_credora_api_key != API_KEY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid Credora API key.")


def rate_limit(request: Request) -> None:
    identity = request.headers.get("x-credora-api-key") or (request.client.host if request.client else "unknown")
    now = time.monotonic()
    bucket = [seen for seen in _rate_limit_buckets.get(identity, []) if now - seen < RATE_LIMIT_WINDOW_SECONDS]
    if len(bucket) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Credora rate limit exceeded.")
    bucket.append(now)
    _rate_limit_buckets[identity] = bucket


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "Credora API"}


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
    path = ensure_within_directory(folder / f"{uuid4().hex}-{safe_name}", folder)
    bytes_written = 0
    with path.open("wb") as handle:
        while chunk := upload.file.read(1024 * 1024):
            bytes_written += len(chunk)
            if bytes_written > MAX_UPLOAD_BYTES:
                path.unlink(missing_ok=True)
                raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Upload exceeds Credora size limit.")
            handle.write(chunk)
    return path


@app.post("/scan/phase1", dependencies=[Depends(require_api_key), Depends(rate_limit)])
def scan_phase1(
    model: UploadFile = File(...),
    dataset: UploadFile = File(...),
    requirements: UploadFile = File(...),
    metadata: UploadFile | None = File(None),
    trust_key: UploadFile | None = File(None),
) -> dict:
    model_path = save_upload(model, "models")
    dataset_path = save_upload(dataset, "datasets")
    requirements_path = save_upload(requirements, "requirements")
    metadata_path = save_upload(metadata, "metadata") if metadata else None
    trust_key_path = save_upload(trust_key, "trust_keys") if trust_key else None
    report = run_phase1_scan(model_path, dataset_path, requirements_path, metadata_path, trusted_public_key_path=trust_key_path)
    return report.to_dict()


@app.get("/alerts")
def alerts(status: str | None = None, limit: int = 100) -> list[dict]:
    return list_runtime_alerts(limit=min(max(limit, 1), 500), status=status)


@app.post("/alerts/{alert_id}/acknowledge", dependencies=[Depends(require_api_key), Depends(rate_limit)])
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


@app.post("/flows/ingest", dependencies=[Depends(require_api_key), Depends(rate_limit)])
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


@app.post("/monitoring/integrity-check", dependencies=[Depends(require_api_key), Depends(rate_limit)])
def integrity_check(model: UploadFile = File(...), metadata: UploadFile = File(...)) -> dict:
    model_path = save_upload(model, "runtime_models")
    metadata_path = save_upload(metadata, "runtime_metadata")
    try:
        return asdict(run_integrity_cycle(model_path, metadata_path))
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/monitoring/drift", dependencies=[Depends(require_api_key), Depends(rate_limit)])
def monitor_drift(
    captured_flows: UploadFile = File(...),
    baseline: UploadFile = File(...),
    model_name: str = Form(...),
    window_size: int = Form(250),
) -> list[dict]:
    captured_path = save_upload(captured_flows, "monitoring")
    baseline_path = save_upload(baseline, "monitoring_baselines")
    safe_model_name = slugify_filename(model_name)
    try:
        results = monitor_rolling_windows(
            model_name=model_name,
            captured_csv_path=captured_path,
            baseline_path=baseline_path,
            output_dir=ensure_within_directory(DATA_DIR / "production_windows" / safe_model_name, DATA_DIR),
            window_size=window_size,
        )
        return [asdict(result) for result in results]
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/packages/verify", dependencies=[Depends(require_api_key), Depends(rate_limit)])
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
