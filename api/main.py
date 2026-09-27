from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import hmac
import time
from typing import Any
from uuid import uuid4

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

Limiter: Any = None
RateLimitExceeded: Any = None
SlowAPIMiddleware: Any = None
get_remote_address: Any = None
_rate_limit_exceeded_handler: Any = None

try:
    from slowapi import Limiter as _Limiter
    from slowapi.errors import RateLimitExceeded as _RateLimitExceeded
    from slowapi.extension import _rate_limit_exceeded_handler as _slowapi_rate_limit_exceeded_handler
    from slowapi.middleware import SlowAPIMiddleware as _SlowAPIMiddleware
    from slowapi.util import get_remote_address as _get_remote_address
except Exception:  # pragma: no cover - optional until requirements are installed.
    pass
else:
    Limiter = _Limiter
    RateLimitExceeded = _RateLimitExceeded
    SlowAPIMiddleware = _SlowAPIMiddleware
    get_remote_address = _get_remote_address
    _rate_limit_exceeded_handler = _slowapi_rate_limit_exceeded_handler

from core.auth import (
    can_view_all,
    create_access_token,
    create_refresh_token,
    enforce_auth_rate_limit,
    get_current_user,
    require_role,
    token_user,
)
from core.config import API_KEY, DATA_DIR, MAX_UPLOAD_BYTES, TRUSTED_ORIGINS
from core.db import (
    acknowledge_runtime_alert,
    add_trusted_signer,
    admin_set_password,
    authenticate_user,
    change_user_password,
    create_deployment_override,
    create_user,
    delete_model_records,
    delete_scan,
    delete_user_account,
    get_deployment_policy,
    get_scan_record,
    get_sensitive_label_taxonomy,
    get_trust_weights,
    init_db,
    latest_scan,
    list_drift_windows,
    list_integrity_checks,
    list_models,
    list_runtime_alerts,
    list_scans,
    list_trusted_signers,
    list_users,
    platform_analytics,
    revoke_user_sessions,
    set_deployment_policy,
    set_sensitive_label_taxonomy,
    set_trust_weights,
    set_trusted_signer_status,
    set_user_disabled,
    update_user_role,
)
from core.model_package import ModelPackageError, verify_model_package
from core.report_signing import verify_report_against_trusted_signers
from core.security import ensure_within_directory, slugify_filename
from modules.phase3_operations.m6_runtime_integrity.scheduler import run_integrity_cycle
from modules.phase3_operations.m7_flow_ingestion.collector import ingest_flow_file
from modules.phase3_operations.m8_production_monitoring.monitor import monitor_rolling_windows
from scripts.run_phase1_scan import run_phase1_scan

app = FastAPI(title="Credora API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=TRUSTED_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["Authorization", "Content-Type", "X-Credora-API-Key"],
)

UPLOAD_DIR = DATA_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
MAX_ONNX_UPLOAD_BYTES = 50 * 1024 * 1024
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 20
_rate_limit_buckets: dict[str, list[float]] = {}
limiter = Limiter(key_func=get_remote_address) if Limiter and get_remote_address else None
if limiter:
    app.state.limiter = limiter
    app.add_middleware(SlowAPIMiddleware)
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str | None = None


class RefreshRequest(BaseModel):
    refresh_token: str


class AdminUserRequest(RegisterRequest):
    role: str = "uploader"

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class UserPatchRequest(BaseModel):
    role: str | None = None
    disabled: bool | None = None
    new_password: str | None = None
    revoke_sessions: bool = False


class PolicyRequest(BaseModel):
    minimum_trust_score: float
    minimum_classifier_score: float
    minimum_adversarial_score: float
    minimum_sensitive_recall: float


class TrustWeightsRequest(BaseModel):
    weights: dict[str, float]


class SensitiveLabelsRequest(BaseModel):
    labels: list[str]


class TrustedSignerRequest(BaseModel):
    name: str
    public_key_pem: str


class TrustedSignerStatusRequest(BaseModel):
    status: str


class DeploymentOverrideRequest(BaseModel):
    decision: str
    justification: str

@app.middleware("http")
async def reject_oversized_requests(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Upload exceeds Credora size limit.")
    return await call_next(request)


def require_api_key(x_credora_api_key: str | None = Header(default=None)) -> None:
    if x_credora_api_key is None or not hmac.compare_digest(x_credora_api_key, API_KEY):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid Credora API key.")


def _rate_limit(request: Request, max_requests: int) -> None:
    identity = request.headers.get("authorization") or request.headers.get("x-credora-api-key") or (request.client.host if request.client else "unknown")
    now = time.monotonic()
    bucket = [seen for seen in _rate_limit_buckets.get(identity, []) if now - seen < RATE_LIMIT_WINDOW_SECONDS]
    if len(bucket) >= max_requests:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Credora rate limit exceeded.")
    bucket.append(now)
    _rate_limit_buckets[identity] = bucket


def rate_limit(request: Request) -> None:
    _rate_limit(request, RATE_LIMIT_MAX_REQUESTS)


def login_rate_limit(request: Request) -> None:
    enforce_auth_rate_limit(request)


def _owner_scope(user: dict[str, Any]) -> tuple[int | None, bool]:
    return (None, True) if can_view_all(user) else (int(user["id"]), False)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "Credora API"}


@app.post("/auth/register", dependencies=[Depends(login_rate_limit)])
def register(payload: RegisterRequest) -> dict[str, Any]:
    try:
        user = create_user(payload.username, payload.password, payload.email, role="uploader")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "user": user,
        "access_token": create_access_token(user),
        "refresh_token": create_refresh_token(user),
        "token_type": "bearer",
    }


@app.post("/auth/login", dependencies=[Depends(login_rate_limit)])
def login(form: OAuth2PasswordRequestForm = Depends()) -> dict[str, Any]:
    user = authenticate_user(form.username, form.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    return {
        "access_token": create_access_token(user),
        "refresh_token": create_refresh_token(user),
        "token_type": "bearer",
        "user": user,
    }


@app.post("/auth/refresh")
def refresh(payload: RefreshRequest) -> dict[str, Any]:
    user = token_user(payload.refresh_token, expected_type="refresh")
    return {"access_token": create_access_token(user), "token_type": "bearer", "user": user}


@app.get("/auth/me")
def me(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    return user


@app.get("/users")
def users(_: dict[str, Any] = Depends(require_role("admin"))) -> list[dict[str, Any]]:
    return list_users()


@app.post("/users")
def admin_create_user(payload: AdminUserRequest, _: dict[str, Any] = Depends(require_role("admin"))) -> dict[str, Any]:
    try:
        return create_user(payload.username, payload.password, payload.email, role=payload.role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc



@app.post("/auth/change-password")
def change_password(payload: ChangePasswordRequest, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, bool]:
    if not change_user_password(int(user["id"]), payload.current_password, payload.new_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    return {"changed": True}


@app.patch("/users/{user_id}")
def admin_update_user(user_id: int, payload: UserPatchRequest, admin: dict[str, Any] = Depends(require_role("admin"))) -> dict[str, bool]:
    if payload.role is not None:
        update_user_role(user_id, payload.role, actor_id=int(admin["id"]))
    if payload.disabled is not None:
        set_user_disabled(user_id, payload.disabled, actor_id=int(admin["id"]))
    if payload.new_password:
        admin_set_password(user_id, payload.new_password, actor_id=int(admin["id"]))
    if payload.revoke_sessions:
        revoke_user_sessions(user_id, actor_id=int(admin["id"]))
    return {"updated": True}


@app.delete("/users/{user_id}")
def admin_delete_user(user_id: int, admin: dict[str, Any] = Depends(require_role("admin"))) -> dict[str, bool]:
    if int(admin["id"]) == int(user_id):
        raise HTTPException(status_code=400, detail="Admins cannot delete their own active account.")
    delete_user_account(user_id, actor_id=int(admin["id"]))
    return {"deleted": True}


@app.get("/admin/analytics")
def admin_analytics(_: dict[str, Any] = Depends(require_role("reviewer", "admin"))) -> dict[str, Any]:
    return platform_analytics()


@app.get("/admin/audit-logs")
def audit_logs(_: dict[str, Any] = Depends(require_role("admin"))) -> list[dict[str, Any]]:
    from core.db import list_audit_logs

    return list_audit_logs()


@app.get("/admin/policy")
def read_policy(_: dict[str, Any] = Depends(require_role("admin"))) -> dict[str, Any]:
    return get_deployment_policy()


@app.put("/admin/policy")
def write_policy(payload: PolicyRequest, admin: dict[str, Any] = Depends(require_role("admin"))) -> dict[str, Any]:
    policy = payload.model_dump()
    set_deployment_policy(policy, actor_id=int(admin["id"]))
    return get_deployment_policy()


@app.get("/admin/trust-weights")
def read_weights(_: dict[str, Any] = Depends(require_role("admin"))) -> dict[str, float]:
    return get_trust_weights()


@app.put("/admin/trust-weights")
def write_weights(payload: TrustWeightsRequest, admin: dict[str, Any] = Depends(require_role("admin"))) -> dict[str, float]:
    try:
        set_trust_weights(payload.weights, actor_id=int(admin["id"]))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return get_trust_weights()


@app.get("/admin/sensitive-labels")
def read_sensitive_labels(_: dict[str, Any] = Depends(require_role("admin"))) -> list[str]:
    return get_sensitive_label_taxonomy()


@app.put("/admin/sensitive-labels")
def write_sensitive_labels(payload: SensitiveLabelsRequest, admin: dict[str, Any] = Depends(require_role("admin"))) -> list[str]:
    try:
        set_sensitive_label_taxonomy(payload.labels, actor_id=int(admin["id"]))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return get_sensitive_label_taxonomy()


@app.get("/admin/trusted-signers")
def trusted_signers(_: dict[str, Any] = Depends(require_role("admin"))) -> list[dict[str, Any]]:
    return list_trusted_signers(include_inactive=True)


@app.post("/admin/trusted-signers")
def create_signer(payload: TrustedSignerRequest, admin: dict[str, Any] = Depends(require_role("admin"))) -> dict[str, int]:
    return {"id": add_trusted_signer(payload.name, payload.public_key_pem, actor_id=int(admin["id"]))}


@app.patch("/admin/trusted-signers/{signer_id}")
def update_signer(signer_id: int, payload: TrustedSignerStatusRequest, admin: dict[str, Any] = Depends(require_role("admin"))) -> dict[str, bool]:
    set_trusted_signer_status(signer_id, payload.status, actor_id=int(admin["id"]))
    return {"updated": True}


@app.post("/scans/{scan_id}/deployment-override")
def override_scan(scan_id: int, payload: DeploymentOverrideRequest, reviewer: dict[str, Any] = Depends(require_role("reviewer", "admin"))) -> dict[str, int]:
    try:
        override_id = create_deployment_override(scan_id, payload.decision, payload.justification, int(reviewer["id"]))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"id": override_id}


@app.get("/scans/{scan_id}/report-signature")
def verify_scan_report_signature(scan_id: int, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    owner_id, include_all = _owner_scope(user)
    scan = get_scan_record(scan_id, include_report=True, owner_id=owner_id, include_all=include_all)
    if not scan or not scan.get("report"):
        raise HTTPException(status_code=404, detail="Scan report not found")
    return verify_report_against_trusted_signers(scan["report"], list_trusted_signers())

@app.delete("/scans/{scan_id}")
def delete_scan_endpoint(scan_id: int, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, bool]:
    owner_id, include_all = _owner_scope(user)
    if not delete_scan(scan_id, owner_id=owner_id, include_all=include_all, actor_id=int(user["id"])):
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": True}


@app.delete("/models/{model_name}")
def delete_model_endpoint(model_name: str, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, int]:
    owner_id, include_all = _owner_scope(user)
    deleted = delete_model_records(model_name, owner_id=owner_id, include_all=include_all, actor_id=int(user["id"]))
    if not deleted:
        raise HTTPException(status_code=404, detail="Model not found")
    return {"deleted_records": deleted}

@app.get("/models")
def models(user: dict[str, Any] = Depends(get_current_user)) -> list[dict]:
    owner_id, include_all = _owner_scope(user)
    return list_models(owner_id=owner_id, include_all=include_all)


@app.get("/scans")
def scans(user: dict[str, Any] = Depends(get_current_user)) -> list[dict]:
    owner_id, include_all = _owner_scope(user)
    return list_scans(owner_id=owner_id, include_all=include_all)


@app.get("/scans/latest")
def scan_latest(user: dict[str, Any] = Depends(get_current_user)) -> dict | None:
    owner_id, include_all = _owner_scope(user)
    return latest_scan(owner_id=owner_id, include_all=include_all)


def save_upload(upload: UploadFile, subdir: str, owner_id: int) -> Path:
    owner_root = ensure_within_directory(UPLOAD_DIR / str(owner_id), UPLOAD_DIR)
    folder = ensure_within_directory(owner_root / subdir, owner_root)
    folder.mkdir(parents=True, exist_ok=True)
    safe_name = Path(upload.filename or "upload.bin").name
    path = ensure_within_directory(folder / f"{uuid4().hex}-{safe_name}", folder)
    upload_limit = MAX_ONNX_UPLOAD_BYTES if Path(safe_name).suffix.lower() == ".onnx" else MAX_UPLOAD_BYTES
    bytes_written = 0
    upload_too_large = False
    with path.open("wb") as handle:
        while chunk := upload.file.read(1024 * 1024):
            bytes_written += len(chunk)
            if bytes_written > upload_limit:
                upload_too_large = True
                break
            handle.write(chunk)
    if upload_too_large:
        path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Upload exceeds Credora size limit.",
        )
    return path


@app.post("/scan/phase1", dependencies=[Depends(rate_limit)])
def scan_phase1(
    model: UploadFile = File(...),
    dataset: UploadFile = File(...),
    requirements: UploadFile = File(...),
    metadata: UploadFile | None = File(None),
    trust_key: UploadFile | None = File(None),
    user: dict[str, Any] = Depends(get_current_user),
) -> dict:
    owner_id = int(user["id"])
    model_path = save_upload(model, "models", owner_id)
    dataset_path = save_upload(dataset, "datasets", owner_id)
    requirements_path = save_upload(requirements, "requirements", owner_id)
    metadata_path = save_upload(metadata, "metadata", owner_id) if metadata else None
    trust_key_path = save_upload(trust_key, "trust_keys", owner_id) if trust_key else None
    report = run_phase1_scan(
        model_path,
        dataset_path,
        requirements_path,
        metadata_path,
        trusted_public_key_path=trust_key_path,
        owner_id=owner_id,
    )
    return report.to_dict()


@app.get("/alerts")
def alerts(status: str | None = None, limit: int = 100, user: dict[str, Any] = Depends(get_current_user)) -> list[dict]:
    owner_id, include_all = _owner_scope(user)
    return list_runtime_alerts(limit=min(max(limit, 1), 500), status=status, owner_id=owner_id, include_all=include_all)


@app.post("/alerts/{alert_id}/acknowledge", dependencies=[Depends(rate_limit)])
def acknowledge_alert(alert_id: int, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, bool]:
    owner_id, include_all = _owner_scope(user)
    if not acknowledge_runtime_alert(alert_id, owner_id=owner_id, include_all=include_all):
        raise HTTPException(status_code=404, detail="Open alert not found")
    return {"acknowledged": True}


@app.get("/monitoring/drift-windows")
def drift_windows(model_name: str | None = None, limit: int = 100, user: dict[str, Any] = Depends(get_current_user)) -> list[dict]:
    owner_id, include_all = _owner_scope(user)
    return list_drift_windows(model_name=model_name, limit=min(max(limit, 1), 500), owner_id=owner_id, include_all=include_all)


@app.get("/monitoring/integrity-checks")
def integrity_checks(model_name: str | None = None, limit: int = 100, user: dict[str, Any] = Depends(get_current_user)) -> list[dict]:
    owner_id, include_all = _owner_scope(user)
    return list_integrity_checks(model_name=model_name, limit=min(max(limit, 1), 500), owner_id=owner_id, include_all=include_all)


@app.post("/flows/ingest", dependencies=[Depends(rate_limit)])
def ingest_flows(
    capture: UploadFile = File(...),
    source_format: str = Form("auto"),
    default_label: str | None = Form(None),
    user: dict[str, Any] = Depends(get_current_user),
) -> dict:
    owner_id = int(user["id"])
    source_path = save_upload(capture, "captures", owner_id)
    output_dir = ensure_within_directory(UPLOAD_DIR / str(owner_id) / "canonical_flows", UPLOAD_DIR)
    output_path = ensure_within_directory(output_dir / f"{source_path.stem}.csv", output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        return asdict(ingest_flow_file(source_path, output_path, source_format, default_label))
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/monitoring/integrity-check", dependencies=[Depends(rate_limit)])
def integrity_check(
    model: UploadFile = File(...),
    metadata: UploadFile = File(...),
    user: dict[str, Any] = Depends(get_current_user),
) -> dict:
    owner_id = int(user["id"])
    model_path = save_upload(model, "runtime_models", owner_id)
    metadata_path = save_upload(metadata, "runtime_metadata", owner_id)
    try:
        return asdict(run_integrity_cycle(model_path, metadata_path, owner_id=owner_id))
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/monitoring/drift", dependencies=[Depends(rate_limit)])
def monitor_drift(
    captured_flows: UploadFile = File(...),
    baseline: UploadFile = File(...),
    model_name: str = Form(...),
    window_size: int = Form(250),
    user: dict[str, Any] = Depends(get_current_user),
) -> list[dict]:
    owner_id = int(user["id"])
    captured_path = save_upload(captured_flows, "monitoring", owner_id)
    baseline_path = save_upload(baseline, "monitoring_baselines", owner_id)
    safe_model_name = slugify_filename(model_name)
    production_root = ensure_within_directory(DATA_DIR / "production_windows" / str(owner_id), DATA_DIR)
    try:
        results = monitor_rolling_windows(
            model_name=model_name,
            captured_csv_path=captured_path,
            baseline_path=baseline_path,
            output_dir=ensure_within_directory(production_root / safe_model_name, production_root),
            window_size=window_size,
            owner_id=owner_id,
        )
        return [asdict(result) for result in results]
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/packages/verify", dependencies=[Depends(rate_limit)])
def verify_package(
    package: UploadFile = File(...),
    trust_key: UploadFile = File(...),
    user: dict[str, Any] = Depends(get_current_user),
) -> dict:
    owner_id = int(user["id"])
    package_path = save_upload(package, "packages", owner_id)
    key_path = save_upload(trust_key, "trust_keys", owner_id)
    owner_root = ensure_within_directory(UPLOAD_DIR / str(owner_id), UPLOAD_DIR)
    extract_dir = ensure_within_directory(owner_root / "verified_packages" / package_path.stem, owner_root)
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






