from __future__ import annotations

from pathlib import Path
import os

from dotenv import load_dotenv
import onnx

try:
    import filetype
except ImportError:  # pragma: no cover - optional dependency fallback for minimal local runs.
    filetype = None

PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env")


def _required_environment_variable(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} must be set before Credora starts.")
    return value


DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
SAMPLE_MODEL_DIR = DATA_DIR / "sample_models"
SAMPLE_REQUIREMENTS_DIR = DATA_DIR / "sample_requirements"
METADATA_DIR = DATA_DIR / "metadata"
REPORT_DIR = PROJECT_ROOT / "reports" / "trust_reports"

SUPPORTED_MODEL_EXTENSIONS = {".joblib", ".pkl", ".onnx"}
RISKY_MODEL_EXTENSIONS = {".joblib", ".pkl"}
DEFAULT_TRUST_THRESHOLD = 75
DEFAULT_DEPLOYMENT_POLICY = {
    "minimum_trust_score": 85,
    "minimum_classifier_score": 85,
    "minimum_adversarial_score": 80,
    "minimum_sensitive_recall": 0.90,
}
TRUSTED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("CREDORA_TRUSTED_ORIGINS", "http://localhost:8501,http://localhost:8502").split(",")
    if origin.strip()
]
API_KEY = _required_environment_variable("CREDORA_API_KEY")
MAX_UPLOAD_BYTES = int(os.getenv("CREDORA_MAX_UPLOAD_BYTES", str(200 * 1024 * 1024)))
MAX_SEQUENCE_MODEL_BYTES = int(
    os.getenv("CREDORA_MAX_SEQUENCE_MODEL_BYTES", str(100 * 1024 * 1024))
)
MAX_SEQUENCE_DATASET_BYTES = int(
    os.getenv("CREDORA_MAX_SEQUENCE_DATASET_BYTES", str(100 * 1024 * 1024))
)
MAX_SEQUENCE_ROWS = int(os.getenv("CREDORA_MAX_SEQUENCE_ROWS", "200000"))
MAX_SEQUENCE_LENGTH = int(os.getenv("CREDORA_MAX_SEQUENCE_LENGTH", "8192"))
SEQUENCE_INFERENCE_BATCH_SIZE = int(os.getenv("CREDORA_SEQUENCE_BATCH_SIZE", "256"))
SEQUENCE_INFERENCE_TIMEOUT_SECONDS = int(os.getenv("CREDORA_SEQUENCE_TIMEOUT_SECONDS", "30"))

for directory in [RAW_DATA_DIR, PROCESSED_DATA_DIR, SAMPLE_MODEL_DIR, SAMPLE_REQUIREMENTS_DIR, METADATA_DIR, REPORT_DIR]:
    directory.mkdir(parents=True, exist_ok=True)


def verify_model_file_type(path: str | Path) -> bool:
    file_path = Path(path)
    extension = file_path.suffix.lower()
    if extension not in SUPPORTED_MODEL_EXTENSIONS:
        return False
    if extension == ".onnx":
        try:
            from core.onnx_safety import validate_onnx_model

            validate_onnx_model(file_path)
        except (onnx.checker.ValidationError, OSError, ValueError):
            return False
        return True
    from core.model_storage import read_model_header

    header = read_model_header(file_path)
    detected = filetype.guess(header) if filetype else None
    if detected and detected.mime not in {"application/octet-stream", "application/x-pickle"}:
        return False
    return header.startswith(b"\x80") or header.startswith((b"(", b"c"))
