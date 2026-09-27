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

for directory in [RAW_DATA_DIR, PROCESSED_DATA_DIR, SAMPLE_MODEL_DIR, SAMPLE_REQUIREMENTS_DIR, METADATA_DIR, REPORT_DIR]:
    directory.mkdir(parents=True, exist_ok=True)


def verify_model_file_type(path: str | Path) -> bool:
    file_path = Path(path)
    extension = file_path.suffix.lower()
    if extension not in SUPPORTED_MODEL_EXTENSIONS:
        return False
    if extension == ".onnx":
        try:
            onnx.checker.check_model(str(file_path))
        except (onnx.checker.ValidationError, OSError, ValueError):
            return False
        return True
    with file_path.open("rb") as model_file:
        header = model_file.read(4)
    detected = filetype.guess(file_path) if filetype else None
    if detected and detected.mime not in {"application/octet-stream", "application/x-pickle"}:
        return False
    return header.startswith(b"\x80") or header.startswith((b"(", b"c"))
