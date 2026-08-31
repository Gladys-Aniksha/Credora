from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
SAMPLE_MODEL_DIR = DATA_DIR / "sample_models"
SAMPLE_REQUIREMENTS_DIR = DATA_DIR / "sample_requirements"
METADATA_DIR = DATA_DIR / "metadata"
REPORT_DIR = PROJECT_ROOT / "reports" / "trust_reports"

SUPPORTED_MODEL_EXTENSIONS = {".joblib", ".pkl"}
RISKY_MODEL_EXTENSIONS = {".joblib", ".pkl"}
DEFAULT_TRUST_THRESHOLD = 75

for directory in [RAW_DATA_DIR, PROCESSED_DATA_DIR, SAMPLE_MODEL_DIR, SAMPLE_REQUIREMENTS_DIR, METADATA_DIR, REPORT_DIR]:
    directory.mkdir(parents=True, exist_ok=True)
