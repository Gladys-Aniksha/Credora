from __future__ import annotations

from io import BytesIO
import json
from pathlib import Path
import subprocess
import sys

import pandas as pd
import pytest
from fastapi import HTTPException, UploadFile

from core.config import verify_model_file_type
from scripts.run_phase1_scan import run_phase1_scan


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SKLEARN_MODEL = PROJECT_ROOT / "data" / "sample_models" / "traffic_rf_v1.joblib"
ONNX_MODEL = PROJECT_ROOT / "data" / "sample_models" / "traffic_rf_v1.onnx"
TEST_DATASET = PROJECT_ROOT / "data" / "processed" / "encrypted_traffic_test.csv"
METADATA = PROJECT_ROOT / "data" / "metadata" / "traffic_rf_v1_metadata.json"


def _features() -> pd.DataFrame:
    return pd.read_csv(TEST_DATASET).drop(columns=["label"])


def test_real_onnx_predictions_match_sklearn_model() -> None:
    assert ONNX_MODEL.exists()
    command = (
        "import json, numpy as np, pandas as pd; "
        "from core.model_backend import load_model_backend; "
        f"features=pd.read_csv({str(TEST_DATASET)!r}).drop(columns=['label']); "
        f"sklearn_predictions=load_model_backend({str(SKLEARN_MODEL)!r}).predict(features); "
        f"onnx=load_model_backend({str(ONNX_MODEL)!r}); "
        "probabilities=onnx.predict_proba(features); "
        "print('PARITY_RESULT='+json.dumps({"
        "'matches': bool(np.array_equal(onnx.predict(features), sklearn_predictions)),"
        "'probability_shape': list(probabilities.shape) if probabilities is not None else None"
        "}))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", command],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    result_line = next(line for line in completed.stdout.splitlines() if line.startswith("PARITY_RESULT="))
    result = json.loads(result_line.removeprefix("PARITY_RESULT="))
    assert result == {"matches": True, "probability_shape": [len(_features()), 3]}


def test_full_scan_chain_produces_onnx_trust_report(tmp_path) -> None:
    missing_requirements = tmp_path / "requirements-unavailable.txt"
    report = run_phase1_scan(
        ONNX_MODEL,
        TEST_DATASET,
        missing_requirements,
        METADATA,
        generate_docx=False,
    )

    results = {result.module: result for result in report.module_results}
    assert report.trust_score > 0
    assert results["classifier_evaluation"].details["f1_score"] >= 0.99
    assert results["robustness_testing"].details["trial_count"] == 25
    assert results["adversarial_validation"].details["trial_count"] == 25
    assert results["security_gate"].details["decision"] == "blocked"
    assert results["trust_score"].details["issued"] is True
    assert results["trust_score"].details["security_gate_passed"] is False
    assert results["trust_score"].details["deployment_eligible"] is False
    assert results["trust_drift_timeline"].status != "not_run"
    assert results["deployment_gate"].details["decision"] == "blocked"
    assert report.threat_model["summary"]["threats_identified"] == 15


def test_full_scan_chain_still_produces_sklearn_trust_report(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("CREDORA_MODEL_LOAD_CHILD", "1")
    report = run_phase1_scan(
        SKLEARN_MODEL,
        TEST_DATASET,
        tmp_path / "requirements-unavailable.txt",
        METADATA,
        generate_docx=False,
    )

    results = {result.module: result for result in report.module_results}
    assert report.trust_score > 0
    assert results["classifier_evaluation"].details["f1_score"] >= 0.99
    assert results["robustness_testing"].details["trial_count"] == 25
    assert results["adversarial_validation"].details["trial_count"] == 25
    assert results["security_gate"].details["decision"] == "blocked"
    assert results["trust_score"].details["issued"] is True
    assert results["trust_score"].details["security_gate_passed"] is False
    assert results["trust_score"].details["deployment_eligible"] is False
    assert results["trust_drift_timeline"].status != "not_run"
    assert results["deployment_gate"].details["decision"] == "blocked"
    assert report.threat_model["summary"]["threats_identified"] == 15


def test_renamed_non_onnx_file_is_rejected(tmp_path) -> None:
    fake_model = tmp_path / "renamed.onnx"
    fake_model.write_bytes(SKLEARN_MODEL.read_bytes())

    assert not verify_model_file_type(fake_model)


def test_onnx_upload_uses_separate_size_cap(monkeypatch, tmp_path) -> None:
    from api import main as api_main

    monkeypatch.setattr(api_main, "UPLOAD_DIR", tmp_path)
    monkeypatch.setattr(api_main, "MAX_ONNX_UPLOAD_BYTES", 8)
    monkeypatch.setattr(api_main, "MAX_UPLOAD_BYTES", 32)

    oversized_onnx = UploadFile(filename="model.onnx", file=BytesIO(b"x" * 9))
    with pytest.raises(HTTPException) as exc_info:
        api_main.save_upload(oversized_onnx, "models", owner_id=1)
    assert exc_info.value.status_code == 413

    ordinary_upload = UploadFile(filename="dataset.csv", file=BytesIO(b"x" * 9))
    saved_path = api_main.save_upload(ordinary_upload, "datasets", owner_id=1)
    assert saved_path.read_bytes() == b"x" * 9
