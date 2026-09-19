from __future__ import annotations

import os
import pickle

import pytest
from fastapi import HTTPException

from api.main import require_api_key
from core.hashing import sha256_file
from core.model_loading import UnsafeModelError, assert_pickle_is_safe
from modules.phase1_foundation.m1_model_verification.verifier import verify_model
from modules.phase2_deep_trust.m4_data_drift.drift import detect_data_drift
from scripts.run_phase1_scan import _safe_report_path


class DangerousPickle:
    def __reduce__(self):
        return (os.system, ("echo unsafe",))


def test_drift_rejects_baseline_path_traversal(tmp_path) -> None:
    current = tmp_path / "current.csv"
    current.write_text("feature,label\n1,Normal\n", encoding="utf-8")

    result = detect_data_drift(current, {"training_dataset_path": "../../outside.csv"})

    assert result.status == "fail"
    assert any(finding.title == "Unsafe baseline dataset path" for finding in result.findings)


def test_report_path_slug_stays_inside_report_directory() -> None:
    path = _safe_report_path("../../evil/model", "phase3_trust_report.json")

    assert ".." not in path.name
    assert path.name.startswith("evil_model")


def test_pickle_opcode_scan_blocks_disallowed_globals(tmp_path) -> None:
    payload = tmp_path / "payload.pkl"
    payload.write_bytes(pickle.dumps(DangerousPickle()))

    with pytest.raises(UnsafeModelError, match="disallowed callable"):
        assert_pickle_is_safe(payload)


def test_self_reported_hash_and_signature_do_not_create_trusted_baseline(tmp_path) -> None:
    model = tmp_path / "model.joblib"
    model.write_bytes(b"\x80\x04.")

    result = verify_model(model, {"sha256": sha256_file(model), "signature_status": "valid", "model_name": "demo", "version": "1"})

    assert result.status == "warning"
    assert result.details["signature_verified"] is False
    assert result.details["expected_sha256_source"] == "none"
    assert any(finding.title == "Self-reported hash ignored" for finding in result.findings)


def test_api_mutating_routes_require_key() -> None:
    with pytest.raises(HTTPException) as exc:
        require_api_key(None)

    assert exc.value.status_code == 401


def test_api_accepts_configured_key() -> None:
    assert require_api_key("dev-credora-key") is None


def test_load_checked_model_runs_isolated_preflight(monkeypatch, tmp_path) -> None:
    from core import model_loading

    model_file = tmp_path / "model.joblib"
    model_file.write_bytes(b"\x80\x04.")
    calls = []

    monkeypatch.setattr(model_loading, "assert_pickle_is_safe", lambda path: None)
    monkeypatch.setattr(model_loading, "_run_deserialization_preflight", lambda path: calls.append(path))
    monkeypatch.setattr(model_loading.joblib, "load", lambda path: {"loaded": str(path)})

    loaded = model_loading.load_checked_model(model_file)

    assert loaded["loaded"] == str(model_file)
    assert calls == [model_file]


def test_deserialization_preflight_reports_child_failure(monkeypatch, tmp_path) -> None:
    import subprocess
    from core.model_loading import UnsafeModelError, _run_deserialization_preflight

    model_file = tmp_path / "model.joblib"
    model_file.write_bytes(b"\x80\x04.")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 1, stdout="", stderr="boom")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(UnsafeModelError, match="isolated preflight"):
        _run_deserialization_preflight(model_file)
