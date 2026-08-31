from __future__ import annotations

from core.hashing import sha256_file
from modules.phase3_operations.m6_runtime_integrity.watcher import check_runtime_integrity


def test_runtime_integrity_accepts_approved_hash(tmp_path) -> None:
    model = tmp_path / "model.joblib"
    model.write_bytes(b"approved-model-artifact")
    result = check_runtime_integrity(model, {"sha256": sha256_file(model), "signature_status": "valid"})
    assert result.status == "pass"
    assert result.details["integrity_state"] == "verified"


def test_runtime_integrity_blocks_hash_change(tmp_path) -> None:
    model = tmp_path / "model.joblib"
    model.write_bytes(b"changed-model-artifact")
    result = check_runtime_integrity(model, {"sha256": "0" * 64, "signature_status": "valid"})
    assert result.status == "fail"
    assert any(finding.severity == "critical" for finding in result.findings)
