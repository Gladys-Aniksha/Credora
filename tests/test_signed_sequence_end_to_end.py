import copy
import json

import core.db as db
from core.report_signing import generate_report_signing_keypair, verify_report_dict
from scripts import run_phase1_scan as scan
from sequence_fixtures import build_sequence_onnx, sequence_metadata, write_sequence_npz


def test_sequence_scan_report_signature_and_gate_remain_independent(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "registry.sqlite3")
    db.init_db()
    monkeypatch.setattr(scan, "REPORT_DIR", tmp_path / "reports")
    model = build_sequence_onnx(tmp_path / "model.onnx")
    dataset = tmp_path / "test.npz"
    write_sequence_npz(dataset)
    metadata = tmp_path / "metadata.json"
    metadata.write_text(json.dumps({**sequence_metadata(), "model_name": "signed-sequence-e2e"}), encoding="utf-8")
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("# Standalone ONNX\n", encoding="utf-8")
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    generate_report_signing_keypair(private, public)
    report = scan.run_phase1_scan(model, dataset, requirements, metadata, generate_docx=False,
                                  report_signing_private_key_path=private, report_signer="test-signer")
    saved = json.loads((tmp_path / "reports" / "signed-sequence-e2e_phase3_trust_report.json").read_text(encoding="utf-8"))
    assert report.input_type == "sequence"
    assert verify_report_dict(saved, public)["verified"]
    results = {item["module"]: item for item in saved["module_results"]}
    assert results["trust_score"]["details"]["issued"] is True
    assert results["security_gate"]["status"] == "fail"
    assert results["deployment_gate"]["details"]["decision"] == "blocked"
    assert saved["execution"]["execution_device"] == "cpu"
    for field in ("execution", "input_provenance"):
        tampered = copy.deepcopy(saved)
        tampered[field]["tampered"] = True
        assert verify_report_dict(tampered, public)["verified"] is False
