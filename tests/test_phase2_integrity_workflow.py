"""Integration regressions for registry integrity and report evidence boundaries."""
from __future__ import annotations

import base64
import json
from copy import deepcopy
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import onnx
import pytest
from sequence_fixtures import build_sequence_onnx, sequence_metadata, write_sequence_npz

from core import db
from core.model_storage import MAGIC, read_model_bytes
from core.report_schema import ModuleResult
from scripts import run_phase1_scan as scan


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("CREDORA_MODEL_ENCRYPTION_KEY", base64.urlsafe_b64encode(bytes(range(32))).decode())
    data = tmp_path / "data"
    reports = tmp_path / "reports"
    monkeypatch.setattr(db, "DB_PATH", data / "registry.sqlite3")
    monkeypatch.setattr(scan, "DATA_DIR", data)
    monkeypatch.setattr(scan, "REPORT_DIR", reports)
    db.init_db()
    owner = int(db.list_users()[0]["id"])
    inputs = data / "uploads" / str(owner)
    inputs.mkdir(parents=True)
    model = build_sequence_onnx(inputs / "model.onnx")
    dataset = write_sequence_npz(inputs / "test.npz")
    metadata = inputs / "metadata.json"
    metadata.write_text(json.dumps({**sequence_metadata(), "model_name": "phase2-integrity"}), encoding="utf-8")
    requirements = inputs / "requirements.txt"
    requirements.write_text("# Standalone ONNX\n", encoding="utf-8")
    return SimpleNamespace(root=tmp_path, data=data, reports=reports, owner=owner,
                           model=model, dataset=dataset, metadata=metadata, requirements=requirements)


def _tamper_model(model_path):
    """Corrupt ciphertext authentication, or keep a raw fixture graph valid."""
    raw = model_path.read_bytes()
    if raw.startswith(MAGIC):
        changed = bytearray(raw)
        changed[-1] ^= 1
        model_path.write_bytes(changed)
        return
    graph = onnx.load(str(model_path))
    graph.graph.doc_string = "Changed after server registration"
    model_path.write_bytes(graph.SerializeToString())


def _run(project, **kwargs):
    kwargs.setdefault("generate_docx", False)
    return scan.run_phase1_scan(project.model, project.dataset, project.requirements,
                                project.metadata, owner_id=project.owner, **kwargs)


def _stub_non_classifier_stages(monkeypatch):
    stages = {
        "scan_dependencies": "dependency_scanner", "test_robustness": "robustness_testing",
        "detect_data_drift": "data_drift_detection", "explain_model": "explainability",
        "check_dataset_leakage": "dataset_leakage", "assess_privacy_risk": "privacy_risk",
        "analyze_behavior": "behavior_analysis", "analyze_model_risk": "model_risk_analyzer",
        "run_adversarial_validation": "adversarial_validation", "check_runtime_integrity": "runtime_integrity",
        "analyze_trust_drift": "trust_drift_timeline",
    }
    for callable_name, module in stages.items():
        def completed(*args, module=module, **kwargs):
            return ModuleResult(module, "pass", 90, "Controlled non-classifier test stage.",
                                details={"fixture": True})

        monkeypatch.setattr(scan, callable_name, completed)


def test_registered_tamper_stops_scan_before_inference_and_preserves_baseline(project, monkeypatch):
    from core.artifact_integrity import register_or_verify_artifact

    binding = register_or_verify_artifact(project.model, owner_id=project.owner)
    with db.connect() as connection:
        original_registration = dict(connection.execute(
            "SELECT * FROM model_artifact_registry WHERE id = ?", (binding["id"],)
        ).fetchone())
    _tamper_model(project.model)
    classifier = Mock(side_effect=AssertionError("Tampered model reached inference"))
    registration = Mock(wraps=scan.register_model)
    monkeypatch.setattr(scan, "evaluate_classifier", classifier)
    monkeypatch.setattr(scan, "register_model", registration)

    with pytest.raises((ValueError, RuntimeError), match="(?i)(integrity|changed|hash|mismatch)"):
        _run(project)

    classifier.assert_not_called()
    registration.assert_not_called()
    assert not project.reports.exists()
    assert db.list_scans(owner_id=project.owner) == []
    with db.connect() as connection:
        current_registration = dict(connection.execute(
            "SELECT * FROM model_artifact_registry WHERE id = ?", (binding["id"],)
        ).fetchone())
    assert current_registration == original_registration


def test_valid_pipeline_binds_artifact_and_preserves_real_classifier_results(project, monkeypatch):
    from core.artifact_integrity import (
        assert_report_artifact_integrity,
        register_or_verify_artifact,
    )
    from core.report_evidence import validate_report_evidence

    _stub_non_classifier_stages(monkeypatch)
    classifier = Mock(wraps=scan.evaluate_classifier)
    monkeypatch.setattr(scan, "evaluate_classifier", classifier)
    report = _run(project)
    payload = report.to_dict()
    binding = register_or_verify_artifact(project.model, owner_id=project.owner)
    public_binding = {key: binding[key] for key in ("id", "owner_id", "sha256")}
    assert payload["model_artifact"] == public_binding
    assert "path" not in payload["model_artifact"]
    assert_report_artifact_integrity(payload, owner_id=project.owner)
    validate_report_evidence(payload)
    classifier.assert_called_once()
    results = {item["module"]: item for item in payload["module_results"]}
    assert results["classifier_evaluation"]["details"]["f1_score"] == 1.0
    assert results["security_gate"]["status"] == "fail"
    assert results["deployment_gate"]["details"]["decision"] == "blocked"
    saved_path = project.reports / str(project.owner) / "phase2-integrity_phase3_trust_report.json"
    saved = json.loads(saved_path.read_text(encoding="utf-8"))
    assert saved["model_artifact"] == public_binding
    assert db.latest_scan(owner_id=project.owner)["model_artifact"] == public_binding


def test_mutation_during_inference_blocks_report_publication(project, monkeypatch):
    _stub_non_classifier_stages(monkeypatch)
    evaluate = scan.evaluate_classifier

    def evaluate_then_replace(*args, **kwargs):
        result = evaluate(*args, **kwargs)
        _tamper_model(project.model)
        return result

    classifier = Mock(side_effect=evaluate_then_replace)
    docx_export, json_export, registration = Mock(), Mock(), Mock()
    monkeypatch.setattr(scan, "evaluate_classifier", classifier)
    monkeypatch.setattr(scan, "create_docx_report", docx_export)
    monkeypatch.setattr(scan, "save_json", json_export)
    monkeypatch.setattr(scan, "register_model", registration)

    with pytest.raises(ValueError, match="(?i)(integrity|changed|hash|mismatch)"):
        _run(project, generate_docx=True)

    classifier.assert_called_once()
    docx_export.assert_not_called()
    json_export.assert_not_called()
    registration.assert_not_called()
    assert db.list_scans(owner_id=project.owner) == []


def _bound_report(project):
    from core.artifact_integrity import register_or_verify_artifact

    binding = register_or_verify_artifact(project.model, owner_id=project.owner)
    return {
        "model_name": "phase2-integrity", "trust_score": 90, "status": "pass",
        "generated_at": db.utc_now(), "input_type": "sequence", "recommendations": [],
        "model_artifact": {key: binding[key] for key in ("id", "owner_id", "sha256")},
        "module_results": [{
            "module": "classifier_evaluation", "status": "pass", "score": 90,
            "summary": "Controlled report fixture.", "details": {"accuracy": 0.9},
            "findings": [{"module": "classifier_evaluation", "metric": "details.accuracy",
                          "title": "Measured accuracy", "severity": "info",
                          "description": "Accuracy is 0.9", "recommendation": ""}],
        }, {
            "module": "model_verification", "status": "pass", "score": 100,
            "summary": "Controlled verification fixture.", "findings": [],
            "details": {"sha256": binding["sha256"], "file_name": project.model.name},
        }],
    }


def test_fabricated_metric_reference_is_rejected(project):
    from core.report_evidence import validate_report_evidence

    valid = _bound_report(project)
    validate_report_evidence(valid)
    fabricated = deepcopy(valid)
    fabricated["module_results"][0]["findings"][0]["metric"] = "details.fabricated_accuracy"
    with pytest.raises((ValueError, RuntimeError), match="(?i)(metric|citation|evidence|resolve)"):
        validate_report_evidence(fabricated)


@pytest.mark.parametrize("existing_export", [False, True])
def test_fabricated_findings_cannot_create_or_replace_json_export(project, existing_export):
    from core.storage import save_json

    report = _bound_report(project)
    report["module_results"][0]["findings"][0]["metric"] = "details.fabricated_accuracy"
    destination = project.root / "publication" / "report.json"
    if existing_export:
        destination.parent.mkdir()
        destination.write_bytes(b"Previously published report")

    with pytest.raises(ValueError, match="(?i)(metric|citation|evidence|resolve)"):
        save_json(destination, report)

    if existing_export:
        assert destination.read_bytes() == b"Previously published report"
    else:
        assert not destination.exists()
        assert not destination.parent.exists()


def test_docx_regeneration_rejects_swapped_artifact_before_replacing_export(project, monkeypatch):
    from dashboard.pages import reports
    from modules.phase2_deep_trust.m9_docx_report import docx_report

    report = _bound_report(project)
    monkeypatch.setattr(docx_report, "REPORT_DIR", project.reports)
    monkeypatch.setattr(reports, "REPORT_DIR", project.reports)
    project.reports.mkdir()
    destination = project.reports / "existing.docx"
    destination.write_bytes(b"Previous successful export")
    report["docx_report_path"] = str(destination)
    regenerated = reports.checked_report_download(report, project.owner, docx=True)
    assert regenerated.startswith(b"PK")
    assert destination.read_bytes() == b"Previous successful export"
    _tamper_model(project.model)

    with pytest.raises((ValueError, RuntimeError), match="(?i)(integrity|changed|hash|mismatch)"):
        reports.checked_report_download(report, project.owner, docx=True)
    assert destination.read_bytes() == b"Previous successful export"


def test_dashboard_does_not_offer_report_downloads_for_swapped_artifact(project, monkeypatch):
    from dashboard.pages import reports

    report = _bound_report(project)
    _tamper_model(project.model)
    ui = _reports_ui(monkeypatch, reports)
    monkeypatch.setattr(reports, "render_page_head", Mock())
    monkeypatch.setattr(reports, "REPORT_DIR", project.reports)
    reports.render_reports_page(
        current_user={"id": project.owner, "role": "uploader"}, report_data=report,
        deployment_gate={}, model_name=report["model_name"], generated_at=report["generated_at"],
        trust_score=90, trust_score_issued=True, threat_model={}, remediation_plan=[], analysis_trace=[],
    )
    ui.download_button.assert_not_called()
    ui.error.assert_called()


def test_report_signing_rejects_fabricated_citation_before_signing(project):
    from core.report_signing import generate_report_signing_keypair, sign_report_file

    report = _bound_report(project)
    report["module_results"][0]["findings"][0]["metric"] = "details.fabricated_accuracy"
    private, public = project.root / "private.pem", project.root / "public.pem"
    generate_report_signing_keypair(private, public)
    report_path = project.root / "fabricated.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    before = report_path.read_bytes()
    with pytest.raises((ValueError, RuntimeError), match="(?i)(metric|citation|evidence|resolve)"):
        sign_report_file(report_path, private)
    assert report_path.read_bytes() == before


def test_api_report_retrieval_allows_original_then_blocks_swapped_artifact(project):
    from fastapi import HTTPException

    from api import main

    report = _bound_report(project)
    db.save_scan(report, project.reports / "fixture.json", owner_id=project.owner)
    user = {"id": project.owner, "role": "uploader"}
    assert main.scan_latest(user=user)["model_artifact"] == report["model_artifact"]
    _tamper_model(project.model)

    with pytest.raises(HTTPException) as caught:
        main.scan_latest(user=user)
    assert caught.value.status_code == 409
    assert "changed" in str(caught.value.detail).lower() or "integrity" in str(caught.value.detail).lower()


def _reports_ui(monkeypatch, reports):
    ui = MagicMock()
    ui.session_state = {}
    ui.columns.return_value = (MagicMock(), MagicMock())
    monkeypatch.setattr(reports, "st", ui)
    return ui


def test_deferred_json_and_docx_downloads_recheck_after_page_render(project, monkeypatch):
    from dashboard.pages import reports

    report = _bound_report(project)
    project.reports.mkdir()
    cached_docx = project.reports / "cached.docx"
    cached_docx.write_bytes(b"Untrusted cached export")
    report["docx_report_path"] = str(cached_docx)
    ui = _reports_ui(monkeypatch, reports)
    monkeypatch.setattr(reports, "REPORT_DIR", project.reports)
    reports.render_reports_page(
        current_user={"id": project.owner, "role": "uploader"}, report_data=report,
        deployment_gate={}, model_name=report["model_name"], generated_at=report["generated_at"],
        trust_score=90, trust_score_issued=True, threat_model={}, remediation_plan=[], analysis_trace=[],
    )
    callbacks = [call.args[1] if len(call.args) > 1 else call.kwargs["data"]
                 for call in ui.download_button.call_args_list]
    assert len(callbacks) == 2 and all(callable(callback) for callback in callbacks)
    assert json.loads(callbacks[0]())["model_artifact"] == report["model_artifact"]
    _tamper_model(project.model)
    for callback in callbacks:
        with pytest.raises(ValueError, match="(?i)(integrity|changed|hash|mismatch)"):
            callback()


@pytest.mark.parametrize("subdir,filename", [
    ("models", "model.onnx"), ("runtime_models", "model.onnx"), ("packages", "model.credora"),
])
def test_api_upload_creates_immutable_registration_before_any_scan(project, monkeypatch, subdir, filename):
    from fastapi import UploadFile

    from api import main
    from core.artifact_integrity import assert_artifact_integrity

    monkeypatch.setattr(main, "UPLOAD_DIR", project.data / "uploads")
    upload = UploadFile(filename=filename, file=BytesIO(project.model.read_bytes()))
    saved = main.save_upload(upload, subdir, project.owner)
    binding = assert_artifact_integrity(saved, owner_id=project.owner)
    assert binding["owner_id"] == project.owner
    assert saved.read_bytes().startswith(MAGIC)
    assert read_model_bytes(saved) == project.model.read_bytes()
    _tamper_model(saved)
    corrupted = saved.read_bytes()
    with pytest.raises(ValueError, match="(?i)(integrity|changed|hash|mismatch)"):
        assert_artifact_integrity(saved, owner_id=project.owner)
    assert saved.read_bytes() == corrupted


def _uploaded(contents):
    uploaded = BytesIO(contents)
    uploaded.name = "same-name.onnx"
    return uploaded


def test_dashboard_cached_upload_rechecks_and_never_overwrites_registered_bytes(project, monkeypatch):
    from dashboard.components import scan_submission

    state = {"auth_user": {"id": project.owner}}
    monkeypatch.setattr(scan_submission.st, "session_state", state)
    original = project.model.read_bytes()
    saved = scan_submission.persist_upload(_uploaded(original), "models", project.root)
    assert saved.read_bytes().startswith(MAGIC)
    assert read_model_bytes(saved) == original
    assert scan_submission.persist_upload(_uploaded(original), "models", project.root) == saved
    _tamper_model(saved)
    tampered_bytes = saved.read_bytes()
    with pytest.raises(ValueError, match="(?i)(integrity|changed|hash|mismatch)"):
        scan_submission.persist_upload(_uploaded(original), "models", project.root)
    assert saved.read_bytes() == tampered_bytes
    different = scan_submission.persist_upload(_uploaded(tampered_bytes), "models", project.root)
    assert different != saved
    assert different.name.endswith("same-name.onnx")
    assert different.read_bytes().startswith(MAGIC)
    assert read_model_bytes(different) == tampered_bytes
    assert saved.read_bytes() == tampered_bytes


def test_explicit_reupload_has_a_new_identity_even_with_the_same_bytes(project, monkeypatch):
    from dashboard.components import scan_submission

    monkeypatch.setattr(scan_submission.st, "session_state", {"auth_user": {"id": project.owner}})
    first = _uploaded(project.model.read_bytes())
    first.file_id = "upload-one"
    old_path = scan_submission.persist_upload(first, "models", project.root)
    _tamper_model(old_path)
    corrupted = old_path.read_bytes()
    second = _uploaded(project.model.read_bytes())
    second.file_id = "upload-two"
    new_path = scan_submission.persist_upload(second, "models", project.root)
    assert new_path != old_path
    assert new_path.read_bytes().startswith(MAGIC)
    assert read_model_bytes(new_path) == project.model.read_bytes()
    with pytest.raises(ValueError, match="(?i)changed since registration"):
        scan_submission.persist_upload(first, "models", project.root)
    assert old_path.read_bytes() == corrupted


def test_api_signature_access_rejects_tamper_before_signature_verification(project, monkeypatch):
    from fastapi import HTTPException

    from api import main

    report = _bound_report(project)
    scan_id = db.save_scan(report, project.reports / "fixture.json", owner_id=project.owner)
    _tamper_model(project.model)
    verification = Mock(side_effect=AssertionError("Tampered model reached signature verification"))
    monkeypatch.setattr(main, "verify_report_against_trusted_signers", verification)
    with pytest.raises(HTTPException) as caught:
        main.verify_scan_report_signature(scan_id, user={"id": project.owner, "role": "uploader"})
    assert caught.value.status_code == 409
    verification.assert_not_called()


def test_api_report_access_rejects_fabricated_metric_reference(project):
    from fastapi import HTTPException

    from api import main

    report = _bound_report(project)
    main._check_report_access(report, owner_id=project.owner)
    report["module_results"][0]["findings"][0]["metric"] = "details.fabricated_accuracy"
    with pytest.raises(HTTPException) as caught:
        main._check_report_access(report, owner_id=project.owner)
    assert caught.value.status_code == 409
    assert "metric" in caught.value.detail.lower()
