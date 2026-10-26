import base64
import builtins
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core.assessment_inputs import prepare_assessment_inputs
from dashboard.theme import credora_brand_html


def test_brand_uses_login_glyphs_not_a_replacement_font() -> None:
    rendered = credora_brand_html()
    payload = rendered.split("base64,", 1)[1].split("'", 1)[0]
    svg = base64.b64decode(payload).decode("utf-8")
    assert "login-wordmark-mask" in svg
    assert "data:image/png;base64," in svg
    assert 'font-family="Arial' not in svg
    assert 'id="credora-c"' in svg


def test_prepared_dataset_does_not_create_files(tmp_path) -> None:
    output = tmp_path / "prepared"
    result = prepare_assessment_inputs(Path("model.onnx"), Path("test.npz"),
                                       {"input_type": "sequence"}, output)
    assert result.dataset_path == Path("test.npz")
    assert result.provenance == {}
    assert not output.exists()


def test_capture_needs_explicit_labels(tmp_path) -> None:
    with pytest.raises(ValueError, match="label mapping"):
        prepare_assessment_inputs(Path("model.onnx"), Path("capture.pcap"), {}, tmp_path)


RAW_WEIGHT_NAMES = [
    "model.safetensors", "model.weights.h5", "model.pt", "model.pth", "model.keras",
    "model.h5", "model.hdf5", "model.ckpt", "model.ckpt.index",
    "model.ckpt.data-00000-of-00001", "saved_model.pb", "model.tflite",
    "pytorch_model.bin", "model.SAFETENSORS", "model.WEIGHTS.H5", "model.PT",
]


@pytest.mark.parametrize("name", RAW_WEIGHT_NAMES)
def test_raw_framework_weights_require_onnx_export_before_preparation(tmp_path, monkeypatch, name) -> None:
    original_import = builtins.__import__

    def without_conversion(module, *args, **kwargs):
        if module in {"torch", "tensorflow"}:
            raise AssertionError(f"Unsupported framework imported: {module}")
        return original_import(module, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_conversion)
    output = tmp_path / "prepared"
    original_metadata = {"framework": "pytorch", "execution_device": "cuda"}
    with pytest.raises(ValueError, match=r"Export raw framework weights to ONNX \(\.onnx\)"):
        prepare_assessment_inputs(Path(name), Path("missing.pcap"), original_metadata, output)
    assert original_metadata == {"framework": "pytorch", "execution_device": "cuda"}
    assert not output.exists()


@pytest.mark.parametrize("name", RAW_WEIGHT_NAMES)
def test_scan_rejects_raw_weights_before_registry_or_assessment(tmp_path, monkeypatch, name) -> None:
    from scripts import run_phase1_scan as scan

    def must_not_run(*args, **kwargs):
        pytest.fail("Raw framework weights reached registry access or assessment")

    monkeypatch.setattr(scan, "latest_model_by_name", must_not_run)
    monkeypatch.setattr(scan, "verify_model", must_not_run)
    with pytest.raises(ValueError, match="Export raw framework weights to ONNX"):
        scan.run_phase1_scan(tmp_path / name, tmp_path / "test.csv", tmp_path / "requirements.txt",
                             owner_id=42, generate_docx=False)


@pytest.mark.parametrize("name", ["model.onnx", "model.ONNX", "model.joblib", "model.pkl"])
def test_supported_artifact_identity_and_trusted_metadata_are_preserved(tmp_path, name) -> None:
    original_metadata = {"_signature_verified": True, "_expected_sha256": "signed-hash"}
    output = tmp_path / "prepared"
    model, dataset = Path(name), Path("test.csv")
    prepared = prepare_assessment_inputs(model, dataset, original_metadata, output)
    assert prepared.model_path == model
    assert prepared.dataset_path == dataset
    assert prepared.metadata == original_metadata
    assert prepared.metadata is not original_metadata
    assert prepared.provenance == {}
    assert not output.exists()


def test_gpu_is_not_claimed_for_sklearn(tmp_path) -> None:
    with pytest.raises(ValueError, match="only for ONNX"):
        prepare_assessment_inputs(Path("model.joblib"), Path("test.csv"), {}, tmp_path,
                                  execution_device="cuda")


@pytest.mark.parametrize("sequence", [False, True])
def test_pcap_preparation_preserves_provenance_and_gpu_policy(tmp_path, sequence) -> None:
    from test_pcap_ingestion import inputs, metadata

    from core.hashing import sha256_file

    source, labels = inputs(tmp_path)
    original_metadata = {**metadata(sequence), "_signature_verified": True}
    before = dict(original_metadata)
    output = tmp_path / "prepared"
    model = Path("model.onnx")
    result = prepare_assessment_inputs(
        model, source, original_metadata, output, flow_labels_path=labels,
        execution_device="auto", allow_cpu_fallback=True,
    )
    assert result.model_path == model
    assert result.dataset_path == (output / ("evaluation.npz" if sequence else "evaluation.csv")).resolve()
    assert result.dataset_path.is_file()
    assert result.metadata["_signature_verified"] is True
    assert result.metadata["execution_device"] == "auto"
    assert result.metadata["execution_fallback"] == "cpu"
    assert original_metadata == before
    assert result.provenance == {"dataset_conversion": {
        "format": "offline_pcap", "schema": original_metadata["pcap_schema"],
        "source_sha256": sha256_file(source), "labels_sha256": sha256_file(labels),
        "rows": 1, "packets": 1, "skipped_packets": 0, "decrypts_tls": False,
    }}


@pytest.mark.parametrize("signed_package", [False, True])
def test_scan_keeps_owner_scoped_preparation_and_package_trust(tmp_path, monkeypatch, signed_package) -> None:
    from test_pcap_ingestion import inputs, metadata

    from scripts import run_phase1_scan as scan

    source, labels = inputs(tmp_path)
    model = tmp_path / "model.onnx"
    model.write_bytes(b"fixed intake fixture; inference is intercepted")
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text(json.dumps(metadata()), encoding="utf-8")
    requirements = tmp_path / "requirements.txt"
    owner_queries = []

    def registered(name, owner_id):
        owner_queries.append(owner_id)
        return {"sha256": "registered-hash"}

    monkeypatch.setattr(scan, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(scan, "latest_model_by_name", registered)
    intake_model = model
    if signed_package:
        from core import model_package

        intake_model = tmp_path / "model.credora"
        intake_model.write_bytes(b"fixed package fixture; verification is intercepted")
        monkeypatch.setattr(model_package, "verify_model_package", lambda *args: SimpleNamespace(
            model_path=model, requirements_path=requirements, metadata_path=metadata_path,
            manifest={"artifacts": {"model": {"sha256": "signed-hash"}}},
        ))

    class IntakeChecked(Exception):
        pass

    def check_intake(path, prepared_metadata):
        assert path == model
        assert prepared_metadata["_signature_verified"] is signed_package
        assert prepared_metadata["_expected_sha256"] == ("signed-hash" if signed_package else "registered-hash")
        assert prepared_metadata["execution_device"] == "auto"
        assert prepared_metadata["execution_fallback"] == "cpu"
        raise IntakeChecked

    monkeypatch.setattr(scan, "verify_model", check_intake)
    with pytest.raises(IntakeChecked):
        scan.run_phase1_scan(
            intake_model, source, requirements, metadata_path,
            trusted_public_key_path=tmp_path / "trusted.pem", owner_id=42,
            flow_labels_path=labels, execution_device="auto", generate_docx=False,
        )
    assert owner_queries == ([] if signed_package else [42])
    prepared = list((tmp_path / "data" / "uploads" / "42" / "prepared").iterdir())
    assert len(prepared) == 1
    assert (prepared[0] / "evaluation.csv").is_file()
    saved = json.loads((prepared[0] / "assessment-metadata.json").read_text())
    assert saved["execution_device"] == "auto"
    assert not any(key.startswith("_") for key in saved)
    assert not (tmp_path / "data" / "uploads" / "shared").exists()


@pytest.mark.parametrize("contents", ["[]", "{not valid JSON"])
def test_invalid_upload_metadata_is_displayed_without_starting_scan(tmp_path, monkeypatch, contents) -> None:
    from dashboard.components import scan_submission

    model = tmp_path / "model.onnx"
    dataset = tmp_path / "test.npz"
    requirements = tmp_path / "requirements.txt"
    metadata = tmp_path / "metadata.json"
    for path in (model, dataset, requirements):
        path.touch()
    metadata.write_text(contents, encoding="utf-8")
    ui = MagicMock()
    ui.session_state = {"scan_require_metadata_hash": True}
    scan = MagicMock()
    monkeypatch.setattr(scan_submission, "st", ui)
    monkeypatch.setattr(scan_submission, "run_phase1_scan", scan)
    scan_submission.execute_scan_submission(
        scan_submission.ScanSubmission(model, dataset, requirements, metadata, True),
        {"id": 1}, MagicMock(),
    )
    scan.assert_not_called()
    assert "Invalid model metadata" in ui.error.call_args.args[0]
