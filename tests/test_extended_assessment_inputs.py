import base64
import json
from pathlib import Path

import pytest
from unittest.mock import MagicMock

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


def test_no_unrestricted_native_checkpoint_fallback(tmp_path) -> None:
    for extension in ("pt", "pth", "keras", "h5"):
        with pytest.raises(ValueError, match="Unrestricted"):
            prepare_assessment_inputs(Path(f"model.{extension}"), Path("test.csv"), {}, tmp_path)


def test_gpu_is_not_claimed_for_sklearn(tmp_path) -> None:
    with pytest.raises(ValueError, match="only for ONNX"):
        prepare_assessment_inputs(Path("model.joblib"), Path("test.csv"), {}, tmp_path,
                                  execution_device="cuda")


def test_native_conversion_stays_unsigned_and_uses_generated_paths(tmp_path, monkeypatch) -> None:
    from core.native_import import NativeImportResult

    def convert(weights, metadata, output):
        output.mkdir()
        path = output / "metadata.json"
        path.write_text(json.dumps({"input_type": "tabular", "conversion_provenance": {
            "is_signature_or_trust": False,
        }}), encoding="utf-8")
        return NativeImportResult(output / "model.onnx", path)

    monkeypatch.setattr("core.native_import.import_native_model", convert)
    result = prepare_assessment_inputs(Path("weights.safetensors"), Path("test.csv"),
                                       {"framework": "pytorch"}, tmp_path / "prepared")
    assert result.model_path.name == "model.onnx"
    assert result.provenance["model_conversion"]["is_signature_or_trust"] is False
    assert not result.metadata.get("_signature_verified", False)


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
