from io import BytesIO
from pathlib import Path
from unittest.mock import Mock

import pytest
from streamlit.testing.v1 import AppTest

import dashboard.components.scan_submission as scan_submission


def _upload(name: str, content: bytes = b"test evidence") -> BytesIO:
    upload = BytesIO(content)
    upload.name = name
    return upload


def _uploaded_app(tmp_path, monkeypatch, metadata: bytes = b"{}"):
    uploads = {
        "sidebar_model_upload": _upload("classifier.onnx"),
        "sidebar_dataset_upload": _upload("evaluation.npz"),
        "sidebar_metadata_upload": _upload("metadata.json", metadata),
    }
    monkeypatch.setattr(scan_submission.st, "file_uploader", lambda *args, key, **kwargs: uploads.get(key))
    app = AppTest.from_string(
        "import streamlit as st\n"
        "from pathlib import Path\n"
        "from dashboard.components.scan_submission import render_scan_submission, execute_scan_submission\n"
        "st.session_state.setdefault('scan_require_metadata_hash', True)\n"
        f"submission = render_scan_submission(Path({str(tmp_path)!r}), standalone=True)\n"
        "st.session_state['test_submission'] = submission\n"
        "if submission.submitted:\n"
        "    execute_scan_submission(submission, {'id': 1}, lambda *args: None)\n",
        default_timeout=60,
    ).run()
    return app, uploads


def test_upload_modes_preserve_submission_readiness() -> None:
    root = Path(__file__).resolve().parents[1]
    app = AppTest.from_string(
        "import streamlit as st\n"
        "from pathlib import Path\n"
        "from dashboard.components.scan_submission import render_scan_submission\n"
        "st.session_state.setdefault('scan_require_metadata_hash', True)\n"
        f"submission = render_scan_submission(Path({str(root)!r}), standalone=True)\n",
        default_timeout=60,
    ).run()
    assert not app.exception
    assert app.button(key="sidebar_run_scan").disabled
    app.radio(key="assessment_input_type").set_value("Sequence tokens/bytes").run()
    assert not app.exception
    assert app.button(key="sidebar_run_scan").disabled
    app.session_state["sequence_preflight_error"] = "Previous sequence failure"
    app.radio(key="assessment_input_type").set_value("Tabular flow features").run()
    assert "sequence_preflight_error" not in app.session_state
    app.radio(key="sidebar_assessment_source").set_value("Demo model").run()
    assert not app.exception
    assert not app.button(key="sidebar_run_scan").disabled


@pytest.mark.parametrize("source", ["pcap", "native_weights"])
def test_failed_npz_preflight_does_not_block_alternate_source(tmp_path, monkeypatch, source) -> None:
    preflight = Mock(side_effect=ValueError("NPZ sequence shape mismatch"))
    monkeypatch.setattr(scan_submission, "validate_sequence_compatibility", preflight)
    app, uploads = _uploaded_app(tmp_path, monkeypatch)
    app.radio(key="assessment_input_type").set_value("Sequence tokens/bytes").run()
    assert not app.exception
    assert app.button(key="sidebar_run_scan").disabled
    assert app.session_state["sequence_preflight_error"] == "NPZ sequence shape mismatch"
    assert "NPZ sequence shape mismatch" in app.error[0].value
    preflight.assert_called_once()

    if source == "pcap":
        uploads["sidebar_dataset_upload"] = _upload("evaluation.pcap")
        uploads["assessment_flow_labels"] = _upload("labels.csv", b"src_ip,src_port,dst_ip,dst_port,protocol,label\n")
        app.selectbox(key="assessment_dataset_kind").set_value("Offline PCAP + labels").run()
        assert app.session_state["test_submission"].flow_labels_path.name == "labels.csv"
        assert app.session_state["test_submission"].dataset_path.suffix == ".pcap"
    else:
        uploads["sidebar_model_upload"] = _upload("classifier.safetensors")
        app.selectbox(key="assessment_artifact_kind").set_value("Approved native weights").run()
        assert app.session_state["test_submission"].model_path.suffix == ".safetensors"

    assert not app.exception
    assert not app.error
    assert "sequence_preflight_error" not in app.session_state
    assert not app.button(key="sidebar_run_scan").disabled
    preflight.assert_called_once()

    # These sources require metadata even when the general metadata gate is off.
    app.session_state["scan_require_metadata_hash"] = False
    metadata = uploads.pop("sidebar_metadata_upload")
    app.run()
    assert not app.exception
    assert app.button(key="sidebar_run_scan").disabled
    uploads["sidebar_metadata_upload"] = metadata
    app.run()
    assert not app.button(key="sidebar_run_scan").disabled
    if source == "pcap":
        labels = uploads.pop("assessment_flow_labels")
        app.run()
        assert app.button(key="sidebar_run_scan").disabled
        uploads["assessment_flow_labels"] = labels
        app.run()
        assert not app.button(key="sidebar_run_scan").disabled
    assert not app.exception


@pytest.mark.parametrize("metadata", [b"{", b"[]"])
def test_invalid_sequence_metadata_disables_submission_without_crashing(tmp_path, monkeypatch, metadata) -> None:
    preflight = Mock()
    monkeypatch.setattr(scan_submission, "validate_sequence_compatibility", preflight)
    app, _ = _uploaded_app(tmp_path, monkeypatch, metadata)
    app.radio(key="assessment_input_type").set_value("Sequence tokens/bytes").run()
    assert not app.exception
    assert app.button(key="sidebar_run_scan").disabled
    assert "Sequence compatibility check failed:" in app.error[0].value
    assert app.session_state["sequence_preflight_error"]
    preflight.assert_not_called()


@pytest.mark.parametrize("metadata", [b"{", b"[]"])
def test_invalid_metadata_is_reported_before_scan_setup(tmp_path, monkeypatch, metadata) -> None:
    history = Mock()
    run_scan = Mock()
    monkeypatch.setattr(scan_submission, "list_scan_reports", history)
    monkeypatch.setattr(scan_submission, "run_phase1_scan", run_scan)
    app, uploads = _uploaded_app(tmp_path, monkeypatch, metadata)
    uploads["sidebar_requirements_upload"] = _upload("requirements.txt")
    app.run()
    assert not app.button(key="sidebar_run_scan").disabled
    app.button(key="sidebar_run_scan").click().run()
    assert not app.exception
    assert "Invalid model metadata:" in app.error[0].value
    history.assert_not_called()
    run_scan.assert_not_called()


def test_execution_device_and_cpu_fallback_controls(tmp_path, monkeypatch) -> None:
    app, _ = _uploaded_app(tmp_path, monkeypatch)
    assert app.selectbox(key="assessment_device").options == ["CPU", "Auto (GPU preferred)", "CUDA"]
    assert len(app.checkbox) == 0
    app.selectbox(key="assessment_device").set_value("cuda").run()
    assert not app.exception
    assert not app.checkbox(key="assessment_cpu_fallback").value
    app.checkbox(key="assessment_cpu_fallback").check().run()
    assert app.session_state["test_submission"].execution_device == "cuda"
    assert app.session_state["test_submission"].allow_cpu_fallback
    app.selectbox(key="assessment_device").set_value("cpu").run()
    assert not app.exception
    assert len(app.checkbox) == 0
    assert app.session_state["test_submission"].execution_device == "cpu"
    assert not app.session_state["test_submission"].allow_cpu_fallback
