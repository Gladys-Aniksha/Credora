import json
import ast
from pathlib import Path
from unittest.mock import MagicMock

from streamlit.testing.v1 import AppTest

from core.report_schema import TrustReport
from dashboard.components import scan_submission as scans
from dashboard.components import common


def _app_source(tmp_path):
    return (
        "import streamlit as st\n"
        "from pathlib import Path\n"
        "from dashboard.components.scan_submission import ScanSubmission, execute_scan_submission, render_saved_upload_assessment\n"
        "st.session_state.setdefault('scan_require_metadata_hash',True)\n"
        "st.session_state.setdefault('scan_generate_docx_report',False)\n"
        "page=st.radio('Page',['Upload','Other'],key='page')\n"
        "if page=='Upload':\n"
        "    run=st.button('Analyze',key='analyze')\n"
        f"    root=Path({str(tmp_path)!r})\n"
        "    execute_scan_submission(ScanSubmission(root/'model.onnx',root/'test.csv',root/'requirements.txt',root/'metadata.json',run),{'id':7},lambda *args:None)\n"
        "    if not run: render_saved_upload_assessment({'id':7},lambda *args:None)\n"
    )


def _prepare(tmp_path, monkeypatch):
    for name in ("model.onnx", "test.csv", "requirements.txt"):
        (tmp_path / name).touch()
    (tmp_path / "metadata.json").write_text(json.dumps({"model_name": "new-model"}), encoding="utf-8")
    monkeypatch.setattr(scans, "list_scan_reports", lambda **kwargs: [])
    monkeypatch.setattr(scans, "get_trust_weights", lambda: {})
    monkeypatch.setattr(scans, "render_motion", lambda *args, **kwargs: None)
    calls = []

    def scan(*args, progress_callback, **kwargs):
        calls.append(kwargs["owner_id"])
        for stage in range(18):
            progress_callback(f"Level {stage} - Check", "Starting check")
            progress_callback(f"Level {stage} - Check", "Completed check")
        return TrustReport.create("new-model", 63 + len(calls), "fail", [], [])

    monkeypatch.setattr(scans, "run_phase1_scan", scan)
    return calls


def test_upload_trace_survives_navigation_without_rescanning(tmp_path, monkeypatch):
    calls = _prepare(tmp_path, monkeypatch)
    app = AppTest.from_string(_app_source(tmp_path), default_timeout=30).run()
    app.button(key="analyze").click().run()
    assert not app.exception
    assert calls == [7]
    assert app.session_state["upload_assessment"]["status"] == "completed"
    app.radio(key="page").set_value("Other").run()
    app.radio(key="page").set_value("Upload").run()
    assert not app.exception
    assert calls == [7]
    assert any("Level 17 - Check" in item.value for item in app.markdown)
    assert len(app.session_state["upload_assessment"]["events"]) == 36
    assert app.session_state["pending_assessment_model"] == "new-model"
    # AppTest exposes a scalar or list depending on the Streamlit version.
    assert app.query_params["model"] in ("new-model", ["new-model"])
    app.button(key="analyze").click().run()
    assert not app.exception
    assert calls == [7, 7]
    assert len(app.session_state["upload_assessment"]["events"]) == 36
    assert app.session_state["upload_assessment"]["report"]["trust_score"] == 65


def test_new_browser_session_does_not_restore_transient_upload_steps(tmp_path, monkeypatch):
    _prepare(tmp_path, monkeypatch)
    source = _app_source(tmp_path)
    app = AppTest.from_string(source).run()
    app.button(key="analyze").click().run()
    fresh = AppTest.from_string(source).run()
    assert not fresh.exception
    assert not any("Level 17 - Check" in item.value for item in fresh.markdown)


def test_upload_trace_is_not_shown_to_another_owner(monkeypatch):
    ui = MagicMock()
    ui.session_state = {"upload_assessment": {"owner_id": 7, "status": "completed", "events": []}}
    monkeypatch.setattr(scans, "st", ui)
    heading = MagicMock()
    assert not scans.render_saved_upload_assessment({"id": 8}, heading)
    heading.assert_not_called()
    ui.markdown.assert_not_called()


def test_cap_explanation_shows_the_distinct_measured_score(monkeypatch):
    ui = MagicMock()
    monkeypatch.setattr(common, "st", ui)
    for measured in (84.14, 91.5):
        common.render_score_evidence({"trust_score": 70, "module_results": [{
            "module": "trust_score", "score": 70,
            "details": {"uncapped_score": measured, "raw_model_trust_cap": 70},
        }]})
        assert f"{measured:.2f}/100" in ui.caption.call_args.args[0]
        assert "unsigned-model cap" in ui.caption.call_args.args[0]


def test_dashboard_reads_the_selected_models_saved_snapshot():
    source = Path(__file__).resolve().parents[1] / "dashboard/app.py"
    function = next(node for node in ast.parse(source.read_text(encoding="utf-8")).body
                    if isinstance(node, ast.FunctionDef) and node.name == "resolve_report")
    saved = {"model_name": "new-model", "trust_score": 64}
    lookup = MagicMock(return_value=saved)
    namespace = {"latest_scan": lookup, "dashboard_owner_scope": lambda: (7, False)}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), "exec"), namespace)
    assert namespace["resolve_report"]("new-model") == saved
    lookup.assert_called_once_with(owner_id=7, include_all=False, model_name="new-model")
