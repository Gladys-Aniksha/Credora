from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
import json
import re
from pathlib import Path

import streamlit as st

from core.config import MAX_UPLOAD_BYTES, METADATA_DIR, PROCESSED_DATA_DIR, SAMPLE_MODEL_DIR, SAMPLE_REQUIREMENTS_DIR
from core.security import ensure_within_directory
from core.db import get_trust_weights, list_scan_reports
from core.sequence_validation import validate_sequence_compatibility
from dashboard.components.assessment_motion import render_motion
from dashboard.components.common import h, render_score_evidence
from scripts.run_phase1_scan import run_phase1_scan


@dataclass(frozen=True)
class ScanSubmission:
    model_path: Path | None
    dataset_path: Path | None
    requirements_path: Path | None
    metadata_path: Path | None
    submitted: bool
    flow_labels_path: Path | None = None
    execution_device: str = "cpu"
    allow_cpu_fallback: bool = False


def render_saved_upload_assessment(current_user: dict, render_page_head: Callable[[str, str], None]) -> bool:
    state = st.session_state.get("upload_assessment")
    if not state or state.get("owner_id") != int(current_user["id"]):
        return False
    completed = state.get("status") == "completed"
    render_page_head("Model Assessment", str(state.get("model_name", "Uploaded model")))
    st.progress(1.0 if completed else state.get("progress", 0.0),
                text="Assessment complete" if completed else "Last recorded assessment progress")
    if state.get("report"):
        render_motion(state["report"], state.get("baseline"))
        render_score_evidence(state["report"])
    with st.container(border=True):
        st.markdown("### Assessment activity")
        for event in state.get("events", []):
            st.markdown(f"**{event['level']}** &nbsp; {event['message']}")
    if state.get("error"):
        st.error(state["error"])
    elif state.get("status") == "interrupted":
        st.warning("This assessment was interrupted before completion. The recorded steps are retained; run a new analysis to finish.")
    return completed


def persist_upload(uploaded: object, subdir: str, project_root: Path) -> Path | None:
    if uploaded is None:
        return None
    if len(uploaded.getbuffer()) > MAX_UPLOAD_BYTES:
        raise ValueError("Upload exceeds the configured file size limit.")
    user = st.session_state.get("auth_user") or {"id": "shared"}
    folder = project_root / "data" / "uploads" / str(user["id"]) / subdir
    safe_name = Path(uploaded.name).name
    path = ensure_within_directory(folder / safe_name, folder)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(uploaded.getbuffer())
    return path


def _upload_step(number: int, title: str, subtitle: str) -> None:
    st.markdown(f'<div class="upload-step upload-step-{number}"><span>{number}</span><div><h3>{h(title)}</h3>'
                f'<p>{h(subtitle)}</p></div></div>', unsafe_allow_html=True)


def _upload_file_row(title: str, description: str, formats: list[str], icon: str, key: str):
    with st.container(key=f"upload_row_{key}"):
        title_col, formats_col, upload_col = st.columns([3.5, 1.1, .5], vertical_alignment="center")
        with title_col:
            st.markdown(
                f'<div class="upload-file-detail"><span class="upload-file-icon" aria-hidden="true">{h(icon)}</span>'
                f'<div><strong>{h(title)}</strong><p>{h(description)}</p></div></div>', unsafe_allow_html=True,
            )
        with formats_col:
            st.caption("Accepted formats: " + ", ".join(f".{ext}" for ext in formats))
        with upload_col:
            return st.file_uploader(title, type=formats, key=key, label_visibility="collapsed")


def render_scan_submission(project_root: Path, *, standalone: bool = False) -> ScanSubmission:
    panel = st.container(border=True, key="upload_evidence") if standalone else st.expander(
        "Upload & Analyze Model",
        expanded=False,
        icon=":material/upload_file:",
    )
    with panel:
        _upload_step(1, "Upload assessment evidence", "Upload a trained classifier and its labeled evaluation evidence.")
        mode = st.radio(
            "Assessment source",
            ["Upload files", "Demo model"],
            horizontal=True,
            key="sidebar_assessment_source",
            label_visibility="collapsed",
            format_func=lambda value: f":material/{'upload_file' if value == 'Upload files' else 'folder'}: **{value}**",
        )
        model_path: Path | None = None
        dataset_path: Path | None = None
        requirements_path: Path | None = None
        metadata_path: Path | None = None
        flow_labels_path: Path | None = None
        execution_device = "cpu"
        allow_cpu_fallback = False
        extra_inputs_ready = True

        if mode == "Demo model":
            model_path = SAMPLE_MODEL_DIR / "traffic_rf_v1.joblib"
            dataset_path = PROCESSED_DATA_DIR / "encrypted_traffic_test.csv"
            requirements_path = SAMPLE_REQUIREMENTS_DIR / "requirements_demo.txt"
            metadata_path = METADATA_DIR / "traffic_rf_v1_metadata.json"
            st.success("Legitimate Random Forest classifier ready")
        else:
            _upload_step(2, "Model input type", "Select how the model will be provided.")
            input_type = st.radio(
                "Model input type",
                ["Tabular flow features", "Sequence tokens/bytes"],
                horizontal=True,
                key="assessment_input_type",
                label_visibility="collapsed",
                format_func=lambda value: f":material/{'bar_chart' if value == 'Tabular flow features' else 'description'}: **{value}**",
            )
            is_sequence = input_type == "Sequence tokens/bytes"
            if not is_sequence:
                st.session_state.pop("sequence_preflight_error", None)
            artifact_col, data_col, device_col = st.columns(3)
            with artifact_col:
                native_weights = st.selectbox("Model artifact", ["ONNX / scikit-learn", "Approved native weights"], key="assessment_artifact_kind") == "Approved native weights"
            with data_col:
                is_pcap = st.selectbox("Evaluation source", ["Prepared dataset", "Offline PCAP + labels"], key="assessment_dataset_kind") == "Offline PCAP + labels"
            if native_weights or is_pcap:
                st.session_state.pop("sequence_preflight_error", None)
            with device_col:
                execution_device = st.selectbox("ONNX execution device", ["cpu", "auto", "cuda"],
                    format_func=lambda value: {"cpu": "CPU", "auto": "Auto (GPU preferred)", "cuda": "CUDA"}[value], key="assessment_device")
            if execution_device == "cuda":
                allow_cpu_fallback = st.checkbox("Allow CPU session fallback", key="assessment_cpu_fallback")
            _upload_step(3, "Upload required files", "Model artifacts and evaluation evidence")
            model_upload = _upload_file_row(
                "Approved model weights" if native_weights else "Trained model", "Approved architecture metadata required" if native_weights else "Sequence ONNX classifier" if is_sequence else "Trained classifier artifact",
                ["safetensors", "h5"] if native_weights else ["onnx"] if is_sequence else ["joblib", "pkl", "onnx"], "deployed_code", "sidebar_model_upload",
            )
            dataset_upload = _upload_file_row(
                "Offline packet capture" if is_pcap else "Labeled test dataset", "Explicit PCAP schema and flow labels required" if is_pcap else "Labeled evaluation sequences" if is_sequence else "Labeled evaluation flow features",
                ["pcap"] if is_pcap else ["npz"] if is_sequence else ["csv"], "description", "sidebar_dataset_upload",
            )
            requirements_upload = _upload_file_row(
                "Dependency requirements" if not is_sequence else "Dependency requirements (optional)",
                "Model dependency manifest", ["txt"], "account_tree", "sidebar_requirements_upload",
            )
            metadata_upload = _upload_file_row(
                "Model metadata", "Required model version, schema and integrity evidence" if st.session_state["scan_require_metadata_hash"] else "Model version, schema and integrity evidence", ["json"], "settings", "sidebar_metadata_upload",
            )
            if is_pcap:
                labels_upload = _upload_file_row("Flow label mapping", "src_ip, src_port, dst_ip, dst_port, protocol, label", ["csv"], "label", "assessment_flow_labels")
                flow_labels_path = persist_upload(labels_upload, "flow_labels", project_root)
                st.download_button("Label CSV template", "src_ip,src_port,dst_ip,dst_port,protocol,label\n", file_name="flow_labels.csv", mime="text/csv", icon=":material/download:")
            model_path = persist_upload(model_upload, "models", project_root)
            dataset_path = persist_upload(dataset_upload, "datasets", project_root)
            requirements_path = persist_upload(requirements_upload, "requirements", project_root)
            metadata_path = persist_upload(metadata_upload, "metadata", project_root)
            if (is_sequence or native_weights) and requirements_path is None:
                requirements_path = SAMPLE_REQUIREMENTS_DIR / "requirements_demo.txt"
                st.caption("Standalone ONNX sequence models do not require a Python dependency manifest.")

            extra_inputs_ready = (not is_pcap or flow_labels_path is not None) and (not (is_pcap or native_weights) or metadata_path is not None)
            if is_sequence and not native_weights and not is_pcap and metadata_path and model_path and dataset_path:
                try:
                    sequence_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                    if not isinstance(sequence_metadata, dict):
                        raise ValueError("Model metadata must be a JSON object.")
                    validate_sequence_compatibility(model_path, dataset_path, sequence_metadata)
                    st.success("Sequence model, metadata, and NPZ dataset are compatible.")
                except (OSError, ValueError, json.JSONDecodeError) as exc:
                    st.error(f"Sequence compatibility check failed: {exc}")
                    st.session_state["sequence_preflight_error"] = str(exc)
                else:
                    st.session_state.pop("sequence_preflight_error", None)

        inputs_ready = all([model_path, dataset_path, requirements_path]) and extra_inputs_ready
        if st.session_state["scan_require_metadata_hash"]:
            inputs_ready = inputs_ready and metadata_path is not None
        if mode == "Upload files" and st.session_state.get("sequence_preflight_error"):
            inputs_ready = False
        submitted = st.button(
            "Analyze model now",
            type="primary",
            width="stretch",
            disabled=not inputs_ready,
            key="sidebar_run_scan",
            icon=":material/monitoring:",
        )

    return ScanSubmission(model_path, dataset_path, requirements_path, metadata_path, submitted,
                          flow_labels_path, execution_device, allow_cpu_fallback)


def execute_scan_submission(
    submission: ScanSubmission,
    current_user: dict,
    render_page_head: Callable[[str, str], None],
) -> None:
    if not submission.submitted:
        return

    state = {"owner_id": int(current_user["id"]), "status": "preparing", "events": [], "progress": 0.0}
    st.session_state["upload_assessment"] = state
    st.session_state.pop("progress_events", None)

    missing = [
        name
        for name, value in {
            "model": submission.model_path,
            "test dataset": submission.dataset_path,
            "requirements": submission.requirements_path,
            **({"metadata": submission.metadata_path} if st.session_state["scan_require_metadata_hash"] else {}),
        }.items()
        if value is None or not Path(value).exists()
    ]
    if missing:
        state.update(status="failed", error=f"Missing required input(s): {', '.join(missing)}")
        st.error(f"Missing required input(s): {', '.join(missing)}")
        st.stop()

    render_page_head("Live Model Assessment", "Deep security, behavior, and reliability analysis in progress")
    progress_bar = st.progress(0, text="Preparing assessment")
    progress_panel = st.empty()
    motion_panel = st.empty()
    progress_events: list[dict[str, str]] = []
    assessment_total = 30
    try:
        metadata = json.loads(submission.metadata_path.read_text(encoding="utf-8")) if submission.metadata_path else {}
        if not isinstance(metadata, dict):
            raise ValueError("Model metadata must be a JSON object, not verification results or a list.")
    except (OSError, ValueError) as exc:
        state.update(status="failed", error=f"Invalid model metadata: {exc}")
        st.error(f"Invalid model metadata: {exc}")
        return
    model_name = metadata.get("model_name") or Path(str(submission.model_path)).stem
    input_type = metadata.get("input_type", "tabular")
    history = list_scan_reports(owner_id=int(current_user["id"]), model_name=model_name, limit=30)
    baseline = next((item for item in history if item.get("input_type", "tabular") == input_type), None)
    state.update(model_name=model_name, baseline=baseline, status="running")
    measured: list[dict] = []
    weights = get_trust_weights()
    live_report = {"model_name": model_name, "input_type": input_type, "trust_score": None, "module_results": measured}
    with motion_panel:
        render_motion(live_report, baseline, live=True)

    def render_result(result) -> None:
        measured.append(asdict(result))
        scored = [item for item in measured if item["module"] in weights and item["status"] not in {"not_applicable", "not_run"}]
        total_weight = sum(weights[item["module"]] for item in scored)
        if result.module == "trust_score":
            live_report["trust_score"] = result.score
        elif total_weight and not any(item["module"] == "trust_score" for item in measured):
            provisional = sum(item["score"] * weights[item["module"]] for item in scored) / total_weight
            live_report["trust_score"] = min(provisional, 70.0)
        with motion_panel:
            render_motion(live_report, baseline, live=result.module != "trust_score")

    def render_progress(level: str, message: str) -> None:
        progress_events.append({"level": level, "message": message})
        stage = re.match(r"Level (\d+)", level)
        if stage:
            state["progress"] = min((int(stage.group(1)) + (1 if message.startswith("Completed") else 0)) / 18, 1.0)
        else:
            state["progress"] = min(len(progress_events) / assessment_total, 1.0)
        state["events"] = list(progress_events)
        progress_bar.progress(state["progress"], text=f"{level}: {message}")
        with progress_panel.container(border=True):
            st.markdown("### Assessment activity")
            for event in progress_events:
                st.markdown(f"**{event['level']}** &nbsp; {event['message']}")

    try:
        report = run_phase1_scan(
            submission.model_path,
            submission.dataset_path,
            submission.requirements_path,
            submission.metadata_path,
            progress_callback=render_progress,
            result_callback=render_result,
            generate_docx=st.session_state["scan_generate_docx_report"],
            owner_id=int(current_user["id"]),
            flow_labels_path=submission.flow_labels_path,
            execution_device=submission.execution_device,
            allow_cpu_fallback=submission.allow_cpu_fallback,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        state.update(status="failed", error=f"Assessment could not start or complete: {exc}")
        st.error(f"Assessment could not start or complete: {exc}")
        return
    finally:
        if state.get("status") == "running":
            state["status"] = "interrupted"
    progress_bar.progress(1.0, text="Assessment complete")
    with motion_panel:
        render_motion(report.to_dict(), baseline)
    render_score_evidence(report.to_dict())
    st.session_state["report"] = report.to_dict()
    st.session_state["progress_events"] = progress_events
    state.update(status="completed", progress=1.0, report=report.to_dict(), events=list(progress_events))
    st.session_state["pending_assessment_model"] = report.model_name
    st.query_params["model"] = report.model_name
    st.success("Deep trust scan completed. The dashboard now shows model-specific evidence and fixes.")
