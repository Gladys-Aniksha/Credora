from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import streamlit as st

from core.config import METADATA_DIR, PROCESSED_DATA_DIR, SAMPLE_MODEL_DIR, SAMPLE_REQUIREMENTS_DIR
from core.security import ensure_within_directory
from scripts.run_phase1_scan import run_phase1_scan


@dataclass(frozen=True)
class ScanSubmission:
    model_path: Path | None
    dataset_path: Path | None
    requirements_path: Path | None
    metadata_path: Path | None
    submitted: bool


def persist_upload(uploaded: object, subdir: str, project_root: Path) -> Path | None:
    if uploaded is None:
        return None
    user = st.session_state.get("auth_user") or {"id": "shared"}
    folder = project_root / "data" / "uploads" / str(user["id"]) / subdir
    safe_name = Path(uploaded.name).name
    path = ensure_within_directory(folder / safe_name, folder)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(uploaded.getbuffer())
    return path


def render_scan_submission(project_root: Path) -> ScanSubmission:
    with st.expander("Upload & Analyze Model", expanded=True, icon=":material/upload_file:"):
        st.caption("Upload a trained classifier and its labeled evaluation evidence.")
        mode = st.radio(
            "Assessment source",
            ["Upload files", "Demo model"],
            horizontal=True,
            key="sidebar_assessment_source",
        )
        model_path: Path | None = None
        dataset_path: Path | None = None
        requirements_path: Path | None = None
        metadata_path: Path | None = None

        if mode == "Demo model":
            model_path = SAMPLE_MODEL_DIR / "traffic_rf_v1.joblib"
            dataset_path = PROCESSED_DATA_DIR / "encrypted_traffic_test.csv"
            requirements_path = SAMPLE_REQUIREMENTS_DIR / "requirements_demo.txt"
            metadata_path = METADATA_DIR / "traffic_rf_v1_metadata.json"
            st.success("Legitimate Random Forest classifier ready")
        else:
            model_upload = st.file_uploader(
                "Trained model (.joblib, .pkl, or .onnx)",
                type=["joblib", "pkl", "onnx"],
                key="sidebar_model_upload",
            )
            dataset_upload = st.file_uploader(
                "Labeled test dataset (.csv)", type=["csv"], key="sidebar_dataset_upload"
            )
            requirements_upload = st.file_uploader(
                "Dependency requirements (.txt)", type=["txt"], key="sidebar_requirements_upload"
            )
            metadata_upload = st.file_uploader(
                "Model metadata (.json)", type=["json"], key="sidebar_metadata_upload"
            )
            model_path = persist_upload(model_upload, "models", project_root)
            dataset_path = persist_upload(dataset_upload, "datasets", project_root)
            requirements_path = persist_upload(requirements_upload, "requirements", project_root)
            metadata_path = persist_upload(metadata_upload, "metadata", project_root)
            if st.session_state["scan_require_metadata_hash"] and metadata_path is None:
                st.caption("Model metadata is required by the current Settings policy.")

        inputs_ready = all([model_path, dataset_path, requirements_path])
        if st.session_state["scan_require_metadata_hash"]:
            inputs_ready = inputs_ready and metadata_path is not None
        submitted = st.button(
            "Analyze model now",
            type="primary",
            width="stretch",
            disabled=not inputs_ready,
            key="sidebar_run_scan",
        )

    return ScanSubmission(model_path, dataset_path, requirements_path, metadata_path, submitted)


def execute_scan_submission(
    submission: ScanSubmission,
    current_user: dict,
    render_page_head: Callable[[str, str], None],
) -> None:
    if not submission.submitted:
        return

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
        st.error(f"Missing required input(s): {', '.join(missing)}")
        st.stop()

    render_page_head("Live Model Assessment", "Deep security, behavior, and reliability analysis in progress")
    progress_bar = st.progress(0, text="Preparing assessment")
    progress_panel = st.empty()
    progress_events: list[dict[str, str]] = []
    assessment_total = 30

    def render_progress(level: str, message: str) -> None:
        progress_events.append({"level": level, "message": message})
        progress_bar.progress(min(len(progress_events) / assessment_total, 1.0), text=f"{level}: {message}")
        with progress_panel.container(border=True):
            st.markdown("### Assessment activity")
            for event in progress_events:
                st.markdown(f"**{event['level']}** &nbsp; {event['message']}")

    report = run_phase1_scan(
        submission.model_path,
        submission.dataset_path,
        submission.requirements_path,
        submission.metadata_path,
        progress_callback=render_progress,
        generate_docx=st.session_state["scan_generate_docx_report"],
        owner_id=int(current_user["id"]),
    )
    progress_bar.progress(1.0, text="Assessment complete")
    st.session_state["report"] = report.to_dict()
    st.session_state["progress_events"] = progress_events
    st.success("Deep trust scan completed. The dashboard now shows model-specific evidence and fixes.")
