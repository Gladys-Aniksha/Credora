from __future__ import annotations

from datetime import datetime
from html import escape
import json
from pathlib import Path
import sys

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.config import DATA_DIR, METADATA_DIR, PROCESSED_DATA_DIR, REPORT_DIR, SAMPLE_MODEL_DIR, SAMPLE_REQUIREMENTS_DIR
from core.db import (
    acknowledge_runtime_alert,
    latest_scan,
    list_drift_windows,
    list_integrity_checks,
    list_models,
    list_runtime_alerts,
    list_scans,
)
from core.security import ensure_within_directory, slugify_filename
from modules.phase3_operations.m7_flow_ingestion.collector import ingest_flow_file
from modules.phase3_operations.m8_production_monitoring.monitor import monitor_rolling_windows
from scripts.run_phase1_scan import run_phase1_scan


st.set_page_config(page_title="Credora", page_icon="shield", layout="wide", initial_sidebar_state="expanded")

TEAL = "#078b7e"
NAVY = "#061b3d"
ORANGE = "#e8790b"
RED = "#dc2626"
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_COLORS = {
    "critical": "#991b1b",
    "high": RED,
    "medium": ORANGE,
    "low": "#2d73c9",
    "info": TEAL,
}
STATUS_COLORS = {"pass": TEAL, "warning": ORANGE, "fail": RED, "not_run": "#64748b"}

for setting_key, default_value in {
    "scan_show_info_findings": False,
    "scan_require_metadata_hash": True,
    "scan_generate_docx_report": True,
}.items():
    if setting_key not in st.session_state:
        st.session_state[setting_key] = default_value

st.markdown(
    """
    <style>
    :root {
        --navy: #061b3d;
        --teal: #078b7e;
        --text: #101b35;
        --muted: #627087;
        --border: #dce3eb;
        --canvas: #f5f8fb;
    }
    .stApp {background: var(--canvas); color: var(--text);}
    header[data-testid="stHeader"] {background: transparent;}
    [data-testid="stMainBlockContainer"] {max-width: 1540px; padding: 1.25rem 1.75rem 2.5rem;}
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #04162f 0%, #06264f 100%);
        border-right: 1px solid rgba(255,255,255,.08);
        min-width: 320px;
        max-width: 320px;
    }
    [data-testid="stSidebar"] > div {padding-top: 0;}
    [data-testid="stSidebar"] .stMarkdown,
    [data-testid="stSidebar"] label,
    [data-testid="stSidebar"] p,
    [data-testid="stSidebar"] span {color: #edf5ff;}
    [data-testid="stSidebar"] [data-testid="stRadio"] > label {display: none;}
    [data-testid="stSidebar"] [role="radiogroup"] {gap: 4px;}
    [data-testid="stSidebar"] label[data-testid="stRadioOption"] {
        min-height: 48px;
        padding: 0 14px;
        border-radius: 0;
        border-left: 4px solid transparent;
        background: transparent;
    }
    [data-testid="stSidebar"] label[data-testid="stRadioOption"]:hover {background: rgba(10,193,184,.12);}
    [data-testid="stSidebar"] label[data-testid="stRadioOption"][data-selected="true"] {
        background: linear-gradient(90deg, rgba(9,183,174,.34), rgba(9,183,174,.10));
        border-left-color: #13c7bd;
    }
    [data-testid="stSidebar"] label[data-testid="stRadioOption"] > div > div > div:first-child {display: none;}
    [data-testid="stSidebar"] [data-testid="stExpander"] {
        background: rgba(255,255,255,.06);
        border: 1px solid rgba(255,255,255,.13);
        border-radius: 7px;
        margin: 16px 8px 0;
    }
    [data-testid="stSidebar"] [data-testid="stExpander"] details > summary,
    [data-testid="stSidebar"] [data-testid="stExpanderDetails"] {
        background: transparent !important;
        color: #edf5ff !important;
    }
    [data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] {
        background: rgba(1, 12, 30, .62) !important;
        border-color: rgba(255,255,255,.16) !important;
    }
    [data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] button {
        background: #10213d !important;
        color: #edf5ff !important;
        border: 1px solid rgba(255,255,255,.18) !important;
    }
    [data-testid="stSidebar"] .stButton button {
        background: #09a99f;
        color: #fff;
        border: 0;
        font-weight: 700;
    }
    [data-testid="stSidebarCollapsedControl"], [data-testid="stExpandSidebarButton"] {
        display: flex !important;
        position: fixed !important;
        top: .75rem !important;
        left: .75rem !important;
        width: 46px !important;
        height: 46px !important;
        min-width: 46px !important;
        align-items: center !important;
        justify-content: center !important;
        overflow: visible !important;
        background: #07978d !important;
        color: #ffffff !important;
        border: 2px solid #ffffff !important;
        border-radius: 7px !important;
        box-shadow: 0 5px 18px rgba(2, 18, 42, .28) !important;
        cursor: pointer !important;
        z-index: 999999 !important;
    }
    [data-testid="stSidebarCollapsedControl"] span,
    [data-testid="stExpandSidebarButton"] span {
        display: block !important;
        color: #ffffff !important;
        font-size: 28px !important;
        line-height: 1 !important;
        opacity: 1 !important;
    }
    [data-testid="stSidebarCollapsedControl"]:hover,
    [data-testid="stExpandSidebarButton"]:hover {background: #057b73 !important;}
    [data-testid="stMain"] [data-testid="stToggle"] {
        padding: 10px 0;
        border-bottom: 1px solid #e5eaf0;
    }
    [data-testid="stMain"] [data-testid="stToggle"] label p {
        color: #17233b !important;
        font-weight: 600 !important;
        opacity: 1 !important;
    }
    [data-testid="stMain"] [data-testid="stToggle"] input + div {
        background: #cbd5e1 !important;
    }
    [data-testid="stMain"] [data-testid="stToggle"] input:checked + div {
        background: #078b7e !important;
    }
    .brand {
        display: flex;
        align-items: center;
        gap: 11px;
        height: 92px;
        padding: 0 17px;
        margin: 0 -1rem 10px;
        border-bottom: 1px solid rgba(255,255,255,.11);
        font-size: 1.08rem;
        font-weight: 800;
        white-space: nowrap;
    }
    .brand-mark {
        width: 34px;
        height: 40px;
        display: grid;
        place-items: center;
        border: 2px solid #10c8be;
        color: #10c8be;
        border-radius: 17px 17px 13px 13px;
        font-size: 1.2rem;
    }
    .page-head {margin: 0 0 16px;}
    .page-head h1 {margin: 0; color: #101b35; font-size: 1.65rem; line-height: 1.2; letter-spacing: 0;}
    .page-head p {margin: 4px 0 0; color: #657087; font-size: .98rem;}
    .readiness {
        display: grid;
        grid-template-columns: 1.7fr 1fr;
        gap: 28px;
        background: #fff;
        border: 1px solid var(--border);
        border-radius: 8px;
        box-shadow: 0 2px 7px rgba(16,27,53,.05);
        padding: 22px 28px;
        margin-bottom: 15px;
    }
    .readiness-main {display: grid; grid-template-columns: 125px 1fr auto; gap: 22px; align-items: center;}
    .eyebrow {color: var(--teal); font-size: .78rem; font-weight: 800; text-transform: uppercase; letter-spacing: .08em; margin-bottom: 8px;}
    .shield {
        width: 100px;
        height: 112px;
        display: grid;
        place-items: center;
        color: #fff;
        background: linear-gradient(145deg, #0aa494, #027b6f);
        clip-path: polygon(50% 0,94% 17%,92% 60%,78% 82%,50% 100%,22% 82%,8% 60%,6% 17%);
        font-size: 3.8rem;
    }
    .readiness h2 {font-size: 1.65rem; margin: 0 0 5px; color: #087a62; letter-spacing: 0;}
    .readiness p {margin: 0; color: #536078; line-height: 1.45;}
    .approval {align-self: start; text-align: right;}
    .approval-badge {
        display: inline-block;
        padding: 9px 16px;
        border-radius: 7px;
        background: #eaf8f4;
        border: 1px solid #b7e2d8;
        color: #08775f;
        font-size: .82rem;
        font-weight: 800;
        text-transform: uppercase;
    }
    .evaluated {margin-top: 48px; font-size: .82rem; color: #66738a; line-height: 1.35;}
    .model-summary {border-left: 1px solid #dce3eb; padding-left: 28px; display: flex; flex-direction: column; justify-content: center;}
    .model-summary .label {color: #5d6980; font-size: .9rem; margin-bottom: 8px;}
    .model-name {
        border: 1px solid #cfd8e3;
        border-radius: 7px;
        padding: 12px 14px;
        color: #13203a;
        font-weight: 600;
        background: #fbfcfe;
        overflow-wrap: anywhere;
    }
    .active-pill {width: fit-content; margin-top: 15px; padding: 8px 14px; background: #eaf8f4; border: 1px solid #b9e3da; border-radius: 7px; color: #08775f; font-weight: 700;}
    .active-pill::before {content: ""; display: inline-block; width: 9px; height: 9px; background: #079a7a; border-radius: 50%; margin-right: 8px;}
    .metric-grid {display: grid; grid-template-columns: repeat(4,minmax(0,1fr)); gap: 15px; margin-bottom: 15px;}
    .metric-card {
        background: #fff;
        border: 1px solid var(--border);
        border-radius: 8px;
        box-shadow: 0 2px 6px rgba(16,27,53,.04);
        padding: 16px 20px;
        min-height: 145px;
    }
    .metric-title {display: flex; align-items: center; gap: 10px; color: #17223b; font-size: .9rem;}
    .metric-icon {display: grid; place-items: center; width: 38px; height: 38px; border-radius: 7px; color: var(--teal); background: #e8f8f6; font-weight: 800;}
    .metric-icon.warn {color: var(--orange); background: #fff4e7;}
    .metric-value {font-size: 1.78rem; font-weight: 800; margin-top: 16px; color: #0f1a34; line-height: 1;}
    .metric-value.teal {color: var(--teal);}
    .metric-value.orange {color: var(--orange);}
    .metric-note {font-size: .82rem; margin-top: 10px; color: #66738a;}
    .metric-note.good {color: var(--teal);}
    [data-testid="stVerticalBlockBorderWrapper"] {
        background: #fff;
        border-color: var(--border) !important;
        border-radius: 8px !important;
        box-shadow: 0 2px 6px rgba(16,27,53,.04);
    }
    h1,h2,h3,h4 {color: #111c35; letter-spacing: 0;}
    h3 {font-size: 1rem !important;}
    .security-list {margin: -4px -16px -14px;}
    .security-row {display: grid; grid-template-columns: 1fr auto; gap: 12px; align-items: center; padding: 12px 16px; border-top: 1px solid #e6ebf1; font-size: .87rem;}
    .security-state {font-weight: 700; color: #078b61; white-space: nowrap;}
    .security-state.warn {color: var(--orange);}
    .finding {border-left: 4px solid var(--teal); padding: 12px 14px; background: #f7fafc; border-radius: 0 7px 7px 0; margin-bottom: 10px;}
    .finding.critical,.finding.high {border-left-color: #dc2626; background: #fff4f4;}
    .finding.medium {border-left-color: var(--orange); background: #fff9f0;}
    .finding.low {border-left-color: #2d73c9; background: #f1f7ff;}
    .finding-title {font-weight: 800; color: #15213a; margin-bottom: 5px;}
    .finding-body {font-size: .88rem; color: #4f5e75; line-height: 1.45;}
    .recommendation {margin-top: 8px; color: #26354f; font-size: .86rem; font-weight: 600;}
    .alert-box {border: 1px solid #f0cf9e; border-radius: 7px; background: #fffaf2; padding: 17px; color: #27344f;}
    .alert-box strong {display: block; margin-bottom: 5px;}
    .alert-box p {margin: 0; font-size: .86rem; color: #5a657a; line-height: 1.4;}
    .module-row {display: grid; grid-template-columns: 1fr auto; gap: 14px; align-items: center; padding: 12px 0; border-bottom: 1px solid #e8edf3;}
    .module-row:last-child {border-bottom: 0;}
    .module-title {font-weight: 750; color: #17223b;}
    .module-summary {font-size: .84rem; color: #68758b; margin-top: 3px; line-height: 1.35;}
    .status-pill {display: inline-block; color: #fff; padding: 4px 9px; border-radius: 5px; font-size: .7rem; font-weight: 800; text-transform: uppercase;}
    .module-score {font-size: .84rem; font-weight: 750; color: #334158; margin-top: 5px; text-align: right;}
    .path-box {font-family: Consolas,monospace; font-size: .8rem; color: #334158; background: #f7f9fc; border: 1px solid #dde5ed; border-radius: 6px; padding: 9px; word-break: break-all;}
    .stButton button,.stDownloadButton button {border-radius: 6px; font-weight: 700;}
    .stButton button[kind="primary"] {background: #062654; border-color: #062654;}
    @media (max-width: 1100px) {
        .readiness {grid-template-columns: 1fr;}
        .model-summary {border-left: 0; border-top: 1px solid #dce3eb; padding: 18px 0 0;}
        .metric-grid {grid-template-columns: repeat(2,minmax(0,1fr));}
    }
    @media (max-width: 720px) {
        [data-testid="stMainBlockContainer"] {padding: 1rem .8rem 2rem;}
        .readiness {padding: 18px;}
        .readiness-main {grid-template-columns: 74px 1fr; gap: 14px;}
        .shield {width: 68px; height: 78px; font-size: 2.6rem;}
        .approval {grid-column: 1/-1; text-align: left;}
        .evaluated {margin-top: 10px;}
        .metric-grid {grid-template-columns: 1fr;}
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def safe_score(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def h(value: object) -> str:
    return escape(str(value))


def module_label(module: str) -> str:
    labels = {
        "model_verification": "Model Integrity",
        "dependency_scanner": "Dependency Risk",
        "classifier_evaluation": "Traffic Classifier",
        "robustness_testing": "Robustness",
        "data_drift_detection": "Data Drift",
        "explainability": "Explainability",
        "behavior_analysis": "Behavior Analysis",
        "model_risk_analyzer": "Model Risk",
        "adversarial_validation": "Adversarial Validation",
        "runtime_integrity": "Runtime Integrity",
        "deployment_gate": "Production Deployment Gate",
        "trust_drift_timeline": "Trust Drift",
        "trust_score": "Trust Score Engine",
    }
    return labels.get(module, module.replace("_", " ").title())


def format_time(value: str) -> str:
    if not value or value == "not generated":
        return "Not evaluated"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.strftime("%d %b %Y, %I:%M %p")
    except ValueError:
        return value


def all_findings(report: dict) -> list[dict]:
    rows: list[dict] = []
    for result in report.get("module_results", []):
        for finding in result.get("findings", []):
            rows.append({**finding, "module_status": result.get("status", "not_run")})
    return rows


def severity_counts(report: dict) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in all_findings(report):
        severity = finding.get("severity", "info")
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def deployment_state(score: float, counts: dict[str, int], gate: dict | None = None) -> tuple[str, str, str]:
    decision = (gate or {}).get("details", {}).get("decision")
    if decision == "blocked":
        return "Do Not Deploy", "Blocked", "Phase 3 mandatory production controls failed."
    if decision == "conditional":
        return "Review Required", "Conditional", "Phase 3 passed required scores, but listed risks must be resolved."
    if decision == "approved":
        return "Production Ready", "Approved", "All Phase 3 deployment, adversarial, and integrity controls passed."
    blocking = counts.get("critical", 0) + counts.get("high", 0)
    if score >= 85 and blocking == 0:
        return "Safe to Deploy", "Approved", "Integrity, behavior, performance, and dependency checks passed."
    if score >= 70 and counts.get("critical", 0) == 0:
        return "Review Required", "Conditional", "Resolve highlighted findings before production deployment."
    return "Do Not Deploy", "Blocked", "Critical trust controls require remediation."


def dependency_state(result: dict) -> tuple[str, str, int]:
    findings = [item for item in result.get("findings", []) if item.get("severity") != "info"]
    severities = {item.get("severity") for item in findings}
    if "critical" in severities or "high" in severities:
        return "High", "orange", len(findings)
    if "medium" in severities:
        return "Medium", "orange", len(findings)
    return "Low", "teal", 0


def traffic_distribution(details: dict) -> pd.DataFrame:
    class_metrics = details.get("class_metrics", {})
    return pd.DataFrame([
        {"Class": label, "Flows": int(metrics.get("support", 0))}
        for label, metrics in class_metrics.items()
    ])


def chart_layout(fig: go.Figure, height: int) -> go.Figure:
    fig.update_layout(
        height=height,
        margin=dict(l=12, r=12, t=12, b=12),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Arial, sans-serif", color="#28364f", size=12),
    )
    return fig


def render_page_head(title: str, subtitle: str) -> None:
    st.markdown(
        f"<div class='page-head'><h1>{h(title)}</h1><p>{h(subtitle)}</p></div>",
        unsafe_allow_html=True,
    )


def remediation_for_finding(finding: dict, remediation_plan: list[dict] | None = None) -> dict | None:
    for item in remediation_plan or []:
        if finding.get("title") in item.get("finding_titles", []):
            return item
    if finding.get("module") == "trust_score":
        gate_item = next((item for item in remediation_plan or [] if item.get("module") == "deployment_gate"), None)
        if gate_item:
            return gate_item
    return next(
        (item for item in remediation_plan or [] if item.get("module") == finding.get("module")),
        None,
    )


def render_finding(finding: dict, remediation_plan: list[dict] | None = None) -> None:
    severity = finding.get("severity", "info")
    remediation = remediation_for_finding(finding, remediation_plan)
    recommendation = (remediation or {}).get("fix") or finding.get("recommendation") or "No corrective action is required."
    validation = (remediation or {}).get("validation")
    st.markdown(
        f"""
        <div class="finding {h(severity)}">
          <div class="finding-title">{h(finding.get('title', 'Finding'))} &middot; {h(severity.title())}</div>
          <div class="finding-body"><strong>{h(module_label(finding.get('module', '')))}</strong>: {h(finding.get('description', ''))}</div>
          <div class="recommendation">Recommended fix: {h(recommendation)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if validation:
        st.caption(f"Retest condition: {validation}")


def resolve_report(selected_model: str | None) -> dict | None:
    session_report = st.session_state.get("report")
    if session_report and (not selected_model or session_report.get("model_name") == selected_model):
        return session_report
    if selected_model:
        for scan in list_scans(limit=100):
            if scan.get("model_name") != selected_model:
                continue
            report_path = Path(scan.get("report_path", ""))
            if report_path.exists() and report_path.suffix.lower() == ".json":
                try:
                    return json.loads(report_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    pass
    return latest_scan()


def persist_upload(uploaded: object, subdir: str) -> Path | None:
    if uploaded is None:
        return None
    folder = PROJECT_ROOT / "data" / "uploads" / subdir
    safe_name = Path(uploaded.name).name
    path = ensure_within_directory(folder / safe_name, folder)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(uploaded.getbuffer())
    return path


def update_setting(setting_key: str, control_key: str) -> None:
    st.session_state[setting_key] = bool(st.session_state.get(control_key, False))


with st.sidebar:
    st.markdown(
        "<div class='brand'><div class='brand-mark'>|</div><div>Credora</div></div>",
        unsafe_allow_html=True,
    )
    page = st.radio(
        "Navigation",
        ["Overview", "Model Registry", "Traffic Classifier", "Trust Score", "Trust Drift", "Reports", "Alerts", "Settings"],
        label_visibility="collapsed",
    )

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
                "Trained model (.joblib or .pkl)", type=["joblib", "pkl"], key="sidebar_model_upload"
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
            model_path = persist_upload(model_upload, "models")
            dataset_path = persist_upload(dataset_upload, "datasets")
            requirements_path = persist_upload(requirements_upload, "requirements")
            metadata_path = persist_upload(metadata_upload, "metadata")
            if st.session_state["scan_require_metadata_hash"] and metadata_path is None:
                st.caption("Model metadata is required by the current Settings policy.")

        inputs_ready = all([model_path, dataset_path, requirements_path])
        if st.session_state["scan_require_metadata_hash"]:
            inputs_ready = inputs_ready and metadata_path is not None
        run_scan = st.button(
            "Analyze model now",
            type="primary",
            width="stretch",
            disabled=not inputs_ready,
            key="sidebar_run_scan",
        )

    sidebar_scan_history = list_scans(limit=100)
    sidebar_model_names = list(dict.fromkeys([scan.get("model_name", "Unknown") for scan in sidebar_scan_history]))
    selected_model = st.selectbox("Active assessment", sidebar_model_names) if sidebar_model_names else None
    st.caption("Credora v2.0")


if page == "Overview":
    render_page_head("Model Trust Overview", "Encrypted Traffic Classification | Security & Reliability")


if run_scan:
    missing = [
        name
        for name, value in {
            "model": model_path,
            "test dataset": dataset_path,
            "requirements": requirements_path,
            **({"metadata": metadata_path} if st.session_state["scan_require_metadata_hash"] else {}),
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
        model_path,
        dataset_path,
        requirements_path,
        metadata_path,
        progress_callback=render_progress,
        generate_docx=st.session_state["scan_generate_docx_report"],
    )
    progress_bar.progress(1.0, text="Assessment complete")
    st.session_state["report"] = report.to_dict()
    st.session_state["progress_events"] = progress_events
    st.success("Deep trust scan completed. The dashboard now shows model-specific evidence and fixes.")


scan_history = list_scans(limit=100)
model_names = list(dict.fromkeys([scan.get("model_name", "Unknown") for scan in scan_history]))
session_model = st.session_state.get("report", {}).get("model_name")
if session_model and session_model not in model_names:
    model_names.insert(0, session_model)
if run_scan and session_model:
    selected_model = session_model
elif selected_model not in model_names:
    selected_model = model_names[0] if model_names else None
report_data = resolve_report(selected_model)

if not report_data:
    if page != "Overview":
        render_page_head("Model Trust Overview", "Encrypted Traffic Classification | Security & Reliability")
    st.info("No assessment report exists yet. Open Upload & Analyze Model in the sidebar to run a scan.")
    st.stop()

modules = {result["module"]: result for result in report_data.get("module_results", [])}
verification = modules.get("model_verification", {})
deps = modules.get("dependency_scanner", {})
classifier = modules.get("classifier_evaluation", {})
classifier_details = classifier.get("details", {})
behavior = modules.get("behavior_analysis", {})
behavior_details = behavior.get("details", {})
drift = modules.get("data_drift_detection", {})
adversarial = modules.get("adversarial_validation", {})
adversarial_details = adversarial.get("details", {})
runtime_integrity = modules.get("runtime_integrity", {})
deployment_gate = modules.get("deployment_gate", {})
gate_details = deployment_gate.get("details", {})
trust_score = safe_score(report_data.get("trust_score"))
counts = severity_counts(report_data)
findings = all_findings(report_data)
action_findings = [item for item in findings if item.get("severity") != "info"]
analysis_trace = report_data.get("analysis_trace", [])
remediation_plan = report_data.get("remediation_plan", [])
generated_at = report_data.get("generated_at", "not generated")
model_name = report_data.get("model_name", "Unknown model")
f1_pct = safe_score(classifier_details.get("f1_score")) * 100
readiness, approval, readiness_note = deployment_state(trust_score, counts, deployment_gate)
readiness_icon = "&#10003;" if gate_details.get("decision") != "blocked" else "!"
dep_level, dep_tone, dep_count = dependency_state(deps)


if page == "Overview":
    st.markdown(
        f"""
        <section class="readiness">
          <div>
            <div class="eyebrow">Deployment readiness</div>
            <div class="readiness-main">
              <div class="shield">{readiness_icon}</div>
              <div><h2>{h(readiness)}</h2><p>{h(readiness_note)}</p></div>
              <div class="approval"><span class="approval-badge">{h(approval)}</span><div class="evaluated">Last evaluated:<br>{h(format_time(generated_at))}</div></div>
            </div>
          </div>
          <div class="model-summary">
            <div class="label">Active Model</div>
            <div class="model-name">{h(model_name)}</div>
            <div class="active-pill">Active</div>
          </div>
        </section>
        """,
        unsafe_allow_html=True,
    )

    integrity_value = "Verified" if verification.get("status") == "pass" else "Review"
    score_note = "Excellent" if trust_score >= 90 else "Good" if trust_score >= 75 else "Needs review"
    st.markdown(
        f"""
        <div class="metric-grid">
          <div class="metric-card"><div class="metric-title"><span class="metric-icon">TS</span>Trust Score</div><div class="metric-value">{trust_score:.1f}<span style="font-size:.9rem;font-weight:500;color:#657087">/100</span></div><div class="metric-note good">{h(score_note)}</div></div>
          <div class="metric-card"><div class="metric-title"><span class="metric-icon">F1</span>F1 Score</div><div class="metric-value">{f1_pct:.1f}%</div><div class="metric-note good">Weighted classifier performance</div></div>
          <div class="metric-card"><div class="metric-title"><span class="metric-icon">MI</span>Model Integrity</div><div class="metric-value teal">{h(integrity_value)}</div><div class="metric-note">SHA-256 captured | artifact inspected</div></div>
          <div class="metric-card"><div class="metric-title"><span class="metric-icon warn">DR</span>Dependency Risk</div><div class="metric-value {h(dep_tone)}">{h(dep_level)}</div><div class="metric-note">{dep_count} actionable finding(s)</div></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    left, middle, right = st.columns([1.0, 1.18, 1.0])
    with left:
        with st.container(border=True):
            st.markdown("### Encrypted Traffic Classification")
            traffic_df = traffic_distribution(classifier_details)
            if not traffic_df.empty and traffic_df["Flows"].sum() > 0:
                donut = px.pie(
                    traffic_df,
                    names="Class",
                    values="Flows",
                    hole=.55,
                    color_discrete_sequence=[TEAL, "#347bd1", "#ffad32", "#e94a45"],
                )
                donut.update_traces(textposition="inside", textinfo="percent", marker=dict(line=dict(color="#fff", width=1)))
                donut.update_layout(legend=dict(orientation="h", y=-.08, x=.5, xanchor="center"))
                st.plotly_chart(chart_layout(donut, 280), width="stretch", config={"displayModeBar": False})
                st.caption(f"{int(traffic_df['Flows'].sum()):,} flows analyzed | No payload decryption")
            else:
                st.info("Class distribution is unavailable for this scan.")

    with middle:
        with st.container(border=True):
            st.markdown("### Confusion Matrix")
            labels = classifier_details.get("labels", [])
            matrix = classifier_details.get("confusion_matrix", [])
            if labels and matrix:
                heatmap = px.imshow(
                    pd.DataFrame(matrix, index=labels, columns=labels),
                    text_auto=True,
                    color_continuous_scale=[[0, "#ffffff"], [1, "#b8e5df"]],
                    aspect="auto",
                )
                heatmap.update_layout(xaxis_title="Predicted", yaxis_title="Actual", coloraxis_showscale=False)
                st.plotly_chart(chart_layout(heatmap, 315), width="stretch", config={"displayModeBar": False})
            else:
                st.info("No confusion matrix was produced.")

    with right:
        with st.container(border=True):
            st.markdown("### Security Checks")
            hash_ok = bool(verification.get("details", {}).get("sha256"))
            dep_ok = dep_count == 0
            drift_ok = drift.get("status") == "pass"
            adversarial_ok = adversarial.get("status") == "pass"
            runtime_ok = runtime_integrity.get("status") == "pass"
            gate_ok = gate_details.get("decision") == "approved"
            rows = [
                ("File hash", "Passed" if hash_ok else "Missing", hash_ok),
                ("Metadata", "Complete" if verification.get("status") == "pass" else "Review", verification.get("status") == "pass"),
                ("Artifact integrity", "Verified" if verification.get("status") == "pass" else "Warning", verification.get("status") == "pass"),
                ("Dependencies", "Clear" if dep_ok else f"{dep_count} warning(s)", dep_ok),
                ("Data drift", "Stable" if drift_ok else "Review", drift_ok),
                ("Behavior", "Stable" if behavior.get("status") == "pass" else "Review", behavior.get("status") == "pass"),
                ("Adversarial tests", "Passed" if adversarial_ok else "Review", adversarial_ok),
                ("Runtime integrity", "Verified" if runtime_ok else "Review", runtime_ok),
                ("Production gate", gate_details.get("decision", "Not run").title(), gate_ok),
            ]
            row_html = "".join(
                f"<div class='security-row'><span>{h(label)}</span><span class='security-state{' warn' if not ok else ''}'>{'&#10003;' if ok else '&#9888;'}&nbsp; {h(state)}</span></div>"
                for label, state, ok in rows
            )
            st.markdown(f"<div class='security-list'>{row_html}</div>", unsafe_allow_html=True)

    drift_col, alert_col = st.columns([2.15, .9])
    with drift_col:
        with st.container(border=True):
            st.markdown("### Trust Drift Timeline")
            scan_rows = [scan for scan in scan_history if scan.get("model_name") == model_name]
            if scan_rows:
                history = pd.DataFrame(scan_rows).sort_values("generated_at")
                history["generated_at"] = pd.to_datetime(history["generated_at"])
                trend = px.line(history, x="generated_at", y="trust_score", markers=True)
                trend.add_hline(y=70, line_dash="dash", line_color=ORANGE, annotation_text="Review threshold")
                trend.update_traces(line_color=TEAL, line_width=3, marker=dict(size=7))
                trend.update_layout(yaxis_range=[0, 105], xaxis_title=None, yaxis_title="Trust score", showlegend=False)
                st.plotly_chart(chart_layout(trend, 250), width="stretch", config={"displayModeBar": False})
            else:
                st.info("Trust history will appear after the next scan.")
    with alert_col:
        with st.container(border=True):
            st.markdown("### Alerts")
            top_alert = action_findings[0] if action_findings else None
            if top_alert:
                st.markdown(
                    f"<div class='alert-box'><strong>{len(action_findings)} deployment alert(s)</strong><p>{h(top_alert.get('title'))}<br>{h(top_alert.get('recommendation', 'Review before deployment.'))}</p></div>",
                    unsafe_allow_html=True,
                )
            else:
                st.success("No deployment-blocking alerts were found.")
            st.caption("Open Alerts for model-specific evidence and recommended fixes.")

    progress_events = st.session_state.get("progress_events", [])
    if progress_events:
        with st.expander("Latest assessment activity", expanded=False, icon=":material/checklist:"):
            for event in progress_events:
                st.markdown(f"**{event['level']}** &nbsp; {event['message']}")


elif page == "Model Registry":
    render_page_head("Model Registry", "Registered classifier artifacts and assessment history")
    st.info("To assess another model, open 'Scan new model' in the sidebar and upload its model, test CSV, requirements, and metadata files.")
    left, right = st.columns([1.15, .85])
    with left:
        with st.container(border=True):
            st.markdown("### Registered Models")
            models = list_models()
            if models:
                model_df = pd.DataFrame(models)
                columns = [column for column in ["model_name", "version", "algorithm", "framework", "task", "created_at"] if column in model_df.columns]
                st.dataframe(model_df[columns], hide_index=True, width="stretch")
            else:
                st.info("No models are registered yet.")
    with right:
        with st.container(border=True):
            st.markdown("### Active Artifact")
            st.markdown(f"**{h(model_name)}**")
            st.caption(f"Last evaluated {format_time(generated_at)}")
            st.metric("Trust score", f"{trust_score:.1f}/100")
    with st.container(border=True):
        st.markdown("### Scan History")
        st.dataframe(pd.DataFrame(scan_history), hide_index=True, width="stretch")


elif page == "Traffic Classifier":
    render_page_head("Traffic Classifier", "Class behavior, prediction quality, confidence, and feature reliance")
    st.markdown("### Deep Assessment Trace")
    st.caption("Open any completed step to see the method used, the exact evidence observed, and the conclusion reached.")
    if analysis_trace:
        for step in analysis_trace:
            label = module_label(str(step.get("module", "assessment")))
            with st.expander(
                f"Step {step.get('step', '')} | {label} | {safe_score(step.get('score')):.1f}/100 | {str(step.get('status', 'unknown')).upper()}"
            ):
                st.markdown(f"**What Credora did:** {step.get('method', '')}")
                st.markdown(f"**Evidence observed:** {step.get('evidence', '')}")
                st.markdown(f"**Conclusion:** {step.get('conclusion', '')}")
                issues = step.get("issue_titles", [])
                if issues:
                    st.markdown(f"**Issues detected:** {', '.join(map(str, issues))}")
    else:
        st.info("This is a legacy report. Run the model again to generate the persistent deep-analysis trace.")

    metric_df = pd.DataFrame([
        {"Metric": "Accuracy", "Value": safe_score(classifier_details.get("accuracy"))},
        {"Metric": "Precision", "Value": safe_score(classifier_details.get("precision"))},
        {"Metric": "Recall", "Value": safe_score(classifier_details.get("recall"))},
        {"Metric": "F1 Score", "Value": safe_score(classifier_details.get("f1_score"))},
    ])
    left, right = st.columns([.85, 1.15])
    with left:
        with st.container(border=True):
            st.markdown("### Performance")
            bars = px.bar(metric_df, x="Metric", y="Value", text="Value", color="Metric", color_discrete_sequence=[TEAL, "#347bd1", "#ffad32", "#075c78"])
            bars.update_traces(texttemplate="%{text:.3f}", textposition="outside")
            bars.update_layout(yaxis_range=[0, 1.08], showlegend=False)
            st.plotly_chart(chart_layout(bars, 330), width="stretch", config={"displayModeBar": False})
    with right:
        with st.container(border=True):
            st.markdown("### Class Confusion")
            labels = classifier_details.get("labels", [])
            matrix = classifier_details.get("confusion_matrix", [])
            if labels and matrix:
                heatmap = px.imshow(pd.DataFrame(matrix, index=labels, columns=labels), text_auto=True, color_continuous_scale="Teal", aspect="auto")
                heatmap.update_layout(coloraxis_showscale=False, xaxis_title="Predicted", yaxis_title="Actual")
                st.plotly_chart(chart_layout(heatmap, 330), width="stretch", config={"displayModeBar": False})

    st.markdown("### Behavior Evidence")
    confidence = behavior_details.get("confidence", {})
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Behavior score", f"{safe_score(behavior.get('score')):.1f}/100")
    c2.metric("Mean confidence", f"{safe_score(confidence.get('mean_confidence')):.3f}")
    c3.metric("Low-confidence rate", f"{safe_score(confidence.get('low_confidence_rate')) * 100:.1f}%")
    c4.metric("Weak classes", len(behavior_details.get("weak_classes", [])))
    left, right = st.columns(2)
    with left:
        with st.container(border=True):
            st.markdown("### Most Influential Flow Patterns")
            top_features = behavior_details.get("top_features", [])
            if top_features:
                feature_df = pd.DataFrame(top_features).sort_values("importance")
                feature_chart = px.bar(feature_df, x="importance", y="feature", orientation="h", color_discrete_sequence=[TEAL])
                st.plotly_chart(chart_layout(feature_chart, 330), width="stretch", config={"displayModeBar": False})
            else:
                st.info("The uploaded model does not expose native feature importance.")
    with right:
        with st.container(border=True):
            st.markdown("### Class-Specific Assessment")
            class_metrics = behavior_details.get("class_metrics", {})
            if class_metrics:
                class_df = pd.DataFrame(class_metrics).T.reset_index().rename(columns={"index": "Class"})
                st.dataframe(class_df, hide_index=True, width="stretch")
            for item in behavior.get("findings", []):
                render_finding(item, remediation_plan)

    st.markdown("### Phase 3 Production Validation")
    p1, p2, p3, p4 = st.columns(4)
    p1.metric("Adversarial score", f"{safe_score(adversarial.get('score')):.1f}/100")
    p2.metric("Worst-case F1", f"{safe_score(adversarial_details.get('worst_case_f1')):.3f}")
    p3.metric("Worst sensitive recall", f"{safe_score(adversarial_details.get('worst_sensitive_recall')):.3f}")
    p4.metric("Deployment decision", gate_details.get("decision", "not run").title())
    adv_col, gate_col = st.columns([1.15, .85])
    with adv_col:
        with st.container(border=True):
            st.markdown("### Adversarial Traffic Scenarios")
            scenarios = adversarial_details.get("scenarios", [])
            if scenarios:
                scenario_df = pd.DataFrame(scenarios)
                show_columns = [column for column in ["scenario", "f1", "f1_drop", "prediction_stability", "sensitive_recall"] if column in scenario_df.columns]
                st.dataframe(scenario_df[show_columns], hide_index=True, width="stretch")
            else:
                st.info("Run a Phase 3 scan to generate adversarial release evidence.")
    with gate_col:
        with st.container(border=True):
            st.markdown("### Production Gate Checks")
            checks = gate_details.get("checks", [])
            if checks:
                gate_frame = pd.DataFrame(checks)
                gate_frame = gate_frame.map(lambda value: str(value))
                st.dataframe(gate_frame, hide_index=True, width="stretch")
            decision = gate_details.get("decision")
            if decision == "blocked":
                st.error(deployment_gate.get("summary", "Production deployment is blocked."))
            elif decision == "conditional":
                st.warning(deployment_gate.get("summary", "Production deployment is conditional."))
            elif decision == "approved":
                st.success(deployment_gate.get("summary", "Production deployment is approved."))

    st.markdown("### Captured Flow Ingestion")
    with st.container(border=True):
        capture_col, format_col, window_col = st.columns([1.35, .8, .65])
        with capture_col:
            captured_flow_upload = st.file_uploader(
                "Zeek conn.log or CICFlowMeter CSV",
                type=["log", "zeek", "csv"],
                key="captured_flow_upload",
            )
        with format_col:
            captured_format_label = st.selectbox(
                "Collector format",
                ["Auto-detect", "Zeek", "CICFlowMeter"],
                key="captured_flow_format",
            )
        with window_col:
            production_window_size = st.number_input(
                "Window rows", min_value=25, max_value=10000, value=250, step=25, key="production_window_size"
            )
        captured_format = {
            "Auto-detect": "auto",
            "Zeek": "zeek",
            "CICFlowMeter": "cicflowmeter",
        }[captured_format_label]
        process_capture = st.button(
            "Ingest and monitor flows",
            type="primary",
            disabled=captured_flow_upload is None,
            key="process_captured_flows",
        )
        if process_capture and captured_flow_upload is not None:
            try:
                capture_path = persist_upload(captured_flow_upload, "captures")
                canonical_path = DATA_DIR / "production_flows" / f"{capture_path.stem}-canonical.csv"
                ingestion = ingest_flow_file(capture_path, canonical_path, captured_format)
                window_results = monitor_rolling_windows(
                    model_name=model_name,
                    captured_csv_path=canonical_path,
                    baseline_path=PROCESSED_DATA_DIR / "encrypted_traffic_train.csv",
                    output_dir=ensure_within_directory(DATA_DIR / "production_windows" / slugify_filename(model_name), DATA_DIR),
                    window_size=int(production_window_size),
                    expected_features=classifier_details.get("feature_columns"),
                )
                st.session_state["last_flow_ingestion"] = {
                    "format": ingestion.source_format,
                    "rows": ingestion.row_count,
                    "output": str(ingestion.output_path),
                    "windows": len(window_results),
                }
                st.success(f"Ingested {ingestion.row_count} flows and evaluated {len(window_results)} production window(s).")
            except (ValueError, OSError) as exc:
                st.error(f"Captured-flow ingestion failed: {exc}")
        ingestion_summary = st.session_state.get("last_flow_ingestion")
        if ingestion_summary:
            i1, i2, i3 = st.columns(3)
            i1.metric("Collector", str(ingestion_summary["format"]).title())
            i2.metric("Flows ingested", ingestion_summary["rows"])
            i3.metric("Drift windows", ingestion_summary["windows"])
            st.caption(ingestion_summary["output"])


elif page == "Trust Score":
    render_page_head("Trust Score", "Weighted deployment evidence across every assessment module")
    left, right = st.columns([.8, 1.2])
    with left:
        with st.container(border=True):
            gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=trust_score,
                number={"suffix": "/100", "font": {"size": 35, "color": "#101b35"}},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": TEAL, "thickness": .3},
                    "steps": [
                        {"range": [0, 50], "color": "#fee2e2"},
                        {"range": [50, 70], "color": "#ffedd5"},
                        {"range": [70, 85], "color": "#fef3c7"},
                        {"range": [85, 100], "color": "#d5f3ed"},
                    ],
                },
            ))
            st.plotly_chart(chart_layout(gauge, 300), width="stretch", config={"displayModeBar": False})
            st.markdown(f"**{h(report_data.get('status', ''))}**")
    with right:
        with st.container(border=True):
            st.markdown("### Module Health")
            for result in report_data.get("module_results", []):
                if result.get("module") == "trust_score":
                    continue
                status = result.get("status", "not_run")
                st.markdown(
                    f"<div class='module-row'><div><div class='module-title'>{h(module_label(result.get('module', '')))}</div><div class='module-summary'>{h(result.get('summary', ''))}</div></div><div><span class='status-pill' style='background:{STATUS_COLORS.get(status, '#64748b')}'>{h(status)}</span><div class='module-score'>{safe_score(result.get('score')):.1f}/100</div></div></div>",
                    unsafe_allow_html=True,
                )


elif page == "Trust Drift":
    render_page_head("Trust Drift", "Changes in deployment confidence across model assessments")
    scan_rows = [scan for scan in scan_history if scan.get("model_name") == model_name]
    with st.container(border=True):
        if scan_rows:
            history = pd.DataFrame(scan_rows).sort_values("generated_at")
            history["generated_at"] = pd.to_datetime(history["generated_at"])
            trend = px.line(history, x="generated_at", y="trust_score", markers=True)
            trend.add_hline(y=70, line_dash="dash", line_color=ORANGE, annotation_text="Review threshold")
            trend.update_traces(line_color=TEAL, line_width=3, marker=dict(size=8))
            trend.update_layout(yaxis_range=[0, 105], xaxis_title="Evaluation", yaxis_title="Trust score", showlegend=False)
            st.plotly_chart(chart_layout(trend, 430), width="stretch", config={"displayModeBar": False})
        else:
            st.info("Run more than one assessment to establish a trust timeline.")
    with st.container(border=True):
        st.markdown("### Feature Drift")
        feature_drift = drift.get("details", {}).get("feature_drift", [])
        if feature_drift:
            st.dataframe(pd.DataFrame(feature_drift), hide_index=True, width="stretch")
    production_windows = list_drift_windows(model_name=model_name, limit=100)
    with st.container(border=True):
        st.markdown("### Production Drift Windows")
        if production_windows:
            production_history = pd.DataFrame(production_windows).sort_values("created_at")
            production_history["created_at"] = pd.to_datetime(production_history["created_at"])
            production_trend = px.line(
                production_history,
                x="created_at",
                y="score",
                markers=True,
                hover_data=["window_label", "mean_psi", "max_psi", "status"],
            )
            production_trend.add_hline(y=80, line_dash="dash", line_color=ORANGE)
            production_trend.update_traces(line_color=TEAL, line_width=3, marker=dict(size=7))
            production_trend.update_layout(yaxis_range=[0, 105], xaxis_title="Window", yaxis_title="Drift score", showlegend=False)
            st.plotly_chart(chart_layout(production_trend, 360), width="stretch", config={"displayModeBar": False})
            st.dataframe(
                production_history[["window_label", "row_count", "score", "status", "mean_psi", "max_psi", "created_at"]].sort_values("created_at", ascending=False),
                hide_index=True,
                width="stretch",
            )
        else:
            st.info("No captured production windows have been analyzed for this model.")


elif page == "Reports":
    render_page_head("Reports", "Deployment evidence, exported assessments, and recommended actions")
    report_phase = "phase3" if deployment_gate else "phase2"
    safe_model_name = slugify_filename(model_name)
    report_path = ensure_within_directory(REPORT_DIR / f"{safe_model_name}_{report_phase}_trust_report.json", REPORT_DIR)
    left, right = st.columns([.9, 1.1])
    with left:
        with st.container(border=True):
            st.markdown("### Generated Artifact")
            st.markdown(f"<div class='path-box'>{h(report_path)}</div>", unsafe_allow_html=True)
            st.caption(f"Generated {format_time(generated_at)} | Trust score {trust_score:.1f}/100")
            st.download_button("Download JSON report", json.dumps(report_data, indent=2), file_name=report_path.name, mime="application/json", width="stretch")
            docx_path = Path(report_data.get("docx_report_path", REPORT_DIR / f"{safe_model_name}_{report_phase}_trust_report.docx"))
            if docx_path.exists():
                st.download_button("Download DOCX report", docx_path.read_bytes(), file_name=docx_path.name, mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document", width="stretch")
    with right:
        with st.container(border=True):
            st.markdown("### Model-Specific Remediation Plan")
            st.caption("These actions are generated from this assessment's measured evidence; they are not selectable suggestions.")
            if remediation_plan:
                for item in remediation_plan:
                    st.markdown(f"**{h(item.get('id', 'FIX'))} | {h(item.get('priority', 'P2'))} | {h(item.get('title', 'Corrective action'))}**")
                    st.markdown(f"**Evidence:** {h(item.get('evidence', ''))}")
                    st.markdown(f"**Diagnosis:** {h(item.get('diagnosis', ''))}")
                    st.markdown(f"**Required change:** {h(item.get('fix', ''))}")
                    st.markdown(f"**Retest condition:** {h(item.get('validation', ''))}")
                    st.divider()
            else:
                st.success("No corrective actions are required by this assessment.")
    with st.expander("Deep assessment evidence", expanded=False):
        if analysis_trace:
            for step in analysis_trace:
                st.markdown(f"**Step {step.get('step', '')}: {h(module_label(str(step.get('module', ''))))}**")
                st.write(step.get("method", ""))
                st.caption(step.get("evidence", ""))
        else:
            st.info("Run this model again to add a deep-analysis trace to the report.")
    with st.expander("Raw assessment JSON"):
        st.json(report_data)


elif page == "Alerts":
    render_page_head("Alerts", "Model-specific vulnerabilities, risk evidence, and corrective actions")
    default_severities = ["Critical", "High", "Medium", "Low"]
    if st.session_state["scan_show_info_findings"]:
        default_severities.append("Info")
    filters = st.multiselect("Severity", [item.title() for item in SEVERITY_ORDER], default=default_severities)
    selected = {value.lower() for value in filters}
    selected_findings = [item for item in findings if item.get("severity", "info") in selected]
    if selected_findings:
        for item in selected_findings:
            render_finding(item, remediation_plan)
    else:
        st.success("No findings match the selected severity levels.")
    st.markdown("### Production Monitoring Alerts")
    runtime_alerts = [alert for alert in list_runtime_alerts(limit=100, status="open") if alert.get("severity") in selected]
    if runtime_alerts:
        for alert in runtime_alerts:
            with st.container(border=True):
                alert_body, alert_action = st.columns([5, 1])
                with alert_body:
                    st.markdown(f"**{h(alert.get('title', 'Production alert'))}**")
                    st.caption(f"{h(alert.get('source', 'monitoring'))} | {h(alert.get('severity', 'info').title())} | {format_time(alert.get('created_at'))}")
                    st.write(alert.get("message", ""))
                    if alert.get("recommendation"):
                        st.markdown(f"**Recommended fix:** {h(alert['recommendation'])}")
                with alert_action:
                    if st.button("Acknowledge", key=f"ack-alert-{alert['id']}"):
                        acknowledge_runtime_alert(int(alert["id"]))
                        st.rerun()
    else:
        st.success("No open production-monitoring alerts match the selected severities.")


else:
    render_page_head("Settings", "Assessment inputs and scanner behavior")
    with st.container(border=True):
        st.markdown("### Scanner Policy")
        st.markdown(
            "Credora runs integrity, dependency, classifier performance, robustness, drift, explainability, behavior, adversarial, runtime-integrity, deployment-gate, and trust-history checks. "
            "Use **Upload & Analyze Model** in the sidebar to assess the bundled classifier or your own assessment pack."
        )
        st.toggle(
            "Include informational findings in Alerts by default",
            value=st.session_state["scan_show_info_findings"],
            key="show_info_findings_control",
            on_change=update_setting,
            args=("scan_show_info_findings", "show_info_findings_control"),
        )
        st.toggle(
            "Require metadata hash verification before analysis",
            value=st.session_state["scan_require_metadata_hash"],
            key="require_metadata_hash_control",
            on_change=update_setting,
            args=("scan_require_metadata_hash", "require_metadata_hash_control"),
        )
        st.toggle(
            "Generate a DOCX evidence report for new scans",
            value=st.session_state["scan_generate_docx_report"],
            key="generate_docx_report_control",
            on_change=update_setting,
            args=("scan_generate_docx_report", "generate_docx_report_control"),
        )
        st.caption("Changes apply immediately and are used by the next assessment.")
    integrity_history = list_integrity_checks(model_name=model_name, limit=25)
    with st.container(border=True):
        st.markdown("### Runtime Integrity History")
        if integrity_history:
            integrity_frame = pd.DataFrame(integrity_history)
            st.dataframe(
                integrity_frame[["integrity_state", "score", "status", "actual_sha256", "checked_at"]],
                hide_index=True,
                width="stretch",
            )
        else:
            st.info("No scheduled runtime integrity checks have been recorded for this model.")
