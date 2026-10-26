from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.auth import can_view_all
from core.threat_model import build_threat_model
from core.db import (
    acknowledge_runtime_alert,
    change_user_password,
    delete_model_records,
    delete_scan,
    latest_scan,
    list_integrity_checks,
    list_models,
    list_runtime_alerts,
    list_scan_reports,
    list_scans,
)
from dashboard.components.common import format_time, h, module_label, render_page_head, render_score_evidence
from dashboard.components.overview import (
    build_drift_figure,
    build_metric_histories,
    render_metric_cards,
    render_model_summary,
    render_readiness_banner,
    render_recent_assessments,
)
from dashboard.components.overview import render_alerts as render_overview_alerts
from dashboard.components.scan_submission import (
    execute_scan_submission,
    render_saved_upload_assessment,
    render_scan_submission,
)
from dashboard.components.sequence_evidence import render_sequence_evidence
from dashboard.components.assessment_motion import render_assessment_comparison
from dashboard.components.topbar import render_dashboard_topbar
from dashboard.pages.admin import render_admin_page
from dashboard.pages.auth import require_dashboard_auth
from dashboard.pages.production_monitoring import (
    render_flow_ingestion,
    render_production_drift_windows,
)
from dashboard.pages.reports import render_reports_page
from dashboard.pages.threat_model import render_threat_model_page
from dashboard.theme import inject_credora_theme


st.set_page_config(page_title="Credora", page_icon="shield", layout="wide", initial_sidebar_state="collapsed")

from core.model_storage import ModelStorageError, require_model_encryption_key

try:
    require_model_encryption_key()
except ModelStorageError as exc:
    st.error(str(exc))
    st.stop()

TEAL = "#A23438"
NAVY = "#201A1A"
ORANGE = "#C67836"
RED = "#A23438"
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_COLORS = {
    "critical": "#A23438",
    "high": "#BB5E61",
    "medium": ORANGE,
    "low": "#526D7A",
    "info": "#2F7252",
}
STATUS_COLORS = {"pass": "#2F8158", "warning": ORANGE, "fail": "#A23438", "not_run": "#8B817F"}

for setting_key, default_value in {
    "scan_show_info_findings": False,
    "scan_require_metadata_hash": True,
    "scan_generate_docx_report": True,
}.items():
    if setting_key not in st.session_state:
        st.session_state[setting_key] = default_value

inject_credora_theme()


def safe_score(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


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
        font=dict(family="Inter, Arial, sans-serif", color="#514847", size=12),
        hoverlabel=dict(bgcolor="#fffdfb", bordercolor="#d99c97", font_color="#201a1a"),
    )
    fig.update_xaxes(gridcolor="#f0e4de", linecolor="#eadbd4", zerolinecolor="#eadbd4")
    fig.update_yaxes(gridcolor="#f0e4de", linecolor="#eadbd4", zerolinecolor="#eadbd4")
    return fig




def assurance_tier_html(score: object, status_text: str) -> str:
    from dashboard.components.assurance_gauge import assurance_gauge_html

    return f"""
    <div class="assurance-panel">
      <div class="assurance-head">
        <div><h3>Assurance Tier Architecture</h3><p>Calibrated Trust Distribution Index</p></div>
        <span class="assurance-control">&#9881;</span>
      </div>
      {assurance_gauge_html(score, status_text)}
      <div class="assurance-bars">
        <div><span>Robustness &amp; Perturbation</span><b>{safe_score(adversarial.get('score')):.0f} / 100</b><i style="width:{safe_score(adversarial.get('score')):.0f}%"></i></div>
        <div><span>Classifier Reliability</span><b>{safe_score(classifier.get('score')):.0f} / 100</b><i style="width:{safe_score(classifier.get('score')):.0f}%"></i></div>
        <div><span>Leakage &amp; Privacy Evidence</span><b>{min(safe_score(leakage.get('score')), safe_score(privacy.get('score'))):.0f} / 100</b><i style="width:{min(safe_score(leakage.get('score')), safe_score(privacy.get('score'))):.0f}%"></i></div>
        <div><span>Cryptographic Data Lineage</span><b>{safe_score(runtime_integrity.get('score')):.0f} / 100</b><i style="width:{safe_score(runtime_integrity.get('score')):.0f}%"></i></div>
      </div>
    </div>
    """


def overview_telemetry_frame(classifier_details: dict, adversarial_details: dict) -> pd.DataFrame:
    labels = [str(label) for label in classifier_details.get("labels", [])]
    matrix = classifier_details.get("confusion_matrix", [])
    support = {}
    if labels and matrix:
        for idx, label in enumerate(labels):
            support[label] = sum(int(value) for value in matrix[idx])
    if not support:
        support = {"Normal": 75, "Suspicious": 75, "VPN": 75}
    normal_base = max(support.get("Normal", max(support.values())), 1)
    suspicious_base = max(next((value for label, value in support.items() if "suspicious" in label.lower()), min(support.values())), 1)
    vpn_base = max(next((value for label, value in support.items() if "vpn" in label.lower()), sorted(support.values())[-1]), 1)
    stability = safe_score(adversarial_details.get("minimum_prediction_stability"), 1.0)
    points = ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00", "Current"]
    normal_shape = [0.45, 0.58, 0.78, 0.64, 0.86, 0.79, 0.92]
    suspicious_shape = [0.18, 0.23, 0.30, 0.26, 0.38, 0.34, 0.42]
    vpn_shape = [0.12, 0.15, 0.20, 0.18, 0.25, 0.23, 0.29]
    rows = []
    for point, normal, suspicious, vpn in zip(points, normal_shape, suspicious_shape, vpn_shape):
        rows.append({"Time": point, "Flow class": "Normal", "Relative volume": round(normal_base * normal, 2)})
        rows.append({"Time": point, "Flow class": "Suspicious", "Relative volume": round(suspicious_base * suspicious * stability, 2)})
        rows.append({"Time": point, "Flow class": "Masked / VPN", "Relative volume": round(vpn_base * vpn, 2)})
    return pd.DataFrame(rows)

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


def dashboard_owner_scope() -> tuple[int | None, bool]:
    user = st.session_state.get("auth_user") or {}
    show_all = bool(st.session_state.get("show_all_users") and can_view_all(user))
    return (None, True) if show_all else (int(user["id"]), False)


def resolve_report(selected_model: str | None) -> dict | None:
    owner_id, include_all = dashboard_owner_scope()
    return latest_scan(owner_id=owner_id, include_all=include_all, model_name=selected_model)


def update_setting(setting_key: str, control_key: str) -> None:
    st.session_state[setting_key] = bool(st.session_state.get(control_key, False))


current_user = require_dashboard_auth()


def navigate_dashboard_page(page_name: str) -> None:
    st.session_state["dashboard_page"] = page_name
    st.session_state["dashboard_query_page"] = page_name
    st.query_params["page"] = page_name


navigation_options = [
    "Overview",
    "Model Registry",
    "Upload Model",
    "Traffic Classifier",
    "Trust Score",
    "Threat Model",
    "Trust Drift",
    "Reports",
    "Alerts",
    "Settings",
] + (["Admin"] if current_user.get("role") in {"reviewer", "admin"} else [])
requested_page = st.query_params.get("page")
requested_model = st.query_params.get("model")
if requested_page in navigation_options and st.session_state.get("dashboard_query_page") != requested_page:
    st.session_state["dashboard_page"] = requested_page
    st.session_state["dashboard_query_page"] = requested_page

owner_id, include_all = dashboard_owner_scope()
sidebar_open_alert_count = len(
    list_runtime_alerts(limit=100, status="open", owner_id=owner_id, include_all=include_all)
)

page = st.session_state.get("dashboard_page", "Overview")

sidebar_scan_history = list_scans(limit=100, owner_id=owner_id, include_all=include_all)
sidebar_model_names = list(dict.fromkeys([scan.get("model_name", "Unknown") for scan in sidebar_scan_history]))
if requested_model in sidebar_model_names:
    st.session_state["active_assessment"] = requested_model
elif sidebar_model_names and st.session_state.get("active_assessment") not in sidebar_model_names:
    st.session_state["active_assessment"] = sidebar_model_names[0]
pending_model = st.session_state.pop("pending_assessment_model", None)
if pending_model in sidebar_model_names:
    st.session_state["active_assessment"] = pending_model
    st.query_params["model"] = pending_model
selected_model = st.session_state.get("active_assessment")

owner_id, include_all = dashboard_owner_scope()
scan_history = list_scans(limit=100, owner_id=owner_id, include_all=include_all)
model_records = list_models(limit=100, owner_id=owner_id, include_all=include_all)
model_names = list(dict.fromkeys([scan.get("model_name", "Unknown") for scan in scan_history]))
session_model = st.session_state.get("report", {}).get("model_name")
if session_model and session_model not in model_names:
    model_names.insert(0, session_model)
if selected_model not in model_names:
    selected_model = model_names[0] if model_names else None

open_alert_count = sidebar_open_alert_count
render_dashboard_topbar(
    current_user,
    model_records,
    scan_history,
    open_alert_count,
    show_overview_heading=page == "Overview",
    can_view_platform=can_view_all(current_user),
    navigation_options=navigation_options,
    assessment_names=sidebar_model_names,
)

if page == "Upload Model":
    st.markdown("<div id='credora-upload-mode'></div>", unsafe_allow_html=True)
    render_page_head(
        "Upload & Analyze Model",
        "Submit a model and its evaluation evidence for the full Credora trust assessment",
    )
    scan_submission = render_scan_submission(PROJECT_ROOT, standalone=True)
    execute_scan_submission(scan_submission, current_user, render_page_head)
    if not scan_submission.submitted:
        render_saved_upload_assessment(current_user, render_page_head)
    upload_state = st.session_state.get("upload_assessment", {})
    if upload_state.get("owner_id") == int(current_user["id"]) and upload_state.get("status") == "completed":
        st.button(
            "Open model overview",
            type="primary",
            icon=":material/dashboard:",
            on_click=navigate_dashboard_page,
            args=("Overview",),
            width="stretch",
        )
    st.stop()

report_data = resolve_report(selected_model)

if page not in {"Overview", "Upload Model"}:
    st.markdown("<div id='credora-detail-mode'></div>", unsafe_allow_html=True)

if not report_data:
    if page != "Overview":
        render_page_head("Model Trust Overview", "Encrypted Traffic Classification | Security & Reliability")
    st.info("No assessment report exists yet. Open Upload Model from the top navigation to run a scan.")
    st.stop()

modules = {result["module"]: result for result in report_data.get("module_results", [])}
verification = modules.get("model_verification", {})
deps = modules.get("dependency_scanner", {})
classifier = modules.get("classifier_evaluation", {})
classifier_details = classifier.get("details", {})
behavior = modules.get("behavior_analysis", {})
behavior_details = behavior.get("details", {})
explainability = modules.get("explainability", {})
explainability_details = explainability.get("details", {})
robustness = modules.get("robustness_testing", {})
robustness_details = robustness.get("details", {})
leakage = modules.get("dataset_leakage", {})
leakage_details = leakage.get("details", {})
privacy = modules.get("privacy_risk", {})
privacy_details = privacy.get("details", {})
drift = modules.get("data_drift_detection", {})
adversarial = modules.get("adversarial_validation", {})
adversarial_details = adversarial.get("details", {})
runtime_integrity = modules.get("runtime_integrity", {})
security_gate = modules.get("security_gate", {})
security_gate_details = security_gate.get("details", {})
deployment_gate = modules.get("deployment_gate", {})
gate_details = deployment_gate.get("details", {})
trust_result = modules.get("trust_score", {})
trust_score_issued = trust_result.get("details", {}).get("issued") is not False
trust_score = safe_score(report_data.get("trust_score"))
counts = severity_counts(report_data)
findings = all_findings(report_data)
action_findings = [item for item in findings if item.get("severity") != "info"]
analysis_trace = report_data.get("analysis_trace", [])
remediation_plan = report_data.get("remediation_plan", [])
generated_at = report_data.get("generated_at", "not generated")
model_name = report_data.get("model_name", "Unknown model")
assessment_owner = next((scan.get("owner_id") for scan in scan_history
    if scan.get("model_name") == model_name and scan.get("generated_at") == generated_at), current_user["id"])
comparison_history = list_scan_reports(
    owner_id=int(assessment_owner) if assessment_owner is not None else int(current_user["id"]),
    model_name=model_name, limit=30,
)
threat_model = report_data.get("threat_model") or build_threat_model(
    report_data.get("module_results", []),
    model_name=model_name,
    report_signed=bool(report_data.get("report_signature")),
)
f1_pct = safe_score(classifier_details.get("f1_score")) * 100
readiness, approval, readiness_note = deployment_state(trust_score, counts, deployment_gate)
readiness_icon = "&#10003;" if gate_details.get("decision") != "blocked" else "!"
dep_level, dep_tone, dep_count = dependency_state(deps)


if page == "Overview":
    integrity_value = safe_score(verification.get("score"))
    dependency_risk = max(0.0, 100.0 - safe_score(deps.get("score")))
    model_scan_rows = [scan for scan in scan_history if scan.get("model_name") == model_name]
    model_records = list_models(limit=100, owner_id=owner_id, include_all=include_all)
    model_record = next((item for item in model_records if item.get("model_name") == model_name), {})
    model_report_history = list_scan_reports(
        limit=15,
        owner_id=owner_id,
        include_all=include_all,
        model_name=model_name,
    )
    metric_histories = build_metric_histories(model_report_history, report_data)

    render_readiness_banner(
        readiness,
        readiness_note,
        str(gate_details.get("decision") or ""),
        trust_score,
        counts.get("critical", 0),
        integrity_value,
        security_gate_details.get("decision") == "passed",
        trust_score_issued,
    )
    render_metric_cards(
        trust_score,
        integrity_value,
        dependency_risk,
        dep_count,
        metric_histories,
        trust_score_issued,
        security_gate_details.get("decision") == "passed",
    )
    render_score_evidence(report_data)
    drift_col, summary_col = st.columns([1.85, 1.0], gap="small")
    with drift_col:
        with st.container(border=True, key="overview_drift"):
            title_col, range_col = st.columns([4, 1], vertical_alignment="center")
            with title_col:
                st.markdown(
                    '<div id="overview-drift-card"></div><div class="overview-card-head chart-head"><h3>Trust Drift Over Time</h3></div>',
                    unsafe_allow_html=True,
                )
            with range_col:
                period = st.selectbox("Drift date range", ["Last 30 days", "Last 90 days", "All assessments"],
                                      label_visibility="collapsed", key="overview_drift_range")
            if period != "All assessments":
                cutoff = pd.Timestamp.now(tz="UTC") - pd.Timedelta(days=30 if period == "Last 30 days" else 90)
                model_scan_rows = [row for row in model_scan_rows
                                   if pd.to_datetime(row.get("generated_at"), utc=True, errors="coerce") >= cutoff]
            if model_scan_rows:
                st.plotly_chart(
                    build_drift_figure(model_scan_rows, trust_score),
                    width="stretch",
                    config={"displayModeBar": False, "responsive": True},
                )
            else:
                st.caption("No assessments in this date range.")
            st.markdown('<div class="chart-legend"><span>● Trust Score</span><span>– – Alert Threshold</span></div>', unsafe_allow_html=True)
    with summary_col:
        render_model_summary(model_name, model_record, generated_at, str(report_data.get("status") or approval))

    recent_col, alerts_col = st.columns([1.35, 1.0], gap="small")
    with recent_col:
        render_recent_assessments(scan_history)
    with alerts_col:
        render_overview_alerts(action_findings, generated_at)

    progress_events = st.session_state.get("progress_events", [])
    if progress_events:
        with st.expander("Latest assessment activity", expanded=False, icon=":material/checklist:"):
            for event in progress_events:
                st.markdown(f"**{event['level']}** &nbsp; {event['message']}")


elif page == "Model Registry":
    render_page_head("Model Registry", "Registered classifier artifacts and assessment history")
    st.info("To assess another model, open Upload Model and submit its model, test CSV, requirements, and metadata files.")
    left, right = st.columns([1.15, .85])
    with left:
        with st.container(border=True):
            st.markdown("### Registered Models")
            models = list_models(owner_id=owner_id, include_all=include_all)
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
            st.metric("Trust score", f"{trust_score:.1f}/100" if trust_score_issued else "Not issued")
    with st.container(border=True):
        st.markdown("### Scan History")
        st.dataframe(pd.DataFrame(scan_history), hide_index=True, width="stretch")


elif page == "Traffic Classifier":
    render_page_head("Traffic Classifier", "Class behavior, prediction quality, confidence, and feature reliance")
    input_type = str(report_data.get("input_type", "tabular"))
    st.caption(f"Input track: {input_type.title()}")
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
        {"Metric": "Observed evaluation accuracy", "Value": safe_score(classifier_details.get("accuracy"))},
        {"Metric": "Precision", "Value": safe_score(classifier_details.get("precision"))},
        {"Metric": "Recall", "Value": safe_score(classifier_details.get("recall"))},
        {"Metric": "F1 Score", "Value": safe_score(classifier_details.get("f1_score"))},
    ])
    left, right = st.columns([.85, 1.15])
    with left:
        with st.container(border=True):
            st.markdown("### Performance")
            st.caption("Metrics are observations from the uploaded evaluation dataset, not guarantees of production accuracy.")
            bars = px.bar(
                metric_df,
                x="Metric",
                y="Value",
                text="Value",
                color="Metric",
                color_discrete_sequence=["#A23438", "#BB5E61", "#D99C97", "#2F7252"],
            )
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

    if input_type == "sequence":
        render_sequence_evidence(report_data, explainability_details, robustness_details, drift)

    st.markdown("### Phase 2 Trustworthiness Evidence")
    e1, e2, e3, e4 = st.columns(4)
    e1.metric("Leakage score", f"{safe_score(leakage.get('score')):.1f}/100")
    e2.metric("Train/test F1 gap", f"{safe_score(leakage_details.get('generalization_gap')):.3f}")
    e3.metric("Privacy confidence gap", f"{safe_score(privacy_details.get('confidence_gap')):.3f}")
    method = str(explainability_details.get("method", "not available")).replace("_", " ").title()
    e4.metric("Explanation method", method)
    with st.container(border=True):
        st.markdown("### Holdout, Privacy, and Explanation Checks")
        phase2_rows = [
            {
                "Check": "Leakage and holdout",
                "Status": leakage.get("status", "not_run"),
                "Evidence": f"Feature overlap {safe_score(leakage_details.get('feature_overlap_rate')) * 100:.1f}%; full-row overlap {safe_score(leakage_details.get('full_row_overlap_rate')) * 100:.1f}%",
            },
            {
                "Check": "Train/test generalization",
                "Status": leakage.get("status", "not_run"),
                "Evidence": f"Train F1 {safe_score(leakage_details.get('train_f1')):.3f}; test F1 {safe_score(leakage_details.get('test_f1')):.3f}",
            },
            {
                "Check": "Privacy and memorization",
                "Status": privacy.get("status", "not_run"),
                "Evidence": f"Train confidence {safe_score(privacy_details.get('train_mean_confidence')):.3f}; holdout confidence {safe_score(privacy_details.get('test_mean_confidence')):.3f}",
            },
            {
                "Check": "Explainability",
                "Status": explainability.get("status", "not_run"),
                "Evidence": f"Method: {method}; top feature: {(explainability_details.get('top_features') or [{'feature': 'not available'}])[0].get('feature')}",
            },
        ]
        st.dataframe(pd.DataFrame(phase2_rows), hide_index=True, width="stretch")
        for result in [leakage, privacy, explainability]:
            for item in result.get("findings", []):
                if item.get("severity") != "info":
                    render_finding(item, remediation_plan)

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

    render_flow_ingestion(
        project_root=PROJECT_ROOT,
        current_user=current_user,
        model_name=model_name,
        classifier_details=classifier_details,
    )


elif page == "Trust Score":
    render_page_head("Trust Score", "Weighted deployment evidence across every assessment module")
    render_score_evidence(report_data)
    left, right = st.columns([.8, 1.2])
    with left:
        with st.container(border=True):
            if trust_score_issued:
                st.markdown(assurance_tier_html(trust_score, str(report_data.get("status", "not run")).title()), unsafe_allow_html=True)
                if security_gate_details.get("decision") != "passed":
                    st.error(
                        "Security Gate failed. This Trust Score is assessment evidence only; "
                        "the model must not be deployed."
                    )
                    failed_checks = [
                        check for check in security_gate_details.get("checks", []) if not check.get("passed")
                    ]
                    if failed_checks:
                        st.dataframe(pd.DataFrame(failed_checks), hide_index=True, width="stretch")
            else:
                st.error("Trust Score not issued. The model must pass every mandatory Security Gate check first.")
                failed_checks = [
                    check for check in security_gate_details.get("checks", []) if not check.get("passed")
                ]
                if failed_checks:
                    st.dataframe(pd.DataFrame(failed_checks), hide_index=True, width="stretch")
    with right:
        with st.container(border=True):
            st.markdown("### Module Health")
            for result in report_data.get("module_results", []):
                if result.get("module") == "trust_score":
                    continue
                status = result.get("status", "not_run")
                st.markdown(
                    f"<div class='module-row'><div><div class='module-title'>{h(module_label(result.get('module', '')))}</div><div class='module-summary'>{h(result.get('summary', ''))}</div></div><div><span class='status-pill' style='color:{STATUS_COLORS.get(status, '#64748b')}'>{h(status.replace('_', ' ').title())}</span><div class='module-score'>{safe_score(result.get('score')):.1f}/100</div></div></div>",
                    unsafe_allow_html=True,
                )


elif page == "Threat Model":
    render_threat_model_page(threat_model)


elif page == "Trust Drift":
    render_page_head("Trust Drift", "Changes in deployment confidence across model assessments")
    render_assessment_comparison(report_data, comparison_history)
    report_input_type = str(report_data.get("input_type", "tabular"))
    scan_rows = [
        scan for scan in scan_history
        if scan.get("model_name") == model_name
        and scan.get("input_type", "tabular") == report_input_type
    ]
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
    render_production_drift_windows(
        model_name=model_name,
        owner_id=owner_id,
        include_all=include_all,
        chart_layout=chart_layout,
        line_color=TEAL,
        threshold_color=ORANGE,
    )


elif page == "Reports":
    render_reports_page(
        current_user=current_user,
        report_data=report_data,
        deployment_gate=deployment_gate,
        model_name=model_name,
        generated_at=generated_at,
        trust_score=trust_score,
        trust_score_issued=trust_score_issued,
        threat_model=threat_model,
        remediation_plan=remediation_plan,
        analysis_trace=analysis_trace,
    )


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
    runtime_alerts = [alert for alert in list_runtime_alerts(limit=100, status="open", owner_id=owner_id, include_all=include_all) if alert.get("severity") in selected]
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
                        acknowledge_runtime_alert(int(alert["id"]), owner_id=owner_id, include_all=include_all)
                        st.rerun()
    else:
        st.success("No open production-monitoring alerts match the selected severities.")


elif page == "Admin":
    render_admin_page(current_user)

else:
    render_page_head("Settings", "Account, scanner behavior, and owned-data controls")
    with st.container(border=True):
        st.markdown("### My Profile")
        profile = pd.DataFrame([{
            "username": current_user.get("username"),
            "email": current_user.get("email"),
            "role": current_user.get("role"),
            "joined": current_user.get("created_at"),
        }])
        st.dataframe(profile, hide_index=True, width="stretch")
        with st.form("change-password"):
            current_password = st.text_input("Current password", type="password")
            new_password = st.text_input("New password", type="password")
            if st.form_submit_button("Change password"):
                if change_user_password(int(current_user["id"]), current_password, new_password):
                    st.success("Password changed. Please log in again.")
                    for key in ["auth_user", "access_token", "refresh_token", "report", "progress_events", "upload_assessment", "pending_assessment_model"]:
                        st.session_state.pop(key, None)
                    st.rerun()
                else:
                    st.error("Current password is incorrect.")

    with st.container(border=True):
        st.markdown("### Scanner Preferences")
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

    with st.container(border=True):
        st.markdown("### Delete My Data")
        st.caption("Deletion is limited to data owned by this account unless you are viewing all users as reviewer/admin.")
        owned_models = list(dict.fromkeys([scan.get("model_name", "Unknown") for scan in scan_history]))
        if owned_models:
            delete_model_name = st.selectbox("Model to delete", owned_models, key="delete-model-name")
            confirm_model = st.text_input("Type DELETE to remove this model, its scan history, and report files", key="confirm-delete-model")
            if st.button("Delete selected model", disabled=confirm_model != "DELETE"):
                deleted = delete_model_records(delete_model_name, owner_id=owner_id, include_all=include_all, actor_id=int(current_user["id"]))
                st.success(f"Deleted {deleted} record(s).")
                st.rerun()
        if scan_history:
            delete_scan_id = st.selectbox("Single scan to delete", [int(scan["id"]) for scan in scan_history], key="delete-scan-id")
            confirm_scan = st.text_input("Type DELETE SCAN to remove only this scan/report", key="confirm-delete-scan")
            if st.button("Delete selected scan", disabled=confirm_scan != "DELETE SCAN"):
                if delete_scan(delete_scan_id, owner_id=owner_id, include_all=include_all, actor_id=int(current_user["id"])):
                    st.success("Scan deleted.")
                    st.rerun()
                else:
                    st.error("Scan was not found or is not owned by this account.")

    integrity_history = list_integrity_checks(model_name=model_name, limit=25, owner_id=owner_id, include_all=include_all)
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







