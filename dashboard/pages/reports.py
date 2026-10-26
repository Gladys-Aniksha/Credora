from __future__ import annotations

import json
import tempfile
from pathlib import Path

import streamlit as st

from core.artifact_integrity import assert_report_artifact_integrity
from core.auth import can_view_all
from core.config import REPORT_DIR
from core.db import list_trusted_signers
from core.model_access import model_access_context
from core.report_evidence import validate_report_evidence
from core.report_signing import verify_report_against_trusted_signers
from core.security import ensure_within_directory, slugify_filename
from dashboard.components.common import format_time, h, module_label, render_page_head


def checked_report_download(
    report_data: dict, owner_id: int | None, *, docx: bool = False, actor_id: int | None = None,
) -> str | bytes:
    with model_access_context(actor_id, "report_download", owner_id=owner_id):
        validate_report_evidence(report_data)
        assert_report_artifact_integrity(report_data, owner_id=owner_id)
        if not docx:
            return json.dumps(report_data, indent=2)

        from modules.phase2_deep_trust.m9_docx_report.docx_report import (
            create_docx_report,
        )

        root = ensure_within_directory(REPORT_DIR / (str(owner_id) if owner_id is not None else "shared"), REPORT_DIR)
        root.mkdir(parents=True, exist_ok=True)
        # Regenerate from the checked snapshot, not a potentially replaced DOCX file.
        with tempfile.TemporaryDirectory(prefix="report-download-", dir=root) as temporary:
            path = create_docx_report(report_data, Path(temporary) / "report.docx")
            assert_report_artifact_integrity(report_data, owner_id=owner_id)
            return path.read_bytes()


def render_reports_page(
    *,
    current_user: dict,
    report_data: dict,
    deployment_gate: dict,
    model_name: str,
    generated_at: str,
    trust_score: float,
    trust_score_issued: bool,
    threat_model: dict,
    remediation_plan: list[dict],
    analysis_trace: list[dict],
) -> None:
    render_page_head("Reports", "Deployment evidence, exported assessments, and recommended actions")
    report_owner: int | None = int(current_user["id"])
    report_actor = int(current_user["id"])
    if can_view_all(current_user) and st.session_state.get("show_all_users"):
        binding = report_data.get("model_artifact")
        report_owner = binding.get("owner_id") if isinstance(binding, dict) else None
    export_error = None
    try:
        with model_access_context(report_actor, "report_render", owner_id=report_owner):
            validate_report_evidence(report_data)
            assert_report_artifact_integrity(report_data, owner_id=report_owner)
    except (OSError, ValueError) as exc:
        export_error = str(exc)
    report_phase = "phase3" if deployment_gate else "phase2"
    if report_data.get("execution") or report_data.get("input_provenance"):
        with st.expander("Execution and input provenance", icon=":material/memory:"):
            evidence = report_data.get("execution", {})
            if evidence:
                st.write(f"Requested device: **{str(evidence.get('execution_device', 'cpu')).upper()}**")
                st.write("Observed execution: " + str(evidence.get("execution_observation", "unavailable")))
                if evidence.get("fallback_reason"):
                    st.warning(str(evidence["fallback_reason"]))
                st.json(evidence)
            if report_data.get("input_provenance"):
                st.json(report_data["input_provenance"])
    safe_model_name = slugify_filename(model_name)
    report_path = ensure_within_directory(
        REPORT_DIR / str(current_user["id"]) / f"{safe_model_name}_{report_phase}_trust_report.json",
        REPORT_DIR,
    )
    left, right = st.columns([0.9, 1.1])
    with left:
        with st.container(border=True):
            st.markdown("### Generated Artifact")
            st.markdown(f"<div class='path-box'>{h(report_path.name)}</div>", unsafe_allow_html=True)
            score_text = f"Trust score {trust_score:.1f}/100" if trust_score_issued else "Trust score not issued"
            st.caption(f"Generated {format_time(generated_at)} | {score_text}")
            if export_error:
                st.error(f"Report download blocked: {export_error}")
            else:
                st.download_button(
                    "Download JSON report",
                    lambda: checked_report_download(report_data, report_owner, actor_id=report_actor),
                    file_name=report_path.name,
                    mime="application/json",
                    width="stretch",
                )
            docx_report_value = report_data.get("docx_report_path") or (
                REPORT_DIR / str(current_user["id"]) / f"{safe_model_name}_{report_phase}_trust_report.docx"
            )
            docx_path = Path(docx_report_value)
            if not export_error and docx_path.exists():
                st.download_button(
                    "Download DOCX report",
                    lambda: checked_report_download(report_data, report_owner, docx=True, actor_id=report_actor),
                    file_name=docx_path.name,
                    mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    width="stretch",
                )
            st.divider()
            st.markdown("### Report Signature")
            signature_status = verify_report_against_trusted_signers(report_data, list_trusted_signers())
            if signature_status.get("trusted"):
                st.success(
                    f"Verified by trusted signer: {signature_status.get('trusted_signer_name', 'trusted signer')}"
                )
                st.caption(
                    f"Signed {format_time(signature_status.get('signed_at'))} | "
                    f"Payload {signature_status.get('payload_sha256', '')[:12]}..."
                )
            elif report_data.get("report_signature"):
                st.warning(
                    signature_status.get("reason", "Report signature could not be matched to a trusted signer.")
                )
                signer = report_data.get("report_signature", {}).get("signer")
                if signer:
                    st.caption(f"Claimed signer: {h(signer)}")
            else:
                st.info(
                    "This JSON report has not been signed yet. Use the Phase 4 report-signing command before "
                    "treating it as release evidence."
                )
    with right:
        with st.container(border=True):
            st.markdown("### Model-Specific Remediation Plan")
            st.caption(
                "These actions are generated from this assessment's measured evidence; "
                "they are not selectable suggestions."
            )
            if remediation_plan:
                for item in remediation_plan:
                    st.markdown(
                        f"**{h(item.get('id', 'FIX'))} | {h(item.get('priority', 'P2'))} | "
                        f"{h(item.get('title', 'Corrective action'))}**"
                    )
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
                st.markdown(
                    f"**Step {step.get('step', '')}: {h(module_label(str(step.get('module', ''))))}**"
                )
                st.write(step.get("method", ""))
                st.caption(step.get("evidence", ""))
        else:
            st.info("Run this model again to add a deep-analysis trace to the report.")
    with st.expander("Threat model summary", expanded=False):
        summary = threat_model.get("summary", {})
        st.markdown(f"**Overall posture:** {h(summary.get('overall_threat_posture', 'Not assessed'))}")
        st.caption(
            f"{int(summary.get('threats_identified', 0))} threats | "
            f"{int(summary.get('critical', 0))} critical | {int(summary.get('high', 0))} high | "
            f"{int(summary.get('not_assessed', 0))} not assessed"
        )
        if summary.get("not_assessed"):
            st.caption(summary.get("not_assessed_note", "Not independently assessed threats are excluded from the headline posture."))
        priority_threats = [
            threat for threat in threat_model.get("threats", [])
            if threat.get("residual_severity") in {"Critical", "High"}
        ]
        if priority_threats:
            st.dataframe(
                [
                    {
                        "Threat": f"{item.get('id')} - {item.get('name')}",
                        "Status": item.get("detection_status"),
                        "Residual risk": item.get("residual_severity"),
                        "Required action": item.get("recommended_action"),
                    }
                    for item in priority_threats
                ],
                hide_index=True,
                width="stretch",
            )
        else:
            st.success("No critical or high residual threats were identified by available evidence.")
    with st.expander("Raw assessment JSON"):
        st.json(report_data)
