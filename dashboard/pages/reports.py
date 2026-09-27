from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

from core.config import REPORT_DIR
from core.db import list_trusted_signers
from core.report_signing import verify_report_against_trusted_signers
from core.security import ensure_within_directory, slugify_filename
from dashboard.components.common import format_time, h, module_label, render_page_head


def render_reports_page(
    *,
    current_user: dict,
    report_data: dict,
    deployment_gate: dict,
    model_name: str,
    generated_at: str,
    trust_score: float,
    remediation_plan: list[dict],
    analysis_trace: list[dict],
) -> None:
    render_page_head("Reports", "Deployment evidence, exported assessments, and recommended actions")
    report_phase = "phase3" if deployment_gate else "phase2"
    safe_model_name = slugify_filename(model_name)
    report_path = ensure_within_directory(
        REPORT_DIR / str(current_user["id"]) / f"{safe_model_name}_{report_phase}_trust_report.json",
        REPORT_DIR,
    )
    left, right = st.columns([0.9, 1.1])
    with left:
        with st.container(border=True):
            st.markdown("### Generated Artifact")
            st.markdown(f"<div class='path-box'>{h(report_path)}</div>", unsafe_allow_html=True)
            st.caption(f"Generated {format_time(generated_at)} | Trust score {trust_score:.1f}/100")
            st.download_button(
                "Download JSON report",
                json.dumps(report_data, indent=2),
                file_name=report_path.name,
                mime="application/json",
                width="stretch",
            )
            docx_report_value = report_data.get("docx_report_path") or (
                REPORT_DIR / str(current_user["id"]) / f"{safe_model_name}_{report_phase}_trust_report.docx"
            )
            docx_path = Path(docx_report_value)
            if docx_path.exists():
                st.download_button(
                    "Download DOCX report",
                    docx_path.read_bytes(),
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
    with st.expander("Raw assessment JSON"):
        st.json(report_data)
