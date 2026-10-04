from __future__ import annotations

import pandas as pd
import streamlit as st

from dashboard.components.common import h, render_page_head


def _risk_tone(value: str) -> str:
    normalized = str(value or "Low").lower().replace(" ", "-")
    return normalized if normalized in {"critical", "high", "medium", "low"} else "low"


def render_threat_model_page(threat_model: dict) -> None:
    """Render the evidence-backed threat model stored with the current report."""
    render_page_head(
        "Threat Model",
        "Assets, attack paths, trust boundaries, control evidence, and residual risk",
    )
    summary = threat_model.get("summary", {})
    st.markdown("### Threat Model Overview")
    severity_metrics = st.columns(5)
    severity_metrics[0].metric("Threats identified", int(summary.get("threats_identified", 0)))
    severity_metrics[1].metric("Critical", int(summary.get("critical", 0)))
    severity_metrics[2].metric("High", int(summary.get("high", 0)))
    severity_metrics[3].metric("Medium", int(summary.get("medium", 0)))
    severity_metrics[4].metric("Low", int(summary.get("low", 0)))
    status_metrics = st.columns(4)
    status_metrics[0].metric("Mitigated", int(summary.get("mitigated", 0)))
    status_metrics[1].metric("Detected", int(summary.get("detected", 0)))
    status_metrics[2].metric("High risk", int(summary.get("high_risk", 0)))
    status_metrics[3].metric("Not assessed", int(summary.get("not_assessed", 0)))

    posture = str(summary.get("overall_threat_posture", "NOT ASSESSED"))
    posture_tone = _risk_tone(posture.replace(" RISK", ""))
    st.markdown(
        f"<div class='threat-posture {h(posture_tone)}'><span>Overall threat posture</span>"
        f"<strong>{h(posture)}</strong><p>{h(threat_model.get('method', ''))}</p></div>",
        unsafe_allow_html=True,
    )
    if summary.get("not_assessed"):
        st.caption(summary.get("not_assessed_note", "Not independently assessed threats are excluded from the headline posture."))

    st.markdown("### Protected Assets")
    assets = threat_model.get("protected_assets", [])
    if assets:
        st.dataframe(pd.DataFrame(assets), hide_index=True, width="stretch")

    actor_col, surface_col = st.columns(2)
    with actor_col:
        st.markdown("### Threat Actors")
        for actor in threat_model.get("threat_actors", []):
            with st.expander(str(actor.get("name", "Threat actor"))):
                st.markdown(f"**Capabilities:** {actor.get('capabilities', '')}")
                st.markdown(f"**Objectives:** {actor.get('objectives', '')}")
    with surface_col:
        st.markdown("### Attack Surfaces")
        surfaces = threat_model.get("attack_surfaces", [])
        if surfaces:
            st.dataframe(pd.DataFrame({"Attack surface": surfaces}), hide_index=True, width="stretch")

    st.markdown("### Trust Boundaries")
    boundaries = threat_model.get("trust_boundaries", [])
    if boundaries:
        st.dataframe(pd.DataFrame(boundaries), hide_index=True, width="stretch")

    st.markdown("### Threat Scenarios")
    for threat in threat_model.get("threats", []):
        title = (
            f"{threat.get('id', 'TM')} | {threat.get('name', 'Threat')} | "
            f"{threat.get('detection_status', 'NOT ASSESSED')} | "
            f"Residual {threat.get('residual_severity', 'Unknown')}"
        )
        with st.expander(title):
            overview, risk = st.columns([1.3, 0.7])
            with overview:
                st.markdown(str(threat.get("description", "")))
                st.markdown(f"**Threat actor:** {threat.get('threat_actor', '')}")
                st.markdown(f"**Target asset:** {threat.get('target_asset', '')}")
                st.markdown(f"**Attack surface:** {threat.get('attack_surface', '')}")
                st.markdown(f"**Existing controls:** {', '.join(threat.get('existing_controls', []))}")
                st.markdown(f"**Observed control evidence:** {threat.get('control_result', '')}")
            with risk:
                st.metric(
                    "Initial risk",
                    f"{threat.get('initial_risk', 0)}/16 ({threat.get('severity', 'Unknown')})",
                )
                st.metric("Residual risk", f"{threat.get('residual_risk', 0)}/16")
                st.caption(
                    f"Likelihood: {threat.get('likelihood', '')} | Impact: {threat.get('impact', '')}"
                )
            st.markdown(f"**Residual risk:** {threat.get('residual_explanation', '')}")
            st.markdown(f"**Recommended action:** {threat.get('recommended_action', '')}")

    st.markdown("### Threat-to-Control Mapping")
    matrix = threat_model.get("control_matrix", [])
    if matrix:
        st.dataframe(pd.DataFrame(matrix), hide_index=True, width="stretch")

    residual_rows = [
        {
            "Threat": f"{threat.get('id')} - {threat.get('name')}",
            "Status": threat.get("detection_status"),
            "Residual risk": threat.get("residual_severity"),
            "Residual score": threat.get("residual_risk"),
            "Required action": threat.get("recommended_action"),
        }
        for threat in threat_model.get("threats", [])
        if threat.get("residual_severity") in {"Critical", "High", "Medium"}
    ]
    st.markdown("### Residual Risks")
    if residual_rows:
        st.dataframe(pd.DataFrame(residual_rows), hide_index=True, width="stretch")
    else:
        st.success("No material residual risks were identified by the available assessment evidence.")

    assumption_col, scope_col = st.columns(2)
    with assumption_col:
        st.markdown("### Security Assumptions")
        for assumption in threat_model.get("security_assumptions", []):
            st.markdown(f"- {assumption}")
    with scope_col:
        st.markdown("### Out of Scope")
        for item in threat_model.get("out_of_scope_threats", []):
            st.markdown(f"- {item}")
