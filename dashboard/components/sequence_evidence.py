from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from dashboard.components.common import module_label


def render_sequence_evidence(
    report_data: dict,
    explainability_details: dict,
    robustness_details: dict,
    drift: dict,
) -> None:
    saliency = explainability_details.get("saliency", [])
    with st.container(border=True):
        st.markdown("### Sequence Occlusion Saliency")
        st.caption("Higher values mean masking that sequence window changed the model's original prediction more strongly.")
        if saliency:
            frame = pd.DataFrame(saliency)
            frame["window"] = frame.apply(lambda row: f"{int(row['position_start'])}-{int(row['position_end'])}", axis=1)
            chart = px.bar(frame, x="window", y="saliency", color_discrete_sequence=["#AD3438"])
            chart.update_layout(height=280, margin=dict(l=12, r=12, t=12, b=12), xaxis_title="Sequence positions", yaxis_title="Probability drop", showlegend=False)
            st.plotly_chart(chart, width="stretch", config={"displayModeBar": False})
        else:
            st.info("Sequence saliency is not available for this assessment.")

    not_applicable = [
        {"Assessment": module_label(str(result.get("module", ""))), "Status": result.get("status"), "Reason": result.get("summary", "")}
        for result in report_data.get("module_results", [])
        if result.get("status") == "not_applicable"
    ]
    if not_applicable:
        st.markdown("### Explicitly Unsupported Sequence Checks")
        st.dataframe(pd.DataFrame(not_applicable), hide_index=True, width="stretch")

    robust_col, drift_col = st.columns(2)
    with robust_col:
        with st.container(border=True):
            st.markdown("### Sequence Robustness Scenarios")
            rows = robustness_details.get("scenarios", [])
            if rows:
                frame = pd.DataFrame(rows)
                columns = [column for column in ["scenario", "f1", "f1_drop", "prediction_stability"] if column in frame.columns]
                st.dataframe(frame[columns], hide_index=True, width="stretch")
            else:
                st.info("Sequence robustness evidence is not available for this assessment.")
    with drift_col:
        with st.container(border=True):
            st.markdown("### Sequence Drift Evidence")
            rows = drift.get("details", {}).get("feature_drift", [])
            if rows:
                st.dataframe(pd.DataFrame(rows)[["feature", "psi", "drift_level"]], hide_index=True, width="stretch")
            else:
                st.info("Sequence aggregate drift evidence is not available for this assessment.")
