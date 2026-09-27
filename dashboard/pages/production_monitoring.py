from __future__ import annotations

from pathlib import Path
from typing import Callable

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from core.config import DATA_DIR, PROCESSED_DATA_DIR
from core.db import list_drift_windows
from core.security import ensure_within_directory, slugify_filename
from dashboard.components.scan_submission import persist_upload
from modules.phase3_operations.m7_flow_ingestion.collector import ingest_flow_file
from modules.phase3_operations.m8_production_monitoring.monitor import monitor_rolling_windows


def render_flow_ingestion(
    *,
    project_root: Path,
    current_user: dict,
    model_name: str,
    classifier_details: dict,
) -> None:
    st.markdown("### Captured Flow Ingestion")
    with st.container(border=True):
        capture_col, format_col, window_col = st.columns([1.35, 0.8, 0.65])
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
                capture_path = persist_upload(captured_flow_upload, "captures", project_root)
                if capture_path is None:
                    raise ValueError("Captured flow upload was not saved.")
                flow_root = ensure_within_directory(DATA_DIR / "production_flows" / str(current_user["id"]), DATA_DIR)
                flow_root.mkdir(parents=True, exist_ok=True)
                canonical_path = ensure_within_directory(flow_root / f"{capture_path.stem}-canonical.csv", flow_root)
                ingestion = ingest_flow_file(capture_path, canonical_path, captured_format)
                output_root = ensure_within_directory(
                    DATA_DIR / "production_windows" / str(current_user["id"]), DATA_DIR
                )
                window_results = monitor_rolling_windows(
                    model_name=model_name,
                    captured_csv_path=canonical_path,
                    baseline_path=PROCESSED_DATA_DIR / "encrypted_traffic_train.csv",
                    output_dir=ensure_within_directory(output_root / slugify_filename(model_name), output_root),
                    window_size=int(production_window_size),
                    expected_features=classifier_details.get("feature_columns"),
                    owner_id=int(current_user["id"]),
                )
                st.session_state["last_flow_ingestion"] = {
                    "format": ingestion.source_format,
                    "rows": ingestion.row_count,
                    "output": str(ingestion.output_path),
                    "windows": len(window_results),
                }
                st.success(
                    f"Ingested {ingestion.row_count} flows and evaluated {len(window_results)} production window(s)."
                )
            except (ValueError, OSError) as exc:
                st.error(f"Captured-flow ingestion failed: {exc}")
        ingestion_summary = st.session_state.get("last_flow_ingestion")
        if ingestion_summary:
            i1, i2, i3 = st.columns(3)
            i1.metric("Collector", str(ingestion_summary["format"]).title())
            i2.metric("Flows ingested", ingestion_summary["rows"])
            i3.metric("Drift windows", ingestion_summary["windows"])
            st.caption(ingestion_summary["output"])


def render_production_drift_windows(
    *,
    model_name: str,
    owner_id: int | None,
    include_all: bool,
    chart_layout: Callable[[go.Figure, int], go.Figure],
    line_color: str,
    threshold_color: str,
) -> None:
    production_windows = list_drift_windows(
        model_name=model_name,
        limit=100,
        owner_id=owner_id,
        include_all=include_all,
    )
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
            production_trend.add_hline(y=80, line_dash="dash", line_color=threshold_color)
            production_trend.update_traces(line_color=line_color, line_width=3, marker=dict(size=7))
            production_trend.update_layout(
                yaxis_range=[0, 105],
                xaxis_title="Window",
                yaxis_title="Drift score",
                showlegend=False,
            )
            st.plotly_chart(chart_layout(production_trend, 360), width="stretch", config={"displayModeBar": False})
            st.dataframe(
                production_history[
                    ["window_label", "row_count", "score", "status", "mean_psi", "max_psi", "created_at"]
                ].sort_values("created_at", ascending=False),
                hide_index=True,
                width="stretch",
            )
        else:
            st.info("No captured production windows have been analyzed for this model.")
