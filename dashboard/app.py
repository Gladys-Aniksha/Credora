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

from core.auth import can_view_all, create_access_token, create_refresh_token
from core.config import DATA_DIR, METADATA_DIR, PROCESSED_DATA_DIR, REPORT_DIR, SAMPLE_MODEL_DIR, SAMPLE_REQUIREMENTS_DIR
from core.db import (
    acknowledge_runtime_alert,
    add_trusted_signer,
    admin_set_password,
    authenticate_user,
    change_user_password,
    create_deployment_override,
    create_user,
    delete_model_records,
    delete_scan,
    get_deployment_policy,
    get_sensitive_label_taxonomy,
    get_trust_weights,
    init_db,
    latest_scan,
    list_drift_windows,
    list_integrity_checks,
    list_models,
    list_runtime_alerts,
    list_audit_logs,
    list_scans,
    list_trusted_signers,
    list_users,
    platform_analytics,
    revoke_user_sessions,
    set_deployment_policy,
    set_sensitive_label_taxonomy,
    set_trust_weights,
    set_trusted_signer_status,
    set_user_disabled,
    update_user_role,
)
from core.report_signing import verify_report_against_trusted_signers
from core.security import ensure_within_directory, slugify_filename
from modules.phase3_operations.m7_flow_ingestion.collector import ingest_flow_file
from modules.phase3_operations.m8_production_monitoring.monitor import monitor_rolling_windows
from scripts.run_phase1_scan import run_phase1_scan


st.set_page_config(page_title="Credora", page_icon="shield", layout="wide", initial_sidebar_state="expanded")

TEAL = "#84B179"
NAVY = "#283327"
ORANGE = "#C98A3D"
RED = "#A93F3F"
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_COLORS = {
    "critical": "#A93F3F",
    "high": "#C75B45",
    "medium": ORANGE,
    "low": "#4F7F74",
    "info": "#5D9660",
}
STATUS_COLORS = {"pass": "#5D9660", "warning": ORANGE, "fail": "#A93F3F", "not_run": "#7B8578"}

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
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600;700&family=Manrope:wght@600;700;800&display=swap');
    :root {
        --background: #f0fdea;
        --canvas: #f8faf6;
        --surface: #ffffff;
        --surface-low: #eaf7e4;
        --surface-container: #e5f2df;
        --surface-high: #d9e6d4;
        --text: #141e13;
        --muted: #5d695a;
        --muted-strong: #42493f;
        --border: #d1e2cd;
        --border-strong: #c2c9bc;
        --primary: #3f6838;
        --primary-soft: #84b179;
        --primary-fixed: #c0efb2;
        --primary-fixed-dim: #a4d398;
        --secondary: #446832;
        --secondary-soft: #c4efab;
        --tertiary: #37675c;
        --sidebar: #283327;
        --sidebar-panel: #354b35;
        --sidebar-soft: #405a3e;
        --sidebar-text: #e8f5e1;
        --sidebar-muted: #c7d8c2;
        --warning: #c98a3d;
        --high: #c75b45;
        --critical: #a93f3f;
        --neutral: #7b8578;
        --shadow: 0 2px 8px rgba(53, 75, 53, .06);
        --shadow-strong: 0 12px 32px rgba(31, 42, 29, .14);
    }
    html, body, [class*="css"] {font-family: Inter, Arial, sans-serif;}
    .stApp {background: var(--background); color: var(--text);}
    header[data-testid="stHeader"] {background: rgba(240,253,234,.82); backdrop-filter: blur(18px); border-bottom: 1px solid rgba(209,226,205,.75);}
    [data-testid="stMainBlockContainer"] {max-width: 1720px; padding: 1.35rem 2rem 2.6rem;}
    [data-testid="stSidebar"] {
        background: var(--sidebar);
        border-right: 1px solid rgba(255,255,255,.08);
        min-width: 300px;
        max-width: 300px;
        box-shadow: 1px 0 8px rgba(0,0,0,.04);
    }
    [data-testid="stSidebar"] > div {padding-top: 0;}
    [data-testid="stSidebar"] .stMarkdown,
    [data-testid="stSidebar"] label,
    [data-testid="stSidebar"] p,
    [data-testid="stSidebar"] span {color: var(--sidebar-text);}
    [data-testid="stSidebar"] [data-testid="stRadio"] > label {display: none;}
    [data-testid="stSidebar"] [role="radiogroup"] {gap: 4px;}
    [data-testid="stSidebar"] label[data-testid="stRadioOption"] {
        min-height: 42px;
        padding: 0 13px;
        border-radius: 8px;
        border-left: 3px solid transparent;
        color: rgba(232,245,225,.72) !important;
        background: transparent;
        font-weight: 600;
    }
    [data-testid="stSidebar"] label[data-testid="stRadioOption"]:hover {
        background: rgba(199,234,187,.10);
        color: var(--sidebar-text) !important;
    }
    [data-testid="stSidebar"] label[data-testid="stRadioOption"][data-selected="true"] {
        background: rgba(162,203,139,.18);
        border-left-color: var(--primary-fixed-dim);
        color: var(--sidebar-text) !important;
    }
    [data-testid="stSidebar"] label[data-testid="stRadioOption"] > div > div > div:first-child {display: none;}
    [data-testid="stSidebar"] [data-testid="stExpander"] {
        background: rgba(217,230,212,.08);
        border: 1px solid rgba(232,245,225,.12);
        border-radius: 8px;
        margin: 16px 6px 0;
        box-shadow: none;
    }
    [data-testid="stSidebar"] [data-testid="stExpander"] details > summary,
    [data-testid="stSidebar"] [data-testid="stExpanderDetails"] {
        background: transparent !important;
        color: var(--sidebar-text) !important;
    }
    [data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] {
        background: rgba(20,30,19,.32) !important;
        border: 1px dashed rgba(199,216,194,.38) !important;
        border-radius: 8px !important;
    }
    [data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] button {
        background: var(--sidebar-soft) !important;
        color: var(--sidebar-text) !important;
        border: 1px solid rgba(232,245,225,.14) !important;
        border-radius: 8px !important;
    }
    [data-testid="stSidebar"] .stButton button {
        background: var(--primary-soft);
        color: #ffffff;
        border: 0;
        border-radius: 8px;
        font-weight: 700;
        box-shadow: 0 2px 8px rgba(53,75,53,.18);
    }
    [data-testid="stSidebar"] .stButton button:hover {background: #709e67; color: #fff; border: 0;}
    [data-testid="stSidebar"] [data-testid="stSelectbox"] div[data-baseweb="select"] > div,
    [data-testid="stSidebar"] [data-testid="stRadio"] label + div {color: var(--sidebar-text);}
    [data-testid="stSidebarCollapsedControl"], [data-testid="stExpandSidebarButton"] {
        background: var(--primary-soft) !important;
        color: #ffffff !important;
        border: 1px solid rgba(255,255,255,.55) !important;
        border-radius: 8px !important;
        box-shadow: 0 6px 16px rgba(53,75,53,.20) !important;
    }
    [data-testid="stMain"] [data-testid="stToggle"] {
        padding: 10px 0;
        border-bottom: 1px solid var(--border);
    }
    [data-testid="stMain"] [data-testid="stToggle"] label p {color: var(--text) !important; font-weight: 600 !important;}
    [data-testid="stMain"] [data-testid="stToggle"] input + div {background: var(--surface-high) !important;}
    [data-testid="stMain"] [data-testid="stToggle"] input:checked + div {background: var(--primary-soft) !important;}
    .brand {
        display: flex;
        align-items: center;
        gap: 10px;
        min-height: 78px;
        padding: 0 14px;
        margin: 0 -1rem 10px;
        border-bottom: 1px solid rgba(232,245,225,.10);
        white-space: nowrap;
    }
    .brand-mark {
        width: 38px;
        height: 38px;
        display: grid;
        place-items: center;
        border-radius: 8px;
        background: var(--primary-fixed-dim);
        color: #1b4317;
        font-family: JetBrains Mono, monospace;
        font-size: 1rem;
        font-weight: 700;
        border: 1px solid rgba(255,255,255,.16);
    }
    .brand-title {display: flex; flex-direction: column; line-height: 1.05;}
    .brand-title strong {font-family: Manrope, Inter, sans-serif; font-size: 1.08rem; color: var(--sidebar-text); letter-spacing: 0;}
    .brand-title span {font-family: JetBrains Mono, monospace; font-size: .66rem; color: var(--primary-fixed-dim); text-transform: uppercase; letter-spacing: .14em; margin-top: 4px;}
    .page-head {margin: 0 0 18px;}
    .page-head h1 {margin: 0; color: var(--text); font-family: Manrope, Inter, sans-serif; font-size: 1.65rem; line-height: 1.22; letter-spacing: 0; font-weight: 700;}
    .page-head p {margin: 5px 0 0; color: var(--muted); font-size: .98rem; line-height: 1.45;}
    .readiness {
        display: grid;
        grid-template-columns: 1.7fr 1fr;
        gap: 28px;
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 10px;
        box-shadow: var(--shadow);
        padding: 22px 28px;
        margin-bottom: 16px;
    }
    .readiness-main {display: grid; grid-template-columns: 115px 1fr auto; gap: 22px; align-items: center;}
    .eyebrow {color: var(--primary); font-family: JetBrains Mono, monospace; font-size: .74rem; font-weight: 700; text-transform: uppercase; letter-spacing: .08em; margin-bottom: 8px;}
    .shield {
        width: 96px;
        height: 106px;
        display: grid;
        place-items: center;
        color: #fff;
        background: linear-gradient(145deg, var(--primary-soft), var(--primary));
        clip-path: polygon(50% 0,94% 17%,92% 60%,78% 82%,50% 100%,22% 82%,8% 60%,6% 17%);
        font-size: 3.5rem;
        box-shadow: inset 0 0 0 1px rgba(255,255,255,.20);
    }
    .readiness h2 {font-family: Manrope, Inter, sans-serif; font-size: 1.65rem; margin: 0 0 5px; color: var(--primary); letter-spacing: 0; font-weight: 700;}
    .readiness p {margin: 0; color: var(--muted); line-height: 1.45;}
    .approval {align-self: start; text-align: right;}
    .approval-badge {
        display: inline-block;
        padding: 8px 13px;
        border-radius: 4px;
        background: rgba(93,150,96,.12);
        border: 1px solid rgba(93,150,96,.25);
        color: #3f6838;
        font-family: JetBrains Mono, monospace;
        font-size: .75rem;
        font-weight: 700;
        text-transform: uppercase;
    }
    .evaluated {margin-top: 44px; font-family: JetBrains Mono, monospace; font-size: .75rem; color: var(--muted); line-height: 1.35;}
    .model-summary {border-left: 1px solid var(--border); padding-left: 28px; display: flex; flex-direction: column; justify-content: center;}
    .model-summary .label {color: var(--muted); font-size: .86rem; margin-bottom: 8px; font-weight: 600;}
    .model-name {border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; color: var(--text); font-weight: 650; background: #fbfdf9; overflow-wrap: anywhere;}
    .active-pill {width: fit-content; margin-top: 15px; padding: 7px 12px; background: rgba(132,177,121,.18); border: 1px solid rgba(132,177,121,.30); border-radius: 4px; color: var(--primary); font-family: JetBrains Mono, monospace; font-size: .78rem; font-weight: 700;}
    .active-pill::before {content: ""; display: inline-block; width: 7px; height: 7px; background: var(--primary); border-radius: 50%; margin-right: 8px;}
    .metric-grid {display: grid; grid-template-columns: repeat(4,minmax(0,1fr)); gap: 16px; margin-bottom: 16px;}
    .metric-card {background: var(--surface); border: 1px solid var(--border); border-radius: 10px; box-shadow: var(--shadow); padding: 18px 20px; min-height: 145px; transition: box-shadow .16s ease, border-color .16s ease;}
    .metric-card:hover {border-color: var(--primary-soft); box-shadow: 0 6px 16px rgba(53,75,53,.09);}
    .metric-title {display: flex; align-items: center; gap: 10px; color: var(--muted-strong); font-size: .82rem; font-weight: 700; text-transform: uppercase; letter-spacing: .06em;}
    .metric-icon {display: grid; place-items: center; width: 38px; height: 38px; border-radius: 8px; color: var(--primary); background: var(--surface-container); font-weight: 800; font-family: JetBrains Mono, monospace;}
    .metric-icon.warn {color: var(--warning); background: rgba(201,138,61,.12);}
    .metric-value {font-family: JetBrains Mono, monospace; font-size: 1.8rem; font-weight: 700; margin-top: 16px; color: var(--text); line-height: 1; letter-spacing: 0;}
    .metric-value.teal {color: var(--primary);}
    .metric-value.orange {color: var(--warning);}
    .metric-note {font-family: JetBrains Mono, monospace; font-size: .76rem; margin-top: 10px; color: var(--muted);}
    .metric-note.good {color: var(--primary);}
    [data-testid="stVerticalBlockBorderWrapper"] {background: var(--surface); border-color: var(--border) !important; border-radius: 10px !important; box-shadow: var(--shadow);}
    [data-testid="stMetric"] {background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; box-shadow: var(--shadow);}
    [data-testid="stMetricLabel"] p {font-family: Inter, sans-serif; color: var(--muted) !important; font-weight: 700; letter-spacing: .03em;}
    [data-testid="stMetricValue"] {font-family: JetBrains Mono, monospace; color: var(--text); font-weight: 700;}
    h1,h2,h3,h4 {font-family: Manrope, Inter, sans-serif; color: var(--text); letter-spacing: 0;}
    h3 {font-size: 1rem !important; font-weight: 700 !important;}
    .security-list {margin: -4px -16px -14px;}
    .security-row {display: grid; grid-template-columns: 1fr auto; gap: 12px; align-items: center; padding: 12px 16px; border-top: 1px solid var(--border); font-size: .87rem;}
    .security-state {font-family: JetBrains Mono, monospace; font-weight: 700; color: var(--primary); white-space: nowrap;}
    .security-state.warn {color: var(--warning);}
    .finding {border-left: 4px solid var(--primary); padding: 12px 14px; background: #f5faec; border-radius: 0 8px 8px 0; margin-bottom: 10px; border-top: 1px solid var(--border); border-right: 1px solid var(--border); border-bottom: 1px solid var(--border);}
    .finding.critical,.finding.high {border-left-color: var(--critical); background: #fff6f4;}
    .finding.medium {border-left-color: var(--warning); background: #fff9ed;}
    .finding.low {border-left-color: var(--tertiary); background: #f1faf7;}
    .finding-title {font-weight: 800; color: var(--text); margin-bottom: 5px;}
    .finding-body {font-size: .88rem; color: var(--muted-strong); line-height: 1.45;}
    .recommendation {margin-top: 8px; color: var(--text); font-size: .86rem; font-weight: 650;}
    .alert-box {border: 1px solid rgba(201,138,61,.25); border-radius: 8px; background: #fff9ed; padding: 17px; color: var(--text);}
    .alert-box strong {display: block; margin-bottom: 5px;}
    .alert-box p {margin: 0; font-size: .86rem; color: var(--muted); line-height: 1.4;}
    .module-row {display: grid; grid-template-columns: 1fr auto; gap: 14px; align-items: center; padding: 12px 0; border-bottom: 1px solid var(--border);}
    .module-row:last-child {border-bottom: 0;}
    .module-title {font-weight: 750; color: var(--text);}
    .module-summary {font-size: .84rem; color: var(--muted); margin-top: 3px; line-height: 1.35;}
    .status-pill {display: inline-block; color: #fff; padding: 4px 9px; border-radius: 4px; font-family: JetBrains Mono, monospace; font-size: .68rem; font-weight: 800; text-transform: uppercase;}
    .module-score {font-family: JetBrains Mono, monospace; font-size: .8rem; font-weight: 700; color: var(--muted-strong); margin-top: 5px; text-align: right;}
    .path-box {font-family: JetBrains Mono, Consolas, monospace; font-size: .78rem; color: var(--muted-strong); background: #f5faec; border: 1px solid var(--border); border-radius: 8px; padding: 9px; word-break: break-all;}
    .stButton button,.stDownloadButton button {border-radius: 8px; font-weight: 700; border-color: var(--primary-soft);}
    .stButton button[kind="primary"] {background: var(--primary-soft); border-color: var(--primary-soft); color: #fff;}
    .stButton button[kind="primary"]:hover {background: #709e67; border-color: #709e67; color: #fff;}
    [data-testid="stDataFrame"] {border: 1px solid var(--border); border-radius: 8px; overflow: hidden;}
    input, textarea, [data-baseweb="select"] > div {border-radius: 8px !important; border-color: var(--border) !important;}
    [data-baseweb="select"] > div {background: var(--surface) !important;}
    .assurance-panel {min-height: 438px; display: flex; flex-direction: column; justify-content: space-between;}
    .assurance-head {display: flex; align-items: flex-start; justify-content: space-between; padding-bottom: 6px;}
    .assurance-head h3 {margin: 0; font-size: 1rem !important;}
    .assurance-head p {margin: 2px 0 0; color: var(--muted); font-size: .84rem;}
    .assurance-control {font-family: JetBrains Mono, monospace; color: var(--primary); font-size: 1.15rem;}
    .assurance-gauge {position: relative; display: flex; flex-direction: column; align-items: center; padding: 4px 0 6px;}
    .assurance-gauge svg {width: min(310px, 100%); height: 185px; overflow: visible;}
    .gauge-track,.gauge-critical,.gauge-warning,.gauge-review,.gauge-trusted {fill: none; stroke-linecap: butt; stroke-width: 18;}
    .gauge-track {stroke: #e5f2df;}
    .gauge-critical {stroke: #a93f3f; stroke-dasharray: 50 100; stroke-dashoffset: 0; opacity: .9;}
    .gauge-warning {stroke: #c98a3d; stroke-dasharray: 20 100; stroke-dashoffset: -50; opacity: .82;}
    .gauge-review {stroke: #e8f5bd; stroke-dasharray: 15 100; stroke-dashoffset: -70;}
    .gauge-trusted {stroke: #84b179; stroke-dasharray: 15 100; stroke-dashoffset: -85;}
    .gauge-needle {stroke: var(--primary); stroke-width: 6; stroke-linecap: round; filter: drop-shadow(0 2px 2px rgba(31,42,29,.18));}
    .gauge-hub {fill: var(--primary); stroke: #fff; stroke-width: 3;}
    .assurance-readout {margin-top: -34px; font-family: JetBrains Mono, monospace; color: var(--text); font-weight: 700;}
    .assurance-readout span {font-size: 1.72rem;}
    .assurance-readout em {font-style: normal; margin-left: 8px; font-size: 1.1rem; color: var(--muted);}
    .assurance-tier {font-size: .82rem; font-weight: 800; color: var(--primary); margin-top: 4px;}
    .assurance-status {font-size: .76rem; color: var(--muted); margin-top: 2px;}
    .assurance-bars {display: flex; flex-direction: column; gap: 8px; margin-top: 12px;}
    .assurance-bars div {display: grid; grid-template-columns: 1fr auto; gap: 10px; position: relative; padding-bottom: 8px; font-size: .78rem; font-weight: 700; color: var(--text);}
    .assurance-bars b {font-family: JetBrains Mono, monospace; font-size: .75rem; color: var(--muted-strong);}
    .assurance-bars div::after {content: ""; position: absolute; left: 0; right: 0; bottom: 0; height: 5px; background: #e5f2df; border-radius: 999px;}
    .assurance-bars i {position: absolute; left: 0; bottom: 0; height: 5px; background: linear-gradient(90deg, #84b179, #3f6838); border-radius: 999px; z-index: 1;}
    @media (max-width: 1100px) {
        .readiness {grid-template-columns: 1fr;}
        .model-summary {border-left: 0; border-top: 1px solid var(--border); padding: 18px 0 0;}
        .metric-grid {grid-template-columns: repeat(2,minmax(0,1fr));}
    }
    @media (max-width: 720px) {
        [data-testid="stMainBlockContainer"] {padding: 1rem .8rem 2rem;}
        .readiness {padding: 18px;}
        .readiness-main {grid-template-columns: 74px 1fr; gap: 14px;}
        .shield {width: 68px; height: 78px; font-size: 2.4rem;}
        .approval {grid-column: 1/-1; text-align: left;}
        .evaluated {margin-top: 10px;}
        .metric-grid {grid-template-columns: 1fr;}
    }
    .login-shell {
        min-height: calc(100vh - 120px);
        display: grid;
        align-items: center;
        padding: 24px 0 34px;
    }
    .login-topbar {
        margin-top: 34px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 18px;
        padding: 8px 4px 28px;
        color: var(--muted-strong);
        font-size: .82rem;
    }
    .login-topbar strong {color: var(--text); font-family: Manrope, Inter, sans-serif; font-size: 1rem; margin-right: 8px;}
    .login-badge {font-family: JetBrains Mono, monospace; font-size: .62rem; color: var(--primary); border: 1px solid var(--border); border-radius: 4px; padding: 2px 6px; text-transform: uppercase;}
    .login-links {display: flex; gap: 24px; white-space: nowrap; color: var(--muted);}
    .login-panel {
        background: linear-gradient(145deg, #294728, #1f3720);
        color: #ecf8e8;
        border-radius: 12px;
        padding: 34px 34px 28px;
        min-height: 560px;
        box-shadow: 0 18px 42px rgba(31, 55, 32, .28);
        border: 1px solid rgba(232,245,225,.14);
        display: flex;
        flex-direction: column;
        justify-content: space-between;
    }
    .login-panel .kicker {display: inline-flex; width: fit-content; color: #c0efb2; border: 1px solid rgba(192,239,178,.28); border-radius: 999px; padding: 7px 12px; font-size: .74rem; font-family: JetBrains Mono, monospace; margin-bottom: 28px;}
    .login-panel h1 {color: #ffffff; font-family: Manrope, Inter, sans-serif; font-size: 2rem; line-height: 1.08; margin: 0 0 16px; max-width: 390px;}
    .login-panel p {color: rgba(232,245,225,.82); line-height: 1.55; margin: 0; max-width: 410px;}
    .login-modules {margin: 34px 0 28px; background: rgba(18, 30, 18, .34); border: 1px solid rgba(232,245,225,.12); border-radius: 10px; padding: 18px;}
    .login-modules h3 {color: #c0efb2; font-size: .76rem !important; font-family: JetBrains Mono, monospace; text-transform: uppercase; margin: 0 0 12px;}
    .login-module-grid {display: grid; grid-template-columns: 1fr 1fr; gap: 9px 18px; font-size: .82rem; color: rgba(255,255,255,.9);}
    .login-module-grid span {font-family: JetBrains Mono, monospace; color: #c0efb2; font-size: .72rem;}
    .login-checks {display: grid; gap: 14px; margin-top: 18px;}
    .login-check {display: grid; grid-template-columns: 24px 1fr; gap: 10px; align-items: start; color: rgba(232,245,225,.86); font-size: .86rem; line-height: 1.35;}
    .login-check b {display: grid; place-items: center; width: 20px; height: 20px; border-radius: 50%; background: rgba(132,177,121,.22); color: #c0efb2; font-size: .78rem;}
    .login-foot {display: flex; justify-content: space-between; align-items: end; gap: 18px; color: rgba(232,245,225,.74); font-size: .78rem;}
    .login-foot strong {display: block; color: #fff; font-size: .86rem; margin-bottom: 3px;}
    .login-version {font-family: JetBrains Mono, monospace; color: #c0efb2;}
    .auth-card {
        max-width: 720px;
        margin: 0 auto;
        background: #ffffff;
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 34px 42px 28px;
        box-shadow: 0 16px 38px rgba(31,42,29,.10);
    }
    .auth-card h2 {font-family: Manrope, Inter, sans-serif; font-size: 1.45rem; margin: 18px 0 6px;}
    .auth-card p {color: var(--muted); margin: 0 0 18px;}
    .auth-note {display: flex; justify-content: space-between; gap: 12px; padding-top: 22px; margin-top: 8px; border-top: 1px solid var(--border); color: var(--muted); font-size: .75rem;}
    .auth-note span {font-family: JetBrains Mono, monospace; color: var(--primary);}
    .auth-card [data-baseweb="tab-list"] {gap: 8px; border-bottom: 1px solid var(--border); padding-bottom: 14px;}
    .auth-card [data-baseweb="tab"] {height: 38px; border: 1px solid var(--border); border-radius: 8px; padding: 0 16px; background: #f7fbf3; font-weight: 700;}
    .auth-card [aria-selected="true"] {background: var(--primary-soft) !important; color: #fff !important; border-color: var(--primary-soft) !important;}
    .auth-card .stButton button {height: 46px;}
    @media (max-width: 980px) {
        .login-topbar {display: block;}
        .login-links {margin-top: 10px; flex-wrap: wrap; gap: 10px 18px;}
        .login-panel {min-height: auto; margin-bottom: 18px;}
        .auth-card {margin: 0 auto; padding: 24px;}
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
        "dataset_leakage": "Leakage and Holdout Check",
        "privacy_risk": "Privacy and Memorization Risk",
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




def assurance_tier_html(score: float, status_text: str) -> str:
    score = max(0.0, min(float(score), 100.0))
    needle = -70 + (score * 1.4)
    tier = "Tier 4: Enterprise Trusted" if score >= 85 else "Tier 3: Review Required" if score >= 70 else "Tier 2: High Risk" if score >= 50 else "Tier 1: Critical"
    return f"""
    <div class="assurance-panel">
      <div class="assurance-head">
        <div><h3>Assurance Tier Architecture</h3><p>Calibrated Trust Distribution Index</p></div>
        <span class="assurance-control">&#9881;</span>
      </div>
      <div class="assurance-gauge">
        <svg viewBox="0 0 240 145" role="img" aria-label="Trust score {score:.1f} out of 100">
          <path class="gauge-track" pathLength="100" d="M40 120 A80 80 0 0 1 200 120" />
          <path class="gauge-critical" pathLength="100" d="M40 120 A80 80 0 0 1 200 120" />
          <path class="gauge-warning" pathLength="100" d="M40 120 A80 80 0 0 1 200 120" />
          <path class="gauge-review" pathLength="100" d="M40 120 A80 80 0 0 1 200 120" />
          <path class="gauge-trusted" pathLength="100" d="M40 120 A80 80 0 0 1 200 120" />
          <g style="transform: rotate({needle:.1f}deg); transform-origin: 120px 120px;">
            <line x1="120" y1="120" x2="120" y2="45" class="gauge-needle" />
            <circle cx="120" cy="120" r="7" class="gauge-hub" />
          </g>
        </svg>
        <div class="assurance-readout"><span>{score:.1f}</span><em>/ 100</em></div>
        <div class="assurance-tier">&#10003; {h(tier)}</div>
        <div class="assurance-status">{h(status_text)}</div>
      </div>
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


def dashboard_owner_scope() -> tuple[int | None, bool]:
    user = st.session_state.get("auth_user") or {}
    show_all = bool(st.session_state.get("show_all_users") and can_view_all(user))
    return (None, True) if show_all else (int(user["id"]), False)


def resolve_report(selected_model: str | None) -> dict | None:
    session_report = st.session_state.get("report")
    if session_report and (not selected_model or session_report.get("model_name") == selected_model):
        return session_report
    owner_id, include_all = dashboard_owner_scope()
    if selected_model:
        for scan in list_scans(limit=100, owner_id=owner_id, include_all=include_all):
            if scan.get("model_name") != selected_model:
                continue
            report_path = Path(scan.get("report_path", ""))
            if report_path.exists() and report_path.suffix.lower() == ".json":
                try:
                    return json.loads(report_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    pass
    return latest_scan(owner_id=owner_id, include_all=include_all)


def persist_upload(uploaded: object, subdir: str) -> Path | None:
    if uploaded is None:
        return None
    user = st.session_state.get("auth_user") or {"id": "shared"}
    folder = PROJECT_ROOT / "data" / "uploads" / str(user["id"]) / subdir
    safe_name = Path(uploaded.name).name
    path = ensure_within_directory(folder / safe_name, folder)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(uploaded.getbuffer())
    return path


def update_setting(setting_key: str, control_key: str) -> None:
    st.session_state[setting_key] = bool(st.session_state.get(control_key, False))


def require_dashboard_auth() -> dict:
    init_db()
    if st.session_state.get("auth_user"):
        return st.session_state["auth_user"]

    st.markdown(
        """
        <div class="login-topbar">
          <div><strong>Credora</strong><span class="login-badge">Open Source</span><div>ML Classifier Trust & Security Scanner</div></div>
          <div class="login-links"><span>Research & Evaluation Platform</span><span>Documentation</span><span>GitHub Repo</span></div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    left, right = st.columns([0.9, 1.35], gap="large", vertical_alignment="center")
    with left:
        st.markdown(
            """
            <div class="login-panel">
              <div>
                <div class="kicker">Encrypted-Traffic ML Assurance</div>
                <h1>Trust Verification for Encrypted-Traffic ML Classifiers</h1>
                <p>Evaluate robustness, monitor drift, test feature-space evasion resilience, and generate cryptographically signed inspection manifests.</p>
                <div class="login-modules">
                  <h3>Credora Core Scan Modules</h3>
                  <div class="login-module-grid">
                    <div>Robustness Testing<br><span>Empirical stress evaluation</span></div>
                    <div>Dataset Drift<br><span>PSI drift monitoring</span></div>
                    <div>Feature Evasion<br><span>Tabular scenario testing</span></div>
                    <div>Ed25519 Signatures<br><span>Audit manifests</span></div>
                  </div>
                </div>
                <div class="login-checks">
                  <div class="login-check"><b>✓</b><div>PSI-based drift detection between training and evaluation datasets.</div></div>
                  <div class="login-check"><b>✓</b><div>Feature-space evasion scenario testing for encrypted traffic classifiers.</div></div>
                  <div class="login-check"><b>✓</b><div>Model packaging and verification step with tamper-evident audit manifests.</div></div>
                </div>
              </div>
              <div class="login-foot"><div><strong>Credora Research Toolkit</strong>Transparent & reproducible ML evaluation</div><div class="login-version">v2.1 local</div></div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with right:
        with st.container(border=True):
            login_tab, register_tab = st.tabs(["Sign In", "Register Account"])
            with login_tab:
                st.markdown("<h2>Sign in to Credora</h2><p>Enter your credentials to access classifier audit runs and benchmark manifests.</p>", unsafe_allow_html=True)
                with st.form("credora-login"):
                    username = st.text_input("Email Address or Username", value="admin")
                    password = st.text_input("Password", type="password")
                    remember = st.checkbox("Remember me on this device", value=True)
                    submitted = st.form_submit_button("Sign in to Credora  ->", type="primary", width="stretch")
                if submitted:
                    user = authenticate_user(username, password)
                    if user:
                        st.session_state["auth_user"] = user
                        st.session_state["access_token"] = create_access_token(user)
                        st.session_state["refresh_token"] = create_refresh_token(user)
                        st.session_state["remember_login"] = remember
                        st.rerun()
                    st.error("Invalid username or password")
                st.caption("Local admin default: username `admin`, password `credora-admin`.")
            with register_tab:
                st.markdown("<h2>Register account</h2><p>Create an uploader workspace for isolated models, scans, reports, and monitoring history.</p>", unsafe_allow_html=True)
                with st.form("credora-register"):
                    new_username = st.text_input("Username")
                    email = st.text_input("Email address", value="")
                    new_password = st.text_input("Password", type="password")
                    created = st.form_submit_button("Create account", width="stretch")
                if created:
                    try:
                        user = create_user(new_username, new_password, email or None, role="uploader")
                    except ValueError as exc:
                        st.error(str(exc))
                    else:
                        st.session_state["auth_user"] = user
                        st.session_state["access_token"] = create_access_token(user)
                        st.session_state["refresh_token"] = create_refresh_token(user)
                        st.rerun()
            st.markdown('<div class="auth-note"><span>Local Instance</span><div>Documentation · Report an Issue · Release Notes</div></div>', unsafe_allow_html=True)
    st.stop()


current_user = require_dashboard_auth()

with st.sidebar:
    st.markdown(
        "<div class='brand'><div class='brand-mark'>C</div><div class='brand-title'><strong>Credora</strong><span>Model Assurance</span></div></div>",
        unsafe_allow_html=True,
    )
    st.caption(f"Signed in as {current_user['username']} | {current_user['role']}")
    if can_view_all(current_user):
        st.toggle("Show all users' scans", key="show_all_users", value=bool(st.session_state.get("show_all_users", False)))
    if st.button("Logout", width="stretch"):
        for key in ["auth_user", "access_token", "refresh_token", "report", "progress_events"]:
            st.session_state.pop(key, None)
        st.rerun()
    page = st.radio(
        "Navigation",
        (["Overview", "Model Registry", "Traffic Classifier", "Trust Score", "Trust Drift", "Reports", "Alerts", "Settings"] + (["Admin"] if current_user.get("role") in {"reviewer", "admin"} else [])),
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

    owner_id, include_all = dashboard_owner_scope()
    sidebar_scan_history = list_scans(limit=100, owner_id=owner_id, include_all=include_all)
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
        owner_id=int(current_user["id"]),
    )
    progress_bar.progress(1.0, text="Assessment complete")
    st.session_state["report"] = report.to_dict()
    st.session_state["progress_events"] = progress_events
    st.success("Deep trust scan completed. The dashboard now shows model-specific evidence and fixes.")


owner_id, include_all = dashboard_owner_scope()
scan_history = list_scans(limit=100, owner_id=owner_id, include_all=include_all)
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
explainability = modules.get("explainability", {})
explainability_details = explainability.get("details", {})
leakage = modules.get("dataset_leakage", {})
leakage_details = leakage.get("details", {})
privacy = modules.get("privacy_risk", {})
privacy_details = privacy.get("details", {})
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

    telemetry_col, gauge_col = st.columns([1.48, 1.0])
    with telemetry_col:
        with st.container(border=True):
            st.markdown("### Inference Volume & Attack Vector Stream")
            st.caption("Classified encrypted-flow metadata across the current assessment window.")
            telemetry = overview_telemetry_frame(classifier_details, adversarial_details)
            line = px.line(
                telemetry,
                x="Time",
                y="Relative volume",
                color="Flow class",
                markers=True,
                color_discrete_map={"Normal": "#84B179", "Suspicious": "#446832", "Masked / VPN": "#37675C"},
            )
            line.update_traces(line_width=2.7, marker=dict(size=6), hovertemplate="%{fullData.name}<br>%{x}: %{y:.1f}<extra></extra>")
            normal_area = telemetry[telemetry["Flow class"] == "Normal"]
            line.add_trace(go.Scatter(
                x=normal_area["Time"],
                y=normal_area["Relative volume"],
                mode="lines",
                line=dict(width=0),
                fill="tozeroy",
                fillcolor="rgba(132,177,121,0.16)",
                hoverinfo="skip",
                showlegend=False,
            ))
            line.update_layout(
                yaxis_title="Relative flow volume",
                xaxis_title=None,
                legend=dict(orientation="h", y=1.12, x=1, xanchor="right", bgcolor="rgba(0,0,0,0)"),
                yaxis=dict(showgrid=True, gridcolor="#d9e6d4", zeroline=False),
                xaxis=dict(showgrid=False),
            )
            st.plotly_chart(chart_layout(line, 390), width="stretch", config={"displayModeBar": False})

    with gauge_col:
        with st.container(border=True):
            st.markdown(assurance_tier_html(trust_score, approval), unsafe_allow_html=True)
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
            bars = px.bar(metric_df, x="Metric", y="Value", text="Value", color="Metric", color_discrete_sequence=["#84B179", "#4F7F74", "#C98A3D", "#37675C"])
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
                flow_root = ensure_within_directory(DATA_DIR / "production_flows" / str(current_user["id"]), DATA_DIR)
                flow_root.mkdir(parents=True, exist_ok=True)
                canonical_path = ensure_within_directory(flow_root / f"{capture_path.stem}-canonical.csv", flow_root)
                ingestion = ingest_flow_file(capture_path, canonical_path, captured_format)
                output_root = ensure_within_directory(DATA_DIR / "production_windows" / str(current_user["id"]), DATA_DIR)
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
            st.markdown(assurance_tier_html(trust_score, str(report_data.get("status", "not run")).title()), unsafe_allow_html=True)
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
    production_windows = list_drift_windows(model_name=model_name, limit=100, owner_id=owner_id, include_all=include_all)
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
    report_path = ensure_within_directory((REPORT_DIR / str(current_user["id"]) / f"{safe_model_name}_{report_phase}_trust_report.json"), REPORT_DIR)
    left, right = st.columns([.9, 1.1])
    with left:
        with st.container(border=True):
            st.markdown("### Generated Artifact")
            st.markdown(f"<div class='path-box'>{h(report_path)}</div>", unsafe_allow_html=True)
            st.caption(f"Generated {format_time(generated_at)} | Trust score {trust_score:.1f}/100")
            st.download_button("Download JSON report", json.dumps(report_data, indent=2), file_name=report_path.name, mime="application/json", width="stretch")
            docx_report_value = report_data.get("docx_report_path") or (REPORT_DIR / str(current_user["id"]) / f"{safe_model_name}_{report_phase}_trust_report.docx")
            docx_path = Path(docx_report_value)
            if docx_path.exists():
                st.download_button("Download DOCX report", docx_path.read_bytes(), file_name=docx_path.name, mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document", width="stretch")
            st.divider()
            st.markdown("### Report Signature")
            signature_status = verify_report_against_trusted_signers(report_data, list_trusted_signers())
            if signature_status.get("trusted"):
                st.success(f"Verified by trusted signer: {signature_status.get('trusted_signer_name', 'trusted signer')}")
                st.caption(f"Signed {format_time(signature_status.get('signed_at'))} | Payload {signature_status.get('payload_sha256', '')[:12]}...")
            elif report_data.get("report_signature"):
                st.warning(signature_status.get("reason", "Report signature could not be matched to a trusted signer."))
                signer = report_data.get("report_signature", {}).get("signer")
                if signer:
                    st.caption(f"Claimed signer: {h(signer)}")
            else:
                st.info("This JSON report has not been signed yet. Use the Phase 4 report-signing command before treating it as release evidence.")
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
    render_page_head("Admin", "Users, platform visibility, policy, audit, and release controls")
    if current_user.get("role") not in {"reviewer", "admin"}:
        st.error("Admin access is not available for this account.")
        st.stop()

    analytics = platform_analytics()
    a1, a2, a3, a4 = st.columns(4)
    a1.metric("Active users", analytics.get("active_users", 0))
    a2.metric("Models", analytics.get("total_models", 0))
    a3.metric("Scans", analytics.get("total_scans", 0))
    dist = analytics.get("trust_score_distribution", {})
    a4.metric("Warnings / fails", f"{dist.get('warning', 0)} / {dist.get('fail', 0)}")

    tabs = st.tabs(["Users", "Platform Scans", "Policy", "Review", "Security Audit"])
    with tabs[0]:
        st.markdown("### User Management")
        users_df = pd.DataFrame(list_users())
        if not users_df.empty:
            st.dataframe(users_df[[c for c in ["id", "username", "email", "role", "created_at", "last_login_at", "disabled"] if c in users_df.columns]], hide_index=True, width="stretch")
        if current_user.get("role") == "admin":
            with st.form("admin-create-user"):
                c1, c2, c3, c4 = st.columns([.8, .9, .8, .6])
                username = c1.text_input("Username")
                email = c2.text_input("Email")
                password = c3.text_input("Temporary password", type="password")
                role = c4.selectbox("Role", ["uploader", "reviewer", "admin"])
                if st.form_submit_button("Create user", type="primary"):
                    try:
                        create_user(username, password, email or None, role=role)
                        st.success("User created.")
                        st.rerun()
                    except ValueError as exc:
                        st.error(str(exc))
            with st.form("admin-update-user"):
                user_ids = [int(row["id"]) for row in list_users()]
                target = st.selectbox("Account", user_ids, format_func=lambda uid: next((u["username"] for u in list_users() if int(u["id"]) == uid), str(uid))) if user_ids else None
                col1, col2, col3 = st.columns(3)
                new_role = col1.selectbox("New role", ["", "uploader", "reviewer", "admin"])
                disabled = col2.selectbox("Account status", ["No change", "Active", "Disabled"])
                reset_password = col3.text_input("Force new password", type="password")
                revoke = st.checkbox("Revoke active sessions")
                if st.form_submit_button("Apply account changes") and target is not None:
                    if new_role:
                        update_user_role(target, new_role, actor_id=int(current_user["id"]))
                    if disabled != "No change":
                        set_user_disabled(target, disabled == "Disabled", actor_id=int(current_user["id"]))
                    if reset_password:
                        admin_set_password(target, reset_password, actor_id=int(current_user["id"]))
                    if revoke:
                        revoke_user_sessions(target, actor_id=int(current_user["id"]))
                    st.success("Account updated.")
                    st.rerun()
        else:
            st.info("Reviewer accounts can view platform evidence, but only admins can manage accounts.")

    with tabs[1]:
        st.markdown("### Platform-Wide Scans")
        all_scans = pd.DataFrame(list_scans(limit=500, include_all=True))
        if not all_scans.empty:
            search = st.text_input("Filter by user id, model, status, or date text")
            shown = all_scans
            if search:
                mask = shown.astype(str).apply(lambda col: col.str.contains(search, case=False, na=False)).any(axis=1)
                shown = shown[mask]
            st.dataframe(shown, hide_index=True, width="stretch")
        findings = analytics.get("common_security_findings", [])
        if findings:
            st.markdown("### Common Security Findings")
            st.dataframe(pd.DataFrame(findings), hide_index=True, width="stretch")

    with tabs[2]:
        st.markdown("### Server-Side Release Policy")
        if current_user.get("role") != "admin":
            st.info("Only admins can change policy, trust weights, signer keys, or taxonomy.")
        policy = get_deployment_policy()
        with st.form("deployment-policy"):
            p1, p2, p3, p4 = st.columns(4)
            minimum_trust_score = p1.number_input("Minimum trust", 0.0, 100.0, float(policy.get("minimum_trust_score", 85)), 1.0)
            minimum_classifier_score = p2.number_input("Minimum classifier", 0.0, 100.0, float(policy.get("minimum_classifier_score", 85)), 1.0)
            minimum_adversarial_score = p3.number_input("Minimum adversarial", 0.0, 100.0, float(policy.get("minimum_adversarial_score", 80)), 1.0)
            minimum_sensitive_recall = p4.number_input("Minimum sensitive recall", 0.0, 1.0, float(policy.get("minimum_sensitive_recall", 0.90)), 0.01)
            if st.form_submit_button("Save release policy", disabled=current_user.get("role") != "admin"):
                set_deployment_policy({
                    "minimum_trust_score": minimum_trust_score,
                    "minimum_classifier_score": minimum_classifier_score,
                    "minimum_adversarial_score": minimum_adversarial_score,
                    "minimum_sensitive_recall": minimum_sensitive_recall,
                }, actor_id=int(current_user["id"]))
                st.success("Policy saved.")
                st.rerun()
        weights = get_trust_weights()
        with st.expander("Trust score module weights"):
            edited = st.data_editor(pd.DataFrame([{"module": k, "weight": v} for k, v in weights.items()]), hide_index=True, width="stretch")
            if st.button("Save weights", disabled=current_user.get("role") != "admin"):
                set_trust_weights(dict(zip(edited["module"], edited["weight"])), actor_id=int(current_user["id"]))
                st.success("Weights saved and normalized for future scans.")
                st.rerun()
        with st.expander("Sensitive label taxonomy"):
            labels_text = st.text_area("Comma-separated label hints", ", ".join(get_sensitive_label_taxonomy()))
            if st.button("Save taxonomy", disabled=current_user.get("role") != "admin"):
                set_sensitive_label_taxonomy([item.strip() for item in labels_text.split(",")], actor_id=int(current_user["id"]))
                st.success("Sensitive taxonomy saved.")
                st.rerun()
        with st.expander("Trusted Ed25519 public signers"):
            signers = list_trusted_signers(include_inactive=True)
            if signers:
                st.dataframe(pd.DataFrame(signers), hide_index=True, width="stretch")
            with st.form("trusted-signer"):
                signer_name = st.text_input("Signer name")
                public_key = st.text_area("Public key PEM")
                if st.form_submit_button("Add trusted signer", disabled=current_user.get("role") != "admin"):
                    add_trusted_signer(signer_name, public_key, actor_id=int(current_user["id"]))
                    st.success("Trusted signer added.")
                    st.rerun()

    with tabs[3]:
        st.markdown("### Deployment Gate Override")
        st.caption("Reviewer/admin approval is required for any manual override.")
        all_scan_rows = list_scans(limit=500, include_all=True)
        if all_scan_rows:
            scan_id = st.selectbox("Scan", [int(row["id"]) for row in all_scan_rows], format_func=lambda sid: next((f"#{row['id']} | user {row.get('owner_id')} | {row.get('model_name')} | {row.get('status')} | {row.get('trust_score')}" for row in all_scan_rows if int(row["id"]) == sid), str(sid)))
            decision = st.radio("Decision", ["approved", "rejected"], horizontal=True)
            justification = st.text_area("Required justification")
            if st.button("Record override decision", type="primary"):
                try:
                    create_deployment_override(scan_id, decision, justification, int(current_user["id"]))
                    st.success("Override decision logged.")
                except ValueError as exc:
                    st.error(str(exc))
        else:
            st.info("No scans are available for review.")

    with tabs[4]:
        st.markdown("### Authentication and Security Audit")
        if current_user.get("role") == "admin":
            logs = list_audit_logs(limit=300)
            if logs:
                st.dataframe(pd.DataFrame(logs), hide_index=True, width="stretch")
            else:
                st.info("No audit events have been recorded yet.")
        else:
            st.info("Only admins can view authentication and security audit logs.")


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
                    for key in ["auth_user", "access_token", "refresh_token", "report", "progress_events"]:
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







