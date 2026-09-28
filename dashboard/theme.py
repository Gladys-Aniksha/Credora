from __future__ import annotations

import base64
from pathlib import Path

import streamlit as st


def inject_credora_theme() -> None:
    assets_dir = Path(__file__).resolve().parent / "assets"

    def asset_data_uri(path: Path, mime_type: str) -> str:
        encoded = base64.b64encode(path.read_bytes()).decode("ascii")
        return f"data:{mime_type};base64,{encoded}"

    asset_uris = {
        "__LOGIN_HERO__": asset_data_uri(assets_dir / "login-hero.png", "image/png"),
        "__INTER_300__": asset_data_uri(assets_dir / "fonts" / "inter-300.ttf", "font/ttf"),
        "__INTER_400__": asset_data_uri(assets_dir / "fonts" / "inter-400.ttf", "font/ttf"),
        "__INTER_500__": asset_data_uri(assets_dir / "fonts" / "inter-500.ttf", "font/ttf"),
        "__INTER_600__": asset_data_uri(assets_dir / "fonts" / "inter-600.ttf", "font/ttf"),
        "__INTER_700__": asset_data_uri(assets_dir / "fonts" / "inter-700.ttf", "font/ttf"),
    }
    css = """
        <style>
        __CREDORA_THEME__
        </style>
    """
    st.markdown(
        css.replace(
            "__CREDORA_THEME__",
            """
        :root {
            --background: #fbf8f5;
            --canvas: #fffdfb;
            --surface: #fffdfb;
            --surface-low: #fbe3d0;
            --surface-container: #f8eee8;
            --surface-high: #f3c9af;
            --text: #201a1a;
            --muted: #716867;
            --muted-strong: #514847;
            --border: #eadbd4;
            --border-strong: #d9c1b8;
            --primary: #a23438;
            --primary-soft: #bb5e61;
            --primary-fixed: #f3c9af;
            --primary-fixed-dim: #d99c97;
            --secondary: #7c3f42;
            --secondary-soft: #fbe3d0;
            --tertiary: #2f7252;
            --sidebar: #f8e9df;
            --sidebar-panel: #fff8f3;
            --sidebar-soft: #f3d6c5;
            --sidebar-text: #2a2020;
            --sidebar-muted: #716867;
            --warning: #c67836;
            --high: #bb5e61;
            --critical: #a23438;
            --neutral: #8b817f;
            --shadow: 0 4px 18px rgba(89, 52, 48, .07);
            --shadow-strong: 0 18px 48px rgba(89, 52, 48, .13);
        }

        html, body, [class*="css"] {font-family: Inter, Arial, sans-serif;}
        .stApp {
            background:
                radial-gradient(circle at 83% 8%, rgba(243,201,175,.18), transparent 24rem),
                #fbf8f5;
            color: var(--text);
        }
        header[data-testid="stHeader"] {
            background: rgba(255,253,251,.90);
            backdrop-filter: blur(18px);
            border-bottom: 1px solid var(--border);
        }
        [data-testid="stMainBlockContainer"] {max-width: 1700px; padding: 1.35rem 2rem 2.8rem;}
        h1, h2, h3, h4 {color: var(--text);}
        a {color: var(--primary);}

        [data-testid="stSidebar"] {
            background:
                radial-gradient(180% 13% at 12% 100%, rgba(162,52,56,.22) 0 38%, transparent 39%),
                radial-gradient(170% 14% at 92% 99%, rgba(187,94,97,.30) 0 42%, transparent 43%),
                radial-gradient(150% 12% at 32% 94%, rgba(217,156,151,.48) 0 44%, transparent 45%),
                #f8e9df;
            border-right: 1px solid #ead5ca;
            min-width: 280px;
            max-width: 280px;
            box-shadow: 5px 0 24px rgba(89,52,48,.05);
        }
        [data-testid="stSidebar"] nav,
        [data-testid="stSidebarNav"],
        [data-testid="stSidebarNavItems"] {display: none !important;}
        [data-testid="stAppDeployButton"] {display: none !important;}
        [data-testid="stSidebar"] > div {padding-top: 0;}
        [data-testid="stSidebar"] .stMarkdown,
        [data-testid="stSidebar"] label,
        [data-testid="stSidebar"] p,
        [data-testid="stSidebar"] span {color: var(--sidebar-text);}
        [data-testid="stSidebar"] [data-testid="stCaptionContainer"] p {color: var(--sidebar-muted) !important;}
        [data-testid="stSidebar"] [data-testid="stRadio"] > label {display: none;}
        [data-testid="stSidebar"] [role="radiogroup"] {gap: 5px;}
        [data-testid="stSidebar"] label[data-testid="stRadioOption"] {
            min-height: 40px;
            padding: 0 14px;
            border-radius: 7px;
            color: var(--sidebar-text) !important;
            background: transparent;
            font-weight: 600;
            border: 1px solid transparent;
        }
        [data-testid="stSidebar"] label[data-testid="stRadioOption"]:hover {
            background: rgba(255,255,255,.50);
            border-color: rgba(162,52,56,.10);
        }
        [data-testid="stSidebar"] label[data-testid="stRadioOption"][data-selected="true"] {
            background: rgba(217,156,151,.28);
            border-color: rgba(162,52,56,.10);
            color: var(--primary) !important;
        }
        [data-testid="stSidebar"] label[data-testid="stRadioOption"] > div > div > div:first-child {display: none;}
        [data-testid="stSidebar"] [data-testid="stExpander"] {
            background: rgba(255,253,251,.72);
            border: 1px solid rgba(162,52,56,.13);
            border-radius: 8px;
            margin: 16px 5px 0;
            box-shadow: 0 8px 24px rgba(89,52,48,.06);
        }
        [data-testid="stSidebar"] [data-testid="stExpander"] details > summary,
        [data-testid="stSidebar"] [data-testid="stExpanderDetails"] {
            background: transparent !important;
            color: var(--sidebar-text) !important;
        }
        [data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] {
            background: #fffaf7 !important;
            border: 1px dashed rgba(162,52,56,.35) !important;
            border-radius: 8px !important;
        }
        [data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] button {
            background: var(--surface-low) !important;
            color: var(--primary) !important;
            border: 1px solid var(--primary-fixed-dim) !important;
            border-radius: 7px !important;
        }
        [data-testid="stSidebar"] .stButton button {
            background: #fffaf7;
            color: var(--primary);
            border: 1px solid rgba(162,52,56,.26);
            border-radius: 7px;
            box-shadow: none;
        }
        [data-testid="stSidebar"] .stButton button:hover {background: var(--primary); color: #fff; border-color: var(--primary);}
        [data-testid="stSidebarCollapsedControl"], [data-testid="stExpandSidebarButton"] {
            background: var(--primary) !important;
            color: #fff !important;
            border: 0 !important;
            border-radius: 7px !important;
        }

        .brand {
            min-height: 98px;
            padding: 0 16px;
            margin: 0 -1rem 10px;
            border-bottom: 1px solid rgba(162,52,56,.12);
            gap: 13px;
        }
        .brand-mark, .credora-emblem {
            width: 42px;
            height: 42px;
            display: grid;
            place-items: center;
            border-radius: 6px;
            background: var(--primary);
            color: #fff;
            font-family: Manrope, Inter, sans-serif;
            font-size: 1.28rem;
            font-weight: 800;
            box-shadow: inset -9px -7px 0 rgba(217,156,151,.46);
        }
        .brand-title strong {font-size: 1.12rem; color: var(--text); letter-spacing: .12em;}
        .brand-title span {color: var(--primary); font-size: .61rem; letter-spacing: .22em;}
        .sidebar-user {
            margin: 0 4px 10px;
            padding: 10px 12px;
            border: 1px solid rgba(162,52,56,.12);
            background: rgba(255,253,251,.56);
            border-radius: 7px;
            font-size: .78rem;
            color: var(--muted);
        }
        .sidebar-user strong {display: block; color: var(--text); font-size: .86rem; margin-bottom: 2px;}

        .workspace-bar {
            display: flex;
            justify-content: flex-end;
            align-items: center;
            gap: 20px;
            min-height: 44px;
            padding: 0 0 14px;
            margin-bottom: 2px;
            border-bottom: 1px solid var(--border);
        }
        .workspace-search {
            width: min(390px, 44vw);
            height: 39px;
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 0 15px;
            border: 1px solid var(--border-strong);
            border-radius: 999px;
            color: var(--muted);
            background: rgba(255,253,251,.82);
            font-size: .8rem;
        }
        .workspace-search::before {content: "⌕"; color: var(--muted-strong); font-size: 1.15rem;}
        .workspace-user {display: flex; align-items: center; gap: 10px; color: var(--muted); font-size: .75rem;}
        .workspace-avatar {display: grid; place-items: center; width: 38px; height: 38px; border-radius: 50%; background: #f0d7cb; color: var(--text); font-weight: 700;}
        .workspace-user strong {display: block; color: var(--text); font-size: .8rem;}

        .page-head {margin: 14px 0 18px;}
        .page-head h1 {font-size: 1.82rem; color: var(--text);}
        .page-head p {color: var(--muted); font-size: .92rem;}

        .readiness {
            position: relative;
            overflow: hidden;
            grid-template-columns: 1.3fr .95fr;
            gap: 30px;
            background:
                radial-gradient(90% 140% at 94% 135%, rgba(162,52,56,.72) 0 31%, transparent 32%),
                radial-gradient(84% 125% at 86% 104%, rgba(217,156,151,.55) 0 41%, transparent 42%),
                linear-gradient(104deg, #fff4ec 0%, #fbe3d0 58%, #f3c9af 100%);
            border: 1px solid #efd8cc;
            border-radius: 8px;
            box-shadow: var(--shadow);
            padding: 24px 30px;
            margin-bottom: 16px;
        }
        .readiness::after {content: ""; position: absolute; inset: auto 0 0 52%; height: 1px; background: rgba(255,255,255,.55); transform: rotate(-8deg);}
        .readiness-main {grid-template-columns: 1fr auto; gap: 20px;}
        .readiness h2 {font-size: 1.8rem; color: var(--text); margin-bottom: 7px;}
        .readiness p {color: var(--muted-strong); max-width: 620px;}
        .eyebrow {color: var(--muted-strong); letter-spacing: .18em;}
        .approval-badge {background: var(--primary); border-color: var(--primary); color: #fff; border-radius: 6px;}
        .evaluated {margin-top: 26px; color: var(--muted-strong);}
        .readiness-checks {position: relative; z-index: 1; border-left: 1px solid rgba(162,52,56,.25); padding-left: 28px; display: grid; align-content: center; gap: 10px;}
        .readiness-check {display: flex; align-items: center; gap: 10px; color: #463b3a; font-size: .84rem;}
        .readiness-check b {display: grid; place-items: center; width: 20px; height: 20px; border-radius: 50%; background: #2f8158; color: #fff; font-size: .7rem;}

        .metric-grid {gap: 14px;}
        .metric-card, [data-testid="stMetric"], [data-testid="stVerticalBlockBorderWrapper"] {
            background: rgba(255,253,251,.94);
            border-color: var(--border) !important;
            border-radius: 8px !important;
            box-shadow: var(--shadow);
        }
        .metric-card {padding: 17px 18px; min-height: 144px;}
        .metric-card:hover {border-color: var(--primary-fixed-dim); box-shadow: 0 8px 24px rgba(89,52,48,.10);}
        .metric-title {color: #4f4544; letter-spacing: .11em; font-size: .74rem;}
        .metric-icon {background: #fbe7dc; color: var(--primary); border-radius: 50%;}
        .metric-icon.good {background: #e7f1e9; color: #2f7252;}
        .metric-icon.warn {background: #fbeddc; color: var(--warning);}
        .metric-value {font-family: Inter, sans-serif; color: var(--text); font-size: 1.72rem;}
        .metric-value.teal {color: #2f7252;}
        .metric-value.orange {color: var(--warning);}
        .metric-note.good {color: #2f7252;}
        .tier-ring {float: right; width: 60px; height: 60px; border-radius: 50%; display: grid; place-items: center; margin-top: -8px; background: conic-gradient(var(--primary) 0 68%, #d99c97 68% 86%, #f3c9af 86% 96%, #fbe3d0 96%);}
        .tier-ring::after {content: attr(data-tier); width: 38px; height: 38px; display: grid; place-items: center; border-radius: 50%; background: #fffdfb; color: var(--text); font-weight: 800;}

        [data-testid="stMetric"] {padding: 15px 17px;}
        [data-testid="stMetricLabel"] p {color: var(--muted) !important;}
        [data-testid="stMetricValue"] {color: var(--text);}
        [data-testid="stDataFrame"] {border: 1px solid var(--border); border-radius: 7px; overflow: hidden;}
        [data-testid="stTable"] {border: 1px solid var(--border); border-radius: 7px; overflow: hidden;}
        [data-baseweb="tab-list"] {border-bottom-color: var(--border) !important;}
        [data-baseweb="tab"][aria-selected="true"] {color: var(--primary) !important; border-bottom-color: var(--primary) !important;}
        [data-testid="stExpander"] {border-color: var(--border) !important; border-radius: 7px !important; background: rgba(255,253,251,.8);}

        .stButton button, .stDownloadButton button {border-radius: 7px; border-color: var(--primary-soft); color: var(--primary);}
        .stButton button:hover, .stDownloadButton button:hover {border-color: var(--primary); color: var(--primary); background: #fff4ee;}
        .stButton button[kind="primary"], .stFormSubmitButton button[kind="primary"] {background: var(--primary); border-color: var(--primary); color: #fff;}
        .stButton button[kind="primary"]:hover, .stFormSubmitButton button[kind="primary"]:hover {background: #84272b; border-color: #84272b; color: #fff;}
        input, textarea, [data-baseweb="select"] > div {border-radius: 7px !important; border-color: var(--border-strong) !important; background: #fffdfb !important;}
        input:focus, textarea:focus {border-color: var(--primary-soft) !important; box-shadow: 0 0 0 1px var(--primary-soft) !important;}
        [data-testid="stToggle"] input:checked + div {background: var(--primary) !important;}
        [data-testid="stProgressBar"] > div > div {background: var(--primary) !important;}
        .status-pill {border-radius: 999px;}
        .finding {background: #fff8f3; border-color: var(--border); border-left-color: var(--primary);}
        .finding.critical, .finding.high {background: #fff1ef;}
        .finding.medium, .alert-box {background: #fff8ed;}
        .finding.low {background: #f1f7f3;}
        .path-box {background: #fff8f3; border-color: var(--border);}

        .assurance-gauge .gauge-track {stroke: #f4e5dc;}
        .assurance-gauge .gauge-critical {stroke: #a23438;}
        .assurance-gauge .gauge-warning {stroke: #bb5e61;}
        .assurance-gauge .gauge-review {stroke: #d99c97;}
        .assurance-gauge .gauge-trusted {stroke: #2f8158;}
        .assurance-gauge .gauge-needle, .assurance-gauge .gauge-hub {stroke: var(--primary); fill: var(--primary);}
        .assurance-tier {color: var(--primary);}
        .assurance-bars div::after {background: #f3e4dc;}
        .assurance-bars i {background: var(--primary);}

        /* Pixel-matched translation of the supplied landscape login reference. */
        @font-face {font-family: "Inter"; src: url("__INTER_300__") format("truetype"); font-style: normal; font-weight: 300; font-display: swap;}
        @font-face {font-family: "Inter"; src: url("__INTER_400__") format("truetype"); font-style: normal; font-weight: 400; font-display: swap;}
        @font-face {font-family: "Inter"; src: url("__INTER_500__") format("truetype"); font-style: normal; font-weight: 500; font-display: swap;}
        @font-face {font-family: "Inter"; src: url("__INTER_600__") format("truetype"); font-style: normal; font-weight: 600; font-display: swap;}
        @font-face {font-family: "Inter"; src: url("__INTER_700__") format("truetype"); font-style: normal; font-weight: 700; font-display: swap;}
        .stApp:has(#credora-login-mode) {font-family: Inter, Arial, sans-serif;}
        .stApp:has(#credora-login-mode) *,
        .stApp:has(#credora-login-mode) *::before,
        .stApp:has(#credora-login-mode) *::after {box-sizing: border-box;}
        .stApp:has(#credora-login-mode) {
            width: 100vw;
            height: 100vh;
            min-width: 960px;
            min-height: 600px;
            overflow: hidden;
            background: #faf9f7;
        }
        .stApp:has(#credora-login-mode) header[data-testid="stHeader"],
        .stApp:has(#credora-login-mode) [data-testid="stSidebar"] {display: none;}
        .stApp:has(#credora-login-mode) [data-testid="stMain"] {
            min-height: calc(100vh + 3.5rem);
            margin-top: -3.5rem;
            overflow: hidden;
        }
        .stApp:has(#credora-login-mode) [data-testid="stMainBlockContainer"] {
            width: 100vw;
            max-width: none;
            height: 100vh;
            padding: 0;
            margin: 0;
        }
        #credora-login-mode, #credora-auth-card {display: none;}
        .stApp:has(#credora-login-mode) [data-testid="stHorizontalBlock"] {
            min-height: 100vh;
            gap: 0;
            align-items: stretch;
        }
        .stApp:has(#credora-login-mode) [data-testid="stForm"] [data-testid="stHorizontalBlock"] {
            min-height: auto;
            align-items: center;
            gap: .5rem;
        }
        .stApp:has(#credora-login-mode) [data-testid="column"] {padding: 0;}
        .stApp:has(#credora-login-mode) [data-testid="column"]:first-child {
            width: 56% !important;
            flex: 0 0 56% !important;
        }
        .stApp:has(#credora-login-mode) [data-testid="column"]:last-child {
            display: flex;
            width: 44% !important;
            flex: 0 0 44% !important;
            min-height: 100vh;
            align-items: center;
            justify-content: center;
            padding: 48px clamp(28px, 4vw, 64px);
            background: #faf9f7;
        }
        .stApp:has(#credora-login-mode) [data-testid="stForm"] [data-testid="column"] {
            display: block;
            width: 50% !important;
            min-height: auto;
            flex: 1 1 50% !important;
            padding: 0;
            background: transparent;
        }
        .login-panel {
            width: 100%;
            height: 100vh;
            min-height: 600px;
            margin: 0;
            padding: 0;
            border: 0;
            border-radius: 0;
            box-shadow: none;
            background-image: url("__LOGIN_HERO__");
            background-size: 100vw 100vh;
            background-position: left top;
            background-repeat: no-repeat;
        }
        .stApp:has(#credora-login-mode) [data-testid="stHorizontalBlock"] > div:nth-child(2) > div {
            width: 100%;
            max-width: 460px;
            margin: auto;
        }
        .stApp:has(#credora-login-mode) [data-testid="stVerticalBlock"]:has(> [data-testid="stElementContainer"]:first-child #credora-auth-card) {
            width: min(460px, 100%) !important;
            max-width: 460px !important;
            flex: 0 0 auto !important;
            margin: auto !important;
            padding: 40px !important;
            transform: translateY(20px);
            border: 1px solid rgba(245,245,244,.92) !important;
            border-radius: 24px !important;
            background: #fff;
            box-shadow: 0 20px 40px -15px rgba(0,0,0,.05), 0 0 1px 1px rgba(0,0,0,.03);
        }
        .auth-heading {margin: 0 0 24px;}
        .auth-heading h2 {
            margin: 0;
            color: #0f172a;
            font-size: 34px;
            font-weight: 700;
            line-height: 1.25;
            letter-spacing: 0;
            padding: 0 !important;
        }
        .auth-heading p {
            margin: 10px 0 0;
            color: #64748b;
            font-size: 14.5px;
            font-weight: 400;
            line-height: 1.65;
        }
        .stApp:has(#credora-auth-card) [data-testid="stForm"] {padding: 0; border: 0;}
        .stApp:has(#credora-auth-card) [data-testid="stForm"] > div {gap: 12px;}
        .stApp:has(#credora-auth-card) .stTextInput {margin: 0;}
        .stApp:has(#credora-auth-card) .stTextInput label p,
        .stApp:has(#credora-auth-card) .stCheckbox label p {
            color: #334155;
            font-size: 13px;
            font-weight: 500;
        }
        .stApp:has(#credora-auth-card) .stTextInput input {
            min-height: 44px;
            padding-top: 10px;
            padding-bottom: 10px;
            border: 1px solid #e2e8f0 !important;
            border-radius: 8px !important;
            background: #fff !important;
            color: #0f172a;
            font-size: 14px;
        }
        .stApp:has(#credora-auth-card) .stTextInput input[aria-label="Email"],
        .stApp:has(#credora-auth-card) .stTextInput input[aria-label="Email address"] {
            padding-left: 40px !important;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2394a3b8' stroke-width='1.75'%3E%3Cpath d='M21.75 6.75v10.5a2.25 2.25 0 0 1-2.25 2.25h-15a2.25 2.25 0 0 1-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0 0 19.5 4.5h-15a2.25 2.25 0 0 0-2.25 2.25m19.5 0v.243a2.25 2.25 0 0 1-1.07 1.916l-7.5 4.615a2.25 2.25 0 0 1-2.36 0L3.32 8.91a2.25 2.25 0 0 1-1.07-1.916V6.75' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E") !important;
            background-position: 13px center !important;
            background-repeat: no-repeat !important;
            background-size: 16px 16px !important;
        }
        .stApp:has(#credora-auth-card) .stTextInput input[aria-label="Username"] {
            padding-left: 40px !important;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2394a3b8' stroke-width='1.75'%3E%3Cpath d='M15.75 6a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0ZM4.5 20.1a7.5 7.5 0 0 1 15 0A17.9 17.9 0 0 1 12 21.75 17.9 17.9 0 0 1 4.5 20.1Z' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E") !important;
            background-position: 13px center !important;
            background-repeat: no-repeat !important;
            background-size: 16px 16px !important;
        }
        .stApp:has(#credora-auth-card) .stTextInput input[aria-label="Password"] {
            padding-left: 40px !important;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2394a3b8' stroke-width='1.75'%3E%3Cpath d='M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E") !important;
            background-position: 13px center !important;
            background-repeat: no-repeat !important;
            background-size: 16px 16px !important;
        }
        .stApp:has(#credora-auth-card) button[aria-label="Show password"],
        .stApp:has(#credora-auth-card) button[aria-label="Hide password"] {
            width: 40px;
            min-width: 40px;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2364748b' stroke-width='1.75'%3E%3Cpath d='M3.98 8.223A10.477 10.477 0 0 0 1.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0 1 12 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 0 1-4.293 5.774M6.228 6.228 3 3m3.228 3.228 3.65 3.65m7.894 7.894L21 21m-3.228-3.228-3.65-3.65m0 0a3 3 0 1 0-4.243-4.243m4.242 4.242L9.88 9.88' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E") !important;
            background-position: center !important;
            background-repeat: no-repeat !important;
            background-size: 16px 16px !important;
        }
        .stApp:has(#credora-auth-card) [data-testid="stIconMaterial"],
        .stApp:has(#credora-auth-card) .material-symbols-rounded,
        .stApp:has(#credora-auth-card) .material-symbols-outlined,
        .stApp:has(#credora-auth-card) [class*="material-symbols"] {
            display: none !important;
            width: 0 !important;
            min-width: 0 !important;
            margin: 0 !important;
            overflow: hidden !important;
        }
        .stApp:has(#credora-auth-card) button p {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            width: 100%;
            margin: 0;
            white-space: nowrap;
        }
        .stApp:has(#credora-auth-card) .stTextInput input:focus {
            border-color: #932d32 !important;
            box-shadow: 0 0 0 1px #932d32 !important;
        }
        .stApp:has(#credora-auth-card) .stCheckbox input:checked + div {
            border-color: #932d32 !important;
            background: #932d32 !important;
        }
        .stApp:has(#credora-auth-card) .stFormSubmitButton button[kind="primary"] {
            width: 100%;
            min-height: 48px;
            border: 1px solid #932d32;
            border-radius: 12px;
            background: #932d32;
            color: #fff;
            font-size: 14px;
            font-weight: 500;
        }
        .stApp:has(#credora-auth-card) .stFormSubmitButton button[kind="primary"]:hover {
            border-color: #7e252a;
            background: #7e252a;
        }
        .stApp:has(#credora-auth-card) .stFormSubmitButton button[kind="tertiary"] {
            min-height: auto;
            padding: 0;
            justify-content: flex-end;
            border: 0;
            background: transparent;
            color: #932d32;
            font-size: 13px;
            font-weight: 400;
        }
        .stApp:has(#credora-auth-card) .stFormSubmitButton button[kind="tertiary"]:hover {
            background: transparent;
            color: #7e252a;
        }
        .stApp:has(#credora-auth-card) .stButton button {
            width: 100%;
            min-height: 48px;
            margin-top: 12px;
            border: 1px solid #f5d5c8;
            border-radius: 12px;
            background: #fdf6f0;
            color: #a84347;
            font-size: 14px;
            font-weight: 500;
        }
        .stApp:has(#credora-auth-card) .stButton button:hover {
            border-color: #f3cebe;
            background: #faeee5;
            color: #932d32;
        }
        .auth-divider {
            display: flex;
            align-items: center;
            gap: 14px;
            margin: 24px 0;
            color: #94a3b8;
            font-size: 12px;
            font-weight: 500;
        }
        .auth-divider::before, .auth-divider::after {
            content: "";
            height: 1px;
            flex: 1;
            background: #e2e8f0;
        }
        .secure-access {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            margin: 0;
            padding: 0;
            border: 0;
            color: #64748b;
            font-size: 12.5px;
            font-weight: 400;
            text-align: center;
        }
        .secure-access svg {width: 16px; height: 16px; flex: 0 0 16px; color: #94a3b8;}

        @media (max-width: 1100px) {
            .readiness {grid-template-columns: 1fr;}
            .readiness-checks {border-left: 0; border-top: 1px solid rgba(162,52,56,.18); padding: 18px 0 0; grid-template-columns: 1fr 1fr;}
            .metric-grid {grid-template-columns: repeat(2,minmax(0,1fr));}
            .workspace-search {width: min(330px, 48vw);}
        }
        @media (max-width: 820px) {
            .workspace-bar {justify-content: space-between;}
            .workspace-search {display: none;}
        }
        @media (max-width: 720px) {
            [data-testid="stMainBlockContainer"] {padding: 1rem .85rem 2rem;}
            .metric-grid {grid-template-columns: 1fr;}
            .readiness {padding: 20px;}
            .readiness-main {grid-template-columns: 1fr;}
            .approval {text-align: left;}
            .readiness-checks {grid-template-columns: 1fr;}
        }
            """,
        )
        .replace("__LOGIN_HERO__", asset_uris["__LOGIN_HERO__"])
        .replace("__INTER_300__", asset_uris["__INTER_300__"])
        .replace("__INTER_400__", asset_uris["__INTER_400__"])
        .replace("__INTER_500__", asset_uris["__INTER_500__"])
        .replace("__INTER_600__", asset_uris["__INTER_600__"])
        .replace("__INTER_700__", asset_uris["__INTER_700__"]),
        unsafe_allow_html=True,
    )
