from __future__ import annotations

import base64
from pathlib import Path

import streamlit as st


def inject_credora_theme() -> None:
    hero_path = Path(__file__).resolve().parent / "assets" / "login-hero.png"
    hero_data = base64.b64encode(hero_path.read_bytes()).decode("ascii")
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

        .stApp:has(#credora-login-mode) header[data-testid="stHeader"],
        .stApp:has(#credora-login-mode) [data-testid="stSidebar"] {display: none;}
        .stApp:has(#credora-login-mode) [data-testid="stMainBlockContainer"] {max-width: none; padding: 0; margin: 0;}
        .stApp:has(#credora-login-mode) [data-testid="stMain"] {min-height: calc(100vh + 3.5rem); margin-top: -3.5rem;}
        .stApp:has(#credora-login-mode) [data-testid="stHorizontalBlock"] {gap: 0; align-items: stretch;}
        .stApp:has(#credora-login-mode) [data-testid="column"] {padding: 0;}
        #credora-login-mode {display: none;}
        .login-panel {
            position: relative;
            overflow: hidden;
            min-height: 100vh;
            margin: 0;
            border: 0;
            border-radius: 0;
            padding: clamp(60px, 8vh, 110px) clamp(46px, 7vw, 115px);
            box-shadow: none;
            background:
                radial-gradient(110% 38% at 18% 106%, #92282d 0 38%, transparent 39%),
                radial-gradient(120% 44% at 86% 101%, rgba(187,94,97,.91) 0 43%, transparent 44%),
                radial-gradient(112% 38% at 26% 87%, rgba(217,156,151,.76) 0 47%, transparent 48%),
                radial-gradient(70% 80% at 104% 8%, rgba(217,156,151,.72) 0 48%, transparent 49%),
                #fff1e7;
            color: var(--text);
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }
        .login-brand {display: flex; align-items: center; gap: 22px; margin-bottom: 74px;}
        .login-brand .credora-emblem {width: 64px; height: 64px; font-size: 2rem;}
        .login-wordmark {font-family: Manrope, Inter, sans-serif; font-size: clamp(2rem, 3vw, 3.1rem); letter-spacing: .22em; line-height: 1; color: #151111;}
        .login-wordmark span {display: block; margin-top: 13px; font-family: Inter, sans-serif; font-size: .72rem; letter-spacing: .42em; color: #403737;}
        .login-rule {width: 64px; height: 3px; background: #d47c77; margin-bottom: 34px;}
        .login-panel h1 {font-size: clamp(1.65rem, 2.2vw, 2.4rem); line-height: 1.28; color: #4e4746; max-width: 600px; font-weight: 500; margin: 0;}
        .login-feature-row {display: flex; gap: clamp(34px, 6vw, 90px); margin-top: 54px;}
        .login-feature {text-align: center; color: #2d2525; font-size: .72rem; font-weight: 700; text-transform: uppercase; letter-spacing: .18em; line-height: 1.45;}
        .login-feature-icon {width: 50px; height: 50px; margin: 0 auto 12px; display: grid; place-items: center; border-radius: 50%; background: rgba(255,255,255,.34); border: 1px solid rgba(162,52,56,.10); color: var(--primary); font-size: 1.15rem;}
        .login-signature {position: relative; z-index: 1; color: rgba(255,255,255,.88); font-size: .68rem; text-transform: uppercase; letter-spacing: .22em; line-height: 1.7;}

        .stApp:has(#credora-login-mode) [data-testid="column"]:last-child {display: flex; align-items: center; justify-content: center; min-height: 100vh; background: #fcfaf8; padding: 5vh 7vw;}
        .stApp:has(#credora-login-mode) [data-testid="stVerticalBlockBorderWrapper"] {
            width: min(620px, 100%);
            border: 1px solid var(--border) !important;
            border-radius: 8px !important;
            background: rgba(255,255,255,.82);
            padding: clamp(24px, 3.2vw, 48px);
            box-shadow: var(--shadow-strong);
        }
        #credora-auth-card {display: none;}
        .auth-heading h2 {font-size: clamp(2rem, 3vw, 2.8rem); margin: 6px 0 8px; color: #111;}
        .auth-heading p {font-size: 1rem; color: var(--muted); line-height: 1.55; margin: 0 0 18px;}
        .stApp:has(#credora-auth-card) [data-baseweb="tab-list"] {gap: 6px; margin-bottom: 18px;}
        .stApp:has(#credora-auth-card) [data-baseweb="tab"] {height: 40px; border-radius: 7px 7px 0 0; font-weight: 700;}
        .stApp:has(#credora-auth-card) .stTextInput input {min-height: 50px;}
        .stApp:has(#credora-auth-card) .stFormSubmitButton button {min-height: 52px; width: 100%; font-size: 1rem;}
        .secure-access {margin-top: 22px; padding-top: 18px; border-top: 1px solid var(--border); text-align: center; color: var(--muted); font-size: .78rem;}

        /* Exact translation of the supplied Tailwind login reference. */
        .stApp:has(#credora-login-mode) {background: #faf9f7;}
        .stApp:has(#credora-login-mode) [data-testid="stHorizontalBlock"] {min-height: 100vh;}
        .stApp:has(#credora-login-mode) [data-testid="stHorizontalBlock"] > div:nth-child(2) {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 48px clamp(28px, 4vw, 64px);
            box-sizing: border-box;
        }
        .stApp:has(#credora-login-mode) [data-testid="stHorizontalBlock"] > div:nth-child(2) > div {
            width: 100%;
            max-width: 460px;
            margin: auto;
        }
        .stApp:has(#credora-login-mode) [data-testid="column"]:first-child {width: 56% !important; flex: 0 0 56% !important;}
        .stApp:has(#credora-login-mode) [data-testid="column"]:last-child {
            width: 44% !important;
            flex: 0 0 44% !important;
            min-height: 100vh;
            padding: 48px clamp(28px, 4vw, 64px);
            background: #faf9f7;
        }
        .login-panel {
            min-height: 100vh;
            padding: 0;
            background-image: url("__LOGIN_HERO__");
            background-size: cover;
            background-position: left top;
            background-repeat: no-repeat;
        }
        .stApp:has(#credora-login-mode) [data-testid="stVerticalBlockBorderWrapper"] {
            width: min(460px, 100%) !important;
            max-width: 460px !important;
            flex: 0 0 auto !important;
            margin: auto !important;
            border: 1px solid rgba(245,245,244,.92) !important;
            border-radius: 24px !important;
            background: #ffffff;
            padding: clamp(28px, 3vw, 40px);
            box-shadow: 0 20px 40px -15px rgba(0,0,0,.05), 0 0 1px 1px rgba(0,0,0,.03);
        }
        .auth-heading {margin-bottom: 24px;}
        .auth-heading h2 {font-size: clamp(1.9rem, 2.4vw, 2.15rem); line-height: 1.2; color: #0f172a; margin: 0; font-weight: 700;}
        .auth-heading p {font-size: .91rem; line-height: 1.65; color: #64748b; margin: 10px 0 0;}
        .stApp:has(#credora-auth-card) [data-testid="stForm"] {border: 0; padding: 0;}
        .stApp:has(#credora-auth-card) .stTextInput {margin-bottom: 2px;}
        .stApp:has(#credora-auth-card) .stTextInput label p,
        .stApp:has(#credora-auth-card) .stCheckbox label p {font-size: .8rem; color: #334155; font-weight: 500;}
        .stApp:has(#credora-auth-card) .stTextInput input {
            min-height: 44px;
            border: 1px solid #e2e8f0 !important;
            border-radius: 8px !important;
            background: #fff !important;
            color: #0f172a;
            font-size: .875rem;
        }
        .stApp:has(#credora-auth-card) .stTextInput input:focus {border-color: #932d32 !important; box-shadow: 0 0 0 1px #932d32 !important;}
        .stApp:has(#credora-auth-card) .stCheckbox input:checked + div {background: #932d32 !important; border-color: #932d32 !important;}
        .stApp:has(#credora-auth-card) .stFormSubmitButton button {
            min-height: 48px;
            border-radius: 12px;
            background: #932d32;
            border-color: #932d32;
            font-size: .875rem;
            font-weight: 500;
        }
        .stApp:has(#credora-auth-card) .stFormSubmitButton button:hover {background: #7e252a; border-color: #7e252a;}
        .auth-secondary .stButton button,
        .stApp:has(#credora-auth-card) .stButton button {
            width: 100%;
            min-height: 48px;
            margin-top: 4px;
            border-radius: 12px;
            background: #fdf6f0;
            border: 1px solid #f5d5c8;
            color: #a84347;
            font-size: .875rem;
            font-weight: 500;
        }
        .stApp:has(#credora-auth-card) .stButton button:hover {background: #faeee5; color: #932d32; border-color: #f3cebe;}
        .auth-divider {display: flex; align-items: center; gap: 14px; margin: 26px 0; color: #94a3b8; font-size: .72rem; font-weight: 600;}
        .auth-divider::before, .auth-divider::after {content: ""; flex: 1; height: 1px; background: #e2e8f0;}
        .secure-access {margin: 0; padding: 0; border: 0; color: #64748b; font-size: .78rem;}
        .secure-access::before {content: "✓"; display: inline-grid; place-items: center; width: 17px; height: 17px; margin-right: 8px; border: 1px solid #94a3b8; border-radius: 50%; color: #64748b; font-size: .62rem;}

        @media (max-width: 1100px) {
            .readiness {grid-template-columns: 1fr;}
            .readiness-checks {border-left: 0; border-top: 1px solid rgba(162,52,56,.18); padding: 18px 0 0; grid-template-columns: 1fr 1fr;}
            .metric-grid {grid-template-columns: repeat(2,minmax(0,1fr));}
            .workspace-search {width: min(330px, 48vw);}
        }
        @media (max-width: 820px) {
            .stApp:has(#credora-login-mode) [data-testid="stHorizontalBlock"] {display: block;}
            .stApp:has(#credora-login-mode) [data-testid="column"]:first-child,
            .stApp:has(#credora-login-mode) [data-testid="column"]:last-child {width: 100% !important; flex: 0 0 100% !important;}
            .login-panel {min-height: 52vw; max-height: 390px; padding: 0; background-size: cover; background-position: left top;}
            .login-brand {margin-bottom: 42px;}
            .login-feature-row {margin-top: 36px; gap: 24px;}
            .stApp:has(#credora-login-mode) [data-testid="column"]:last-child {min-height: 54vh; padding: 36px 20px;}
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
            .login-feature-row {justify-content: space-between; gap: 10px;}
            .login-wordmark {font-size: 1.8rem;}
        }
            """,
        ).replace("__LOGIN_HERO__", f"data:image/png;base64,{hero_data}"),
        unsafe_allow_html=True,
    )
