from __future__ import annotations

import base64
from pathlib import Path
from xml.etree import ElementTree

import streamlit as st


ASSETS_DIR = Path(__file__).resolve().parent / "assets"


def _asset_data_uri(path: Path, mime_type: str) -> str:
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{mime_type};base64,{encoded}"


def credora_brand_html() -> str:
    namespace = "http://www.w3.org/2000/svg"
    ElementTree.register_namespace("", namespace)
    logo = ElementTree.parse(ASSETS_DIR / "credora-header-logo.svg").getroot()
    for word in logo.findall(f"{{{namespace}}}text"):
        logo.remove(word)
    # Reuse the original glyphs, masking out the pink raster background.
    artwork = _asset_data_uri(ASSETS_DIR / "login-hero.png", "image/png")
    lettering = ElementTree.fromstring(f'''<svg xmlns="{namespace}" x="56" y="11" width="174" height="48" viewBox="200 185 310 85">
      <defs><filter id="login-wordmark-ink" color-interpolation-filters="sRGB">
        <feColorMatrix type="saturate" values="0"/>
        <feComponentTransfer><feFuncR type="linear" slope="-5" intercept="3.5"/><feFuncG type="linear" slope="-5" intercept="3.5"/><feFuncB type="linear" slope="-5" intercept="3.5"/></feComponentTransfer>
      </filter><mask id="login-wordmark-mask" maskUnits="userSpaceOnUse" x="200" y="185" width="310" height="85" style="mask-type:luminance">
        <image href="{artwork}" width="1672" height="941" filter="url(#login-wordmark-ink)"/>
      </mask></defs><rect x="200" y="185" width="310" height="85" fill="#111722" mask="url(#login-wordmark-mask)"/>
    </svg>''')
    logo.append(lettering)
    encoded = base64.b64encode(ElementTree.tostring(logo, encoding="utf-8")).decode("ascii")
    logo_uri = f"data:image/svg+xml;base64,{encoded}"
    return (
        "<div class='credora-brand'>"
        f"<img class='credora-brand-logo' src='{logo_uri}' alt='CREDORA Model Assurance'>"
        "</div>"
    )


def inject_credora_theme() -> None:
    asset_uris = {
        "__LOGIN_HERO__": _asset_data_uri(ASSETS_DIR / "login-hero.png", "image/png"),
        "__INTER_300__": _asset_data_uri(ASSETS_DIR / "fonts" / "inter-300.ttf", "font/ttf"),
        "__INTER_400__": _asset_data_uri(ASSETS_DIR / "fonts" / "inter-400.ttf", "font/ttf"),
        "__INTER_500__": _asset_data_uri(ASSETS_DIR / "fonts" / "inter-500.ttf", "font/ttf"),
        "__INTER_600__": _asset_data_uri(ASSETS_DIR / "fonts" / "inter-600.ttf", "font/ttf"),
        "__INTER_700__": _asset_data_uri(ASSETS_DIR / "fonts" / "inter-700.ttf", "font/ttf"),
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

        .stApp [data-testid="stSidebar"] .brand,
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] .brand {
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

        /* Model Trust Overview: desktop composition matched to the supplied reference. */
        .stApp:has(#credora-overview-mode) {
            background: #fffdfb;
        }
        .stApp:has(#credora-overview-mode) header[data-testid="stHeader"] {display: none;}
        .stApp:has(#credora-overview-mode) [data-testid="stMain"] {margin-top: 0;}
        .stApp:has(#credora-overview-mode) [data-testid="stMainBlockContainer"] {
            width: 100%;
            max-width: none;
            padding: 24px 22px 18px 26px;
        }
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] {
            position: relative;
            min-width: 260px;
            max-width: 260px;
            background: #fff3ed;
            border-right: 1px solid #eee0d9;
            box-shadow: none;
            overflow: hidden;
        }
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] > div {position: relative; z-index: 1;}
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] [data-testid="stSidebarContent"] {padding: 0 10px;}
        .stApp:has(#credora-overview-mode) .sidebar-user,
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] [data-testid="stToggle"],
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] [data-testid="stElementContainer"]:has([role="switch"]),
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] [data-testid="stButton"],
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] [data-testid="stExpander"],
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] [data-testid="stSelectbox"],
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] [data-testid="stCaptionContainer"] {display: none !important;}
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] [role="radiogroup"] {gap: 3px;}
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"] {
            position: relative;
            min-height: 47px;
            padding: 0 14px 0 52px;
            border: 0;
            border-radius: 9px;
            color: #4d4746 !important;
            font-size: .92rem;
            font-weight: 500;
        }
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"]::before {
            content: "";
            position: absolute;
            left: 18px;
            top: 50%;
            width: 21px;
            height: 21px;
            transform: translateY(-50%);
            background-position: center;
            background-repeat: no-repeat;
            background-size: contain;
            opacity: .9;
        }
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(1)::before {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23a23438' stroke-width='1.8'%3E%3Crect x='3' y='3' width='7' height='7' rx='1'/%3E%3Crect x='14' y='3' width='7' height='7' rx='1'/%3E%3Crect x='3' y='14' width='7' height='7' rx='1'/%3E%3Crect x='14' y='14' width='7' height='7' rx='1'/%3E%3C/svg%3E");}
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(2)::before {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23554d4b' stroke-width='1.8'%3E%3Cellipse cx='12' cy='5' rx='7' ry='3'/%3E%3Cpath d='M5 5v6c0 1.7 3.1 3 7 3s7-1.3 7-3V5M5 11v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6'/%3E%3C/svg%3E");}
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(3)::before {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23554d4b' stroke-width='1.8'%3E%3Ccircle cx='12' cy='5' r='2'/%3E%3Ccircle cx='5' cy='18' r='2'/%3E%3Ccircle cx='19' cy='18' r='2'/%3E%3Cpath d='M12 7v5M5 16v-3h14v3'/%3E%3C/svg%3E");}
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(4)::before {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23554d4b' stroke-width='1.8'%3E%3Cpath d='M12 3 5 6v5c0 4.7 2.9 8.1 7 10 4.1-1.9 7-5.3 7-10V6l-7-3Z'/%3E%3Cpath d='m9 12 2 2 4-4'/%3E%3C/svg%3E");}
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(5)::before {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23554d4b' stroke-width='1.8'%3E%3Cpath d='M3 20V10m0 10h18M6 15l4-4 3 3 6-7'/%3E%3C/svg%3E");}
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(6)::before {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23554d4b' stroke-width='1.8'%3E%3Cpath d='M6 3h9l4 4v14H6z'/%3E%3Cpath d='M14 3v5h5M9 13h7M9 17h7'/%3E%3C/svg%3E");}
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(7)::before {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23554d4b' stroke-width='1.8'%3E%3Cpath d='M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4'/%3E%3C/svg%3E");}
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(8)::before {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23554d4b' stroke-width='1.8'%3E%3Ccircle cx='12' cy='12' r='3'/%3E%3Cpath d='M19 12a7 7 0 0 0-.1-1l2-1.5-2-3.5-2.5 1A7 7 0 0 0 15 6l-.4-2.7h-4L10 6a7 7 0 0 0-1.4.9l-2.5-1-2 3.5 2 1.6a7 7 0 0 0 0 2l-2 1.5 2 3.5 2.5-1A7 7 0 0 0 10 18l.5 2.7h4L15 18a7 7 0 0 0 1.4-.9l2.5 1 2-3.5-2-1.6c.1-.3.1-.7.1-1Z'/%3E%3C/svg%3E");}
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(9)::before {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23554d4b' stroke-width='1.8'%3E%3Ccircle cx='9' cy='8' r='3'/%3E%3Ccircle cx='17' cy='9' r='2.5'/%3E%3Cpath d='M3 20c0-4 2.5-6 6-6s6 2 6 6M14 15c3.5-.3 6 1.4 6 5'/%3E%3C/svg%3E");}
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"][data-selected="true"] {
            background: #f3d8cf;
            color: #1a1818 !important;
        }
        #credora-overview-mode {display: none;}
        .stApp:has(#credora-overview-mode) *,
        .stApp:has(#credora-overview-mode) *::before,
        .stApp:has(#credora-overview-mode) *::after {box-sizing: border-box;}
        .overview-header {display:flex; align-items:center; justify-content:space-between; gap:28px; margin:0 0 20px;}
        .overview-heading {min-width:0; flex:1 1 auto;}
        .overview-heading h1 {margin:0; color:#101114; font-size:2rem; line-height:1.12; font-weight:700; letter-spacing:0;}
        .overview-heading p {margin:6px 0 0; color:#68707a; font-size:.95rem;}
        .overview-tools {display:flex; align-items:center; gap:18px;}
        .overview-search {width:350px; height:42px; display:flex; align-items:center; gap:11px; padding:0 16px; border:1px solid #ddd7d3; border-radius:24px; color:#80858b; background:#fff; font-size:.77rem;}
        .ui-icon {width:20px; height:20px; fill:none; stroke:currentColor; stroke-linecap:round; stroke-linejoin:round;}
        .overview-bell {position:relative; display:grid; place-items:center; width:44px; height:38px; color:#373435; border-left:1px solid #e9e1dc; border-right:1px solid #e9e1dc;}
        .overview-bell i {position:absolute; right:6px; top:1px; min-width:8px; height:8px; padding:0; overflow:hidden; border-radius:50%; background:#ad3438; color:transparent;}
        .overview-profile {display:flex; align-items:center; gap:10px; min-width:165px; color:#101114;}
        .overview-profile > span {display:grid; place-items:center; width:38px; height:38px; border-radius:50%; background:#f2ded5; font-size:.78rem;}
        .overview-profile strong,.overview-profile small {display:block;}
        .overview-profile strong {font-size:.79rem;}.overview-profile small{margin-top:2px;color:#68707a;font-size:.67rem}.overview-profile b{margin-left:auto;font-weight:400}
        .overview-readiness {position:relative; overflow:hidden; display:grid; grid-template-columns:1.3fr 1.05fr .62fr; align-items:center; min-height:158px; padding:24px 30px; margin-bottom:16px; border:1px solid #efddd5; border-radius:11px; background:linear-gradient(104deg,#fff1e9 0%,#f8ded3 60%,#e5a19d 100%); box-shadow:0 4px 14px rgba(70,40,25,.035);}
        .overview-readiness::after {content:"";position:absolute;right:-30px;bottom:-92px;width:520px;height:210px;border-radius:50% 45% 0 0;background:rgba(173,52,56,.18);transform:rotate(-11deg);pointer-events:none}.overview-readiness::before{content:"";position:absolute;right:70px;bottom:-136px;width:430px;height:230px;border-radius:50%;background:rgba(255,235,226,.38);z-index:1}
        .readiness-copy,.overview-checks,.overview-primary-link{position:relative;z-index:2}.readiness-copy{padding-right:28px;border-right:1px solid rgba(173,52,56,.32)}
        .overview-eyebrow{text-transform:uppercase;letter-spacing:.2em;color:#545052;font-size:.68rem;font-weight:600}.readiness-copy h2{margin:8px 0 7px;color:#101114;font-size:2rem;line-height:1.08}.readiness-copy p{margin:0;max-width:510px;color:#5f5d60;font-size:.92rem;line-height:1.45}
        .overview-checks{display:grid;gap:9px;padding-left:34px}.overview-checks .readiness-check{display:flex;align-items:center;gap:10px;color:#484446;font-size:.78rem}.overview-checks .readiness-check b{display:grid;place-items:center;width:18px;height:18px;border-radius:50%;background:#238656;color:#fff;font-size:.65rem}.overview-checks .readiness-check.bad b{background:#b83336}.overview-primary-link{justify-self:end;display:flex;align-items:center;justify-content:center;gap:16px;width:100%;max-width:260px;height:48px;border-radius:8px;background:#ad3438;color:#fff!important;text-decoration:none!important;font-size:.82rem;font-weight:600;box-shadow:0 8px 18px rgba(146,40,45,.18)}
        .stApp:has(#credora-overview-mode) [data-testid="stElementContainer"]:has(#overview-report-action) + [data-testid="stElementContainer"]{position:relative;z-index:4;width:188px;margin:-111px 30px 63px auto}.stApp:has(#credora-overview-mode) [data-testid="stElementContainer"]:has(#overview-report-action) + [data-testid="stElementContainer"] button{width:188px;height:48px;border:0;border-radius:8px;background:#ad3438;color:#fff;font-size:.76rem;font-weight:600;box-shadow:0 8px 18px rgba(146,40,45,.18)}
        .overview-metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:14px}.overview-metric{position:relative;overflow:hidden;min-height:172px;padding:17px 18px 0;border:1px solid #eee6e1;border-radius:11px;background:#fff;box-shadow:0 5px 18px rgba(70,40,25,.035)}
        .metric-label{display:flex;justify-content:space-between;align-items:center;color:#3f4650;font-size:.68rem;font-weight:600;letter-spacing:.17em;text-transform:uppercase}.metric-label span{color:#7f858b}.metric-label .ui-icon{width:17px;height:17px}
        .metric-core{display:flex;align-items:center;gap:16px;margin-top:13px}.metric-round{display:grid;place-items:center;flex:0 0 auto;width:58px;height:58px;border-radius:50%}.metric-round .ui-icon{width:29px;height:29px}.metric-round.red{color:#ad3438;background:#fbe8df}.metric-round.green{color:#238656;background:#e8f2e8}.metric-core strong{display:block;color:#101114;font-size:1.65rem;line-height:1.05}.metric-core strong small{margin-left:5px;color:#68707a;font-size:.72rem;font-weight:500}.metric-core p{margin:8px 0 0;color:#68707a;font-size:.7rem;line-height:1.4}.metric-spark{position:absolute;left:18px;right:18px;bottom:0;width:calc(100% - 36px);height:47px}
        .tier-card{padding-bottom:14px}.tier-content{display:grid;grid-template-columns:112px 1fr;align-items:center;gap:12px;margin-top:12px}.overview-tier-ring{width:104px;height:104px;display:grid;place-items:center;border-radius:50%;background:conic-gradient(#ad3438 0 var(--tier-score),#e8a6a0 var(--tier-score) 86%,#f1c5b5 86% 96%,#f9e4d7 96%)}.overview-tier-ring::before{content:"";grid-area:1/1;width:66px;height:66px;border-radius:50%;background:#fff}.overview-tier-ring span{grid-area:1/1;z-index:1;text-align:center}.overview-tier-ring b,.overview-tier-ring small{display:block;text-transform:uppercase}.overview-tier-ring b{font-size:1.45rem}.overview-tier-ring small{font-size:.6rem;letter-spacing:.08em}.tier-legend p{display:flex;align-items:center;gap:8px;margin:0 0 7px;color:#667080;font-size:.66rem;white-space:nowrap}.tier-legend p i{width:9px;height:9px;border-radius:50%;background:#f1c5b5}.tier-legend p.active i{background:#ad3438}.tier-legend strong{color:#ad3438;font-size:.63rem}
        .stApp:has(#credora-overview-mode) [data-testid="stHorizontalBlock"]{gap:14px}.stApp:has(#credora-overview-mode) [data-testid="stVerticalBlockBorderWrapper"]{border:1px solid #eee6e1!important;border-radius:11px!important;background:#fff!important;box-shadow:0 5px 18px rgba(70,40,25,.035)!important}.stApp:has(#credora-overview-mode) [data-testid="stVerticalBlockBorderWrapper"]:has(#overview-drift-card){height:255px;padding:13px 16px 8px!important;margin-bottom:14px}.stApp:has(#credora-overview-mode) [data-testid="stVerticalBlockBorderWrapper"]:has(#overview-drift-card) [data-testid="stPlotlyChart"]{margin-top:-7px}
        .overview-card-head{display:flex;align-items:center;justify-content:space-between;gap:16px}.overview-card-head h3{margin:0;color:#171719;font-size:1rem;line-height:1.2}.overview-card-head a{display:flex;align-items:center;gap:10px;padding:7px 12px;border:1px solid #d99c97;border-radius:8px;color:#a23438!important;text-decoration:none!important;font-size:.68rem}.chart-head>span{padding:7px 11px;border:1px solid #ded8d4;border-radius:8px;color:#3f4650;font-size:.68rem}.chart-legend{display:flex;justify-content:center;gap:34px;margin-top:-17px;color:#68707a;font-size:.62rem}.chart-legend span:first-child{color:#ad3438}
        .model-summary-card{height:255px;padding:16px 18px;border:1px solid #eee6e1;border-radius:11px;background:#fff;box-shadow:0 5px 18px rgba(70,40,25,.035)}.model-summary-grid{display:grid;grid-template-columns:1fr 1fr;margin-top:10px}.summary-item{display:grid;grid-template-columns:28px 1fr;align-items:center;min-height:61px;padding:8px 12px;border-top:1px solid #f1e9e5}.summary-item:nth-child(-n+2){border-top:0}.summary-item:nth-child(odd){border-right:1px solid #f1e9e5}.summary-item.no-icon{grid-template-columns:1fr}.summary-item .ui-icon{width:18px;height:18px;color:#4e575d}.summary-item small,.summary-item strong{display:block}.summary-item small{margin-bottom:3px;color:#81858b;font-size:.65rem}.summary-item strong{color:#263044;font-size:.73rem;font-weight:600}.version-tag{display:inline-block!important;width:max-content;padding:5px 8px;border-radius:6px;background:#fbeae4;color:#ad5a58!important}.summary-status{display:flex!important;align-items:center;gap:6px}.summary-status i{width:8px;height:8px;border-radius:50%;background:#238656}.summary-status.review i{background:#c88927}.summary-status.failed i{background:#b83336}
        .overview-table-card{height:198px;margin-top:0;padding:14px 16px;border:1px solid #eee6e1;border-radius:11px;background:#fff;box-shadow:0 5px 18px rgba(70,40,25,.035);overflow:hidden}.overview-table-card .overview-card-head{margin-bottom:10px}.overview-table-card .overview-card-head a{padding:0;border:0}.overview-table-head,.overview-table-row{display:grid;grid-template-columns:1.18fr .68fr 1.12fr .72fr .92fr .9fr 16px;align-items:center;gap:8px}.overview-table-head{padding:0 2px 7px;color:#777b82;font-size:.53rem;font-weight:600;letter-spacing:.14em;text-transform:uppercase}.overview-table-row{min-height:32px;padding:5px 2px;border-top:1px solid #f2ebe7;color:#59616e;font-size:.62rem}.overview-table-row strong{overflow:hidden;color:#20242c;font-size:.66rem;text-overflow:ellipsis;white-space:nowrap}.overview-table-row>b,.alert-table-row>b{font-size:.9rem;font-weight:500}.status-chip,.severity-chip{display:inline-flex;align-items:center;gap:5px;width:max-content;padding:4px 7px;border-radius:999px;font-size:.56rem;font-style:normal}.status-chip.passed{background:#e7f3e8;color:#237a48}.status-chip.review{background:#faedd9;color:#b8751a}.status-chip.failed{background:#f7e1e1;color:#a62e31}
        .alert-table-head,.alert-table-row{display:grid;grid-template-columns:.72fr 1.8fr .9fr 15px;align-items:center;gap:8px}.alert-table-head{padding:0 2px 7px;color:#777b82;font-size:.53rem;font-weight:600;letter-spacing:.14em;text-transform:uppercase}.alert-table-row{min-height:32px;padding:5px 2px;border-top:1px solid #f2ebe7;color:#59616e;font-size:.59rem}.alert-table-row strong{overflow:hidden;color:#3e4650;font-size:.61rem;font-weight:500;text-overflow:ellipsis;white-space:nowrap}.severity-chip.critical{background:#f7e1e1;color:#a62e31}.severity-chip.high{background:#fae6dc;color:#b95835}.severity-chip.medium{background:#faedd9;color:#b8751a}.severity-chip.low,.severity-chip.info{background:#e4eef8;color:#3977c5}.overview-empty{padding:28px 8px;color:#81858b;font-size:.72rem;text-align:center}
        .stApp:has(#credora-overview-mode) [data-testid="stVerticalBlock"]:has(#overview-model-action),.stApp:has(#credora-overview-mode) [data-testid="stVerticalBlock"]:has(#overview-assessments-action),.stApp:has(#credora-overview-mode) [data-testid="stVerticalBlock"]:has(#overview-alerts-action){position:relative}.stApp:has(#credora-overview-mode) [data-testid="stElementContainer"]:has(#overview-model-action) + [data-testid="stElementContainer"],.stApp:has(#credora-overview-mode) [data-testid="stElementContainer"]:has(#overview-assessments-action) + [data-testid="stElementContainer"],.stApp:has(#credora-overview-mode) [data-testid="stElementContainer"]:has(#overview-alerts-action) + [data-testid="stElementContainer"]{position:absolute;z-index:3;right:18px;top:15px;width:auto}.stApp:has(#credora-overview-mode) [data-testid="stElementContainer"]:has(#overview-model-action) + [data-testid="stElementContainer"] button,.stApp:has(#credora-overview-mode) [data-testid="stElementContainer"]:has(#overview-assessments-action) + [data-testid="stElementContainer"] button,.stApp:has(#credora-overview-mode) [data-testid="stElementContainer"]:has(#overview-alerts-action) + [data-testid="stElementContainer"] button{min-height:32px;padding:0 12px;border:1px solid #d99c97;border-radius:8px;background:#fff;color:#a23438;font-size:.64rem;box-shadow:none}
        @media(max-height:800px){.stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"]{min-height:42px}}
        @media(max-width:1250px){.overview-search{width:270px}.overview-readiness{grid-template-columns:1.2fr 1fr}.overview-primary-link{display:none}.overview-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.overview-metric{min-height:170px}}
        @media(max-width:1100px){.overview-tools{display:none}.overview-header{align-items:flex-start}}
        @media(max-width:900px){.stApp:has(#credora-overview-mode) [data-testid="stSidebar"]{min-width:230px;max-width:230px}.overview-header{align-items:flex-start}.overview-tools{display:none}.overview-readiness{grid-template-columns:1fr}.readiness-copy{border-right:0}.overview-checks{padding:18px 0 0}.stApp:has(#credora-overview-mode) [data-testid="stHorizontalBlock"]{flex-wrap:wrap}.stApp:has(#credora-overview-mode) [data-testid="column"]{min-width:100%!important}.model-summary-card{margin-bottom:14px}.overview-table-card{height:auto;min-height:198px}}

        /* Shared application chrome sourced from the exact login artwork. */
        .stApp [data-testid="stSidebar"],
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] {
            width: 255px !important;
            min-width: 255px !important;
            max-width: 255px !important;
            height: 100vh;
            flex: 0 0 255px !important;
            overflow: hidden;
            background: #fff4ee;
            border-right: 1px solid #eaded8;
        }
        .stApp [data-testid="stSidebar"] [data-testid="stSidebarContent"],
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] [data-testid="stSidebarContent"] {
            width: 255px !important;
            min-width: 255px !important;
            max-width: 255px !important;
            height: 100vh;
            padding: 0 20px !important;
            box-sizing: border-box;
        }
        .stApp [data-testid="stSidebar"] > div {position: relative; z-index: 1;}
        .sidebar-wave-container {
            position: fixed;
            z-index: 0;
            left: 0;
            bottom: 0;
            width: 255px;
            height: clamp(185px, 24vh, 240px);
            overflow: hidden;
            pointer-events: none;
        }
        .sidebar-waves {display: block; width: 100%; height: 100%;}
        .sidebar-waves .wave-back {fill: #E9BBB0;}
        .sidebar-waves .wave-mid {fill: #D67572;}
        .sidebar-waves .wave-front {fill: #AE3439;}
        .sidebar-waves .wave-deep {fill: #982B30;}
        .sidebar-footer-copy {
            display: block !important;
            position: fixed;
            z-index: 3;
            left: 30px;
            bottom: 42px;
            color: rgba(255,255,255,.78);
            font-size: 10px;
            font-weight: 500;
            line-height: 1.8;
            letter-spacing: .28em;
            pointer-events: none;
        }
        .credora-brand {
            display: block;
            width: 205px;
            min-height: 60px;
            padding: 0;
            margin: -49px 0 34px -5px;
            border: 0;
            background: transparent;
            overflow: visible;
        }
        .stApp [data-testid="stSidebar"] .credora-brand-logo,
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] .credora-brand-logo {
            display: block;
            width: 100%;
            max-width: 205px;
            height: auto;
            object-fit: contain;
            overflow: visible;
        }
        .stApp [data-testid="stSidebar"] [role="radiogroup"],
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] [role="radiogroup"] {width:100%;gap:4px;padding:0!important;}
        .stApp [data-testid="stSidebar"] .st-key-dashboard_page,
        .stApp [data-testid="stSidebar"] .st-key-dashboard_page [data-testid="stRadio"],
        .stApp [data-testid="stSidebar"] .st-key-dashboard_page [role="radiogroup"],
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] .st-key-dashboard_page,
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] .st-key-dashboard_page [data-testid="stRadio"],
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] .st-key-dashboard_page [role="radiogroup"] {
            width: 100% !important;
            max-width: none !important;
        }
        .stApp [data-testid="stSidebar"] label[data-testid="stRadioOption"],
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"] {
            position: relative;
            display: flex;
            align-items: center;
            width: 100% !important;
            min-height: 46px;
            margin: 0 0 4px !important;
            padding: 0 14px 0 48px !important;
            border: 1px solid transparent !important;
            border-radius: 10px !important;
            box-sizing: border-box;
            color: #282421 !important;
            font-family: Inter, Arial, sans-serif;
            font-size: 15px;
            font-weight: 450;
        }
        .stApp [data-testid="stSidebar"] label[data-testid="stRadioOption"]::before,
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"]::before {
            content: "";
            position: absolute;
            left: 14px;
            top: 50%;
            width: 20px;
            height: 20px;
            background-repeat: no-repeat;
            background-position: center;
            background-size: contain;
            transform: translateY(-50%);
        }
        .stApp [data-testid="stSidebar"] label[data-testid="stRadioOption"][data-selected="true"],
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"][data-selected="true"] {
            width: 100% !important;
            background: #f4d9d1 !important;
            border-color: transparent !important;
            color: #24201e !important;
            font-weight: 500;
        }
        .stApp [data-testid="stSidebar"] label[data-testid="stRadioOption"][data-selected="true"]::before,
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"][data-selected="true"]::before {
            filter: sepia(1) saturate(5) hue-rotate(305deg) brightness(.72);
        }
        .stApp [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(9)::after,
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(9)::after {
            position: absolute;
            right: 13px;
            top: 50%;
            display: grid;
            place-items: center;
            min-width: 20px;
            height: 20px;
            padding: 0 5px;
            transform: translateY(-50%);
            border-radius: 999px;
            background: #b84d4c;
            color: #fff;
            font-size: 11px;
            font-weight: 600;
            line-height: 1;
        }
        .stApp [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(10),
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(10) {margin-top:22px!important;}
        .stApp [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(10)::after,
        .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(10)::after {
            content:"";
            position:absolute;
            left:10px;
            right:10px;
            top:-12px;
            height:1px;
            background:#e8dcd5;
        }
        [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(1)::before {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23a23438' stroke-width='1.8'%3E%3Crect x='3' y='3' width='7' height='7' rx='1'/%3E%3Crect x='14' y='3' width='7' height='7' rx='1'/%3E%3Crect x='3' y='14' width='7' height='7' rx='1'/%3E%3Crect x='14' y='14' width='7' height='7' rx='1'/%3E%3C/svg%3E")!important;}
        [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(2)::before {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23554d4b' stroke-width='1.8'%3E%3Cellipse cx='12' cy='5' rx='7' ry='3'/%3E%3Cpath d='M5 5v6c0 1.7 3.1 3 7 3s7-1.3 7-3V5M5 11v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6'/%3E%3C/svg%3E")!important;}
        [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(3)::before {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23554d4b' stroke-width='1.8'%3E%3Cpath d='M12 3v12m0 0 4-4m-4 4-4-4'/%3E%3Cpath d='M5 15v4h14v-4'/%3E%3C/svg%3E")!important;}
        [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(4)::before {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23554d4b' stroke-width='1.8'%3E%3Ccircle cx='12' cy='5' r='2'/%3E%3Ccircle cx='5' cy='18' r='2'/%3E%3Ccircle cx='19' cy='18' r='2'/%3E%3Cpath d='M12 7v5M5 16v-3h14v3'/%3E%3C/svg%3E")!important;}
        [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(5)::before {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23554d4b' stroke-width='1.8'%3E%3Cpath d='M12 3 5 6v5c0 4.7 2.9 8.1 7 10 4.1-1.9 7-5.3 7-10V6l-7-3Z'/%3E%3Cpath d='m9 12 2 2 4-4'/%3E%3C/svg%3E")!important;}
        [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(6)::before {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23554d4b' stroke-width='1.8'%3E%3Cpath d='M12 3 4 7v5c0 5 3.4 8.1 8 9.5 4.6-1.4 8-4.5 8-9.5V7l-8-4Z'/%3E%3Cpath d='M8 12h8M12 8v8'/%3E%3C/svg%3E")!important;}
        [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(7)::before {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23554d4b' stroke-width='1.8'%3E%3Cpath d='M3 20V10m0 10h18M6 15l4-4 3 3 6-7'/%3E%3C/svg%3E")!important;}
        [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(8)::before {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23554d4b' stroke-width='1.8'%3E%3Cpath d='M6 3h9l4 4v14H6z'/%3E%3Cpath d='M14 3v5h5M9 13h7M9 17h7'/%3E%3C/svg%3E")!important;}
        [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(9)::before {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23554d4b' stroke-width='1.8'%3E%3Cpath d='M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4'/%3E%3C/svg%3E")!important;}
        [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(10)::before {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23554d4b' stroke-width='1.8'%3E%3Ccircle cx='12' cy='12' r='3'/%3E%3Cpath d='M19 12a7 7 0 0 0-.1-1l2-1.5-2-3.5-2.5 1A7 7 0 0 0 15 6l-.4-2.7h-4L10 6a7 7 0 0 0-1.4.9l-2.5-1-2 3.5 2 1.6a7 7 0 0 0 0 2l-2 1.5 2 3.5 2.5-1A7 7 0 0 0 10 18l.5 2.7h4L15 18a7 7 0 0 0 1.4-.9l2.5 1 2-3.5-2-1.6c.1-.3.1-.7.1-1Z'/%3E%3C/svg%3E")!important;}
        [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(11)::before {background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23554d4b' stroke-width='1.8'%3E%3Ccircle cx='9' cy='8' r='3'/%3E%3Ccircle cx='17' cy='9' r='2.5'/%3E%3Cpath d='M3 20c0-4 2.5-6 6-6s6 2 6 6M14 15c3.5-.3 6 1.4 6 5'/%3E%3C/svg%3E")!important;}

        .threat-posture {margin:16px 0 26px;padding:18px 20px;border:1px solid #eadbd4;border-left:5px solid #526d7a;border-radius:8px;background:#fffdfb;}
        .threat-posture span {display:block;color:#746a67;font-size:.75rem;text-transform:uppercase;letter-spacing:.12em;}
        .threat-posture strong {display:block;margin-top:4px;color:#201a1a;font-size:1.35rem;}
        .threat-posture p {margin:7px 0 0;color:#665e5c;font-size:.85rem;}
        .threat-posture.critical,.threat-posture.high {border-left-color:#a23438;}
        .threat-posture.medium {border-left-color:#c67836;}
        .threat-posture.low {border-left-color:#2f8158;}

        .st-key-dashboard_topbar {min-height:64px;margin:0 0 18px;padding:6px 0 4px;}
        .st-key-dashboard_topbar > div,
        .st-key-dashboard_topbar [data-testid="stHorizontalBlock"] {min-height:54px;align-items:center;}
        .st-key-dashboard_search {width:350px;max-width:100%;}
        .st-key-dashboard_search [data-testid="stTextInputRootElement"] {
            position:relative;
            height:44px;border:1px solid #d8c9c2;border-radius:999px;background:#fffdfc;
            box-shadow:none;overflow:hidden;
        }
        .st-key-dashboard_search [data-testid="stTextInputRootElement"]::before {
            content:"";position:absolute;z-index:2;left:16px;top:50%;width:16px;height:16px;
            transform:translateY(-50%);pointer-events:none;
            background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%238A7E79' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='11' cy='11' r='7'/%3E%3Cpath d='m16 16 5 5'/%3E%3C/svg%3E");
            background-repeat:no-repeat;background-position:center;background-size:16px 16px;
        }
        .st-key-dashboard_search [data-testid="stTextInputRootElement"]:focus-within {border-color:#b85a5d;box-shadow:0 0 0 1px rgba(184,90,93,.12);}
        .st-key-dashboard_search [data-testid="stTextInput"] input {
            width:100%;height:42px;padding:0 16px 0 42px;border:0!important;border-radius:999px;
            outline:0;color:#5f5a57;font-size:14px;box-shadow:none!important;
            background-color:transparent;
        }
        .st-key-dashboard_topbar button {min-height: 42px; border-radius: 22px; box-shadow: none;}
        .st-key-dashboard_topbar [data-testid="stPopover"] button {
            justify-content: flex-start;
            border: 0;
            background: transparent;
            color: #202124;
            font-size: .72rem;
            font-weight: 600;
        }
        .profile-menu-head {padding: 5px 2px 12px; border-bottom: 1px solid #eee5df;}
        .profile-menu-head strong,.profile-menu-head span {display:block;}
        .profile-menu-head strong {color:#201a1a;font-size:.9rem}.profile-menu-head span{margin-top:3px;color:#716867;font-size:.72rem}
        .st-key-global_search_results {margin: -9px 0 18px; border-color: #eadbd4 !important; background: #fffdfb; box-shadow: var(--shadow);}
        .st-key-global_search_results button {justify-content:flex-start; min-height:38px; border:0; background:#fff; color:#514847; text-align:left; box-shadow:none;}
        .st-key-global_search_results button:hover {background:#fff1eb;color:#a23438;}
        .st-key-overview_upload_action {display:flex;justify-content:flex-end;margin:-8px 0 10px;}
        .st-key-overview_upload_action button {min-height:40px;border:0;border-radius:8px;background:#ad3438;color:#fff;font-weight:600;box-shadow:0 8px 18px rgba(146,40,45,.16)}
        @media(max-height:800px){
            .credora-brand{width:205px;min-height:60px;margin:-49px 0 34px -5px;background:transparent}
            .stApp [data-testid="stSidebar"] .credora-brand-logo,
            .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] .credora-brand-logo{width:100%;max-width:205px}
            .stApp [data-testid="stSidebar"] label[data-testid="stRadioOption"],
            .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"]{min-height:34px;margin-bottom:0!important;font-size:13px}
            .stApp [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(9),
            .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(9){margin-top:14px!important}
            .stApp [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(10)::after,
            .stApp:has(#credora-overview-mode) [data-testid="stSidebar"] label[data-testid="stRadioOption"]:nth-child(10)::after{top:-8px}
            .sidebar-wave-container{height:185px}
            .sidebar-footer-copy{bottom:24px;font-size:8.5px;line-height:1.65}
        }
        @media(max-width:1100px){.st-key-dashboard_topbar [data-testid="column"]:nth-child(1){display:none}.st-key-dashboard_topbar [data-testid="column"]:nth-child(2){min-width:58%!important}.st-key-dashboard_topbar [data-testid="column"]:nth-child(3){min-width:38%!important}}

        /* Balanced authentication layout shared by sign-in and registration. */
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
            min-height: 100vh;
            overflow-x: hidden;
            background: #faf9f7;
        }
        .stApp:has(#credora-login-mode) header[data-testid="stHeader"],
        .stApp:has(#credora-login-mode) [data-testid="stSidebar"] {display: none;}
        .stApp:has(#credora-login-mode) [data-testid="stMain"] {
            min-height: 100vh;
            margin-top: 0;
            overflow-y: auto;
        }
        .stApp:has(#credora-login-mode) [data-testid="stMainBlockContainer"] {
            width: 100vw;
            max-width: none;
            min-height: 100vh;
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
        .stApp:has(#credora-login-mode) [data-testid="stColumn"] {padding: 0;}
        .stApp:has(#credora-login-mode) [data-testid="stColumn"]:first-child {
            width: 50% !important;
            flex: 0 0 50% !important;
        }
        .stApp:has(#credora-login-mode) [data-testid="stColumn"]:last-child {
            display: flex;
            width: 50% !important;
            flex: 0 0 50% !important;
            min-height: 100vh;
            align-items: center;
            justify-content: center;
            padding: 40px clamp(24px, 3vw, 52px);
            background: #faf9f7;
        }
        .stApp:has(#credora-login-mode) [data-testid="stForm"] [data-testid="stColumn"] {
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
            background-size: 176.4% 100%;
            background-position: left top;
            background-repeat: no-repeat;
        }
        .stApp:has(#credora-login-mode) [data-testid="stHorizontalBlock"] > div:nth-child(2) > div {
            width: 100%;
            max-width: 640px;
            margin: auto;
        }
        .stApp:has(#credora-login-mode) [data-testid="stVerticalBlock"]:has(> [data-testid="stElementContainer"]:first-child #credora-auth-card) {
            width: min(640px, 100%) !important;
            max-width: 640px !important;
            flex: 0 0 auto !important;
            margin: auto !important;
            padding: 44px !important;
            border: 1px solid rgba(245,245,244,.92) !important;
            border-radius: 8px !important;
            background: #fff;
            box-shadow: 0 20px 40px -15px rgba(0,0,0,.05), 0 0 1px 1px rgba(0,0,0,.03);
        }
        .auth-heading {margin: 0 0 24px;}
        .stApp:has(#credora-login-mode) [data-testid="stElementContainer"]:has(style),
        .stApp:has(#credora-login-mode) [data-testid="stElementContainer"]:has(#credora-login-mode),
        .stApp:has(#credora-login-mode) [data-testid="stElementContainer"]:has(#credora-auth-card) {display:none;}
        .stApp:has(#credora-login-mode) [data-testid="stMainBlockContainer"] > [data-testid="stVerticalBlock"] {gap:0;}
        .stApp:has(#credora-login-mode) [data-testid="stHorizontalBlock"]:has(.login-panel) {
            display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); min-height:100vh; gap:0; width:100%;
        }
        .stApp:has(#credora-login-mode) [data-testid="stHorizontalBlock"]:has(.login-panel) > [data-testid="stColumn"] {
            width:100% !important; min-width:0 !important; max-width:none; flex:none !important;
        }
        .stApp:has(#credora-login-mode) [data-testid="stHorizontalBlock"]:has(.login-panel) > [data-testid="stColumn"]:last-child {
            display:flex; flex-direction:column; justify-content:center; padding:32px; min-height:100vh;
        }
        .stApp:has(#credora-login-mode) [data-testid="stHorizontalBlock"]:has(.login-panel) > [data-testid="stColumn"]:last-child > [data-testid="stVerticalBlock"] {height:auto !important; flex:0 0 auto; min-height:0;}
        .stApp:has(#credora-login-mode) [data-testid="stForm"] [data-testid="stHorizontalBlock"] {display:grid; grid-template-columns:repeat(2,minmax(0,1fr));}
        .stApp:has(#credora-login-mode) [data-testid="stForm"] [data-testid="stHorizontalBlock"] > [data-testid="stColumn"] {width:100% !important; flex:none !important; min-width:0;}
        .stApp:has(#credora-login-mode) [data-testid="stHorizontalBlock"]:has(.login-panel) > [data-testid="stColumn"]:first-child {background:#fae4db;}
        .st-key-auth_form_card {width:100% !important; max-width:640px !important; margin:auto !important;}
        @media(max-width:760px) {
            .stApp:has(#credora-login-mode) [data-testid="stHorizontalBlock"]:has(.login-panel) {grid-template-columns:1fr;}
            .stApp:has(#credora-login-mode) [data-testid="stHorizontalBlock"]:has(.login-panel) > [data-testid="stColumn"]:last-child {min-height:auto; padding:24px 16px;}
            .stApp:has(#credora-login-mode) .login-panel {height:260px; min-height:260px; background-size:176.4% auto;}
            .stApp:has(#credora-login-mode) .st-key-auth_form_card {padding:28px 24px !important;}
            .auth-heading h2 {font-size:28px !important;}
        }
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
        .stApp:has(#credora-auth-card) .stTextInput [data-testid="stTextInputRootElement"] {
            display:flex;
            align-items:center;
            height:52px;
            min-height:52px;
            overflow:hidden;
            border:1px solid #d8dde4;
            border-radius:8px;
            background:#fff;
            box-shadow:none;
        }
        .stApp:has(#credora-auth-card) .stTextInput [data-testid="stTextInputRootElement"]:focus-within {
            border-color:#c96774;
            background:#fff;
            box-shadow:none;
            outline:none;
        }
        .stApp:has(#credora-auth-card) [data-testid="InputInstructions"] {display:none !important;}
        .stApp:has(#credora-auth-card) .stTextInput input::-ms-reveal,
        .stApp:has(#credora-auth-card) .stTextInput input::-ms-clear {display:none;}
        .stApp:has(#credora-auth-card) .stTextInput label p,
        .stApp:has(#credora-auth-card) .stCheckbox label p {
            color: #334155;
            font-size: 13px;
            font-weight: 500;
        }
        .stApp:has(#credora-auth-card) .stTextInput input {
            min-height: 50px;
            padding-top: 12px;
            padding-bottom: 12px;
            height:50px;
            border:0 !important;
            border-radius:0 !important;
            outline:none !important;
            box-shadow:none !important;
            background: #fff !important;
            color: #0f172a;
            font-size: 14.5px;
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
            height:50px;
            min-height:50px;
            border:0 !important;
            border-radius:0 !important;
            background-color:#fff !important;
            box-shadow:none !important;
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
            border:0 !important;
            box-shadow:none !important;
            outline:none !important;
        }
        .stApp:has(#credora-auth-card) .stCheckbox input:checked + div {
            border-color: #932d32 !important;
            background: #932d32 !important;
        }
        .stApp:has(#credora-auth-card) .stFormSubmitButton button[kind="primary"] {
            width: 100%;
            min-height: 52px;
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
            min-height: 52px;
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

        /* Compact top navigation replaces the sidebar. */
        .stApp:not(:has(#credora-login-mode)) {
            background: #fbf8f5;
        }
        .stApp:not(:has(#credora-login-mode)) [data-testid="stVerticalBlockBorderWrapper"],
        .stApp:has(#credora-overview-mode) [data-testid="stVerticalBlockBorderWrapper"],
        .overview-metric, .model-summary-card, .overview-table-card, .threat-posture {
            background: #fffdfb !important;
            border: 1px solid #eadbd4 !important;
            box-shadow: 0 3px 12px rgba(89,52,48,.04) !important;
        }
        [data-testid="stSidebar"], [data-testid="stSidebarCollapsedControl"] {display:none !important;}
        .st-key-dashboard_navigation {padding-bottom:14px; border-bottom:1px solid #eadbd4;}
        .st-key-dashboard_navigation .credora-brand {width:205px; max-width:100%; margin:0; padding:0;}
        .st-key-icon_navigation {gap:6px !important; flex-wrap:wrap;}
        .st-key-icon_navigation button {height:40px; min-height:40px; padding:0 !important; border-radius:6px;}
        .st-key-icon_navigation button p {font-size:0 !important; width:0; overflow:hidden;}
        .st-key-icon_navigation button [data-testid="stIconMaterial"] {font-size:21px; margin:0;}
        .st-key-icon_navigation button[kind="tertiary"] {color:#716867; background:transparent;}
        .st-key-icon_navigation button[kind="primary"] {background:#f3d8d2; border:1px solid #e7bfb8; color:#a23438;}
        .st-key-icon_navigation button:hover {background:#f8e8e2; color:#a23438;}
        .st-key-assessment_context {padding-top:4px;}
        .st-key-account_menu {max-width:220px; margin-left:auto;}
        .stApp:not(:has(#credora-login-mode)) [data-testid="stMainBlockContainer"] {max-width:1700px; margin:0 auto; padding-top:1.3rem;}
        .st-key-dashboard_navigation .credora-brand-logo {display:block; width:100%; max-width:205px; height:auto; object-fit:contain;}
        @media(max-width:720px) {
            .st-key-dashboard_navigation > [data-testid="stHorizontalBlock"] {flex-wrap:wrap;}
            .st-key-dashboard_navigation [data-testid="stColumn"] {width:100% !important; flex:1 1 100% !important;}
            .st-key-icon_navigation {justify-content:flex-start !important;}
        }
        .stButton button, .stDownloadButton button {
            transition: background-color .18s ease, box-shadow .18s ease, transform .18s ease;
            box-shadow: inset 0 1px 0 rgba(255,255,255,.3);
        }
        .stButton button:hover, .stDownloadButton button:hover {box-shadow: 0 4px 14px rgba(162,52,56,.12), inset 0 1px 0 rgba(255,255,255,.35);}
        .stButton button:active, .stDownloadButton button:active {transform: translateY(1px);}
        .overview-metric {transition: box-shadow .2s ease;}
        .overview-metric:hover {box-shadow: 0 10px 28px rgba(89,52,48,.1), inset 0 1px 0 #fff;}
        @media (prefers-reduced-motion: reduce) {
            .stButton button, .stDownloadButton button, .overview-metric {transition: none; transform: none;}
        }
        /* Landscape dashboard reference: one header and a compact results grid. */
        /* Detail pages use rose accents without changing overview or upload styling. */
        [data-testid="stElementContainer"]:has(#credora-detail-mode) {display:none;}
        .stApp:has(#credora-detail-mode) {background:#fcf5f2;}
        .stApp:has(#credora-detail-mode) .page-head {
            margin:2px -32px 20px; padding:22px 32px 24px;
            border-bottom:1px solid #edcec5;
            background:linear-gradient(105deg,#f9e2da 0%,#fcefe9 64%,#f0c4bc 100%);
        }
        .stApp:has(#credora-detail-mode) .page-head h1 {
            margin:0; padding:0 !important; color:#272025; font-size:28px; line-height:1.2;
        }
        .stApp:has(#credora-detail-mode) .page-head p {margin:8px 0 0; color:#69545a; line-height:1.5;}
        .stApp:has(#credora-detail-mode) [data-testid="stMarkdownContainer"] h3 {
            padding:10px 0 12px; color:#82383f; font-size:20px; line-height:1.3;
        }
        .stApp:has(#credora-detail-mode) [data-testid="stMetric"] {
            background:#fffaf7; border:1px solid #e9cfc6; border-top:3px solid #cc7775;
            border-radius:7px; box-shadow:0 3px 12px rgba(112,48,56,.04);
        }
        .stApp:has(#credora-detail-mode) [data-testid="stMetricValue"] {color:#91343c;}
        .stApp:has(#credora-detail-mode) [data-testid="stMetric"] {border-color:#e9cfc6 !important; border-top-color:#cc7775 !important;}
        .stApp:has(#credora-detail-mode) [data-testid="stMetricLabel"] p {color:#6d5358 !important;}
        .stApp:has(#credora-detail-mode) [data-testid="stDataFrame"] {
            background:#fffdfb; border:1px solid #e1bcb3; border-top:3px solid #d89c94; border-radius:6px;
        }
        .stApp:has(#credora-detail-mode) [data-testid="stVerticalBlockBorderWrapper"] {
            border-color:#e7c6bc !important; background:#fffdfb !important;
            box-shadow:0 3px 12px rgba(112,48,56,.035) !important;
        }
        .stApp:has(#credora-detail-mode) [data-testid="stTabs"] [role="tablist"] {
            background:#f8e4de; border-bottom:1px solid #e7c4bb; padding:4px 8px; gap:8px;
        }
        .stApp:has(#credora-detail-mode) [data-testid="stTabs"] [role="tab"] {
            padding:10px 14px; color:#6d5358; border-radius:5px 5px 0 0;
        }
        .stApp:has(#credora-detail-mode) [data-testid="stTabs"] [role="tab"][aria-selected="true"] {
            color:#982f38; background:#fff8f4; font-weight:600;
        }
        .stApp:has(#credora-detail-mode) [data-testid="stTabs"] [data-baseweb="tab-highlight"] {background:#a23438;}
        .stApp:has(#credora-detail-mode) [data-testid="stExpander"] {
            border:1px solid #e3bfb4 !important; border-radius:6px !important; background:#fffaf7;
        }
        .stApp:has(#credora-detail-mode) [data-testid="stExpander"] details > summary {
            background:#f9e8e2; color:#70363e; border-left:3px solid #ce8781; border-radius:5px;
        }
        .stApp:has(#credora-detail-mode) [data-testid="stForm"] {border-color:#e5c0b6; background:#fffaf7;}
        .stApp:has(#credora-detail-mode) .stButton button[kind="secondary"],
        .stApp:has(#credora-detail-mode) .stDownloadButton button[kind="secondary"] {
            color:#94323c; border-color:#d99a92; background:#fff7f2;
        }
        .stApp:has(#credora-detail-mode) .stButton button[kind="secondary"]:hover,
        .stApp:has(#credora-detail-mode) .stDownloadButton button[kind="secondary"]:hover {
            background:#f8e0d8; border-color:#bd6c69;
        }
        .stApp:has(#credora-detail-mode) [data-testid="stTextInputRootElement"]:focus-within,
        .stApp:has(#credora-detail-mode) [data-testid="stSelectbox"] [data-baseweb="select"]:focus-within {
            outline:2px solid #cf817b; outline-offset:2px;
        }
        .stApp:has(#credora-detail-mode) .threat-posture {background:#fff9f5 !important;}
        @media(max-width:720px) {
            .stApp:has(#credora-detail-mode) .page-head {margin:0 -16px 16px; padding:20px 16px;}
            .stApp:has(#credora-detail-mode) [data-testid="stTabs"] [role="tablist"] {gap:2px;}
            .stApp:has(#credora-detail-mode) [data-testid="stTabs"] [role="tab"] {padding:10px;}
        }
        .stApp:has(#credora-upload-mode) .page-head {
            position:relative; padding:22px 16px 26px; margin:0 0 10px;
            background:linear-gradient(115deg,#fbf8f5 45%,#f7e2dc 75%,#edb0a8);
        }
        .stApp:has(#credora-upload-mode) .page-head::after {
            content:""; position:absolute; right:-32px; bottom:0; width:46%; height:110px;
            border-radius:65% 25% 0 0; background:#df8e8830; pointer-events:none;
        }
        .stApp:has(#credora-upload-mode) .page-head h1 {font-size:28px; margin:0; padding:0;}
        .stApp:has(#credora-upload-mode) .page-head p {font-size:16px; margin:8px 0 0; color:#5c6877;}
        .st-key-upload_evidence {padding:18px 20px; gap:10px !important;}
        .upload-step {display:flex; align-items:flex-start; gap:28px; margin:0; padding:10px 4px;}
        .upload-step > span {display:grid; place-items:center; width:32px; height:32px; flex:0 0 32px; border-radius:50%; background:#cf867c; color:white; font-size:20px;}
        .upload-step h3 {padding:0 !important; margin:0 0 4px !important; font-size:18px; color:#17202b;}
        .upload-step p {padding:0; margin:0; font-size:14px; color:#5c6877;}
        .st-key-upload_evidence .stRadio {margin-left:64px; max-width:940px; margin-bottom:8px;}
        .st-key-upload_evidence [role="radiogroup"] {display:grid; grid-template-columns:1fr 1fr; gap:24px;}
        .st-key-upload_evidence label[data-testid="stRadioOption"] {
            width:100%; min-height:72px; border:1px solid #e4dedb; border-radius:6px; padding:12px 20px; background:#fffdfb;
        }
        .st-key-upload_evidence label[data-testid="stRadioOption"]:has(input:checked) {border-color:#c75c60; background:#fcf0ed;}
        .st-key-upload_evidence label[data-testid="stRadioOption"] p {font-size:14px;}
        .st-key-upload_evidence label[data-testid="stRadioOption"] [data-testid="stIconMaterial"] {font-size:28px; color:#a23438; padding:10px; background:#f8e7e2; border-radius:6px; margin:0 16px;}
        .st-key-upload_evidence label[data-testid="stRadioOption"] p::after {display:block; font-size:13px; color:#5c6877; font-weight:400; margin:4px 0 0 64px;}
        .st-key-sidebar_assessment_source label:nth-child(1) p::after {content:"Provide your own model and files";}
        .st-key-sidebar_assessment_source label:nth-child(2) p::after {content:"Use a sample model for testing";}
        .st-key-assessment_input_type label:nth-child(1) p::after {content:"Structured network flow data";}
        .st-key-assessment_input_type label:nth-child(2) p::after {content:"Sequential tokens or bytes";}
        .st-key-upload_evidence [class*="st-key-upload_row_"] {margin-left:64px; width:calc(100% - 64px); border:1px solid #e4dedb; border-radius:6px; padding:6px 14px; min-height:54px; gap:0;}
        .st-key-upload_evidence [class*="st-key-upload_row_"] [data-testid="stVerticalBlock"] {gap:0;}
        .st-key-upload_evidence [class*="st-key-upload_row_"] p {margin:0; font-size:13px;}
        .st-key-upload_evidence [class*="st-key-upload_row_"] [data-testid="stIconMaterial"] {font-size:24px; padding:7px; margin-right:18px; background:#fbf1ed; border-radius:5px;}
        .st-key-upload_evidence [class*="st-key-upload_row_"] [data-testid="stCaptionContainer"] p {font-size:12px; color:#657080;}
        .st-key-upload_evidence [class*="st-key-upload_row_"] [data-testid="stColumn"]:first-child [data-testid="stCaptionContainer"] {margin-left:58px;}
        .st-key-upload_evidence [data-testid="stFileUploaderDropzone"] {padding:0; border:0; background:transparent; min-height:40px;}
        .st-key-upload_evidence [data-testid="stFileUploaderDropzoneInstructions"] {display:none;}
        .st-key-upload_evidence [data-testid="stFileUploaderDropzone"] button {height:40px; min-height:40px; width:100%; border:1px solid #b6353d; border-radius:5px; color:#a23438; background:#fffdfb;}
        .st-key-upload_evidence [data-testid="stFileUploaderDropzone"] button p {font-size:0;}
        .st-key-upload_evidence [data-testid="stFileUploaderDropzone"] button p::after {content:"Upload"; font-size:14px;}
        .st-key-sidebar_run_scan button {margin-top:12px; height:44px; border-radius:6px; background:#b6353d;}
        [data-testid="stElementContainer"]:has(#credora-upload-mode) {display:none;}
        .st-key-upload_evidence {background:#fffdfb;}
        .upload-step-2,.upload-step-3 {border-top:1px solid #eee5e0; padding-top:14px;}
        .st-key-sidebar_assessment_source,.st-key-assessment_input_type {width:calc(100% - 64px) !important; max-width:940px; margin-left:64px;}
        .st-key-upload_evidence .stRadio {width:100%; max-width:none; margin-left:0;}
        .st-key-upload_evidence [role="radiogroup"] {width:100%;}
        .st-key-upload_evidence label[data-testid="stRadioOption"] p {position:relative; padding-left:64px; min-height:48px; display:flex; flex-direction:column; justify-content:center;}
        .st-key-upload_evidence label[data-testid="stRadioOption"] p span[role="img"] {
            position:absolute; left:0; top:0; display:grid !important; place-items:center;
            width:48px; height:48px; font-size:28px; color:#a23438; background:#f8e7e2; border-radius:6px;
        }
        .st-key-upload_evidence label[data-testid="stRadioOption"] p::after {margin:5px 0 0;}
        .upload-file-detail {display:flex; align-items:center; gap:24px; min-height:40px;}
        .upload-file-icon {display:grid; place-items:center; flex:0 0 38px; width:38px; height:38px; font-family:"Material Symbols Rounded"; font-size:24px; background:#fbf1ed; border-radius:5px;}
        .upload-file-detail strong {font-size:14px; color:#18202c;}
        .upload-file-detail p {font-size:13px !important; color:#657080; line-height:1.35; margin:3px 0 0 !important;}
        .upload-file-detail > div {display:flex; flex-direction:column; gap:3px;}
        .upload-file-detail strong {display:block; line-height:18px;}
        .upload-file-detail p {margin:0 !important; line-height:16px !important;}
        .stApp:has(#credora-upload-mode) .page-head::after {
            width:55%; height:128px; border-radius:0; background:transparent;
            background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 800 128' preserveAspectRatio='none'%3E%3Cpath fill='%23e5aba330' d='M0 128C110 110 155 0 285 10S480 160 800 0V128Z'/%3E%3Cpath fill='%23da857e38' d='M190 128C300 70 345 30 445 67S620 140 800 60V128Z'/%3E%3C/svg%3E");
            background-size:100% 100%;
        }
        @media(max-width:720px) {
            .st-key-upload_evidence {padding:12px;}
            .upload-step {gap:12px;}
            .st-key-upload_evidence .stRadio {margin-left:0;}
            .st-key-sidebar_assessment_source,.st-key-assessment_input_type {width:100% !important; margin-left:0;}
            .st-key-upload_evidence [role="radiogroup"] {grid-template-columns:1fr; gap:10px;}
            .st-key-upload_evidence [class*="st-key-upload_row_"] {margin-left:0; width:100%; padding:10px;}
            .st-key-upload_evidence [class*="st-key-upload_row_"] [data-testid="stColumn"] {width:100% !important; flex:1 1 100% !important;}
            .stApp:has(#credora-upload-mode) .page-head {padding:16px 0;}
        }
        .stApp:not(:has(#credora-login-mode)) [data-testid="stElementContainer"]:has(style) {display:none;}
        .stApp:not(:has(#credora-login-mode)) [data-testid="stMainBlockContainer"] > [data-testid="stVerticalBlock"] {gap:12px;}
        .stApp:not(:has(#credora-login-mode)) header[data-testid="stHeader"] {display:none;}
        .stApp:not(:has(#credora-login-mode)) [data-testid="stMainBlockContainer"] {
            width:100%; max-width:1360px; padding:0 24px 28px; margin:0 auto;
        }
        .st-key-dashboard_topbar {width:calc(100% + 48px) !important; min-height:60px; margin:0 -24px; padding:8px 24px; border-bottom:1px solid #e8ded9;}
        .st-key-dashboard_topbar > [data-testid="stElementContainer"]:has(#credora-overview-mode) {display:none;}
        .st-key-dashboard_topbar [data-testid="stHorizontalBlock"] {min-height:44px; gap:14px;}
        .st-key-dashboard_topbar .credora-brand {width:205px; min-height:0; margin:0; padding:0;}
        .st-key-dashboard_topbar .credora-brand-logo {display:block; width:100%; height:auto; object-fit:contain; mix-blend-mode:multiply;}
        .st-key-dashboard_topbar .credora-brand {width:180px; max-width:100%;}
        .st-key-icon_navigation {justify-content:flex-start !important; gap:8px !important;}
        .st-key-icon_navigation button {height:40px; min-height:40px; border-radius:6px; border:0; box-shadow:none;}
        .st-key-icon_navigation button [data-testid="stIconMaterial"] {font-size:22px; color:#19202b;}
        .st-key-icon_navigation button[kind="primary"] {background:#fbe7e2; border:0;}
        .st-key-icon_navigation button[kind="primary"] [data-testid="stIconMaterial"] {color:#ae2029;}
        .st-key-account_menu {margin:0; max-width:none;}
        .st-key-account_menu > div [data-testid="stPopover"] > button {
            border:0; border-left:1px solid #eadbd4; border-radius:0; padding:0 12px; background:transparent;
        }
        .st-key-account_menu [data-testid="stPopover"] > button p {
            display:grid; place-items:center; width:34px; height:34px; flex:0 0 34px;
            border-radius:50%; background:#efdad5; color:#201a1a; font-weight:600;
        }
        .st-key-dashboard_topbar .st-key-account_menu [data-testid="stPopover"] button p {
            display:grid; place-items:center; width:34px; height:34px; flex:0 0 34px;
            border-radius:50%; background:#efdad5; color:#201a1a; font-size:14px;
        }
        .st-key-dashboard_search input {font-size:13px !important;}
        .st-key-readiness_banner {
            position:relative; overflow:hidden; min-height:132px; padding:18px 24px;
            border:1px solid #efddd5; border-radius:8px;
            background:linear-gradient(105deg,#fcece5,#f8ded5 65%,#e58b88);
        }
        .st-key-readiness_banner::after {
            content:""; position:absolute; right:-60px; bottom:-120px; width:600px; height:235px;
            border-radius:50%; background:rgba(174,45,54,.13); transform:rotate(-13deg); pointer-events:none;
        }
        .st-key-readiness_banner > div {position:relative; z-index:1;}
        .readiness-copy {padding-right:24px;}
        .overview-eyebrow {font-size:12px; letter-spacing:0; color:#445061;}
        .readiness-copy h2 {font-size:28px; line-height:1.15; margin:8px 0;}
        .readiness-copy h2 {padding:0 !important; margin:8px 0 !important;}
        .readiness-copy p {padding:0 !important; margin:0 !important;}
        .overview-card-head h3 {padding:0 !important; margin:0 !important; line-height:1.25;}
        .st-key-overview_drift {height:244px; padding:14px 20px 6px; gap:6px !important;}
        .st-key-overview_drift [data-testid="stPlotlyChart"] {margin:0 !important;}
        .chart-legend {font-size:12px; margin:0;}
        .readiness-copy p {font-size:15px; max-width:540px; line-height:1.4; color:#4e5b70;}
        .overview-checks {padding-left:24px; gap:8px;}
        .overview-checks .readiness-check {font-size:13px; color:#344259;}
        .overview-checks .readiness-check b {width:20px; height:20px; font-size:12px; background:#00785b;}
        .st-key-readiness_banner button {height:40px; border-radius:6px; background:#ad2931; font-size:14px;}
        .overview-metrics {gap:12px; margin-bottom:12px;}
        .overview-metric {min-height:168px; border-radius:8px; padding:16px 16px 0;}
        .metric-label {font-size:12px; letter-spacing:0; color:#344259;}
        .metric-label .ui-icon {width:19px; height:19px;}
        .metric-core {gap:14px; margin-top:12px;}
        .metric-round {width:48px; height:48px;}
        .metric-round .ui-icon {width:28px; height:28px;}
        .metric-round .material-symbols-rounded {display:block; font-size:28px;}
        .metric-core strong {font-size:26px;}
        .metric-core strong small {font-size:13px; color:#344259; font-weight:400;}
        .metric-core p {font-size:13px; line-height:1.4; margin-top:6px; color:#344259;}
        .metric-spark {height:55px; left:20px; right:20px; width:calc(100% - 40px); bottom:8px;}
        .tier-content {grid-template-columns:100px 1fr; gap:12px; margin-top:12px;}
        .overview-tier-ring {width:100px; height:100px;}
        .overview-tier-ring::before {width:68px; height:68px;}
        .overview-tier-ring b {font-size:26px;}
        .overview-tier-ring small {font-size:12px; letter-spacing:0;}
        .tier-legend p {font-size:12px; color:#344259; margin-bottom:10px;}
        .tier-legend strong {font-size:11px;}
        .overview-card-head h3 {font-size:18px; color:#13171c;}
        .stApp:has(#credora-overview-mode) [data-testid="stVerticalBlockBorderWrapper"]:has(#overview-drift-card) {
            height:244px; padding:14px 20px 6px !important; margin-bottom:0; border-radius:8px !important;
        }
        .model-summary-card {height:244px; border-radius:8px; padding:14px 20px;}
        .model-summary-card {margin-bottom:12px;}
        .summary-item {min-height:62px; padding:8px 10px; grid-template-columns:42px 1fr;}
        .summary-item small {font-size:12px; color:#647086;}
        .summary-item strong {font-size:14px; font-weight:400; color:#263751;}
        .summary-item .ui-icon {width:22px; height:22px;}
        .overview-table-card {height:206px; padding:14px 20px; border-radius:8px;}
        .overview-table-card {height:auto; min-height:206px;}
        .overview-table-head, .alert-table-head {font-size:10px; letter-spacing:0;}
        .overview-table-row {font-size:12px; min-height:32px;}
        .overview-table-row strong {font-size:12px;}
        .alert-table-row {font-size:11px; min-height:32px;}
        .alert-table-row strong {font-size:11px;}
        .status-chip, .severity-chip, .status-pill {
            background:transparent !important; border:0; border-radius:0;
            box-shadow:none; padding:0; font-style:normal; font-weight:600; line-height:1.5;
        }
        .status-chip, .severity-chip {font-size:13px;}
        .module-row {display:grid; grid-template-columns:minmax(0,1fr) 110px; align-items:center; gap:24px; padding:16px 0; border-bottom:1px solid var(--border);}
        .module-row:last-child {border-bottom:0;}
        .module-title {font-size:15px; font-weight:600; color:var(--text);}
        .module-summary {font-size:14px; line-height:1.5; color:var(--muted-strong); margin-top:4px; overflow-wrap:anywhere;}
        .module-row > div:last-child {text-align:right;}
        .module-score {font-size:14px; color:var(--muted-strong); margin-top:4px;}
        .assurance-head {display:flex; align-items:center; justify-content:space-between; gap:12px;}
        .assurance-head h3 {font-size:20px; margin:0; padding:0;}
        .assurance-head p {font-size:14px; color:var(--muted-strong); margin:6px 0 16px;}
        .assurance-control {color:var(--muted);}
        .assurance-tier {font-size:16px; font-weight:600; color:var(--primary);}
        .assurance-status {font-size:14px; margin-top:6px;}
        .assurance-bars {display:grid; gap:16px; margin-top:24px;}
        .assurance-bars > div {display:grid; grid-template-columns:minmax(0,1fr) auto; gap:8px; font-size:14px;}
        .assurance-bars b {font-weight:600; white-space:nowrap;}
        .assurance-bars i {display:block; grid-column:1 / -1; height:4px; max-width:100%; background:var(--primary);}
        .stApp:has(#credora-login-mode) [data-testid="stHorizontalBlock"]:has(.login-panel) > [data-testid="stColumn"]:last-child {
            padding:48px 8%;
        }
        .stApp:has(#credora-login-mode) [data-testid="stHorizontalBlock"]:has(.login-panel) > [data-testid="stColumn"]:last-child > div {
            width:100%; max-width:none;
        }
        .stApp:has(#credora-login-mode) .st-key-auth_form_card,
        .stApp:has(#credora-login-mode) [data-testid="stVerticalBlock"]:has(> [data-testid="stElementContainer"]:first-child #credora-auth-card) {
            width:100% !important; max-width:600px !important; padding:36px !important;
        }
        .stApp:has(#credora-detail-mode) .page-head {margin:2px -24px 16px; padding:16px 24px 18px;}
        .stApp:has(#credora-detail-mode) .page-head h1 {font-size:26px;}
        .stApp:has(#credora-detail-mode) [data-testid="stMarkdownContainer"] h3 {font-size:18px;}
        .stApp:has(#credora-upload-mode) .page-head {padding:22px 16px; min-height:104px;}
        .stApp:has(#credora-upload-mode) .page-head h1 {font-size:26px;}
        .stApp:not(:has(#credora-login-mode)) [data-testid="stMetricValue"] {font-size:26px;}
        .stApp:has(#credora-overview-mode) [data-testid="stElementContainer"]:has(#overview-model-action) + [data-testid="stElementContainer"] button,
        .stApp:has(#credora-overview-mode) [data-testid="stElementContainer"]:has(#overview-assessments-action) + [data-testid="stElementContainer"] button,
        .stApp:has(#credora-overview-mode) [data-testid="stElementContainer"]:has(#overview-alerts-action) + [data-testid="stElementContainer"] button {font-size:12px;}
        @media(max-width:1400px) {
            .st-key-icon_navigation > [data-testid="stLayoutWrapper"] {max-width:48px;}
            .metric-core {gap:14px;}
            .metric-round {width:48px; height:48px;}
            .metric-core strong {font-size:26px;}
            .metric-core p {font-size:12px;}
            .tier-content {gap:10px; grid-template-columns:104px 1fr;}
            .overview-tier-ring {width:104px; height:104px;}
            .overview-tier-ring::before {width:72px; height:72px;}
        }
        @media(max-width:1050px) {
            .st-key-dashboard_topbar > div > [data-testid="stHorizontalBlock"] {flex-wrap:wrap;}
            .st-key-dashboard_topbar [data-testid="stColumn"] {min-width:140px; flex:1 1 auto;}
            .st-key-dashboard_topbar [data-testid="stColumn"]:nth-child(2) {min-width:420px;}
            .overview-metrics {grid-template-columns:repeat(2,minmax(0,1fr));}
            .readiness-copy h2 {font-size:28px;}
            .readiness-copy p {font-size:14px;}
        }
        @media(max-width:720px) {
            .module-row {grid-template-columns:minmax(0,1fr) 80px; gap:12px;}
            .stApp:has(#credora-login-mode) [data-testid="stHorizontalBlock"]:has(.login-panel) > [data-testid="stColumn"]:last-child {padding:24px 16px;}
            .stApp:has(#credora-login-mode) .st-key-auth_form_card {padding:28px 24px !important;}
            .stApp:not(:has(#credora-login-mode)) [data-testid="stMainBlockContainer"] {padding:0 16px 20px;}
            .st-key-dashboard_topbar {margin:0 -16px 12px; padding:10px 16px;}
            .st-key-dashboard_topbar [data-testid="stColumn"]:nth-child(2) {min-width:100%;}
            .st-key-readiness_banner {padding:20px;}
            .readiness-copy {border:0; padding:0;}
            .overview-checks {padding:12px 0;}
            .overview-metrics {grid-template-columns:1fr;}
            .overview-table-card, .model-summary-card {height:auto; min-height:206px; overflow-x:auto;}
            .overview-table-head, .overview-table-row {min-width:650px;}
            .alert-table-head, .alert-table-row {min-width:450px;}
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
