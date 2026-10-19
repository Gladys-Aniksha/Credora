from __future__ import annotations

import ast
from xml.etree import ElementTree
from pathlib import Path

from dashboard.components.overview import _metric_series, build_metric_histories
from dashboard.components.topbar import PAGE_ICONS, build_search_results

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_ROOT = PROJECT_ROOT / "dashboard"


def _function_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def test_dashboard_uses_page_and_component_modules() -> None:
    app_path = DASHBOARD_ROOT / "app.py"
    app_source = app_path.read_text(encoding="utf-8")

    expected_imports = {
        "dashboard.components.common",
        "dashboard.components.overview",
        "dashboard.components.scan_submission",
        "dashboard.components.topbar",
        "dashboard.pages.admin",
        "dashboard.pages.auth",
        "dashboard.pages.production_monitoring",
        "dashboard.pages.reports",
    }
    tree = ast.parse(app_source)
    imported_modules = {
        node.module
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }

    assert expected_imports <= imported_modules
    assert len(app_source.splitlines()) < 1300


def test_extracted_dashboard_sections_have_stable_entry_points() -> None:
    expected_functions = {
        DASHBOARD_ROOT / "pages" / "auth.py": {"require_dashboard_auth"},
        DASHBOARD_ROOT / "pages" / "reports.py": {"render_reports_page"},
        DASHBOARD_ROOT / "pages" / "admin.py": {"render_admin_page"},
        DASHBOARD_ROOT / "pages" / "production_monitoring.py": {
            "render_flow_ingestion",
            "render_production_drift_windows",
        },
        DASHBOARD_ROOT / "components" / "scan_submission.py": {
            "render_scan_submission",
            "execute_scan_submission",
        },
        DASHBOARD_ROOT / "components" / "topbar.py": {
            "build_search_results",
            "render_dashboard_topbar",
        },
    }

    for path, function_names in expected_functions.items():
        assert path.exists()
        assert function_names <= _function_names(path)


def test_login_uses_local_reference_artwork_and_streamlit_auth_controls() -> None:
    theme_source = (DASHBOARD_ROOT / "theme.py").read_text(encoding="utf-8")
    auth_source = (DASHBOARD_ROOT / "pages" / "auth.py").read_text(encoding="utf-8")
    hero_path = DASHBOARD_ROOT / "assets" / "login-hero.png"
    hero_bytes = hero_path.read_bytes()

    assert hero_bytes.startswith(b"\x89PNG\r\n\x1a\n")
    assert int.from_bytes(hero_bytes[16:20], "big") == 1672
    assert int.from_bytes(hero_bytes[20:24], "big") == 941
    assert "login-hero.png" in theme_source
    assert all(
        (DASHBOARD_ROOT / "assets" / "fonts" / font_name).is_file()
        for font_name in (
            "inter-300.ttf",
            "inter-400.ttf",
            "inter-500.ttf",
            "inter-600.ttf",
            "inter-700.ttf",
        )
    )
    assert "data:image/svg+xml" in theme_source
    assert 'button[aria-label=\"Show password\"]' in theme_source
    assert '[data-testid=\"stIconMaterial\"]' in theme_source
    assert '[class*=\"material-symbols\"]' in theme_source
    assert "width: 50% !important" in theme_source
    assert "flex: 0 0 50% !important" in theme_source
    assert "background-size: 176.4% 100%" in theme_source
    assert "max-width: 640px" in theme_source
    assert "grid-template-columns:repeat(2,minmax(0,1fr))" in theme_source
    assert 'key="auth_form_card"' in auth_source
    assert '[data-testid="InputInstructions"] {display:none !important;}' in theme_source
    assert '[data-testid="stTextInputRootElement"]:focus-within' in theme_source
    assert 'st.form("credora-login", enter_to_submit=False)' in auth_source
    assert 'st.form("credora-register", enter_to_submit=False)' in auth_source
    assert ":material/" not in auth_source
    assert "st.tabs" not in auth_source


def test_overview_matches_reference_structure_and_uses_real_navigation() -> None:
    overview_source = (DASHBOARD_ROOT / "components" / "overview.py").read_text(encoding="utf-8")
    app_source = (DASHBOARD_ROOT / "app.py").read_text(encoding="utf-8")
    theme_source = (DASHBOARD_ROOT / "theme.py").read_text(encoding="utf-8")

    for section in (
        "Model Trust Overview",
        "Deployment Readiness",
        "Model Summary",
        "Recent Assessments",
        "Alerts",
    ):
        assert section in overview_source
    assert "Trust Drift Over Time" in app_source
    assert 'args=("Reports",)' in overview_source
    assert 'args=("Model Registry",)' in overview_source
    assert 'args=("Alerts",)' in overview_source
    assert "build_drift_figure(model_scan_rows, trust_score)" in app_source
    assert "render_metric_cards(" in app_source
    assert "trust_score_issued," in app_source
    assert "Security Gate failed. This Trust Score is assessment evidence only" in app_source
    assert "Security Gate failed · Do not deploy" in overview_source
    assert "#credora-overview-mode" in theme_source


def test_threat_model_is_available_in_navigation_and_reports() -> None:
    app_source = (DASHBOARD_ROOT / "app.py").read_text(encoding="utf-8")
    page_source = (DASHBOARD_ROOT / "pages" / "threat_model.py").read_text(encoding="utf-8")
    report_source = (DASHBOARD_ROOT / "pages" / "reports.py").read_text(encoding="utf-8")

    assert '"Threat Model"' in app_source
    assert 'elif page == "Threat Model"' in app_source
    assert "render_threat_model_page(threat_model)" in app_source
    for section in (
        "Protected Assets",
        "Threat Actors",
        "Attack Surfaces",
        "Trust Boundaries",
        "Threat Scenarios",
        "Threat-to-Control Mapping",
        "Security Assumptions",
        "Out of Scope",
        "Residual Risks",
    ):
        assert section in page_source
    assert 'with st.expander("Threat model summary"' in report_source


def test_dashboard_search_profile_and_upload_are_functional() -> None:
    app_source = (DASHBOARD_ROOT / "app.py").read_text(encoding="utf-8")
    topbar_source = (DASHBOARD_ROOT / "components" / "topbar.py").read_text(encoding="utf-8")

    assert '"Upload Model"' in app_source
    assert "render_scan_submission(PROJECT_ROOT, standalone=True)" in app_source
    assert 'key="global_search_query"' in topbar_source
    assert "build_search_results(query, models, scans)" in topbar_source
    assert 'st.query_params["model"] = model_name' in topbar_source
    assert "with st.popover(" in topbar_source
    assert 'key="profile_logout"' in topbar_source


def test_top_navigation_brand_and_layout_contract() -> None:
    app_source = (DASHBOARD_ROOT / "app.py").read_text(encoding="utf-8")
    theme_source = (DASHBOARD_ROOT / "theme.py").read_text(encoding="utf-8")

    topbar_source = (DASHBOARD_ROOT / "components" / "topbar.py").read_text(encoding="utf-8")
    assert "credora_brand_html()" in topbar_source
    assert "sidebar_open_alert_count" in app_source
    assert "credora-brand-logo" in theme_source
    assert "credora-header-logo.svg" in theme_source
    assert "alt='CREDORA Model Assurance'" in theme_source
    assert "max-width: 205px" in theme_source
    assert "width: 255px !important" in theme_source
    assert ".st-key-dashboard_page" in theme_source
    assert ".sidebar-wave-container" in theme_source
    assert "height: clamp(185px, 24vh, 240px)" in theme_source
    assert "with st.sidebar" not in app_source
    assert "render_icon_navigation(" in topbar_source
    assert "navigation_options=navigation_options" in app_source
    assert 'key="dashboard_topbar"' in topbar_source
    assert ".st-key-icon_navigation" in theme_source
    assert set(PAGE_ICONS) == {
        "Overview", "Model Registry", "Upload Model", "Traffic Classifier",
        "Trust Score", "Threat Model", "Trust Drift", "Reports", "Alerts", "Settings", "Admin",
    }
    assert len(set(PAGE_ICONS.values())) == len(PAGE_ICONS)


def test_header_logo_preserves_wordmark_and_separate_folded_facets() -> None:
    logo = ElementTree.parse(DASHBOARD_ROOT / "assets" / "credora-header-logo.svg").getroot()
    ns = {"svg": "http://www.w3.org/2000/svg"}
    symbol = logo.find("svg:g[@id='credora-c']", ns)
    assert symbol is not None
    facets = symbol.findall("svg:path", ns)
    assert len(facets) == 6
    assert len({facet.attrib["fill"] for facet in facets}) == 6
    assert [text.text for text in logo.findall("svg:text", ns)] == ["CREDORA", "MODEL ASSURANCE"]
    assert logo.attrib["viewBox"] == "0 0 240 64"


def test_detail_page_accents_exclude_reference_pages() -> None:
    app_source = (DASHBOARD_ROOT / "app.py").read_text(encoding="utf-8")
    theme_source = (DASHBOARD_ROOT / "theme.py").read_text(encoding="utf-8")
    assert 'if page not in {"Overview", "Upload Model"}:' in app_source
    assert "id='credora-detail-mode'" in app_source
    for surface in (".page-head", '[data-testid="stMetric"]', '[data-testid="stTabs"]', '[data-testid="stExpander"]'):
        assert f".stApp:has(#credora-detail-mode) {surface}" in theme_source


def test_dashboard_search_retrieves_models_assessments_and_reports() -> None:
    models = [{"model_name": "traffic_rf_v1", "version": "1.0", "algorithm": "Random Forest"}]
    scans = [
        {
            "id": 9,
            "model_name": "traffic_rf_v1",
            "status": "warning",
            "trust_score": 78,
            "report_path": "reports/trust_reports/traffic_rf_v1.json",
        }
    ]

    results = build_search_results("traffic", models, scans)

    assert {result["kind"] for result in results} == {"Model", "Assessment", "Report"}
    assert all(result["model_name"] == "traffic_rf_v1" for result in results)


def test_metric_series_uses_observed_values_and_ends_at_current_score() -> None:
    single = _metric_series([98.0], 98.0)
    observed = _metric_series([72.0, 78.0, 75.0, 84.0], 84.0)

    assert single == [98.0]
    assert observed == [72.0, 78.0, 75.0, 84.0]


def test_metric_histories_use_real_reports_for_the_active_model() -> None:
    reports = [
        {
            "model_name": "traffic-a",
            "generated_at": "2026-01-01T00:00:00+00:00",
            "trust_score": 71,
            "module_results": [
                {"module": "model_verification", "score": 82},
                {"module": "dependency_scanner", "score": 91},
            ],
        },
        {
            "model_name": "traffic-a",
            "generated_at": "2026-02-01T00:00:00+00:00",
            "trust_score": 79,
            "module_results": [
                {"module": "model_verification", "score": 94},
                {"module": "dependency_scanner", "score": 76},
            ],
        },
    ]

    trust, integrity, dependency_risk = build_metric_histories(reports, reports[-1])

    assert trust == [71.0, 79.0]
    assert integrity == [82.0, 94.0]
    assert dependency_risk == [9.0, 24.0]


def test_single_scan_fallback_uses_real_component_scores() -> None:
    report = {
        "generated_at": "2026-02-01T00:00:00+00:00",
        "trust_score": 74,
        "module_results": [
            {"module": "model_verification", "score": 88},
            {"module": "dependency_scanner", "score": 93},
            {"module": "runtime_integrity", "score": 81},
            {"module": "trust_score", "score": 74},
        ],
    }

    trust, integrity, dependency_risk = build_metric_histories([report], report)

    assert trust == [88.0, 93.0, 81.0, 74.0]
    assert integrity == [88.0, 81.0, 88.0]
    assert dependency_risk == [7.0]
