from __future__ import annotations

import ast
from pathlib import Path


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
        "dashboard.components.scan_submission",
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
    }

    for path, function_names in expected_functions.items():
        assert path.exists()
        assert function_names <= _function_names(path)


def test_login_uses_local_reference_artwork_and_streamlit_auth_controls() -> None:
    theme_source = (DASHBOARD_ROOT / "theme.py").read_text(encoding="utf-8")
    auth_source = (DASHBOARD_ROOT / "pages" / "auth.py").read_text(encoding="utf-8")
    hero_path = DASHBOARD_ROOT / "assets" / "login-hero.png"

    assert hero_path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    assert "login-hero.png" in theme_source
    assert "st.form(\"credora-login\")" in auth_source
    assert "st.form(\"credora-register\")" in auth_source
    assert "st.tabs" not in auth_source
