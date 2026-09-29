from __future__ import annotations

from typing import Any

import streamlit as st

from dashboard.components.common import h


def _navigate(page: str, model_name: str | None = None) -> None:
    if model_name:
        st.session_state["active_assessment"] = model_name
        st.query_params["model"] = model_name
    st.session_state["dashboard_page"] = page
    st.session_state["dashboard_query_page"] = page
    st.query_params["page"] = page


def _logout() -> None:
    for key in [
        "auth_user",
        "access_token",
        "refresh_token",
        "report",
        "progress_events",
        "global_search_query",
    ]:
        st.session_state.pop(key, None)
    st.query_params.clear()


def build_search_results(
    query: str,
    models: list[dict[str, Any]],
    scans: list[dict[str, Any]],
) -> list[dict[str, str]]:
    normalized = query.strip().casefold()
    if not normalized:
        return []

    results: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for model in models:
        model_name = str(model.get("model_name") or "Unknown model")
        searchable = " ".join(
            str(model.get(field) or "")
            for field in ["model_name", "version", "algorithm", "framework", "task"]
        ).casefold()
        if normalized in searchable and ("model", model_name) not in seen:
            results.append(
                {
                    "kind": "Model",
                    "title": model_name,
                    "detail": str(model.get("algorithm") or model.get("framework") or "Registered artifact"),
                    "page": "Model Registry",
                    "model_name": model_name,
                }
            )
            seen.add(("model", model_name))

    for scan in scans:
        model_name = str(scan.get("model_name") or "Unknown model")
        searchable = " ".join(
            str(scan.get(field) or "")
            for field in ["model_name", "status", "trust_score", "generated_at", "report_path"]
        ).casefold()
        if normalized not in searchable:
            continue
        scan_key = str(scan.get("id") or scan.get("generated_at") or model_name)
        if ("assessment", scan_key) not in seen:
            results.append(
                {
                    "kind": "Assessment",
                    "title": model_name,
                    "detail": f"Trust {float(scan.get('trust_score') or 0):.0f}/100 · {str(scan.get('status') or 'unknown').title()}",
                    "page": "Trust Score",
                    "model_name": model_name,
                }
            )
            seen.add(("assessment", scan_key))
        report_path = str(scan.get("report_path") or "")
        if report_path and ("report", report_path) not in seen:
            results.append(
                {
                    "kind": "Report",
                    "title": model_name,
                    "detail": "Generated trust report",
                    "page": "Reports",
                    "model_name": model_name,
                }
            )
            seen.add(("report", report_path))
        if len(results) >= 8:
            break

    return results[:8]


def render_dashboard_topbar(
    user: dict[str, Any],
    models: list[dict[str, Any]],
    scans: list[dict[str, Any]],
    alert_count: int,
    *,
    show_overview_heading: bool,
    can_view_platform: bool,
) -> None:
    username = str(user.get("username") or "Credora user")
    role = str(user.get("role") or "uploader").title()
    initials = "".join(part[:1].upper() for part in username.split()[:2]) or "CU"

    with st.container(key="dashboard_topbar"):
        column_widths = [1.45, 1.05, 0.72]
        heading_col, search_col, actions_col = st.columns(
            column_widths,
            gap="medium",
            vertical_alignment="center",
        )
        with heading_col:
            if show_overview_heading:
                st.markdown(
                    "<div id='credora-overview-mode'></div><div class='overview-heading'><h1>Model Trust Overview</h1>"
                    "<p>Monitor, assess, and ensure the trustworthiness of your AI models.</p></div>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown("<div class='topbar-spacer'></div>", unsafe_allow_html=True)
        with search_col:
            with st.container(key="dashboard_search"):
                query = st.text_input(
                    "Search Credora",
                    placeholder="Search models, assessments, or reports...",
                    label_visibility="collapsed",
                    key="global_search_query",
                )
        with actions_col:
            alert_col, profile_col = st.columns([0.26, 0.74], gap="small", vertical_alignment="center")
            with alert_col:
                st.button(
                    "",
                    icon=":material/notifications:",
                    key="topbar_alerts",
                    help=f"Open alerts ({alert_count})",
                    on_click=_navigate,
                    args=("Alerts",),
                    width="stretch",
                )
            with profile_col:
                with st.popover(
                    f"{initials}  {username}",
                    icon=":material/account_circle:",
                    width="stretch",
                ):
                    st.markdown(
                        f"<div class='profile-menu-head'><strong>{h(username)}</strong><span>{h(role)} workspace</span></div>",
                        unsafe_allow_html=True,
                    )
                    if can_view_platform:
                        st.toggle("Show all users' scans", key="show_all_users")
                    st.button(
                        "Log out",
                        icon=":material/logout:",
                        key="profile_logout",
                        on_click=_logout,
                        width="stretch",
                    )

    results = build_search_results(query, models, scans)
    if query.strip():
        with st.container(border=True, key="global_search_results"):
            st.markdown("**Search results**")
            if not results:
                st.caption("No matching models, assessments, or reports were found.")
            for index, result in enumerate(results):
                st.button(
                    f"{result['kind']}  ·  {result['title']}  —  {result['detail']}",
                    key=f"search_result_{index}_{result['kind']}_{result['title']}",
                    on_click=_navigate,
                    args=(result["page"], result["model_name"]),
                    width="stretch",
                )
