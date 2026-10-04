from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from dashboard.components.common import h


def _icon(name: str) -> str:
    paths = {
        "shield": '<path d="M12 3 5 6v5c0 4.7 2.9 8.1 7 10 4.1-1.9 7-5.3 7-10V6l-7-3Z"/><path d="m9 12 2 2 4-4"/>',
        "integrity": '<path d="M12 3 5 6v5c0 4.7 2.9 8.1 7 10 4.1-1.9 7-5.3 7-10V6l-7-3Z"/><path d="m9 12 2 2 4-4"/>',
        "database": '<ellipse cx="12" cy="5" rx="7" ry="3"/><path d="M5 5v6c0 1.7 3.1 3 7 3s7-1.3 7-3V5M5 11v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6"/>',
        "model": '<path d="m12 3 7 4-7 4-7-4 7-4Z"/><path d="m5 7 7 4 7-4v8l-7 4-7-4V7Z"/>',
        "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
        "chip": '<rect x="7" y="7" width="10" height="10" rx="2"/><path d="M9 2v3m6-3v3M9 19v3m6-3v3M2 9h3m-3 6h3m14-6h3m-3 6h3"/>',
        "search": '<circle cx="11" cy="11" r="7"/><path d="m16 16 5 5"/>',
        "bell": '<path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4"/>',
        "info": '<circle cx="12" cy="12" r="9"/><path d="M12 11v5m0-8h.01"/>',
    }
    return f'<svg class="ui-icon" aria-hidden="true" viewBox="0 0 24 24">{paths.get(name, paths["info"])}</svg>'


def _short_date(value: Any) -> str:
    try:
        parsed = pd.to_datetime(value)
        return parsed.strftime("%b %d, %Y")
    except (TypeError, ValueError):
        return "Not available"


def _short_datetime(value: Any) -> str:
    try:
        parsed = pd.to_datetime(value)
        return parsed.strftime("%b %d, %Y, %I:%M %p")
    except (TypeError, ValueError):
        return "Not available"


def _status_label(value: str) -> tuple[str, str]:
    normalized = str(value or "warning").lower()
    if normalized in {"pass", "passed", "approved"}:
        return "Passed", "passed"
    if normalized in {"fail", "failed", "blocked"}:
        return "Failed", "failed"
    return "Needs Review", "review"


def _tier(score: float) -> tuple[str, str]:
    if score >= 85:
        return "A", "High Assurance"
    if score >= 70:
        return "B", "Moderate"
    if score >= 50:
        return "C", "Limited"
    return "D", "High Risk"


def _navigate(page: str) -> None:
    st.session_state["dashboard_page"] = page
    st.session_state["dashboard_query_page"] = page
    st.query_params["page"] = page


def _sparkline(values: list[float], color: str) -> str:
    clean = [max(0.0, min(float(value), 100.0)) for value in values if value is not None]
    if not clean:
        return ""
    width, height = 260, 48
    if len(clean) == 1:
        y = height - (clean[0] / 100 * 36) - 4
        return (
            f'<svg class="metric-spark" viewBox="0 0 {width} {height}" preserveAspectRatio="none" aria-hidden="true">'
            f'<line x1="112" y1="{y:.1f}" x2="148" y2="{y:.1f}" stroke="{color}" stroke-width="1.2" opacity=".38"/>'
            f'<circle cx="130" cy="{y:.1f}" r="2.8" fill="{color}"/></svg>'
        )
    step = width / (len(clean) - 1)
    points = " ".join(f"{idx * step:.1f},{height - (value / 100 * 36) - 4:.1f}" for idx, value in enumerate(clean))
    area = f"0,{height} {points} {width},{height}"
    return (
        f'<svg class="metric-spark" viewBox="0 0 {width} {height}" preserveAspectRatio="none" aria-hidden="true">'
        f'<defs><linearGradient id="spark-{color[1:]}" x1="0" y1="0" x2="0" y2="1">'
        f'<stop offset="0" stop-color="{color}" stop-opacity=".2"/><stop offset="1" stop-color="{color}" stop-opacity="0"/>'
        f'</linearGradient></defs><polygon points="{area}" fill="url(#spark-{color[1:]})"/>'
        f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="1.6" vector-effect="non-scaling-stroke"/></svg>'
    )


def _metric_series(values: list[float], current: float) -> list[float]:
    clean = [max(0.0, min(float(value), 100.0)) for value in values if value is not None]
    series = clean[-12:]
    if not series or abs(series[-1] - current) > 0.01:
        series.append(max(0.0, min(float(current), 100.0)))
    return series


def _module_score(report: dict[str, Any], module_name: str) -> float | None:
    for result in report.get("module_results", []):
        if result.get("module") == module_name and result.get("score") is not None:
            return max(0.0, min(float(result["score"]), 100.0))
    return None


def build_metric_histories(
    reports: list[dict[str, Any]],
    current_report: dict[str, Any],
) -> tuple[list[float], list[float], list[float]]:
    ordered = sorted(reports, key=lambda report: str(report.get("generated_at") or ""))
    trust_history = [float(report["trust_score"]) for report in ordered if report.get("trust_score") is not None]
    integrity_history = [
        score for report in ordered if (score := _module_score(report, "model_verification")) is not None
    ]
    dependency_risk_history = [
        100.0 - score for report in ordered if (score := _module_score(report, "dependency_scanner")) is not None
    ]

    current_trust = float(current_report.get("trust_score") or 0.0)
    current_integrity = _module_score(current_report, "model_verification") or 0.0
    current_dependency_score = _module_score(current_report, "dependency_scanner") or 0.0

    if len(trust_history) < 2:
        component_scores = [
            score
            for result in current_report.get("module_results", [])
            if result.get("module") != "trust_score"
            and result.get("score") is not None
            and (score := max(0.0, min(float(result["score"]), 100.0))) is not None
        ]
        trust_history = component_scores + [current_trust]
    if len(integrity_history) < 2:
        integrity_history = [
            score
            for module_name in ("model_verification", "runtime_integrity")
            if (score := _module_score(current_report, module_name)) is not None
        ]

    return (
        _metric_series(trust_history, current_trust),
        _metric_series(integrity_history, current_integrity),
        _metric_series(dependency_risk_history, 100.0 - current_dependency_score),
    )


def render_overview_header(user: dict[str, Any], alert_count: int) -> None:
    username = str(user.get("username") or "Credora user")
    role = str(user.get("role") or "uploader").title()
    initials = "".join(part[:1].upper() for part in username.split()[:2]) or "CU"
    st.markdown(
        f"""
        <div id="credora-overview-mode"></div>
        <header class="overview-header">
          <div class="overview-heading">
            <h1>Model Trust Overview</h1>
            <p>Monitor, assess, and ensure the trustworthiness of your AI models.</p>
          </div>
          <div class="overview-tools">
            <div class="overview-search">{_icon('search')}<span>Search models, assessments, or reports...</span></div>
            <span class="overview-bell" aria-label="Alerts">{_icon('bell')}<i>{alert_count}</i></span>
            <div class="overview-profile"><span>{h(initials)}</span><div><strong>{h(username)}</strong><small>{h(role)}</small></div><b>⌄</b></div>
          </div>
        </header>
        """,
        unsafe_allow_html=True,
    )


def render_readiness_banner(
    readiness: str,
    note: str,
    decision: str,
    trust_score: float,
    critical_count: int,
    integrity_score: float,
    security_gate_passed: bool,
    trust_score_issued: bool,
) -> None:
    blocked = decision == "blocked"
    checklist = [
        (security_gate_passed, "Security Gate passed" if security_gate_passed else "Security Gate blocked deployment"),
        (critical_count == 0, "No critical risks detected" if critical_count == 0 else f"{critical_count} critical risk(s) detected"),
        (
            trust_score_issued and trust_score >= 70,
            "Trust score above threshold"
            if trust_score_issued and trust_score >= 70
            else "Trust score not issued"
            if not trust_score_issued
            else "Trust score below threshold",
        ),
        (integrity_score >= 70, "Model integrity verified" if integrity_score >= 70 else "Model integrity needs review"),
    ]
    checks = "".join(
        f'<div class="readiness-check {"ok" if ok else "bad"}"><b>{"✓" if ok else "!"}</b><span>{h(label)}</span></div>'
        for ok, label in checklist
    )
    st.markdown(
        f"""
        <section class="overview-readiness {'blocked' if blocked else ''}">
          <div class="readiness-copy"><div class="overview-eyebrow">Deployment Readiness</div><h2>{h(readiness)}</h2><p>{h(note)}</p></div>
          <div class="overview-checks">{checks}</div>
          <div id="overview-report-action"></div>
        </section>
        """,
        unsafe_allow_html=True,
    )
    st.button(
        "View Full Report  →",
        key="overview-view-report",
        on_click=_navigate,
        args=("Reports",),
    )


def render_metric_cards(
    trust_score: float,
    integrity_score: float,
    dependency_risk: float,
    dep_count: int,
    metric_histories: tuple[list[float], list[float], list[float]],
    trust_score_issued: bool,
    security_gate_passed: bool,
) -> None:
    tier, tier_name = _tier(trust_score) if trust_score_issued else ("–", "Score unavailable")
    if trust_score_issued and not security_gate_passed:
        tier_name = f"{tier_name} · Deployment blocked"
    trust_note = "High trust" if trust_score >= 85 else "Review recommended" if trust_score >= 70 else "High risk"
    trust_value = f"{trust_score:.0f}<small>/ 100</small>" if trust_score_issued else "Not issued"
    trust_detail = (
        f"{h(trust_note)}<br>{'Security Gate failed · Do not deploy' if not security_gate_passed else 'Ready for production' if trust_score >= 85 else 'Policy review required'}"
        if trust_score_issued
        else "Assessment score unavailable"
    )
    integrity_note = "No integrity issues detected" if integrity_score >= 85 else "Integrity evidence requires review"
    dep_note = "All dependencies verified" if dep_count == 0 else f"{dep_count} actionable finding(s)"
    trust_values, integrity_values, dependency_values = metric_histories
    st.markdown(
        f"""
        <section class="overview-metrics">
          <article class="overview-metric">
            <div class="metric-label">Trust Score <span>{_icon('info')}</span></div>
            <div class="metric-core"><i class="metric-round red">{_icon('shield')}</i><div><strong>{trust_value}</strong><p>{trust_detail}</p></div></div>
            {_sparkline(trust_values, '#AD3438') if trust_score_issued else ''}
          </article>
          <article class="overview-metric">
            <div class="metric-label">Model Integrity <span>{_icon('info')}</span></div>
            <div class="metric-core"><i class="metric-round green">{_icon('integrity')}</i><div><strong>{integrity_score:.0f}<small>/ 100</small></strong><p>{h(integrity_note)}</p></div></div>
            {_sparkline(integrity_values, '#238656')}
          </article>
          <article class="overview-metric">
            <div class="metric-label">Dependency Risk <span>{_icon('info')}</span></div>
            <div class="metric-core"><i class="metric-round green">{_icon('database')}</i><div><strong>{dependency_risk:.0f}<small>/ 100</small></strong><p>{'Low risk' if dependency_risk < 25 else 'Elevated risk'}<br>{h(dep_note)}</p></div></div>
            {_sparkline(dependency_values, '#397B5B')}
          </article>
          <article class="overview-metric tier-card">
            <div class="metric-label">Model Assurance Tier <span>{_icon('info')}</span></div>
            <div class="tier-content">
              <div class="overview-tier-ring" style="--tier-score:{trust_score if trust_score_issued else 0:.0f}%"><span><b>{h(tier)}</b><small>Tier</small></span></div>
              <div class="tier-legend"><p class="active"><i></i>A – High Assurance</p><p><i></i>B – Moderate</p><p><i></i>C – Limited</p><p><i></i>D – High Risk</p><strong>{h(tier_name)}</strong></div>
            </div>
          </article>
        </section>
        """,
        unsafe_allow_html=True,
    )


def build_drift_figure(scan_rows: list[dict[str, Any]], trust_score: float, threshold: float = 70.0) -> go.Figure:
    ordered = sorted(scan_rows, key=lambda row: str(row.get("generated_at") or ""))[-30:]
    if ordered:
        dates = [pd.to_datetime(row.get("generated_at")) for row in ordered]
        scores = [float(row.get("trust_score") or 0.0) for row in ordered]
    else:
        dates = [datetime.now(timezone.utc)]
        scores = [trust_score]
    figure = go.Figure()
    figure.add_trace(go.Scatter(
        x=dates,
        y=scores,
        mode="lines+markers",
        name="Trust Score",
        line={"color": "#AD3438", "width": 2.2, "shape": "spline"},
        marker={"color": "#AD3438", "size": 4},
        fill="tozeroy",
        fillcolor="rgba(217,124,121,.16)",
        hovertemplate="%{x|%b %d, %Y}<br>Trust score: %{y:.1f}<extra></extra>",
    ))
    figure.add_hline(y=threshold, line_dash="dash", line_color="#C9585B", line_width=1.4)
    figure.update_layout(
        height=218,
        margin={"l": 8, "r": 8, "t": 8, "b": 8},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=False,
        hovermode="x unified",
        font={"family": "Inter, Arial, sans-serif", "color": "#68707A", "size": 10},
        yaxis={"range": [0, 100], "tickvals": [0, 25, 50, 75, 100], "gridcolor": "#EEE6E1", "zeroline": False, "title": None},
        xaxis={"showgrid": True, "gridcolor": "#F2EBE7", "title": None, "tickformat": "%b %d"},
    )
    return figure


def render_model_summary(model_name: str, model_record: dict[str, Any], generated_at: Any, status: str) -> None:
    status_label, status_class = _status_label(status)
    st.markdown(
        f"""
        <section class="model-summary-card">
          <div id="overview-model-action"></div>
          <div class="overview-card-head"><h3>Model Summary</h3></div>
          <div class="model-summary-grid">
            <div class="summary-item">{_icon('model')}<span><small>Active Model</small><strong>{h(model_name)}</strong></span></div>
            <div class="summary-item no-icon"><span><small>Version</small><strong class="version-tag">{h(str(model_record.get('version') or 'Not set'))}</strong></span></div>
            <div class="summary-item">{_icon('chip')}<span><small>Model Type</small><strong>{h(str(model_record.get('algorithm') or model_record.get('framework') or 'Classifier'))}</strong></span></div>
            <div class="summary-item no-icon"><span><small>Last Evaluated</small><strong>{h(_short_datetime(generated_at))}</strong></span></div>
            <div class="summary-item">{_icon('database')}<span><small>Environment</small><strong>Production</strong></span></div>
            <div class="summary-item no-icon"><span><small>Evaluation Status</small><strong class="summary-status {status_class}"><i></i>{h(status_label)}</strong></span></div>
          </div>
        </section>
        """,
        unsafe_allow_html=True,
    )
    st.button(
        "View Model  →",
        key="overview-view-model",
        on_click=_navigate,
        args=("Model Registry",),
    )


def render_recent_assessments(scans: list[dict[str, Any]]) -> None:
    rows = []
    for scan in scans[:4]:
        status_label, status_class = _status_label(str(scan.get("status") or "warning"))
        rows.append(
            f"<div class='overview-table-row'><strong>{h(str(scan.get('model_name') or 'Unknown'))}</strong>"
            f"<span>{h(str(scan.get('version') or '1.0'))}</span><span>Full Assessment</span>"
            f"<span>{float(scan.get('trust_score') or 0):.0f}</span><span><i class='status-chip {status_class}'>● {h(status_label)}</i></span>"
            f"<span>{h(_short_date(scan.get('generated_at')))}</span><b>⋮</b></div>"
        )
    if not rows:
        rows.append("<div class='overview-empty'>Run an assessment to populate this history.</div>")
    st.markdown(
        f"""
        <section class="overview-table-card recent-card">
          <div id="overview-assessments-action"></div>
          <div class="overview-card-head"><h3>Recent Assessments</h3></div>
          <div class="overview-table-head"><span>Model Name</span><span>Version</span><span>Assessment Type</span><span>Trust Score</span><span>Status</span><span>Date</span><span></span></div>
          {''.join(rows)}
        </section>
        """,
        unsafe_allow_html=True,
    )
    st.button(
        "View All  →",
        key="overview-view-assessments",
        on_click=_navigate,
        args=("Model Registry",),
    )


def render_alerts(findings: list[dict[str, Any]], generated_at: Any) -> None:
    rows = []
    for finding in findings[:4]:
        severity = str(finding.get("severity") or "low").lower()
        rows.append(
            f"<div class='alert-table-row'><span><i class='severity-chip {h(severity)}'>● {h(severity.title())}</i></span>"
            f"<strong>{h(str(finding.get('title') or finding.get('description') or 'Assessment finding'))}</strong>"
            f"<span>{h(_short_datetime(generated_at))}</span><b>⋮</b></div>"
        )
    if not rows:
        rows.append("<div class='overview-empty'>No actionable alerts for this assessment.</div>")
    st.markdown(
        f"""
        <section class="overview-table-card alerts-card">
          <div id="overview-alerts-action"></div>
          <div class="overview-card-head"><h3>Alerts</h3></div>
          <div class="alert-table-head"><span>Severity</span><span>Message</span><span>Time</span><span></span></div>
          {''.join(rows)}
        </section>
        """,
        unsafe_allow_html=True,
    )
    st.button(
        "View All  →",
        key="overview-view-alerts",
        on_click=_navigate,
        args=("Alerts",),
    )
