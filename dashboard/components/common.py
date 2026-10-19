from __future__ import annotations

from datetime import datetime
from html import escape

import streamlit as st

from core.score_evidence import trust_score_evidence


def h(value: object) -> str:
    return escape(str(value))


def render_score_evidence(report: dict) -> None:
    evidence = trust_score_evidence(report)
    if not evidence["cap_applied"] or evidence["published_score"] is None:
        return
    measured = evidence["measured_score"]
    measured_text = f"Measured assessment score: {measured:.2f}/100. " if measured is not None else ""
    st.caption(
        f"{measured_text}Trust Score: {evidence['published_score']:.2f}/100, "
        f"limited by the unsigned-model cap of {evidence['cap']:.0f}. "
        "This score does not approve deployment; failed Security Gates still block it."
    )


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
        "security_gate": "Security Gate",
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


def render_page_head(title: str, subtitle: str) -> None:
    st.markdown(
        f"<div class='page-head'><h1>{h(title)}</h1><p>{h(subtitle)}</p></div>",
        unsafe_allow_html=True,
    )
