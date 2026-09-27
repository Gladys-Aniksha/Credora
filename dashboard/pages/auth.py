from __future__ import annotations

import streamlit as st

from core.auth import create_access_token, create_refresh_token
from core.db import authenticate_user, create_user, init_db


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
                <p>Evaluate sklearn and ONNX tabular classifiers, monitor drift, test feature-space evasion resilience, and generate cryptographically signed inspection manifests.</p>
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
                st.markdown(
                    "<h2>Sign in to Credora</h2><p>Enter your credentials to access classifier audit runs and benchmark manifests.</p>",
                    unsafe_allow_html=True,
                )
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
            with register_tab:
                st.markdown(
                    "<h2>Register account</h2><p>Create an uploader workspace for isolated models, scans, reports, and monitoring history.</p>",
                    unsafe_allow_html=True,
                )
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
            st.markdown(
                '<div class="auth-note"><span>Local Instance</span><div>Documentation · Report an Issue · Release Notes</div></div>',
                unsafe_allow_html=True,
            )
    st.stop()
