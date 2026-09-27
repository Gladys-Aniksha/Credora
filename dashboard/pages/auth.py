from __future__ import annotations

import streamlit as st

from core.auth import create_access_token, create_refresh_token
from core.db import authenticate_user, create_user, init_db


def require_dashboard_auth() -> dict:
    init_db()
    if st.session_state.get("auth_user"):
        return st.session_state["auth_user"]

    st.markdown('<div id="credora-login-mode"></div>', unsafe_allow_html=True)
    left, right = st.columns(2, gap=None, vertical_alignment="center")
    with left:
        st.markdown(
            """
            <div class="login-panel">
              <div>
                <div class="login-brand">
                  <div class="credora-emblem">C</div>
                  <div class="login-wordmark">CREDORA<span>MODEL ASSURANCE</span></div>
                </div>
                <div class="login-rule"></div>
                <h1>Trust and security assessment<br>for encrypted traffic classifiers.</h1>
                <div class="login-feature-row">
                  <div class="login-feature"><div class="login-feature-icon">&#10003;</div>Verify<br>Models</div>
                  <div class="login-feature"><div class="login-feature-icon">!</div>Assess<br>Risks</div>
                  <div class="login-feature"><div class="login-feature-icon">III</div>Strengthen<br>Trust</div>
                </div>
              </div>
              <div class="login-signature">Trust<br>Encrypted<br>Intelligence</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with right:
        with st.container(border=True):
            st.markdown('<div id="credora-auth-card"></div>', unsafe_allow_html=True)
            login_tab, register_tab = st.tabs(["Sign In", "Register Account"])
            with login_tab:
                st.markdown(
                    "<div class='auth-heading'><h2>Welcome back</h2><p>Sign in to your Credora account to continue securing and validating your models.</p></div>",
                    unsafe_allow_html=True,
                )
                with st.form("credora-login"):
                    username = st.text_input("Email or username", placeholder="you@company.com")
                    password = st.text_input("Password", type="password", placeholder="Enter your password")
                    remember = st.checkbox("Remember me", value=True)
                    submitted = st.form_submit_button("Sign in", type="primary", width="stretch")
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
                    "<div class='auth-heading'><h2>Create your account</h2><p>Start an isolated workspace for your models, assessments, reports, and monitoring history.</p></div>",
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
            st.markdown('<div class="secure-access">Secure access protected by signed sessions and role-based permissions</div>', unsafe_allow_html=True)
    st.stop()
