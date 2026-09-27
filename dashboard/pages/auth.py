from __future__ import annotations

import streamlit as st

from core.auth import create_access_token, create_refresh_token
from core.db import authenticate_user, create_user, init_db


def require_dashboard_auth() -> dict:
    init_db()
    if st.session_state.get("auth_user"):
        return st.session_state["auth_user"]

    st.markdown('<div id="credora-login-mode"></div>', unsafe_allow_html=True)
    left, right = st.columns([56, 44], gap=None, vertical_alignment="center")
    with left:
        st.markdown(
            '<div class="login-panel" role="img" aria-label="Credora Model Assurance"></div>',
            unsafe_allow_html=True,
        )
    with right:
        with st.container(border=True):
            st.markdown('<div id="credora-auth-card"></div>', unsafe_allow_html=True)
            auth_mode = st.session_state.get("dashboard_auth_mode", "sign_in")
            if auth_mode == "sign_in":
                st.markdown(
                    "<div class='auth-heading'><h2>Welcome back</h2><p>Sign in to your Credora account to continue securing and validating your models.</p></div>",
                    unsafe_allow_html=True,
                )
                with st.form("credora-login"):
                    username = st.text_input("Email", placeholder="you@company.com")
                    password = st.text_input("Password", type="password", placeholder="Enter your password")
                    remember = st.checkbox("Remember me", value=True)
                    submitted = st.form_submit_button("Sign In  ->", type="primary", width="stretch")
                if submitted:
                    user = authenticate_user(username, password)
                    if user:
                        st.session_state["auth_user"] = user
                        st.session_state["access_token"] = create_access_token(user)
                        st.session_state["refresh_token"] = create_refresh_token(user)
                        st.session_state["remember_login"] = remember
                        st.rerun()
                    st.error("Invalid username or password")
                if st.button("Create Account", width="stretch", key="show-register"):
                    st.session_state["dashboard_auth_mode"] = "register"
                    st.rerun()
            else:
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
                if st.button("Back to Sign In", width="stretch", key="show-sign-in"):
                    st.session_state["dashboard_auth_mode"] = "sign_in"
                    st.rerun()
            st.markdown(
                '<div class="auth-divider">OR</div><div class="secure-access">Secure access with enterprise-grade encryption</div>',
                unsafe_allow_html=True,
            )
    st.stop()
