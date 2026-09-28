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
                    username = st.text_input(
                        "Email",
                        placeholder="you@company.com",
                        autocomplete="username",
                    )
                    password = st.text_input(
                        "Password",
                        type="password",
                        placeholder="Enter your password",
                        autocomplete="current-password",
                    )
                    remember_col, forgot_col = st.columns(2, gap="small", vertical_alignment="center")
                    with remember_col:
                        remember = st.checkbox("Remember me", value=True)
                    with forgot_col:
                        forgot_password = st.form_submit_button(
                            "Forgot password?",
                            type="tertiary",
                            width="stretch",
                        )
                    submitted = st.form_submit_button(
                        "Sign In  →",
                        type="primary",
                        width="stretch",
                    )
                if forgot_password:
                    st.info("Contact a Credora administrator to reset your password.")
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
                    new_username = st.text_input("Username", autocomplete="username")
                    email = st.text_input(
                        "Email address",
                        value="",
                        autocomplete="email",
                    )
                    new_password = st.text_input(
                        "Password",
                        type="password",
                        autocomplete="new-password",
                    )
                    created = st.form_submit_button(
                        "Create Account  →",
                        type="primary",
                        width="stretch",
                    )
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
                """
                <div class="auth-divider">OR</div>
                <div class="secure-access">
                  <svg aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.75" viewBox="0 0 24 24">
                    <path d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" stroke-linecap="round" stroke-linejoin="round"></path>
                  </svg>
                  <span>Secure access with enterprise-grade encryption</span>
                </div>
                """,
                unsafe_allow_html=True,
            )
    st.stop()
