from __future__ import annotations

import pandas as pd
import streamlit as st

from core.db import (
    add_trusted_signer,
    admin_set_password,
    create_deployment_override,
    create_user,
    get_deployment_policy,
    get_sensitive_label_taxonomy,
    get_trust_weights,
    list_audit_logs,
    list_scans,
    list_trusted_signers,
    list_users,
    platform_analytics,
    revoke_user_sessions,
    set_deployment_policy,
    set_sensitive_label_taxonomy,
    set_trust_weights,
    set_user_disabled,
    update_user_role,
)
from dashboard.components.common import render_page_head


def render_admin_page(current_user: dict) -> None:
    render_page_head("Admin", "Users, platform visibility, policy, audit, and release controls")
    if current_user.get("role") not in {"reviewer", "admin"}:
        st.error("Admin access is not available for this account.")
        st.stop()

    analytics = platform_analytics()
    a1, a2, a3, a4 = st.columns(4)
    a1.metric("Active users", analytics.get("active_users", 0))
    a2.metric("Models", analytics.get("total_models", 0))
    a3.metric("Scans", analytics.get("total_scans", 0))
    dist = analytics.get("trust_score_distribution", {})
    a4.metric("Warnings / fails", f"{dist.get('warning', 0)} / {dist.get('fail', 0)}")

    tabs = st.tabs(["Users", "Platform Scans", "Policy", "Review", "Security Audit"])
    with tabs[0]:
        st.markdown("### User Management")
        users_df = pd.DataFrame(list_users())
        if not users_df.empty:
            columns = [
                column
                for column in ["id", "username", "email", "role", "created_at", "last_login_at", "disabled"]
                if column in users_df.columns
            ]
            st.dataframe(users_df[columns], hide_index=True, width="stretch")
        if current_user.get("role") == "admin":
            with st.form("admin-create-user"):
                c1, c2, c3, c4 = st.columns([0.8, 0.9, 0.8, 0.6])
                username = c1.text_input("Username")
                email = c2.text_input("Email")
                password = c3.text_input("Temporary password", type="password")
                role = c4.selectbox("Role", ["uploader", "reviewer", "admin"])
                if st.form_submit_button("Create user", type="primary"):
                    try:
                        create_user(username, password, email or None, role=role)
                        st.success("User created.")
                        st.rerun()
                    except ValueError as exc:
                        st.error(str(exc))
            with st.form("admin-update-user"):
                users = list_users()
                user_ids = [int(row["id"]) for row in users]
                target = (
                    st.selectbox(
                        "Account",
                        user_ids,
                        format_func=lambda uid: next(
                            (user["username"] for user in users if int(user["id"]) == uid), str(uid)
                        ),
                    )
                    if user_ids
                    else None
                )
                col1, col2, col3 = st.columns(3)
                new_role = col1.selectbox("New role", ["", "uploader", "reviewer", "admin"])
                disabled = col2.selectbox("Account status", ["No change", "Active", "Disabled"])
                reset_password = col3.text_input("Force new password", type="password")
                revoke = st.checkbox("Revoke active sessions")
                if st.form_submit_button("Apply account changes") and target is not None:
                    if new_role:
                        update_user_role(target, new_role, actor_id=int(current_user["id"]))
                    if disabled != "No change":
                        set_user_disabled(target, disabled == "Disabled", actor_id=int(current_user["id"]))
                    if reset_password:
                        admin_set_password(target, reset_password, actor_id=int(current_user["id"]))
                    if revoke:
                        revoke_user_sessions(target, actor_id=int(current_user["id"]))
                    st.success("Account updated.")
                    st.rerun()
        else:
            st.info("Reviewer accounts can view platform evidence, but only admins can manage accounts.")

    with tabs[1]:
        st.markdown("### Platform-Wide Scans")
        all_scans = pd.DataFrame(list_scans(limit=500, include_all=True))
        if not all_scans.empty:
            search = st.text_input("Filter by user id, model, status, or date text")
            shown = all_scans
            if search:
                mask = shown.astype(str).apply(
                    lambda column: column.str.contains(search, case=False, na=False)
                ).any(axis=1)
                shown = shown[mask]
            st.dataframe(shown, hide_index=True, width="stretch")
        findings = analytics.get("common_security_findings", [])
        if findings:
            st.markdown("### Common Security Findings")
            st.dataframe(pd.DataFrame(findings), hide_index=True, width="stretch")

    with tabs[2]:
        st.markdown("### Server-Side Release Policy")
        if current_user.get("role") != "admin":
            st.info("Only admins can change policy, trust weights, signer keys, or taxonomy.")
        policy = get_deployment_policy()
        with st.form("deployment-policy"):
            p1, p2, p3, p4 = st.columns(4)
            minimum_trust_score = p1.number_input(
                "Minimum trust", 0.0, 100.0, float(policy.get("minimum_trust_score", 85)), 1.0
            )
            minimum_classifier_score = p2.number_input(
                "Minimum classifier", 0.0, 100.0, float(policy.get("minimum_classifier_score", 85)), 1.0
            )
            minimum_adversarial_score = p3.number_input(
                "Minimum adversarial", 0.0, 100.0, float(policy.get("minimum_adversarial_score", 80)), 1.0
            )
            minimum_sensitive_recall = p4.number_input(
                "Minimum sensitive recall", 0.0, 1.0, float(policy.get("minimum_sensitive_recall", 0.90)), 0.01
            )
            if st.form_submit_button("Save release policy", disabled=current_user.get("role") != "admin"):
                set_deployment_policy(
                    {
                        "minimum_trust_score": minimum_trust_score,
                        "minimum_classifier_score": minimum_classifier_score,
                        "minimum_adversarial_score": minimum_adversarial_score,
                        "minimum_sensitive_recall": minimum_sensitive_recall,
                    },
                    actor_id=int(current_user["id"]),
                )
                st.success("Policy saved.")
                st.rerun()
        weights = get_trust_weights()
        with st.expander("Trust score module weights"):
            edited = st.data_editor(
                pd.DataFrame([{"module": key, "weight": value} for key, value in weights.items()]),
                hide_index=True,
                width="stretch",
            )
            if st.button("Save weights", disabled=current_user.get("role") != "admin"):
                set_trust_weights(
                    dict(zip(edited["module"], edited["weight"])), actor_id=int(current_user["id"])
                )
                st.success("Weights saved and normalized for future scans.")
                st.rerun()
        with st.expander("Sensitive label taxonomy"):
            labels_text = st.text_area("Comma-separated label hints", ", ".join(get_sensitive_label_taxonomy()))
            if st.button("Save taxonomy", disabled=current_user.get("role") != "admin"):
                set_sensitive_label_taxonomy(
                    [item.strip() for item in labels_text.split(",")], actor_id=int(current_user["id"])
                )
                st.success("Sensitive taxonomy saved.")
                st.rerun()
        with st.expander("Trusted Ed25519 public signers"):
            signers = list_trusted_signers(include_inactive=True)
            if signers:
                st.dataframe(pd.DataFrame(signers), hide_index=True, width="stretch")
            with st.form("trusted-signer"):
                signer_name = st.text_input("Signer name")
                public_key = st.text_area("Public key PEM")
                if st.form_submit_button("Add trusted signer", disabled=current_user.get("role") != "admin"):
                    add_trusted_signer(signer_name, public_key, actor_id=int(current_user["id"]))
                    st.success("Trusted signer added.")
                    st.rerun()

    with tabs[3]:
        st.markdown("### Deployment Gate Override")
        st.caption("Reviewer/admin approval is required for any manual override.")
        all_scan_rows = list_scans(limit=500, include_all=True)
        if all_scan_rows:
            scan_id = st.selectbox(
                "Scan",
                [int(row["id"]) for row in all_scan_rows],
                format_func=lambda sid: next(
                    (
                        f"#{row['id']} | user {row.get('owner_id')} | {row.get('model_name')} | "
                        f"{row.get('status')} | {row.get('trust_score')}"
                        for row in all_scan_rows
                        if int(row["id"]) == sid
                    ),
                    str(sid),
                ),
            )
            decision = st.radio("Decision", ["approved", "rejected"], horizontal=True)
            justification = st.text_area("Required justification")
            if st.button("Record override decision", type="primary"):
                try:
                    create_deployment_override(scan_id, decision, justification, int(current_user["id"]))
                    st.success("Override decision logged.")
                except ValueError as exc:
                    st.error(str(exc))
        else:
            st.info("No scans are available for review.")

    with tabs[4]:
        st.markdown("### Authentication and Security Audit")
        if current_user.get("role") == "admin":
            logs = list_audit_logs(limit=300)
            if logs:
                st.dataframe(pd.DataFrame(logs), hide_index=True, width="stretch")
            else:
                st.info("No audit events have been recorded yet.")
        else:
            st.info("Only admins can view authentication and security audit logs.")
