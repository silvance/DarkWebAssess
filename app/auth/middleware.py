"""Streamlit auth gate.

Usage from `app/ui/streamlit_app.py`:

    from app.auth.middleware import gate, require_role
    user = gate()
    require_role(user, "admin")  # in admin-only pages

The gate is a no-op when `AUTH_ENABLED=0` (default) so existing single-user
setups keep working. When enabled, it renders a login form and stops
execution until credentials succeed against the `users` table. The user
dict (without password_hash) is returned and also stashed in
`st.session_state.auth_user`.

There is also a "first run" branch: when AUTH_ENABLED=1 and the users table
is empty, the gate offers a one-shot bootstrap form to create the initial
admin account.
"""
import os
from typing import Optional

from app.config import AUTH_ENABLED
from app.database import get_connection


def _safe_user(row: dict) -> dict:
    return {k: v for k, v in row.items() if k != "password_hash"}


def _get_streamlit():
    try:
        import streamlit as st  # noqa: WPS433 — only here to avoid a hard dep at import time
        return st
    except ImportError:
        return None


def gate(*, allow_anonymous: bool = False) -> Optional[dict]:
    """Block until a user is authenticated; return the user dict.

    When auth is disabled, returns a synthetic user with role=admin so any
    `require_role` checks downstream pass through transparently.
    """
    if not AUTH_ENABLED:
        return {"username": os.getenv("AUTH_DEFAULT_USER", "local"),
                "role": "admin", "enabled": True, "auth_disabled": True}

    st = _get_streamlit()
    if st is None:
        # Outside Streamlit (CLI / tests / scheduler): no UI to render.
        return None

    if "auth_user" in st.session_state and st.session_state.auth_user:
        return st.session_state.auth_user

    # Bootstrap: offer to create the first admin if no users exist yet.
    with get_connection() as conn:
        from app.auth.users import authenticate, count_users, create_user

        if count_users(conn) == 0:
            st.title("First-run setup")
            st.info(
                "No users exist yet. Create an admin account to enable login. "
                "(Set `AUTH_ENABLED=0` instead if you want to disable auth.)"
            )
            with st.form("bootstrap_admin"):
                username = st.text_input("Admin username", value="admin")
                password = st.text_input("Password", type="password")
                full_name = st.text_input("Full name (optional)")
                submitted = st.form_submit_button("Create admin")
            if submitted:
                if not username or not password:
                    st.error("Both username and password are required.")
                    st.stop()
                with get_connection() as bootstrap_conn:
                    create_user(
                        bootstrap_conn, username, password,
                        role="admin", full_name=full_name or None, actor="bootstrap",
                    )
                    bootstrap_conn.commit()
                st.success("Admin created. Sign in below.")
                st.rerun()
            st.stop()

        # Normal login form
        st.title("Sign in")
        with st.form("login"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign in")
        if submitted:
            with get_connection() as login_conn:
                user = authenticate(login_conn, username, password)
                login_conn.commit()
            if user is None:
                st.error("Invalid credentials, or account disabled.")
                st.stop()
            st.session_state.auth_user = _safe_user(user)
            st.rerun()
        if not allow_anonymous:
            st.stop()
    return None


def require_role(user: Optional[dict], required: str) -> None:
    """Halt the page if `user` doesn't have the required role."""
    from app.auth.users import has_role

    st = _get_streamlit()
    if user is None or not has_role(user.get("role"), required):
        if st is not None:
            st.error(f"This page requires the `{required}` role.")
            st.stop()
        raise PermissionError(f"role required: {required}")


def logout() -> None:
    st = _get_streamlit()
    if st is None:
        return
    st.session_state.pop("auth_user", None)
    st.rerun()
