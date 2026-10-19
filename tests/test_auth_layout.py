from streamlit.testing.v1 import AppTest


def test_login_and_registration_render_with_shared_layout(monkeypatch) -> None:
    monkeypatch.setattr("dashboard.pages.auth.init_db", lambda: None)
    app = AppTest.from_string(
        "from dashboard.pages.auth import require_dashboard_auth\n"
        "require_dashboard_auth()\n",
        default_timeout=60,
    ).run()
    assert not app.exception
    assert len(app.text_input) == 2
    app.button(key="show-register").click().run()
    assert not app.exception
    assert len(app.text_input) == 4
    assert any(field.label == "Confirm password" for field in app.text_input)
    app.button(key="show-sign-in").click().run()
    assert not app.exception
    assert len(app.text_input) == 2
