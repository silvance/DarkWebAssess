"""Tests for SMTP email delivery.

No real network: smtplib.SMTP / SMTP_SSL are replaced with a fake that
records what would have been done (starttls, login, send). We assert
is_configured semantics, message construction, and transport selection
(STARTTLS vs implicit SSL vs plain).
"""
from __future__ import annotations

import pytest

from app import config
from app.delivery import email as em


class _FakeSMTP:
    """Records interactions; used for both SMTP and SMTP_SSL."""
    instances = []

    def __init__(self, host, port, timeout=None, context=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context = context
        self.started_tls = False
        self.logged_in = None
        self.sent = None
        _FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        self.started_tls = True

    def login(self, user, password):
        self.logged_in = (user, password)

    def send_message(self, msg, from_addr=None, to_addrs=None):
        self.sent = {"msg": msg, "from": from_addr, "to": to_addrs}


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    _FakeSMTP.instances = []
    # Clean SMTP config each test; individual tests set what they need.
    for k, v in {
        "SMTP_HOST": "", "SMTP_PORT": 587, "SMTP_USER": "", "SMTP_PASSWORD": "",
        "SMTP_FROM": "", "SMTP_TO": "", "SMTP_USE_TLS": True, "SMTP_USE_SSL": False,
        "SMTP_TIMEOUT": 30,
    }.items():
        monkeypatch.setattr(config, k, v)
    monkeypatch.setattr(em.smtplib, "SMTP", _FakeSMTP)
    monkeypatch.setattr(em.smtplib, "SMTP_SSL", _FakeSMTP)
    yield


def _configure(monkeypatch, **overrides):
    base = {
        "SMTP_HOST": "smtp.example.com", "SMTP_FROM": "bot@example.com",
        "SMTP_TO": "me@example.com",
    }
    base.update(overrides)
    for k, v in base.items():
        monkeypatch.setattr(config, k, v)


# --- is_configured ------------------------------------------------------
def test_not_configured_by_default():
    assert em.is_configured() is False
    assert "SMTP_HOST" in em.unconfigured_reason()


def test_configured_when_host_from_to_set(monkeypatch):
    _configure(monkeypatch)
    assert em.is_configured() is True


def test_recipients_parsing(monkeypatch):
    monkeypatch.setattr(config, "SMTP_TO", " a@x.co , b@x.co ,")
    assert em._recipients() == ["a@x.co", "b@x.co"]


# --- message construction ----------------------------------------------
def test_build_message_plain(monkeypatch):
    _configure(monkeypatch)
    msg = em.build_message("Subj", "hello")
    assert msg["Subject"] == "Subj"
    assert msg["From"] == "bot@example.com"
    assert msg["To"] == "me@example.com"
    assert msg.get_content().strip() == "hello"


def test_build_message_html_alternative(monkeypatch):
    _configure(monkeypatch)
    msg = em.build_message("Subj", "plain", body_html="<b>hi</b>")
    assert msg.is_multipart()
    types = {p.get_content_type() for p in msg.iter_parts()}
    assert "text/plain" in types
    assert "text/html" in types


# --- send: transport selection -----------------------------------------
def test_send_starttls_path(monkeypatch):
    _configure(monkeypatch, SMTP_USER="u", SMTP_PASSWORD="p")
    ok, err = em.send_email("s", "b")
    assert ok is True and err is None
    inst = _FakeSMTP.instances[-1]
    assert inst.started_tls is True          # STARTTLS used
    assert inst.logged_in == ("u", "p")      # auth performed
    assert inst.sent["to"] == ["me@example.com"]


def test_send_ssl_path(monkeypatch):
    _configure(monkeypatch, SMTP_USE_TLS=False, SMTP_USE_SSL=True, SMTP_PORT=465)
    ok, err = em.send_email("s", "b")
    assert ok is True
    inst = _FakeSMTP.instances[-1]
    # Implicit SSL: no starttls call.
    assert inst.started_tls is False
    assert inst.port == 465


def test_send_plain_no_auth(monkeypatch):
    _configure(monkeypatch, SMTP_USE_TLS=False)
    ok, err = em.send_email("s", "b")
    assert ok is True
    inst = _FakeSMTP.instances[-1]
    assert inst.started_tls is False
    assert inst.logged_in is None            # no SMTP_USER → no login


def test_send_unconfigured_returns_error():
    ok, err = em.send_email("s", "b")
    assert ok is False
    assert "not configured" in err


def test_send_override_recipient(monkeypatch):
    _configure(monkeypatch)
    ok, err = em.send_email("s", "b", to="other@x.co,third@x.co")
    assert ok is True
    assert _FakeSMTP.instances[-1].sent["to"] == ["other@x.co", "third@x.co"]


def test_send_swallows_transport_error(monkeypatch):
    _configure(monkeypatch)

    def boom(*a, **k):
        raise ConnectionError("smtp down")
    monkeypatch.setattr(em.smtplib, "SMTP", boom)
    ok, err = em.send_email("s", "b")
    assert ok is False
    assert "ConnectionError" in err


# --- doctor integration ------------------------------------------------
def test_doctor_email_check_states(monkeypatch):
    from app.cli import cmd_doctor
    for k in ("SMTP_HOST", "SMTP_FROM", "SMTP_TO"):
        monkeypatch.delenv(k, raising=False)
    assert cmd_doctor._check_email().status == "INFO"

    monkeypatch.setenv("SMTP_HOST", "smtp.x")
    assert cmd_doctor._check_email().status == "WARN"  # partial

    monkeypatch.setenv("SMTP_FROM", "a@x")
    monkeypatch.setenv("SMTP_TO", "b@x")
    assert cmd_doctor._check_email().status == "OK"
