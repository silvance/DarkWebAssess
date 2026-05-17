"""Tests for the onion collector and source-type dispatch.

We never make real Tor connections in tests — `requests.Session.get` is
monkeypatched to return canned responses. The goal is to verify:

- the URL allowlist (only *.onion accepted)
- the SOCKS5h proxy config is wired correctly (DNS-via-Tor, not local)
- the Pydantic config rejects mismatched type/URL combinations
- pipeline dispatches `type: onion` to the onion collector and not to RSS
"""
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from app.collectors import onion_collector
from app.config_models import SourceEntry


# --- URL allowlist ------------------------------------------------------
def test_is_onion_url_accepts_v2_and_v3():
    v3 = "http://" + ("a" * 56) + ".onion/"
    v2 = "http://" + ("b" * 16) + ".onion/path"
    assert onion_collector.is_onion_url(v3) is True
    assert onion_collector.is_onion_url(v2) is True


def test_is_onion_url_rejects_clearweb():
    assert onion_collector.is_onion_url("https://example.com/") is False
    assert onion_collector.is_onion_url("http://example.onion.attacker.com/") is False
    assert onion_collector.is_onion_url("https://example.onion.example.com/") is False


def test_is_onion_url_rejects_garbage():
    assert onion_collector.is_onion_url("") is False
    assert onion_collector.is_onion_url("not a url") is False
    assert onion_collector.is_onion_url("http://shorthost.onion") is False  # 9 chars, not 16/56


# --- Tor session config -------------------------------------------------
def test_build_tor_session_uses_socks5h_for_dns_safety():
    """`socks5h://` resolves DNS at the Tor exit. `socks5://` would resolve
    locally and leak the onion lookup to the host's resolver."""
    session = onion_collector.build_tor_session(host="127.0.0.1", port=9050)
    assert session.proxies["http"] == "socks5h://127.0.0.1:9050"
    assert session.proxies["https"] == "socks5h://127.0.0.1:9050"
    assert "User-Agent" in session.headers


def test_build_tor_session_honors_overrides():
    session = onion_collector.build_tor_session(host="tor", port=9999, user_agent="X")
    assert session.proxies["http"] == "socks5h://tor:9999"
    assert session.headers["User-Agent"] == "X"


# --- collect_onion ------------------------------------------------------
def _fake_response(text, *, status_code: int = 200, content_type: str = "text/html"):
    resp = MagicMock()
    resp.status_code = status_code
    if isinstance(text, bytes):
        resp.content = text
        resp.text = text.decode("utf-8", errors="replace")
    else:
        resp.text = text
        resp.content = text.encode("utf-8")
    resp.headers = {"Content-Type": content_type}
    resp.raise_for_status = MagicMock()
    return resp


def test_collect_onion_refuses_clearweb_url(monkeypatch):
    """Defense in depth: even if config validation is bypassed somehow,
    the collector itself must refuse to send a clearweb URL through Tor."""
    monkeypatch.setattr(onion_collector, "build_tor_session",
                        lambda **kw: pytest.fail("session was built; should have refused first"))
    with pytest.raises(RuntimeError, match="non-onion"):
        list(onion_collector.collect_onion(
            {"name": "X", "type": "onion", "url": "https://example.com/"}
        ))


def test_collect_onion_yields_normalized_doc(monkeypatch):
    onion_url = "http://" + ("a" * 56) + ".onion/"
    body = "<html><head><title>Leak Watch</title></head><body><p>Hello darkness</p></body></html>"

    fake_session = MagicMock()
    fake_session.get.return_value = _fake_response(body)
    monkeypatch.setattr(onion_collector, "build_tor_session", lambda **kw: fake_session)

    docs = list(onion_collector.collect_onion(
        {"name": "Leak Watch", "type": "onion", "url": onion_url}
    ))
    assert len(docs) == 1
    doc = docs[0]
    assert doc["source_type"] == "onion"
    assert doc["source_url"] == onion_url
    assert doc["title"] == "Leak Watch"
    assert "Hello darkness" in doc["raw_text"]
    # And the GET went through the (Tor) session, not bare requests.
    fake_session.get.assert_called_once()


def test_collect_onion_drops_binary_octet_stream(monkeypatch):
    """Hard policy: a binary response yields ZERO documents. We do not
    store a placeholder row — that would let a hostile source inject text
    into our DB by abusing the placeholder."""
    onion_url = "http://" + ("c" * 56) + ".onion/file"
    fake_session = MagicMock()
    fake_session.get.return_value = _fake_response(
        b"\x00\x01\x02\x03binary garbage",
        content_type="application/octet-stream",
    )
    monkeypatch.setattr(onion_collector, "build_tor_session", lambda **kw: fake_session)

    docs = list(onion_collector.collect_onion(
        {"name": "Bin", "type": "onion", "url": onion_url}
    ))
    assert docs == []


def test_collect_onion_drops_jpeg_even_with_lying_mime(monkeypatch):
    """If the server lies about content-type but the bytes are clearly
    a JPEG, we still reject. Magic-byte sniff backs up the MIME allowlist."""
    onion_url = "http://" + ("d" * 56) + ".onion/lying.html"
    jpeg_bytes = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01...rest of a jpeg"
    fake_session = MagicMock()
    fake_session.get.return_value = _fake_response(
        jpeg_bytes, content_type="text/html",
    )
    monkeypatch.setattr(onion_collector, "build_tor_session", lambda **kw: fake_session)

    docs = list(onion_collector.collect_onion(
        {"name": "Liar", "type": "onion", "url": onion_url}
    ))
    assert docs == []


def test_collect_onion_drops_missing_content_type(monkeypatch):
    """Missing Content-Type used to be permitted; the new policy is strict
    allowlist, so unlabeled responses are dropped."""
    onion_url = "http://" + ("e" * 56) + ".onion/"
    fake_session = MagicMock()
    fake_session.get.return_value = _fake_response(
        "<html>x</html>", content_type="",
    )
    monkeypatch.setattr(onion_collector, "build_tor_session", lambda **kw: fake_session)

    docs = list(onion_collector.collect_onion(
        {"name": "Missing", "type": "onion", "url": onion_url}
    ))
    assert docs == []


def test_collect_onion_drops_image_mime(monkeypatch):
    onion_url = "http://" + ("f" * 56) + ".onion/img"
    fake_session = MagicMock()
    fake_session.get.return_value = _fake_response(
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
        content_type="image/png",
    )
    monkeypatch.setattr(onion_collector, "build_tor_session", lambda **kw: fake_session)

    docs = list(onion_collector.collect_onion(
        {"name": "Pic", "type": "onion", "url": onion_url}
    ))
    assert docs == []


# --- Pydantic config-time guards ----------------------------------------
def test_pydantic_rejects_type_onion_with_clearweb_url():
    with pytest.raises(ValidationError):
        SourceEntry(name="X", type="onion", url="https://example.com/")


def test_pydantic_rejects_type_rss_with_onion_url():
    onion_url = "http://" + ("a" * 56) + ".onion/feed"
    with pytest.raises(ValidationError):
        SourceEntry(name="X", type="rss", url=onion_url)


def test_pydantic_accepts_type_onion_with_onion_url():
    onion_url = "http://" + ("d" * 56) + ".onion/"
    entry = SourceEntry(name="X", type="onion", url=onion_url)
    assert entry.type == "onion"


# --- Pipeline dispatch --------------------------------------------------
def test_pipeline_dispatches_onion_type_to_onion_collector(monkeypatch, tmp_path):
    """End-to-end: write a sources.yaml with one onion source, monkeypatch
    both collectors, and confirm the right one gets called."""
    import os
    from app import database as dbm
    from app import pipeline
    from app.database import init_db

    onion_url = "http://" + ("e" * 56) + ".onion/"
    sources_path = tmp_path / "sources.yaml"
    sources_path.write_text(
        f"sources:\n  - name: Tester\n    type: onion\n    url: {onion_url}\n    enabled: true\n"
    )
    db_path = str(tmp_path / "test.db")
    init_db(db_path)
    monkeypatch.setattr(dbm, "DATABASE_PATH", db_path)
    monkeypatch.setenv("SOURCES_PATH", str(sources_path))
    # config.py reads SOURCES_PATH at module import time, so patch it too.
    monkeypatch.setattr(pipeline, "SOURCES_PATH", str(sources_path))

    rss_called = []
    onion_called = []
    monkeypatch.setattr(pipeline, "collect_rss",
                        lambda src: rss_called.append(src) or [])
    monkeypatch.setattr(pipeline, "collect_onion",
                        lambda src: onion_called.append(src) or [])

    totals = pipeline.run_collection_cycle()
    assert onion_called and not rss_called
    assert onion_called[0]["type"] == "onion"
    assert totals["errors"] == 0
