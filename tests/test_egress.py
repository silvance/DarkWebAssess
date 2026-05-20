"""Tests for the egress-IP verification layer.

The properties we pin down:

  1. CIDR parsing tolerates whitespace and a mix of IPv4/IPv6; bad entries
     are dropped, valid ones are kept.
  2. `check_egress` returns ok=False when the egress is outside the
     allowlist, even if the lookup itself succeeded.
  3. `check_egress` returns ok=True with reason='no-allowlist-configured'
     when no prefixes are provided (so `network-check` can still print the
     egress IP for inspection).
  4. `preflight_or_exit` is a no-op when STRICT_EGRESS is unset.
  5. `preflight_or_exit` raises SystemExit when STRICT_EGRESS=1 but no
     allowlist is configured (fail-closed by design).
  6. `preflight_or_exit` raises SystemExit when the egress is outside the
     allowlist.
  7. `preflight_or_exit` returns normally when the egress is inside the
     allowlist.
"""
from __future__ import annotations

import pytest

from app.network import egress


# --- CIDR parsing -------------------------------------------------------
def test_parse_prefixes_handles_empty():
    assert egress._parse_prefixes("") == []
    assert egress._parse_prefixes("   ") == []


def test_parse_prefixes_handles_whitespace_and_commas():
    nets = egress._parse_prefixes(" 10.0.0.0/8 , 192.168.1.0/24 ")
    assert len(nets) == 2
    assert str(nets[0]) == "10.0.0.0/8"
    assert str(nets[1]) == "192.168.1.0/24"


def test_parse_prefixes_drops_invalid_entries():
    nets = egress._parse_prefixes("10.0.0.0/8,not-a-cidr,192.168.0.0/16")
    assert {str(n) for n in nets} == {"10.0.0.0/8", "192.168.0.0/16"}


def test_parse_prefixes_supports_ipv6():
    nets = egress._parse_prefixes("2001:db8::/32")
    assert str(nets[0]) == "2001:db8::/32"


def test_parse_prefixes_accepts_single_ip_as_host():
    nets = egress._parse_prefixes("198.51.100.7")
    assert str(nets[0]) == "198.51.100.7/32"


# --- check_egress -------------------------------------------------------
def test_check_egress_ok_when_ip_in_allowlist(monkeypatch):
    monkeypatch.setattr(egress, "get_egress_ip", lambda **kw: "10.0.0.42")
    result = egress.check_egress("10.0.0.0/8")
    assert result.ok is True
    assert result.ip == "10.0.0.42"
    assert result.reason.startswith("in-prefix:")


def test_check_egress_fail_when_ip_not_in_allowlist(monkeypatch):
    monkeypatch.setattr(egress, "get_egress_ip", lambda **kw: "1.2.3.4")
    result = egress.check_egress("10.0.0.0/8,192.168.0.0/16")
    assert result.ok is False
    assert result.ip == "1.2.3.4"
    assert result.reason == "ip-not-in-any-allowlisted-prefix"


def test_check_egress_no_allowlist_returns_ok_with_reason(monkeypatch):
    """When no allowlist is set, the check just reports the IP. The
    STRICT_EGRESS preflight handles the policy decision."""
    monkeypatch.setattr(egress, "get_egress_ip", lambda **kw: "203.0.113.7")
    result = egress.check_egress("")
    assert result.ok is True
    assert result.ip == "203.0.113.7"
    assert result.reason == "no-allowlist-configured"
    assert result.expected_prefixes == []


def test_check_egress_lookup_failure(monkeypatch):
    def boom(**kw):
        raise ConnectionError("network unreachable")
    monkeypatch.setattr(egress, "get_egress_ip", boom)
    result = egress.check_egress("10.0.0.0/8")
    assert result.ok is False
    assert result.ip is None
    assert "egress-lookup-failed" in result.reason
    assert "ConnectionError" in result.reason


def test_check_egress_uses_env_when_arg_omitted(monkeypatch):
    monkeypatch.setenv("EXPECTED_EGRESS_PREFIXES", "10.0.0.0/8")
    monkeypatch.setattr(egress, "get_egress_ip", lambda **kw: "10.1.2.3")
    result = egress.check_egress()  # no explicit prefixes arg
    assert result.ok is True


# --- preflight_or_exit --------------------------------------------------
def test_preflight_noop_when_strict_unset(monkeypatch):
    monkeypatch.delenv("STRICT_EGRESS", raising=False)
    def should_not_run(**kw):
        pytest.fail("egress lookup ran but STRICT_EGRESS was unset")
    monkeypatch.setattr(egress, "get_egress_ip", should_not_run)
    egress.preflight_or_exit()  # must not raise


def test_preflight_fails_closed_with_no_allowlist(monkeypatch):
    monkeypatch.setenv("STRICT_EGRESS", "1")
    monkeypatch.setenv("EXPECTED_EGRESS_PREFIXES", "")
    with pytest.raises(SystemExit, match="EXPECTED_EGRESS_PREFIXES is empty"):
        egress.preflight_or_exit()


def test_preflight_exits_when_egress_outside_allowlist(monkeypatch):
    monkeypatch.setenv("STRICT_EGRESS", "1")
    monkeypatch.setenv("EXPECTED_EGRESS_PREFIXES", "10.0.0.0/8")
    monkeypatch.setattr(egress, "get_egress_ip", lambda **kw: "1.2.3.4")
    with pytest.raises(SystemExit, match="preflight failed"):
        egress.preflight_or_exit()


def test_preflight_exits_when_lookup_fails(monkeypatch):
    monkeypatch.setenv("STRICT_EGRESS", "1")
    monkeypatch.setenv("EXPECTED_EGRESS_PREFIXES", "10.0.0.0/8")
    def boom(**kw):
        raise ConnectionError("nope")
    monkeypatch.setattr(egress, "get_egress_ip", boom)
    with pytest.raises(SystemExit, match="preflight failed"):
        egress.preflight_or_exit()


def test_preflight_passes_when_inside_allowlist(monkeypatch):
    monkeypatch.setenv("STRICT_EGRESS", "1")
    monkeypatch.setenv("EXPECTED_EGRESS_PREFIXES", "10.0.0.0/8")
    monkeypatch.setattr(egress, "get_egress_ip", lambda **kw: "10.1.2.3")
    egress.preflight_or_exit()  # must not raise


def test_strict_egress_enabled_parses_common_truthy_values(monkeypatch):
    for v in ("1", "true", "yes", "on", "TRUE", "YES"):
        monkeypatch.setenv("STRICT_EGRESS", v)
        assert egress.strict_egress_enabled() is True, v


def test_strict_egress_disabled_when_unset_or_falsy(monkeypatch):
    monkeypatch.delenv("STRICT_EGRESS", raising=False)
    assert egress.strict_egress_enabled() is False
    monkeypatch.setenv("STRICT_EGRESS", "0")
    assert egress.strict_egress_enabled() is False
    monkeypatch.setenv("STRICT_EGRESS", "no")
    assert egress.strict_egress_enabled() is False


# --- URL resolution / fallback chain ------------------------------------
def test_resolve_egress_urls_default_chain(monkeypatch):
    monkeypatch.delenv("EGRESS_CHECK_URL", raising=False)
    monkeypatch.delenv("EGRESS_CHECK_URLS", raising=False)
    urls = egress._resolve_egress_urls()
    assert len(urls) >= 3  # at least api.ipify.org + 2 fallbacks
    assert urls[0] == "https://api.ipify.org"


def test_resolve_egress_urls_explicit_override_disables_fallback(monkeypatch):
    monkeypatch.delenv("EGRESS_CHECK_URL", raising=False)
    monkeypatch.delenv("EGRESS_CHECK_URLS", raising=False)
    urls = egress._resolve_egress_urls("https://custom.example.com/ip")
    assert urls == ["https://custom.example.com/ip"]


def test_resolve_egress_urls_singular_env_disables_fallback(monkeypatch):
    monkeypatch.setenv("EGRESS_CHECK_URL", "https://my.only.choice/")
    monkeypatch.delenv("EGRESS_CHECK_URLS", raising=False)
    urls = egress._resolve_egress_urls()
    assert urls == ["https://my.only.choice/"]


def test_resolve_egress_urls_plural_env_overrides_default(monkeypatch):
    monkeypatch.delenv("EGRESS_CHECK_URL", raising=False)
    monkeypatch.setenv("EGRESS_CHECK_URLS", "https://a.example/, https://b.example/")
    urls = egress._resolve_egress_urls()
    assert urls == ["https://a.example/", "https://b.example/"]


def test_resolve_egress_urls_plural_env_skips_empty_entries(monkeypatch):
    monkeypatch.delenv("EGRESS_CHECK_URL", raising=False)
    monkeypatch.setenv("EGRESS_CHECK_URLS", "https://a.example/, ,https://b.example/,,")
    urls = egress._resolve_egress_urls()
    assert urls == ["https://a.example/", "https://b.example/"]


# --- get_egress_ip with fallback ---------------------------------------
class _FakeResponse:
    def __init__(self, text: str = "1.2.3.4", status: int = 200):
        self.text = text
        self.status = status

    def raise_for_status(self):
        if self.status >= 400:
            import requests
            raise requests.HTTPError(f"HTTP {self.status}")


def test_get_egress_ip_uses_first_url_on_success(monkeypatch):
    monkeypatch.delenv("EGRESS_CHECK_URL", raising=False)
    monkeypatch.delenv("EGRESS_CHECK_URLS", raising=False)
    calls = []
    def fake_get(url, timeout):
        calls.append(url)
        return _FakeResponse("203.0.113.7")
    monkeypatch.setattr(egress.requests, "get", fake_get)
    ip = egress.get_egress_ip()
    assert ip == "203.0.113.7"
    assert len(calls) == 1  # second URL never tried


def test_get_egress_ip_falls_back_on_request_exception(monkeypatch):
    monkeypatch.delenv("EGRESS_CHECK_URL", raising=False)
    monkeypatch.setenv("EGRESS_CHECK_URLS", "https://broken.example/,https://ok.example/")
    import requests as _req
    calls = []
    def fake_get(url, timeout):
        calls.append(url)
        if "broken" in url:
            raise _req.ConnectionError("dns failed")
        return _FakeResponse("198.51.100.42")
    monkeypatch.setattr(egress.requests, "get", fake_get)
    ip = egress.get_egress_ip()
    assert ip == "198.51.100.42"
    assert calls == ["https://broken.example/", "https://ok.example/"]


def test_get_egress_ip_falls_back_on_unparseable_response(monkeypatch):
    """First URL returns 200 with HTML body (e.g. rate-limit page).
    Second URL returns a real IP. We should fall through and use it."""
    monkeypatch.delenv("EGRESS_CHECK_URL", raising=False)
    monkeypatch.setenv("EGRESS_CHECK_URLS", "https://garbage.example/,https://ok.example/")
    def fake_get(url, timeout):
        if "garbage" in url:
            return _FakeResponse("<html>rate limited</html>")
        return _FakeResponse("198.51.100.42")
    monkeypatch.setattr(egress.requests, "get", fake_get)
    ip = egress.get_egress_ip()
    assert ip == "198.51.100.42"


def test_get_egress_ip_raises_when_all_urls_fail(monkeypatch):
    """If every URL fails, we surface a RuntimeError with the per-URL
    error chain so the operator can see which services were tried."""
    monkeypatch.delenv("EGRESS_CHECK_URL", raising=False)
    monkeypatch.setenv("EGRESS_CHECK_URLS", "https://a.example/,https://b.example/")
    import requests as _req
    def fake_get(url, timeout):
        raise _req.Timeout(f"timeout on {url}")
    monkeypatch.setattr(egress.requests, "get", fake_get)
    with pytest.raises(RuntimeError, match="egress lookup failed"):
        egress.get_egress_ip()


def test_check_egress_propagates_total_failure_through_to_result(monkeypatch):
    """check_egress() wraps get_egress_ip() — when the entire chain
    fails, the wrapper returns ok=False with the RuntimeError in the
    reason rather than letting it propagate."""
    monkeypatch.delenv("EGRESS_CHECK_URL", raising=False)
    monkeypatch.delenv("EGRESS_CHECK_URLS", raising=False)
    import requests as _req
    def fake_get(url, timeout):
        raise _req.ConnectionError(f"unreachable {url}")
    monkeypatch.setattr(egress.requests, "get", fake_get)
    result = egress.check_egress("10.0.0.0/8")
    assert result.ok is False
    assert result.ip is None
    assert "egress-lookup-failed" in result.reason
