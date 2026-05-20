"""Egress IP verification.

The intent is OPSEC: before the tool makes any clearweb HTTP request
(including to onion aggregators like ahmia.fi, which IS clearweb), confirm
the box is routing through the expected VPN. If a WireGuard tunnel has
dropped and you forgot to enable a firewall kill switch, this is the
last line of defense before your residential IP shows up in an aggregator's
access log.

Layering
--------
- WireGuard + OS firewall handle routing. The tool does NOT manage the
  tunnel.
- This module just *checks* the egress. It calls `https://api.ipify.org`
  (a tiny, long-running IP-echo service) and compares the result against
  operator-configured allowlists.
- `network-check` is a standalone CLI command. The `collect` and
  `scheduler` commands run the same check at startup as a preflight when
  `STRICT_EGRESS=1`; on failure they refuse to proceed.

Configuration (all optional, all via env)
-----------------------------------------
  EXPECTED_EGRESS_PREFIXES   Comma-separated CIDR list. Egress IP must be
                             inside one of these. E.g.
                             "185.156.176.0/20,194.110.0.0/16"
  EXPECTED_EGRESS_COUNTRY    Two-letter country code. Requires the
                             optional country lookup (ipapi.co).
  EGRESS_CHECK_URL           Single IP-echo URL override. Bypasses the
                             fallback chain — only this URL is tried.
                             Use this when you want a hard dependency on
                             one service.
  EGRESS_CHECK_URLS          Comma-separated fallback chain (overrides
                             the built-in default). Tried in order
                             until one returns a parseable IP.
                             Default chain: api.ipify.org, icanhazip.com,
                             ifconfig.me/ip, ipv4.icanhazip.com.
  EGRESS_CHECK_TIMEOUT       Per-URL request timeout in seconds
                             (default 10). Total wall-clock budget is
                             roughly timeout × number of URLs tried.
  STRICT_EGRESS              "1" enables the preflight on collect /
                             scheduler. Default off — opt-in.
"""
from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import dataclass
from typing import List, Optional

import requests

log = logging.getLogger(__name__)


@dataclass
class EgressResult:
    ok: bool
    ip: Optional[str]
    reason: str
    expected_prefixes: List[str]


DEFAULT_EGRESS_URLS = (
    "https://api.ipify.org",
    "https://icanhazip.com",
    "https://ifconfig.me/ip",
    "https://ipv4.icanhazip.com",
)


def _resolve_egress_urls(url_override: Optional[str] = None) -> List[str]:
    """Pick which IP-echo URL(s) to try, in priority order.

    Precedence:
      1. Explicit `url_override` arg (used by tests + the `network-check
         --url` flag) — single URL, no fallback.
      2. `EGRESS_CHECK_URL` env var — single URL, no fallback.
      3. `EGRESS_CHECK_URLS` env var — operator-supplied chain.
      4. Built-in DEFAULT_EGRESS_URLS chain.
    """
    if url_override:
        return [url_override]
    single = os.getenv("EGRESS_CHECK_URL", "").strip()
    if single:
        return [single]
    chain = os.getenv("EGRESS_CHECK_URLS", "").strip()
    if chain:
        urls = [u.strip() for u in chain.split(",") if u.strip()]
        if urls:
            return urls
    return list(DEFAULT_EGRESS_URLS)


def _parse_prefixes(raw: str) -> List[ipaddress._BaseNetwork]:
    nets: List[ipaddress._BaseNetwork] = []
    for piece in (raw or "").split(","):
        piece = piece.strip()
        if not piece:
            continue
        try:
            nets.append(ipaddress.ip_network(piece, strict=False))
        except ValueError as exc:
            log.warning("egress: ignoring invalid CIDR %r (%s)", piece, exc)
    return nets


def get_egress_ip(
    url: Optional[str] = None,
    timeout: Optional[float] = None,
) -> str:
    """Fetch the public egress IP.

    Walks the URL chain returned by `_resolve_egress_urls(url)` and
    returns the IP from the first service that responds with a parseable
    IP address. Raises the LAST exception encountered if every URL
    fails.

    Intentionally uses bare `requests.get` (no session, no proxies). If
    you've routed the default interface through WireGuard, this call
    automatically goes through it. If WG is down, this call goes out via
    your physical NIC — and that's exactly the failure we want to detect.
    """
    timeout = timeout or float(os.getenv("EGRESS_CHECK_TIMEOUT", "10"))
    urls = _resolve_egress_urls(url)
    errors: list[str] = []
    for u in urls:
        try:
            resp = requests.get(u, timeout=timeout)
            resp.raise_for_status()
            ip = resp.text.strip()
            # Validate the response is actually an IP, not "rate limited" HTML
            # or a CDN's 200-with-error-body. ip_address raises ValueError if
            # the text isn't an IP, which falls through to the next URL.
            ipaddress.ip_address(ip)
            if len(urls) > 1 and u != urls[0]:
                log.info("egress: using fallback URL %s (first %d failed)",
                         u, urls.index(u))
            return ip
        except (requests.RequestException, ValueError) as exc:
            errors.append(f"{u}: {exc.__class__.__name__}: {exc}")
            continue
    # All URLs failed — surface a combined message so the operator can
    # see which services were tried.
    raise RuntimeError(
        "egress lookup failed across all " f"{len(urls)} URL(s): " + " | ".join(errors)
    )


def check_egress(
    expected_prefixes: Optional[str] = None,
    *,
    url: Optional[str] = None,
    timeout: Optional[float] = None,
) -> EgressResult:
    """Run the egress check. Never raises — failures are returned as ok=False."""
    raw = expected_prefixes
    if raw is None:
        raw = os.getenv("EXPECTED_EGRESS_PREFIXES", "")
    nets = _parse_prefixes(raw)
    try:
        ip = get_egress_ip(url=url, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return EgressResult(
            ok=False, ip=None,
            reason=f"egress-lookup-failed: {exc.__class__.__name__}: {exc}",
            expected_prefixes=[str(n) for n in nets],
        )

    if not nets:
        # No allowlist configured — return the IP for inspection but mark
        # ok=True. The strict-egress preflight has its own enforcement that
        # turns "no allowlist configured" into a hard error.
        return EgressResult(
            ok=True, ip=ip, reason="no-allowlist-configured",
            expected_prefixes=[],
        )

    addr = ipaddress.ip_address(ip)
    for net in nets:
        if addr in net:
            return EgressResult(
                ok=True, ip=ip, reason=f"in-prefix:{net}",
                expected_prefixes=[str(n) for n in nets],
            )
    return EgressResult(
        ok=False, ip=ip,
        reason=f"ip-not-in-any-allowlisted-prefix",
        expected_prefixes=[str(n) for n in nets],
    )


def strict_egress_enabled() -> bool:
    return os.getenv("STRICT_EGRESS", "0").lower() in ("1", "true", "yes", "on")


def preflight_or_exit() -> None:
    """Used by collect / scheduler at startup.

    When STRICT_EGRESS=1, refuse to proceed if either:
      - no EXPECTED_EGRESS_PREFIXES is configured (fail-closed by design),
      - the egress IP is outside the allowlist,
      - or the egress lookup itself fails (network down, etc.).
    """
    if not strict_egress_enabled():
        return
    raw = os.getenv("EXPECTED_EGRESS_PREFIXES", "")
    if not raw.strip():
        msg = (
            "STRICT_EGRESS=1 but EXPECTED_EGRESS_PREFIXES is empty. "
            "Refusing to make outbound requests without an allowlist. "
            "Set EXPECTED_EGRESS_PREFIXES to your VPN's egress CIDR(s)."
        )
        log.error(msg)
        raise SystemExit(msg)

    result = check_egress(raw)
    if not result.ok:
        msg = (
            f"STRICT_EGRESS preflight failed. "
            f"egress_ip={result.ip} reason={result.reason} "
            f"expected={','.join(result.expected_prefixes)}. "
            "Refusing to start. Check that WireGuard is up and routing."
        )
        log.error(msg)
        raise SystemExit(msg)
    log.info(
        "STRICT_EGRESS preflight ok: %s in %s",
        result.ip, ",".join(result.expected_prefixes),
    )
