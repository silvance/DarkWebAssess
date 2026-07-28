"""`dwa doctor` — one-shot health check.

Runs a series of named checks and prints a labeled report. Designed to
answer the new-operator question "did I configure this right?" without
having to run every subcommand individually.

Exit code: 0 unless at least one check reports FAIL.

Output format (one line per check):

    [STATUS]  check name
              detail line, optionally with a remediation hint

Status levels:
  OK    — fully configured and working
  INFO  — optional feature, not configured (no action needed)
  WARN  — configured but degraded, or misconfigured-but-tolerated
  FAIL  — something the operator needs to fix
"""
from __future__ import annotations

import dataclasses
import os
import sys
from pathlib import Path
from typing import Callable, List, Optional


# --- Result type --------------------------------------------------------
@dataclasses.dataclass
class CheckResult:
    name: str
    status: str  # OK / INFO / WARN / FAIL
    detail: str = ""
    hint: Optional[str] = None


def register(sub) -> None:
    p = sub.add_parser(
        "doctor",
        help="Run a health check: config / DB / providers / OPSEC / Rust.",
    )
    p.add_argument(
        "--no-network",
        action="store_true",
        help="Skip checks that touch the network (Tor reachability, egress).",
    )
    p.set_defaults(func=_run)


# --- Individual checks --------------------------------------------------
def _check_python_version() -> CheckResult:
    major, minor = sys.version_info[:2]
    if (major, minor) >= (3, 10):
        return CheckResult(
            "Python version", "OK",
            detail=f"Python {major}.{minor}.{sys.version_info.micro}",
        )
    return CheckResult(
        "Python version", "FAIL",
        detail=f"Python {major}.{minor} detected; project requires 3.10+",
        hint="Install a newer Python and recreate the venv.",
    )


def _check_database() -> CheckResult:
    from app.config import DATABASE_PATH
    from app.database import get_connection

    path = Path(DATABASE_PATH)
    if not path.exists():
        return CheckResult(
            "Database file", "FAIL",
            detail=f"{DATABASE_PATH} does not exist",
            hint="Run `dwa init-db` (or `python -m app.main init-db`).",
        )
    try:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='documents'"
            ).fetchone()
        if row is None:
            return CheckResult(
                "Database schema", "FAIL",
                detail=f"{DATABASE_PATH} exists but `documents` table is missing",
                hint="Run `dwa init-db` to (re)create the schema.",
            )
        # Best-effort row counts for the diagnostic.
        with get_connection() as conn:
            doc_count = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
            wl_count = conn.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0]
        return CheckResult(
            "Database", "OK",
            detail=f"{DATABASE_PATH}  ({doc_count} documents, {wl_count} watchlist rules)",
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            "Database", "FAIL",
            detail=f"could not query DB: {exc.__class__.__name__}: {exc}",
        )


def _check_yaml(name: str, path: str, loader_name: str) -> CheckResult:
    """Try to load + validate a config YAML via its Pydantic loader."""
    if not Path(path).exists():
        return CheckResult(
            name, "WARN",
            detail=f"{path} not found",
            hint=f"Create it (or copy from the repo) and re-run `dwa doctor`.",
        )
    try:
        from app import config_models as cm
        loader = getattr(cm, loader_name)
        cfg = loader(path)
        # Count items for the diagnostic.
        items = (
            getattr(cfg, "sources", None)
            or getattr(cfg, "watchlist", None)
            or getattr(cfg, "suppress", None)
            or getattr(cfg, "directories", None)
            or []
        )
        enabled = [i for i in items if getattr(i, "enabled", True)]
        return CheckResult(
            name, "OK",
            detail=f"{path}  ({len(items)} entries, {len(enabled)} enabled)",
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            name, "FAIL",
            detail=f"{path}: {exc.__class__.__name__}: {exc}",
            hint="Fix the YAML so Pydantic accepts it, then re-run doctor.",
        )


def _check_rust_accelerator() -> CheckResult:
    try:
        import dwa_extractors  # noqa: F401
    except ImportError:
        return CheckResult(
            "Rust extractor", "INFO",
            detail="`dwa_extractors` wheel not installed (Python fallback is fine)",
            hint="Optional. `pip install dwa_extractors` for ~25× faster regex.",
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            "Rust extractor", "WARN",
            detail=f"wheel installed but errored: {exc.__class__.__name__}: {exc}",
        )
    # Wheel imports cleanly. Check whether the project's entities module
    # actually routes through it (newer entry.py has DWA_DISABLE_RUST).
    enabled = True
    try:
        from app.extractors.entities import _rust_enabled
        enabled = _rust_enabled()
    except ImportError:
        # Older entities.py without the runtime toggle: assume enabled
        # because _HAVE_RUST is set at import.
        pass
    except Exception:  # noqa: BLE001
        pass
    if not enabled:
        return CheckResult(
            "Rust extractor", "INFO",
            detail="wheel installed but disabled by DWA_DISABLE_RUST",
        )
    try:
        version = dwa_extractors.version()
    except Exception:  # noqa: BLE001
        version = "(unknown version)"
    return CheckResult(
        "Rust extractor", "OK",
        detail=f"dwa_extractors {version} loaded; extract_observables active",
    )


def _check_tor_connectivity(skip_network: bool) -> CheckResult:
    """Only checks Tor if any onion source is enabled. Otherwise INFO."""
    from app.config import SOURCES_PATH

    try:
        from app.config_models import load_sources
        cfg = load_sources(SOURCES_PATH)
    except Exception:  # noqa: BLE001
        return CheckResult(
            "Tor sidecar", "INFO",
            detail="sources.yaml not loadable (covered above); skipped",
        )
    enabled_onions = [s for s in cfg.sources if s.enabled and s.type == "onion"]
    if not enabled_onions:
        return CheckResult(
            "Tor sidecar", "INFO",
            detail="no enabled onion sources; Tor not required",
        )
    if skip_network:
        return CheckResult(
            "Tor sidecar", "INFO",
            detail=f"{len(enabled_onions)} onion source(s) configured; skipped (--no-network)",
        )
    try:
        from app.cli.cmd_tor import _tor_check_ok  # not present in old branches
    except ImportError:
        # Fall back to a direct socket connect to the configured SOCKS port.
        import socket
        from app.config import TOR_SOCKS_HOST, TOR_SOCKS_PORT
        try:
            with socket.create_connection(
                (TOR_SOCKS_HOST, int(TOR_SOCKS_PORT)), timeout=3
            ):
                pass
            return CheckResult(
                "Tor sidecar", "OK",
                detail=f"SOCKS5 reachable at {TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
            )
        except OSError as exc:
            return CheckResult(
                "Tor sidecar", "FAIL",
                detail=(
                    f"{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT} unreachable: {exc}; "
                    f"but {len(enabled_onions)} onion source(s) are enabled"
                ),
                hint="Start the Tor daemon or set TOR_SOCKS_HOST/PORT.",
            )
    # The dedicated helper exists — defer to it.
    ok, reason = _tor_check_ok()
    if ok:
        return CheckResult("Tor sidecar", "OK", detail=reason)
    return CheckResult(
        "Tor sidecar", "FAIL",
        detail=reason,
        hint="Start the Tor daemon (`systemctl start tor` or the Docker sidecar).",
    )


def _check_egress(skip_network: bool) -> CheckResult:
    """Reports the OPSEC posture: STRICT_EGRESS on/off, allowlist presence."""
    strict = os.getenv("STRICT_EGRESS", "0").lower() in ("1", "true", "yes", "on")
    allowlist = os.getenv("EXPECTED_EGRESS_PREFIXES", "").strip()
    if not strict and not allowlist:
        return CheckResult(
            "Egress preflight", "INFO",
            detail="STRICT_EGRESS off; no allowlist set",
            hint="See docs/OPSEC.md if you want VPN-leak protection.",
        )
    if strict and not allowlist:
        return CheckResult(
            "Egress preflight", "FAIL",
            detail="STRICT_EGRESS=1 but EXPECTED_EGRESS_PREFIXES is empty (fail-closed)",
            hint="Set EXPECTED_EGRESS_PREFIXES to your VPN's CIDR(s), or unset STRICT_EGRESS.",
        )
    if not strict and allowlist:
        return CheckResult(
            "Egress preflight", "INFO",
            detail=f"allowlist set ({allowlist}) but STRICT_EGRESS off (advisory only)",
            hint="Set STRICT_EGRESS=1 to actually enforce the allowlist.",
        )
    # STRICT_EGRESS=1 AND allowlist set — do the live check unless skipped.
    if skip_network:
        return CheckResult(
            "Egress preflight", "INFO",
            detail=f"STRICT_EGRESS=1 with allowlist {allowlist}; skipped (--no-network)",
        )
    try:
        from app.network.egress import check_egress
        result = check_egress(allowlist)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            "Egress preflight", "FAIL",
            detail=f"check raised: {exc.__class__.__name__}: {exc}",
        )
    if result.ok:
        return CheckResult(
            "Egress preflight", "OK",
            detail=f"egress {result.ip}  ({result.reason})",
        )
    return CheckResult(
        "Egress preflight", "FAIL",
        detail=f"egress {result.ip or '?'}  reason={result.reason}",
        hint="Bring WireGuard up (or fix the allowlist) — collect/scheduler will refuse to start.",
    )


def _check_provider_keys() -> List[CheckResult]:
    """One row per optional provider — INFO when missing, OK when set."""
    providers = [
        ("Anthropic LLM", "ANTHROPIC_API_KEY", "summaries / `dwa summarize`"),
        ("VirusTotal", "VIRUSTOTAL_API_KEY", "VT enrichment"),
        ("AbuseIPDB", "ABUSEIPDB_API_KEY", "IP-reputation enrichment"),
        ("abuse.ch", "ABUSECH_AUTH_KEY", "URLhaus / MalwareBazaar enrichment"),
    ]
    out: List[CheckResult] = []
    for name, env, used_for in providers:
        if os.getenv(env, "").strip():
            out.append(CheckResult(f"{name} key", "OK", detail=f"${env} is set"))
        else:
            out.append(CheckResult(
                f"{name} key", "INFO",
                detail=f"${env} not set; {used_for} disabled",
            ))
    return out


def _check_telegram() -> CheckResult:
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    if token and chat:
        return CheckResult(
            "Telegram alerts", "OK",
            detail="bot token + chat id both set",
        )
    if token or chat:
        return CheckResult(
            "Telegram alerts", "WARN",
            detail="one of TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID is set, the other isn't",
            hint="Set both, or unset both. Half-configured alerts won't fire.",
        )
    return CheckResult(
        "Telegram alerts", "INFO",
        detail="not configured (no alerts will be sent)",
    )


def _check_email() -> CheckResult:
    host = os.getenv("SMTP_HOST", "").strip()
    frm = os.getenv("SMTP_FROM", "").strip()
    to = os.getenv("SMTP_TO", "").strip()
    if host and frm and to:
        return CheckResult(
            "Email delivery", "OK",
            detail=f"SMTP host + from + to set (host {host})",
        )
    if host or frm or to:
        present = [n for n, v in (("SMTP_HOST", host), ("SMTP_FROM", frm), ("SMTP_TO", to)) if v]
        return CheckResult(
            "Email delivery", "WARN",
            detail=f"partially configured (only {', '.join(present)} set)",
            hint="Set SMTP_HOST, SMTP_FROM, and SMTP_TO. `dwa email-test` to verify.",
        )
    return CheckResult(
        "Email delivery", "INFO",
        detail="not configured (report --email will no-op)",
    )


# --- Driver -------------------------------------------------------------
_STATUS_LABELS = {
    "OK":   "[ OK ]",
    "INFO": "[INFO]",
    "WARN": "[WARN]",
    "FAIL": "[FAIL]",
}


def _print_result(r: CheckResult) -> None:
    label = _STATUS_LABELS.get(r.status, f"[{r.status}]")
    print(f"  {label}  {r.name}")
    if r.detail:
        print(f"          {r.detail}")
    if r.hint:
        print(f"          → {r.hint}")


def _run_all_checks(skip_network: bool) -> List[CheckResult]:
    from app.config import (
        ONION_DIRECTORIES_PATH, SOURCES_PATH, SUPPRESSION_PATH, WATCHLIST_PATH,
    )
    checks: List[Callable[[], CheckResult | List[CheckResult]]] = [
        _check_python_version,
        _check_database,
        lambda: _check_yaml("sources.yaml", SOURCES_PATH, "load_sources"),
        lambda: _check_yaml("watchlist.yaml", WATCHLIST_PATH, "load_watchlist"),
        lambda: _check_yaml("suppression.yaml", SUPPRESSION_PATH, "load_suppression"),
        lambda: _check_yaml(
            "onion_directories.yaml", ONION_DIRECTORIES_PATH, "load_onion_directories"
        ),
        _check_rust_accelerator,
        lambda: _check_tor_connectivity(skip_network),
        lambda: _check_egress(skip_network),
        _check_provider_keys,
        _check_telegram,
        _check_email,
    ]
    results: List[CheckResult] = []
    for check in checks:
        try:
            out = check()
        except Exception as exc:  # noqa: BLE001
            results.append(CheckResult(
                check.__name__ if hasattr(check, "__name__") else "(anonymous)",
                "FAIL",
                detail=f"check itself raised: {exc.__class__.__name__}: {exc}",
            ))
            continue
        if isinstance(out, list):
            results.extend(out)
        else:
            results.append(out)
    return results


def _run(args) -> None:
    print("dwa doctor — health check")
    print()
    results = _run_all_checks(skip_network=getattr(args, "no_network", False))
    for r in results:
        _print_result(r)
    fails = sum(1 for r in results if r.status == "FAIL")
    warns = sum(1 for r in results if r.status == "WARN")
    print()
    print(f"  Summary: {len(results)} checks, {fails} fail, {warns} warn")
    if fails:
        sys.exit(1)
