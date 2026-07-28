"""Orchestrate scrub providers over a target and persist the run.

Self-monitoring only: given one identifier you control, run each
applicable provider, collect findings, and store a run + findings so the
result is browsable later (CLI report, dashboard, export).
"""
from __future__ import annotations

import logging
import re
import sqlite3
import time
from dataclasses import dataclass, field
from typing import List, Optional

from app.config import SCRUB_REQUEST_DELAY
from app.repository import (
    add_scrub_finding,
    create_scrub_run,
    finalize_scrub_run,
)
from app.scrub.base import Finding, ScrubProvider, Target, max_severity
from app.scrub.providers.gravatar import GravatarProvider
from app.scrub.providers.hibp import HibpProvider
from app.scrub.providers.local_xref import LocalXrefProvider

log = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)


def detect_type(value: str) -> str:
    """Best-effort target-type detection from a raw string."""
    v = value.strip()
    if _EMAIL_RE.match(v):
        return "email"
    if _DOMAIN_RE.match(v):
        return "domain"
    return "username"


def default_providers(conn: sqlite3.Connection) -> List[ScrubProvider]:
    """Native providers available in the core. External-tool passthrough
    providers are added in a later change."""
    return [
        LocalXrefProvider(conn),
        GravatarProvider(),
        HibpProvider(),
    ]


@dataclass
class ProviderRun:
    provider: str
    ran: bool
    findings: List[Finding] = field(default_factory=list)
    skipped_reason: Optional[str] = None
    error: Optional[str] = None


@dataclass
class ScrubReport:
    run_id: Optional[int]
    target: Target
    provider_runs: List[ProviderRun]

    @property
    def findings(self) -> List[Finding]:
        out: List[Finding] = []
        for pr in self.provider_runs:
            out.extend(pr.findings)
        return out

    @property
    def highest_severity(self) -> Optional[str]:
        return max_severity(f.severity for f in self.findings)


def run_scrub(
    conn: sqlite3.Connection,
    target: Target,
    *,
    providers: Optional[List[ScrubProvider]] = None,
    actor: Optional[str] = None,
    persist: bool = True,
    delay: Optional[float] = None,
) -> ScrubReport:
    """Run all applicable, available providers over `target`.

    Returns a ScrubReport. When persist=True, writes a scrub_runs row and
    one scrub_findings row per finding.
    """
    providers = providers if providers is not None else default_providers(conn)
    delay = SCRUB_REQUEST_DELAY if delay is None else delay

    run_id = None
    if persist:
        run_id = create_scrub_run(
            conn, target_type=target.type, target_value=target.normalized(),
            actor=actor,
        )

    provider_runs: List[ProviderRun] = []
    ran_names: List[str] = []
    first_network = True

    for provider in providers:
        if not provider.supports(target.type):
            continue
        if not provider.is_available():
            provider_runs.append(ProviderRun(
                provider=provider.name, ran=False,
                skipped_reason=provider.unavailable_reason(),
            ))
            continue

        # Polite spacing between providers that hit the network. The local
        # cross-reference is offline, so it doesn't count.
        if delay and provider.name != "local_xref":
            if not first_network:
                time.sleep(delay)
            first_network = False

        try:
            findings = provider.scrub(target)
        except Exception as exc:  # noqa: BLE001
            log.warning("scrub provider %s failed: %s", provider.name, exc)
            provider_runs.append(ProviderRun(
                provider=provider.name, ran=True,
                error=f"{exc.__class__.__name__}: {exc}",
            ))
            continue

        ran_names.append(provider.name)
        provider_runs.append(ProviderRun(
            provider=provider.name, ran=True, findings=findings,
        ))
        if persist and run_id is not None:
            for f in findings:
                add_scrub_finding(
                    conn, run_id, provider=provider.name, kind=f.kind,
                    title=f.title, severity=f.severity, detail=f.detail,
                    url=f.url, data=f.data,
                )

    report = ScrubReport(run_id=run_id, target=target, provider_runs=provider_runs)

    if persist and run_id is not None:
        finalize_scrub_run(
            conn, run_id, providers_run=ran_names,
            findings_count=len(report.findings),
            highest_severity=report.highest_severity,
        )
        conn.commit()

    return report
