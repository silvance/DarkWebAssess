"""Interfaces for the self-monitoring "scrub" feature.

A *scrub* checks what is publicly exposed about an identifier you control
— your email, your username, your domain. It is a self-monitoring tool
(the OSINT-hygiene equivalent of checking your own credit report), not a
targeting engine: there is no mass-target mode, and every provider queries
only public/consented surfaces on behalf of the operator.

A provider takes a `Target` and returns a list of `Finding`s. Providers
self-skip when they can't run (missing API key, external tool not
installed) via `is_available()`, mirroring the enrichment-provider
pattern.
"""
from __future__ import annotations

import dataclasses
from abc import ABC, abstractmethod
from typing import Iterable, List, Optional

# Ordered low → high so we can compute a run's highest severity.
SEVERITY_ORDER = ("info", "low", "medium", "high")


def max_severity(severities: Iterable[str]) -> Optional[str]:
    best = None
    best_rank = -1
    for s in severities:
        try:
            rank = SEVERITY_ORDER.index(s)
        except ValueError:
            continue
        if rank > best_rank:
            best_rank = rank
            best = s
    return best


@dataclasses.dataclass
class Target:
    """An identifier being scrubbed."""
    type: str   # email | username | domain
    value: str

    def normalized(self) -> str:
        v = self.value.strip()
        # Emails and domains are case-insensitive; usernames we leave as-is
        # (some sites are case-sensitive) but strip surrounding whitespace.
        if self.type in ("email", "domain"):
            return v.lower()
        return v


@dataclasses.dataclass
class Finding:
    """One discrete piece of exposure surfaced by a provider."""
    kind: str                       # breach | account | profile | avatar | mention | ...
    title: str                      # short human summary
    severity: str = "info"          # info | low | medium | high
    detail: Optional[str] = None    # longer description
    url: Optional[str] = None       # link to the evidence
    data: Optional[dict] = None     # structured extras

    def __post_init__(self):
        if self.severity not in SEVERITY_ORDER:
            self.severity = "info"


class ScrubProvider(ABC):
    name: str = ""
    supported_types: Iterable[str] = ()

    def is_available(self) -> bool:
        """True when the provider can run (key present, tool installed, …).

        Unavailable providers are skipped silently by the runner — the
        report notes which providers were skipped and why.
        """
        return True

    def unavailable_reason(self) -> str:
        return "not configured"

    def supports(self, target_type: str) -> bool:
        return target_type in self.supported_types

    @abstractmethod
    def scrub(self, target: Target) -> List[Finding]:
        """Return the findings for this target. Raise on hard failure; the
        runner records the error and continues with the next provider."""
