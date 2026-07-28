"""Render a ScrubReport to text / markdown / json."""
from __future__ import annotations

import json
from typing import List

from app.scrub.base import SEVERITY_ORDER
from app.scrub.runner import ScrubReport

_SEV_LABEL = {
    "high": "HIGH", "medium": "MED", "low": "LOW", "info": "INFO",
}


def _sorted_findings(report: ScrubReport):
    def rank(f):
        try:
            return -SEVERITY_ORDER.index(f.severity)
        except ValueError:
            return 0
    return sorted(report.findings, key=rank)


def render_text(report: ScrubReport) -> str:
    lines: List[str] = []
    t = report.target
    lines.append(f"Scrub report for {t.type}: {t.normalized()}")
    hs = report.highest_severity
    n = len(report.findings)
    lines.append(
        f"  {n} finding(s); highest severity: {hs or 'none'}"
    )
    lines.append("")

    # Provider status (what ran / skipped / errored).
    lines.append("Providers:")
    for pr in report.provider_runs:
        if not pr.ran and pr.skipped_reason:
            lines.append(f"  - {pr.provider}: skipped ({pr.skipped_reason})")
        elif pr.error:
            lines.append(f"  - {pr.provider}: ERROR ({pr.error})")
        else:
            lines.append(f"  - {pr.provider}: {len(pr.findings)} finding(s)")
    lines.append("")

    if not report.findings:
        lines.append("No exposure found by the available providers.")
        return "\n".join(lines)

    lines.append("Findings (most severe first):")
    for f in _sorted_findings(report):
        tag = _SEV_LABEL.get(f.severity, f.severity.upper())
        lines.append(f"  [{tag}] {f.title}")
        if f.detail:
            lines.append(f"         {f.detail}")
        if f.url:
            lines.append(f"         {f.url}")
    return "\n".join(lines)


def render_markdown(report: ScrubReport) -> str:
    t = report.target
    hs = report.highest_severity
    out: List[str] = []
    out.append(f"# Scrub report — `{t.normalized()}` ({t.type})")
    out.append("")
    out.append(f"**{len(report.findings)} finding(s)** · highest severity: "
               f"**{hs or 'none'}**")
    out.append("")
    out.append("## Providers")
    out.append("")
    out.append("| Provider | Result |")
    out.append("|---|---|")
    for pr in report.provider_runs:
        if not pr.ran and pr.skipped_reason:
            res = f"skipped — {pr.skipped_reason}"
        elif pr.error:
            res = f"error — {pr.error}"
        else:
            res = f"{len(pr.findings)} finding(s)"
        out.append(f"| `{pr.provider}` | {res} |")
    out.append("")

    if not report.findings:
        out.append("_No exposure found by the available providers._")
        return "\n".join(out)

    out.append("## Findings")
    out.append("")
    for f in _sorted_findings(report):
        tag = _SEV_LABEL.get(f.severity, f.severity.upper())
        title = f"### [{tag}] {f.title}"
        out.append(title)
        if f.detail:
            out.append("")
            out.append(f.detail)
        if f.url:
            out.append("")
            out.append(f"<{f.url}>")
        out.append("")
    return "\n".join(out)


def render_json(report: ScrubReport) -> str:
    payload = {
        "target": {"type": report.target.type, "value": report.target.normalized()},
        "run_id": report.run_id,
        "highest_severity": report.highest_severity,
        "findings_count": len(report.findings),
        "providers": [
            {
                "name": pr.provider,
                "ran": pr.ran,
                "skipped_reason": pr.skipped_reason,
                "error": pr.error,
                "findings": [
                    {
                        "kind": f.kind, "title": f.title, "severity": f.severity,
                        "detail": f.detail, "url": f.url, "data": f.data,
                    }
                    for f in pr.findings
                ],
            }
            for pr in report.provider_runs
        ],
    }
    return json.dumps(payload, indent=2, default=str)
