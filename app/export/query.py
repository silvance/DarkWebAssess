"""Fetch watchlist matches as normalized indicator rows for export.

An indicator row is source-format-agnostic; the CSV / STIX / MISP
renderers each map from it. The indicator *type* is derived from the
watchlist entry's type, refined from the value where the watchlist type
is generic (hash → md5/sha1/sha256 by length; ip → v4/v6 by colon).
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from typing import List, Optional

from app.config import SEVERITY_ORDER

_HEX = re.compile(r"^[a-fA-F0-9]+$")


@dataclass
class Indicator:
    value: str
    itype: str            # domain|ipv4|ipv6|url|email|md5|sha1|sha256|cve|onion|wallet|handle|keyword|malware|actor
    severity: str
    score: Optional[int]
    first_seen: str
    source_name: Optional[str]
    source_url: Optional[str]
    doc_title: Optional[str]
    context: Optional[str]


def _refine_type(watchlist_type: str, value: str) -> str:
    wt = (watchlist_type or "").lower()
    v = value.strip()
    if wt == "hash":
        if _HEX.match(v):
            n = len(v)
            if n == 32:
                return "md5"
            if n == 40:
                return "sha1"
            if n == 64:
                return "sha256"
        return "hash"
    if wt == "ip":
        return "ipv6" if ":" in v else "ipv4"
    return wt


def _parse_since(since: Optional[str]) -> Optional[str]:
    """Parse '7d' / '24h' / '30m' into an ISO cutoff string, or None.

    Returns the ISO timestamp N units ago. Uses a real clock (this is a CLI
    action, not a workflow), so it's fine to read the wall clock here.
    """
    if not since:
        return None
    m = re.fullmatch(r"(\d+)\s*([dhm])", since.strip(), re.I)
    if not m:
        raise ValueError(f"invalid --since {since!r}; use forms like 7d, 24h, 30m")
    from datetime import datetime, timedelta, timezone
    n = int(m.group(1))
    unit = m.group(2).lower()
    delta = {"d": timedelta(days=n), "h": timedelta(hours=n), "m": timedelta(minutes=n)}[unit]
    cutoff = datetime.now(timezone.utc) - delta
    return cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch_indicators(
    conn: sqlite3.Connection,
    *,
    since: Optional[str] = None,
    min_severity: Optional[str] = None,
    statuses: Optional[List[str]] = None,
    limit: int = 5000,
) -> List[Indicator]:
    """Return exportable indicators from watchlist matches.

    Filters: since (time window), min_severity, statuses (default excludes
    false_positive), limit. Deduped on (itype, value), keeping the
    highest-scored occurrence.
    """
    cutoff = _parse_since(since)
    sql = [
        """
        SELECT m.matched_value, w.type AS wtype, m.severity, m.score,
               m.created_at, m.status, m.context,
               d.source_name, d.source_url, d.title AS doc_title
        FROM matches m
        JOIN watchlist w ON w.id = m.watchlist_id
        JOIN documents d ON d.id = m.document_id
        WHERE 1=1
        """
    ]
    params: list = []
    if cutoff:
        sql.append("AND m.created_at >= ?")
        params.append(cutoff)
    if statuses:
        placeholders = ",".join("?" * len(statuses))
        sql.append(f"AND m.status IN ({placeholders})")
        params.extend(statuses)
    else:
        sql.append("AND m.status != 'false_positive'")
    sql.append("ORDER BY COALESCE(m.score, -1) DESC, m.created_at DESC")
    sql.append("LIMIT ?")
    params.append(int(limit))

    rows = conn.execute("\n".join(sql), tuple(params)).fetchall()

    min_rank = SEVERITY_ORDER.get((min_severity or "").lower()) if min_severity else None

    seen = set()
    out: List[Indicator] = []
    for r in rows:
        sev = (r["severity"] or "medium").lower()
        if min_rank is not None and SEVERITY_ORDER.get(sev, 0) < min_rank:
            continue
        itype = _refine_type(r["wtype"], r["matched_value"])
        key = (itype, r["matched_value"].lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(Indicator(
            value=r["matched_value"],
            itype=itype,
            severity=sev,
            score=r["score"],
            first_seen=r["created_at"],
            source_name=r["source_name"],
            source_url=r["source_url"],
            doc_title=r["doc_title"],
            context=r["context"],
        ))
    return out
