"""Report templates. Each template is a function that takes a sqlite3
Connection and an optional window spec, and returns a `Report`.

Add a new template by importing `register` from `app.reports.base` and
decorating a function. Make sure to import this module from
`app.reports.runner` so registrations happen on first use.
"""
import json
import sqlite3
from typing import Optional

from app.normalizer import utcnow_iso
from app.reports.base import Report, ReportSection, register, window_bounds


def _rows(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list:
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


# ---- daily_summary ------------------------------------------------------
@register("daily_summary")
def daily_summary(conn: sqlite3.Connection, *, window: Optional[str] = "24h") -> Report:
    """Daily threat summary: top open matches, severity breakdown, fresh docs, source errors."""
    start, end = window_bounds(window)
    sections = []

    top_matches = _rows(
        conn,
        """
        SELECT m.id, m.score, m.severity, m.matched_value, m.match_type,
               d.source_name, d.title
        FROM matches m
        JOIN documents d ON d.id = m.document_id
        WHERE m.status IN ('new', 'reviewing')
          AND (? IS NULL OR m.created_at >= ?)
          AND m.created_at <= ?
        ORDER BY COALESCE(m.score, -1) DESC, m.created_at DESC
        LIMIT 20
        """,
        (start, start, end),
    )
    sections.append(
        ReportSection(
            title="Top open matches by score",
            description="Highest-priority unresolved findings in the window.",
            columns=["id", "score", "severity", "matched_value", "match_type", "source_name", "title"],
            rows=top_matches,
        )
    )

    sev_breakdown = _rows(
        conn,
        """
        SELECT severity, COUNT(*) AS new_matches
        FROM matches
        WHERE created_at <= ?
          AND (? IS NULL OR created_at >= ?)
        GROUP BY severity
        ORDER BY CASE severity
            WHEN 'critical' THEN 0
            WHEN 'high' THEN 1
            WHEN 'medium' THEN 2
            WHEN 'low' THEN 3
            ELSE 4 END
        """,
        (end, start, start),
    )
    sections.append(
        ReportSection(
            title="Match volume by severity",
            columns=["severity", "new_matches"],
            rows=sev_breakdown,
        )
    )

    docs = _rows(
        conn,
        """
        SELECT id, retrieved_at, source_name, title, source_url
        FROM documents
        WHERE retrieved_at <= ?
          AND (? IS NULL OR retrieved_at >= ?)
        ORDER BY retrieved_at DESC
        LIMIT 25
        """,
        (end, start, start),
    )
    sections.append(
        ReportSection(
            title="Recent documents",
            columns=["retrieved_at", "source_name", "title", "source_url"],
            rows=docs,
        )
    )

    failing = _rows(
        conn,
        """
        SELECT name, last_checked_at, last_error, error_count
        FROM sources
        WHERE error_count > 0
        ORDER BY error_count DESC, last_checked_at DESC
        """,
    )
    sections.append(
        ReportSection(
            title="Sources with current errors",
            description="(Empty means every source last checked successfully.)",
            columns=["name", "error_count", "last_checked_at", "last_error"],
            rows=failing,
        )
    )

    return Report(
        name="daily_summary",
        title="Daily threat summary",
        description="Snapshot of high-priority matches, new collection volume, and source health.",
        generated_at=utcnow_iso(),
        window_start=start,
        window_end=end,
        sections=sections,
        metadata={
            "open_matches_total": len(top_matches),
            "documents_in_window": len(docs),
        },
    )


# ---- weekly_watchlist ----------------------------------------------------
@register("weekly_watchlist")
def weekly_watchlist(conn: sqlite3.Connection, *, window: Optional[str] = "7d") -> Report:
    """Weekly watchlist report: hits per watched entity over the window."""
    start, end = window_bounds(window)

    hits = _rows(
        conn,
        """
        SELECT w.type AS watchlist_type, w.value AS watchlist_value,
               w.severity, w.description,
               COUNT(m.id) AS hits,
               COUNT(DISTINCT m.document_id) AS distinct_docs,
               MAX(m.created_at) AS last_hit
        FROM watchlist w
        LEFT JOIN matches m
          ON m.watchlist_id = w.id
         AND (? IS NULL OR m.created_at >= ?)
         AND m.created_at <= ?
        WHERE w.enabled = 1
        GROUP BY w.id
        ORDER BY hits DESC, w.severity DESC
        """,
        (start, start, end),
    )

    new_values = _rows(
        conn,
        """
        SELECT matched_value, match_type, COUNT(*) AS hits, MIN(created_at) AS first_seen
        FROM matches
        WHERE created_at <= ?
          AND (? IS NULL OR created_at >= ?)
        GROUP BY matched_value, match_type
        ORDER BY hits DESC, first_seen DESC
        LIMIT 50
        """,
        (end, start, start),
    )

    top_sources = _rows(
        conn,
        """
        SELECT d.source_name, COUNT(m.id) AS matches
        FROM matches m
        JOIN documents d ON d.id = m.document_id
        WHERE m.created_at <= ?
          AND (? IS NULL OR m.created_at >= ?)
        GROUP BY d.source_name
        ORDER BY matches DESC
        LIMIT 20
        """,
        (end, start, start),
    )

    return Report(
        name="weekly_watchlist",
        title="Weekly watchlist report",
        description="Match counts per watched entity, plus top matched values and source contribution.",
        generated_at=utcnow_iso(),
        window_start=start,
        window_end=end,
        sections=[
            ReportSection(
                title="Watchlist entries with hits",
                columns=["watchlist_type", "watchlist_value", "severity", "hits", "distinct_docs", "last_hit", "description"],
                rows=hits,
            ),
            ReportSection(
                title="Most-matched values in window",
                columns=["matched_value", "match_type", "hits", "first_seen"],
                rows=new_values,
            ),
            ReportSection(
                title="Sources contributing matches",
                columns=["source_name", "matches"],
                rows=top_sources,
            ),
        ],
    )


# ---- source_health ------------------------------------------------------
@register("source_health")
def source_health(conn: sqlite3.Connection, *, window: Optional[str] = "7d") -> Report:
    """Source health report: per-source status, error counts, recent collection volume."""
    start, end = window_bounds(window)
    sources = _rows(
        conn,
        """
        SELECT s.name, s.type, s.url, s.enabled,
               s.last_checked_at, s.last_success_at, s.error_count, s.last_error,
               (SELECT COUNT(*) FROM documents d
                  WHERE d.source_name = s.name
                    AND d.retrieved_at <= ?
                    AND (? IS NULL OR d.retrieved_at >= ?)) AS docs_in_window
        FROM sources s
        ORDER BY s.error_count DESC, s.name
        """,
        (end, start, start),
    )

    job_runs = _rows(
        conn,
        """
        SELECT job_name, started_at, finished_at, success, duration_seconds, message
        FROM job_runs
        WHERE started_at <= ?
          AND (? IS NULL OR started_at >= ?)
        ORDER BY started_at DESC
        LIMIT 50
        """,
        (end, start, start),
    )

    return Report(
        name="source_health",
        title="Source health report",
        description="Per-source health, recent collection volume, and scheduler activity.",
        generated_at=utcnow_iso(),
        window_start=start,
        window_end=end,
        sections=[
            ReportSection(
                title="Sources",
                columns=[
                    "name", "type", "enabled", "error_count",
                    "last_checked_at", "last_success_at", "docs_in_window", "last_error",
                ],
                rows=sources,
            ),
            ReportSection(
                title="Recent scheduler runs",
                description="(Empty if you've never started the scheduler.)",
                columns=["job_name", "started_at", "success", "duration_seconds", "message"],
                rows=job_runs,
            ),
        ],
    )


# ---- executive ----------------------------------------------------------
@register("executive")
def executive(conn: sqlite3.Connection, *, window: Optional[str] = "30d") -> Report:
    """Executive summary: high-level metrics and top entities by sightings."""
    start, end = window_bounds(window)

    totals = conn.execute(
        """
        SELECT
            (SELECT COUNT(*) FROM documents) AS docs_total,
            (SELECT COUNT(*) FROM documents WHERE retrieved_at <= ? AND (? IS NULL OR retrieved_at >= ?)) AS docs_window,
            (SELECT COUNT(*) FROM matches) AS matches_total,
            (SELECT COUNT(*) FROM matches WHERE created_at <= ? AND (? IS NULL OR created_at >= ?)) AS matches_window,
            (SELECT COUNT(*) FROM matches WHERE status='new' AND severity IN ('high','critical')) AS open_high_critical,
            (SELECT COUNT(*) FROM cases WHERE status NOT IN ('closed', 'false_positive')) AS cases_open,
            (SELECT COUNT(*) FROM cases WHERE status = 'closed') AS cases_closed,
            (SELECT COALESCE(MAX(score), 0) FROM matches WHERE status='new') AS top_open_score
        """,
        (end, start, start, end, start, start),
    ).fetchone()

    metric_rows = [{"metric": k, "value": v} for k, v in dict(totals).items()]

    top_entities = _rows(
        conn,
        """
        SELECT entity_type, entity_value, COUNT(DISTINCT document_id) AS sightings
        FROM entities
        WHERE first_seen <= ?
          AND (? IS NULL OR first_seen >= ?)
        GROUP BY entity_type, entity_value
        ORDER BY sightings DESC, entity_value
        LIMIT 25
        """,
        (end, start, start),
    )

    top_actors = _rows(
        conn,
        """
        SELECT entity_value AS actor, COUNT(DISTINCT document_id) AS sightings
        FROM entities
        WHERE entity_type IN ('actor', 'malware')
          AND first_seen <= ?
          AND (? IS NULL OR first_seen >= ?)
        GROUP BY entity_value
        ORDER BY sightings DESC
        LIMIT 15
        """,
        (end, start, start),
    )

    top_cves = _rows(
        conn,
        """
        SELECT entity_value AS cve, COUNT(DISTINCT document_id) AS mentions
        FROM entities
        WHERE entity_type = 'cve'
          AND first_seen <= ?
          AND (? IS NULL OR first_seen >= ?)
        GROUP BY entity_value
        ORDER BY mentions DESC
        LIMIT 15
        """,
        (end, start, start),
    )

    return Report(
        name="executive",
        title="Executive summary",
        description="High-level operating metrics with a window of recent activity.",
        generated_at=utcnow_iso(),
        window_start=start,
        window_end=end,
        sections=[
            ReportSection(
                title="Headline metrics",
                columns=["metric", "value"],
                rows=metric_rows,
            ),
            ReportSection(
                title="Top entities by sightings",
                columns=["entity_type", "entity_value", "sightings"],
                rows=top_entities,
            ),
            ReportSection(
                title="Threat actors / malware",
                columns=["actor", "sightings"],
                rows=top_actors,
            ),
            ReportSection(
                title="Most-cited CVEs",
                columns=["cve", "mentions"],
                rows=top_cves,
            ),
        ],
    )
