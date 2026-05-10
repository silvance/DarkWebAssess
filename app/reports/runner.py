"""Generate, persist, and look up reports."""
import json
import sqlite3
from typing import List, Optional

from app.normalizer import utcnow_iso
from app.reports import templates as _templates  # noqa: F401  (registers templates)
from app.reports.base import Report, get_template, list_templates as _list
from app.reports.renderers import render_html, render_json, render_markdown


def list_templates():
    return _list()


def generate_report(
    conn: sqlite3.Connection,
    name: str,
    *,
    window: Optional[str] = None,
) -> Report:
    fn = get_template(name)
    if window is None:
        return fn(conn)
    return fn(conn, window=window)


def save_report(conn: sqlite3.Connection, report: Report) -> int:
    """Persist a generated report, storing all three rendered bodies."""
    md = render_markdown(report)
    html = render_html(report)
    js = render_json(report)
    cur = conn.execute(
        """
        INSERT INTO reports (
            name, title, generated_at, window_start, window_end,
            body_markdown, body_html, body_json, metadata_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            report.name,
            report.title,
            report.generated_at,
            report.window_start,
            report.window_end,
            md,
            html,
            js,
            json.dumps(report.metadata, default=str),
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def list_saved(
    conn: sqlite3.Connection,
    *,
    name: Optional[str] = None,
    limit: int = 50,
) -> List[dict]:
    sql = (
        "SELECT id, name, title, generated_at, window_start, window_end "
        "FROM reports"
    )
    params: list = []
    if name:
        sql += " WHERE name = ?"
        params.append(name)
    sql += " ORDER BY generated_at DESC LIMIT ?"
    params.append(int(limit))
    return [dict(r) for r in conn.execute(sql, tuple(params)).fetchall()]


def get_saved(conn: sqlite3.Connection, report_id: int) -> Optional[dict]:
    row = conn.execute(
        "SELECT * FROM reports WHERE id = ?", (int(report_id),)
    ).fetchone()
    return dict(row) if row else None
