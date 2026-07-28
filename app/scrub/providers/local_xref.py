"""Local cross-reference.

Answers "has this identifier already shown up in the sources *this* tool
collects?" — the passive side of the platform meeting the active scrub.
If your email appears in a document you already pulled from a leak-index
feed, that's the highest-signal finding of all, and it needs no external
service.

Offline and always available. Checks three places:
  - `entities` (extracted observables) exact-matching the value
  - `matches` (watchlist hits) matching the value
  - `documents` full-text/`LIKE` mentioning the value
"""
from __future__ import annotations

import sqlite3
from typing import List

from app.scrub.base import Finding, ScrubProvider, Target

# Which entity types a target type can match against in the entities table.
_ENTITY_TYPES = {
    "email": ("email",),
    "domain": ("domain",),
    "username": ("handle",),
}


class LocalXrefProvider(ScrubProvider):
    name = "local_xref"
    supported_types = ("email", "domain", "username")

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def scrub(self, target: Target) -> List[Finding]:
        value = target.normalized()
        findings: List[Finding] = []

        # 1. Watchlist matches referencing this value (highest signal).
        match_rows = self.conn.execute(
            """
            SELECT m.id, m.matched_value, m.match_type, m.severity, m.score,
                   d.source_name, d.title, d.source_url
            FROM matches m
            JOIN documents d ON d.id = m.document_id
            WHERE LOWER(m.matched_value) = ?
            ORDER BY COALESCE(m.score, -1) DESC
            LIMIT 25
            """,
            (value.lower(),),
        ).fetchall()
        for r in match_rows:
            findings.append(Finding(
                kind="mention",
                title=f"Already a watchlist match in collected source: {r['source_name']}",
                severity="high",
                detail=(
                    f"'{r['matched_value']}' matched ({r['match_type']}) in "
                    f"\"{r['title'] or 'untitled'}\" — score {r['score']}."
                ),
                url=r["source_url"] or None,
                data={"match_id": r["id"], "source": r["source_name"]},
            ))

        # 2. Extracted entities of the relevant type exactly equal to value.
        ent_types = _ENTITY_TYPES.get(target.type, ())
        if ent_types:
            placeholders = ",".join("?" * len(ent_types))
            ent_rows = self.conn.execute(
                f"""
                SELECT e.entity_value, e.context, d.source_name, d.title,
                       d.source_url, COUNT(*) AS hits
                FROM entities e
                JOIN documents d ON d.id = e.document_id
                WHERE e.entity_type IN ({placeholders})
                  AND LOWER(e.entity_value) = ?
                GROUP BY d.id
                ORDER BY hits DESC
                LIMIT 25
                """,
                (*ent_types, value.lower()),
            ).fetchall()
            # Skip docs already surfaced as matches (avoid double reporting).
            for r in ent_rows:
                findings.append(Finding(
                    kind="mention",
                    title=f"Appears as an extracted {target.type} in: {r['source_name']}",
                    severity="medium",
                    detail=(
                        f"Found in \"{r['title'] or 'untitled'}\". "
                        f"Context: {(r['context'] or '')[:160]}"
                    ),
                    url=r["source_url"] or None,
                    data={"source": r["source_name"]},
                ))

        # 3. Free-text mention in any document body (broadest, lowest signal).
        # Only run when we found nothing more specific, to avoid noise.
        if not findings:
            like = f"%{value}%"
            doc_rows = self.conn.execute(
                """
                SELECT source_name, title, source_url
                FROM documents
                WHERE raw_text LIKE ? OR title LIKE ?
                ORDER BY retrieved_at DESC
                LIMIT 10
                """,
                (like, like),
            ).fetchall()
            for r in doc_rows:
                findings.append(Finding(
                    kind="mention",
                    title=f"Text mention in collected document: {r['source_name']}",
                    severity="low",
                    detail=f"Mentioned in \"{r['title'] or 'untitled'}\".",
                    url=r["source_url"] or None,
                    data={"source": r["source_name"]},
                ))

        return findings
