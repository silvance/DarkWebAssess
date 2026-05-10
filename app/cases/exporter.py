"""Markdown exporter for cases.

Resolves the polymorphic `case_evidence` rows into a self-contained analyst
report. Designed for read-only consumption — the report inlines the relevant
match / document / summary / enrichment bits so a recipient doesn't need DB
access.
"""
import json
import sqlite3
from typing import List, Optional

from app.cases.repository import get_case_detail


def _md_escape(text: Optional[str]) -> str:
    if text is None:
        return ""
    return str(text).replace(" ", " ").replace("|", "\\|")


def _truncate(text: Optional[str], limit: int = 800) -> str:
    if not text:
        return ""
    return text if len(text) <= limit else text[:limit] + "…"


def _resolve_evidence(conn: sqlite3.Connection, ev: dict) -> dict:
    """Look up the referenced row for an evidence entry; return resolved data."""
    kind = ev["kind"]
    ref = ev["ref"] or ""
    out = {"kind": kind, "label": ev["label"], "body": ev["body"], "ref": ref}
    if kind == "match" and ref.startswith("match:"):
        mid = int(ref.split(":", 1)[1])
        row = conn.execute(
            """
            SELECT m.id, m.matched_value, m.match_type, m.severity, m.score,
                   m.score_reasons, m.context AS match_context, m.status,
                   d.title, d.source_name, d.source_url, d.retrieved_at
            FROM matches m JOIN documents d ON d.id = m.document_id
            WHERE m.id = ?
            """,
            (mid,),
        ).fetchone()
        if row:
            out["match"] = dict(row)
    elif kind == "document" and ref.startswith("document:"):
        did = int(ref.split(":", 1)[1])
        row = conn.execute(
            "SELECT id, title, source_name, source_url, retrieved_at, raw_text FROM documents WHERE id = ?",
            (did,),
        ).fetchone()
        if row:
            out["document"] = dict(row)
    elif kind == "summary" and ref.startswith("summary:"):
        sid = int(ref.split(":", 1)[1])
        row = conn.execute(
            "SELECT id, model, summary_text, why_it_matters, confidence, "
            "confidence_explanation, next_steps_json, unknowns_json, entities_json, created_at "
            "FROM llm_summaries WHERE id = ?",
            (sid,),
        ).fetchone()
        if row:
            out["summary"] = dict(row)
    elif kind == "enrichment" and ref.startswith("enrichment:"):
        eid = int(ref.split(":", 1)[1])
        row = conn.execute(
            "SELECT id, entity_type, entity_value, provider, success, result_json, error, enriched_at "
            "FROM enrichments WHERE id = ?",
            (eid,),
        ).fetchone()
        if row:
            out["enrichment"] = dict(row)
    elif kind == "entity":
        # ref looks like "entity:domain:example.com"
        parts = ref.split(":", 2)
        if len(parts) == 3:
            out["entity"] = {"type": parts[1], "value": parts[2]}
    return out


def _format_event(ev: dict) -> str:
    payload = ev.get("payload") or {}
    actor = ev.get("actor") or "system"
    et = ev["event_type"]
    if et == "status_changed":
        return f"`{ev['created_at']}` — **status** {payload.get('from')} → {payload.get('to')} (by {actor})"
    if et == "severity_changed":
        return f"`{ev['created_at']}` — **severity** {payload.get('from')} → {payload.get('to')} (by {actor})"
    if et == "owner_changed":
        return f"`{ev['created_at']}` — **owner** {payload.get('from')} → {payload.get('to')}"
    if et == "title_changed":
        return f"`{ev['created_at']}` — **title** changed (by {actor})"
    if et == "summary_changed":
        return f"`{ev['created_at']}` — **summary** updated (by {actor})"
    if et == "note_added":
        return f"`{ev['created_at']}` — note added by {actor}: _{_md_escape(payload.get('preview') or '')}_"
    if et == "evidence_added":
        return (
            f"`{ev['created_at']}` — evidence added: **{payload.get('kind')}**"
            f" {payload.get('label') or payload.get('ref') or ''} (by {actor})"
        )
    if et == "evidence_removed":
        return f"`{ev['created_at']}` — evidence removed: {payload.get('ref')} (by {actor})"
    if et == "created":
        return f"`{ev['created_at']}` — case created (by {actor})"
    return f"`{ev['created_at']}` — {et} (by {actor})"


def export_markdown(conn: sqlite3.Connection, case_id: int) -> Optional[str]:
    """Render a case as a markdown report. Returns None if the case is missing."""
    case = get_case_detail(conn, case_id)
    if not case:
        return None

    out: List[str] = []
    out.append(f"# Case #{case['id']} — {_md_escape(case['title'])}\n")
    out.append(
        f"- **Status:** `{case['status']}`  ·  **Severity:** `{case['severity']}`  ·  "
        f"**Owner:** {case['owner'] or '_unassigned_'}"
    )
    out.append(f"- **Created:** {case['created_at']}  ·  **Updated:** {case['updated_at']}")
    if case.get("closed_at"):
        out.append(f"- **Closed:** {case['closed_at']}")
    if case.get("summary"):
        out.append("\n## Summary\n")
        out.append(case["summary"])

    # Resolved evidence
    resolved = [_resolve_evidence(conn, ev) for ev in case["evidence"]]

    matches = [r for r in resolved if r["kind"] == "match" and r.get("match")]
    documents = [r for r in resolved if r["kind"] == "document" and r.get("document")]
    entities = [r for r in resolved if r["kind"] == "entity"]
    summaries = [r for r in resolved if r["kind"] == "summary" and r.get("summary")]
    enrichments = [r for r in resolved if r["kind"] == "enrichment" and r.get("enrichment")]
    text_entries = [r for r in resolved if r["kind"] == "text"]

    if matches:
        out.append("\n## Linked matches")
        out.append("| ID | Value | Type | Score | Severity | Source | Title |")
        out.append("|---|---|---|---|---|---|---|")
        for r in matches:
            m = r["match"]
            out.append(
                "| {id} | `{val}` | {mt} | {score} | {sev} | {src} | {title} |".format(
                    id=m["id"],
                    val=_md_escape(m["matched_value"]),
                    mt=_md_escape(m["match_type"]),
                    score=m["score"] if m["score"] is not None else "—",
                    sev=_md_escape(m["severity"]),
                    src=_md_escape(m["source_name"]),
                    title=_md_escape(m["title"] or ""),
                )
            )

    if documents:
        out.append("\n## Documents")
        for r in documents:
            d = r["document"]
            out.append(f"### {_md_escape(d['title'] or d['source_url'])}")
            out.append(
                f"- **Source:** {_md_escape(d['source_name'])}  ·  "
                f"**URL:** {d['source_url']}  ·  **Retrieved:** {d['retrieved_at']}"
            )
            excerpt = _truncate(d["raw_text"])
            if excerpt:
                out.append("\n> " + excerpt.replace("\n", "\n> "))

    if entities:
        out.append("\n## Entities of interest")
        for r in entities:
            e = r.get("entity") or {}
            out.append(f"- **{_md_escape(e.get('type'))}**: `{_md_escape(e.get('value'))}`")

    if summaries:
        out.append("\n## Analyst summaries (LLM)")
        for r in summaries:
            s = r["summary"]
            try:
                steps = json.loads(s["next_steps_json"]) if s["next_steps_json"] else []
                gaps = json.loads(s["unknowns_json"]) if s["unknowns_json"] else []
            except (TypeError, ValueError):
                steps, gaps = [], []
            out.append(f"### Generated {s['created_at']} ({s['model']})")
            out.append(
                f"_Confidence: **{s['confidence']}** — {_md_escape(s['confidence_explanation'])}_"
            )
            out.append("\n" + s["summary_text"])
            if s.get("why_it_matters"):
                out.append("\n**Why it matters:** " + s["why_it_matters"])
            if steps:
                out.append("\n**Recommended next steps:**")
                for st in steps:
                    out.append(f"- {st}")
            if gaps:
                out.append("\n**Unknowns:**")
                for g in gaps:
                    out.append(f"- {g}")

    if enrichments:
        out.append("\n## Enrichment results")
        for r in enrichments:
            e = r["enrichment"]
            try:
                payload = json.loads(e["result_json"] or "null")
            except (TypeError, ValueError):
                payload = None
            out.append(
                f"- **{_md_escape(e['provider'])}** on `{_md_escape(e['entity_type'])}={_md_escape(e['entity_value'])}` "
                f"({'OK' if e['success'] else 'ERROR'})"
            )
            if e["success"] and payload is not None:
                out.append("  ```json\n  " + json.dumps(payload, indent=2).replace("\n", "\n  ") + "\n  ```")
            elif not e["success"] and e.get("error"):
                out.append(f"  - error: `{_md_escape(e['error'])}`")

    if text_entries:
        out.append("\n## Free-form evidence")
        for r in text_entries:
            label = r.get("label") or "Note"
            out.append(f"### {_md_escape(label)}")
            if r.get("body"):
                out.append(r["body"])

    if case["notes"]:
        out.append("\n## Analyst notes")
        for n in case["notes"]:
            out.append(f"### `{n['created_at']}` — {n['author'] or '_anonymous_'}")
            out.append(n["body"])

    out.append("\n## Timeline")
    for ev in case["events"]:
        out.append(f"- {_format_event(ev)}")

    return "\n".join(out) + "\n"
