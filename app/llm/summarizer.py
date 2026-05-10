"""Generate analyst summaries for watchlist matches via the Claude API.

The summarizer follows the structured-outputs pattern from the Anthropic
SDK: a Pydantic schema (`AnalystSummary`) is passed as `output_format=` to
`client.messages.parse()`, which returns a validated instance on the
response's `.parsed_output`. The static system prompt carries
`cache_control: {ephemeral}` so re-summarizing benefits from prompt caching
once the prefix is large enough to clear the model's minimum threshold.
"""
import json
import logging
import os
import sqlite3
from dataclasses import dataclass
from typing import Optional

import anthropic

from app.config import LLM_DOC_TEXT_CHARS, LLM_MAX_TOKENS, LLM_MODEL
from app.llm.prompts import SYSTEM_PROMPT, build_user_prompt
from app.llm.schemas import AnalystSummary
from app.normalizer import utcnow_iso

log = logging.getLogger(__name__)


class SummarizerNotConfigured(RuntimeError):
    """Raised when ANTHROPIC_API_KEY is not set."""


@dataclass
class SummaryRecord:
    match_id: int
    model: str
    summary: AnalystSummary
    input_tokens: int
    output_tokens: int
    cache_read_input_tokens: int
    cache_creation_input_tokens: int


def _is_configured() -> bool:
    return bool(os.getenv("ANTHROPIC_API_KEY"))


def _client() -> anthropic.Anthropic:
    if not _is_configured():
        raise SummarizerNotConfigured(
            "ANTHROPIC_API_KEY is not set; cannot call the Claude API."
        )
    return anthropic.Anthropic()


def _load_match_context(conn: sqlite3.Connection, match_id: int) -> Optional[dict]:
    row = conn.execute(
        """
        SELECT m.id AS match_id, m.matched_value, m.match_type, m.severity,
               m.score, m.score_reasons, m.context AS match_context,
               w.description AS watchlist_description,
               d.id AS document_id, d.source_name, d.source_url, d.title,
               d.raw_text, d.retrieved_at, d.published_at, d.language
        FROM matches m
        JOIN documents d ON d.id = m.document_id
        LEFT JOIN watchlist w ON w.id = m.watchlist_id
        WHERE m.id = ?
        """,
        (int(match_id),),
    ).fetchone()
    if row is None:
        return None
    record = dict(row)
    try:
        record["score_reasons_list"] = (
            json.loads(record["score_reasons"]) if record["score_reasons"] else []
        )
    except (TypeError, ValueError):
        record["score_reasons_list"] = []

    record["entities"] = [
        dict(r)
        for r in conn.execute(
            "SELECT entity_type, entity_value, context FROM entities "
            "WHERE document_id = ? ORDER BY entity_type, entity_value LIMIT 200",
            (record["document_id"],),
        ).fetchall()
    ]

    # Pull enrichments tied to either the matched value itself or any other
    # entity present on the same document — gives the model crosspoint context.
    record["enrichments"] = [
        dict(r)
        for r in conn.execute(
            """
            SELECT entity_type, entity_value, provider, success, result_json,
                   error
            FROM enrichments
            WHERE (entity_type, entity_value) IN (
                SELECT DISTINCT entity_type, entity_value FROM entities
                WHERE document_id = ?
            )
            ORDER BY provider
            """,
            (record["document_id"],),
        ).fetchall()
    ]
    return record


def _build_messages(record: dict) -> tuple[list, str]:
    """Return (system_blocks, user_text) ready for the SDK call."""
    system_blocks = [
        {
            "type": "text",
            "text": SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }
    ]
    document = {
        "source_name": record["source_name"],
        "source_url": record["source_url"],
        "title": record["title"],
        "raw_text": record["raw_text"],
        "retrieved_at": record["retrieved_at"],
        "published_at": record["published_at"],
    }
    user_text = build_user_prompt(
        matched_value=record["matched_value"],
        match_type=record["match_type"],
        severity=record["severity"],
        score=record["score"],
        score_reasons=record["score_reasons_list"],
        watchlist_description=record.get("watchlist_description"),
        document=document,
        entities=record["entities"],
        enrichments=record["enrichments"],
    )
    return system_blocks, user_text


def _persist(conn: sqlite3.Connection, rec: SummaryRecord) -> int:
    summary = rec.summary
    conn.execute(
        """
        INSERT INTO llm_summaries (
            match_id, model, summary_text, entities_json, why_it_matters,
            confidence, confidence_explanation, next_steps_json, unknowns_json,
            input_tokens, output_tokens, cache_read_input_tokens,
            cache_creation_input_tokens, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(match_id, model) DO UPDATE SET
            summary_text = excluded.summary_text,
            entities_json = excluded.entities_json,
            why_it_matters = excluded.why_it_matters,
            confidence = excluded.confidence,
            confidence_explanation = excluded.confidence_explanation,
            next_steps_json = excluded.next_steps_json,
            unknowns_json = excluded.unknowns_json,
            input_tokens = excluded.input_tokens,
            output_tokens = excluded.output_tokens,
            cache_read_input_tokens = excluded.cache_read_input_tokens,
            cache_creation_input_tokens = excluded.cache_creation_input_tokens,
            created_at = excluded.created_at
        """,
        (
            rec.match_id,
            rec.model,
            summary.summary,
            json.dumps(summary.relevant_entities),
            summary.why_it_matters,
            summary.confidence,
            summary.confidence_explanation,
            json.dumps(summary.next_steps),
            json.dumps(summary.unknowns),
            int(rec.input_tokens),
            int(rec.output_tokens),
            int(rec.cache_read_input_tokens),
            int(rec.cache_creation_input_tokens),
            utcnow_iso(),
        ),
    )
    row = conn.execute(
        "SELECT id FROM llm_summaries WHERE match_id = ? AND model = ?",
        (rec.match_id, rec.model),
    ).fetchone()
    return int(row["id"])


def get_summary(conn: sqlite3.Connection, match_id: int, model: Optional[str] = None) -> Optional[dict]:
    sql = "SELECT * FROM llm_summaries WHERE match_id = ?"
    params: list = [int(match_id)]
    if model:
        sql += " AND model = ?"
        params.append(model)
    sql += " ORDER BY created_at DESC LIMIT 1"
    row = conn.execute(sql, tuple(params)).fetchone()
    return dict(row) if row else None


def summarize_match(
    conn: sqlite3.Connection,
    match_id: int,
    *,
    model: Optional[str] = None,
    max_tokens: Optional[int] = None,
    force: bool = False,
) -> Optional[SummaryRecord]:
    """Summarize a single match. Returns None if the match doesn't exist."""
    record = _load_match_context(conn, match_id)
    if record is None:
        return None
    chosen_model = model or LLM_MODEL
    if not force:
        existing = get_summary(conn, match_id, chosen_model)
        if existing:
            log.info("Skipping match %s: summary already exists for %s", match_id, chosen_model)
            return None

    client = _client()
    system_blocks, user_text = _build_messages(record)

    response = client.messages.parse(
        model=chosen_model,
        max_tokens=max_tokens or LLM_MAX_TOKENS,
        system=system_blocks,
        messages=[{"role": "user", "content": user_text}],
        output_format=AnalystSummary,
    )
    parsed: AnalystSummary = response.parsed_output
    usage = getattr(response, "usage", None)
    rec = SummaryRecord(
        match_id=match_id,
        model=chosen_model,
        summary=parsed,
        input_tokens=getattr(usage, "input_tokens", 0) or 0,
        output_tokens=getattr(usage, "output_tokens", 0) or 0,
        cache_read_input_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
        cache_creation_input_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
    )
    _persist(conn, rec)
    conn.commit()
    return rec
