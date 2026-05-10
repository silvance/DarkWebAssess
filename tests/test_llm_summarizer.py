import json
import os
import tempfile
from types import SimpleNamespace

import pytest

from app.database import get_connection, init_db
from app.llm import summarizer
from app.llm.prompts import build_user_prompt
from app.llm.schemas import AnalystSummary
from app.repository import (
    insert_document,
    insert_entities,
    insert_match,
    upsert_enrichment,
    upsert_watchlist_entry,
)


@pytest.fixture
def conn():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    c = get_connection(path)
    try:
        yield c
    finally:
        c.close()
        os.unlink(path)


def _seed_match(conn, *, raw_text="Source text mentions example.com today.") -> int:
    doc_id = insert_document(
        conn,
        {
            "source_name": "Test Feed",
            "source_type": "rss",
            "source_url": "https://example.com/post",
            "title": "Example Mention",
            "raw_text": raw_text,
            "raw_html": None,
            "language": "en",
            "published_at": "2026-05-09T12:00:00Z",
            "retrieved_at": "2026-05-10T00:00:00Z",
            "content_hash": f"hash-{raw_text[:20]}",
        },
    )
    insert_entities(
        conn,
        doc_id,
        [
            {"entity_type": "domain", "entity_value": "example.com", "context": ""},
            {"entity_type": "cve", "entity_value": "CVE-2024-3400", "context": ""},
        ],
    )
    wid = upsert_watchlist_entry(
        conn,
        {"type": "domain", "value": "example.com", "severity": "high", "enabled": True,
         "description": "Test entity"},
    )
    upsert_enrichment(
        conn,
        "cve",
        "CVE-2024-3400",
        "cisa_kev",
        success=True,
        result={"in_kev": True, "vendor_project": "Palo Alto"},
    )
    return insert_match(
        conn,
        document_id=doc_id,
        watchlist_id=wid,
        matched_value="example.com",
        match_type="exact_domain",
        context="ctx",
        severity="high",
    )


def _fake_response(parsed: AnalystSummary, *, input_tokens=120, output_tokens=80,
                   cache_read=0, cache_creation=0):
    usage = SimpleNamespace(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cache_read_input_tokens=cache_read,
        cache_creation_input_tokens=cache_creation,
    )
    return SimpleNamespace(parsed_output=parsed, usage=usage)


# --- prompts -----------------------------------------------------------
def test_build_user_prompt_includes_match_and_doc():
    text = build_user_prompt(
        matched_value="example.com",
        match_type="exact_domain",
        severity="high",
        score=80,
        score_reasons=["+15 exact match", "+20 CVE in CISA KEV"],
        watchlist_description="Primary domain",
        document={
            "source_name": "Test Feed",
            "source_url": "https://x/y",
            "title": "T",
            "raw_text": "body text",
            "retrieved_at": "2026-05-10T00:00:00Z",
            "published_at": "2026-05-09T12:00:00Z",
        },
        entities=[{"entity_type": "domain", "entity_value": "example.com", "context": ""}],
        enrichments=[],
    )
    assert "matched_value: example.com" in text
    assert "score: 80" in text
    assert "+15 exact match" in text
    assert "Test Feed" in text
    assert "body text" in text
    assert "(none recorded)" in text  # enrichments section


def test_build_user_prompt_truncates_long_text():
    long_text = "x" * 100_000
    out = build_user_prompt(
        matched_value="x",
        match_type="exact_domain",
        severity="low",
        score=None,
        score_reasons=[],
        watchlist_description=None,
        document={
            "source_name": "s",
            "source_url": "u",
            "title": "t",
            "raw_text": long_text,
            "retrieved_at": "t1",
            "published_at": None,
        },
        entities=[],
        enrichments=[],
    )
    assert "[...truncated]" in out
    assert len(out) < len(long_text)  # truncation happened


# --- summarizer ----------------------------------------------------------
def test_summarize_match_persists_and_returns(conn, monkeypatch):
    match_id = _seed_match(conn)
    parsed = AnalystSummary(
        summary="The source mentions example.com in a benign context.",
        relevant_entities=["example.com", "CVE-2024-3400"],
        why_it_matters="example.com is on the watchlist; the post links it to a recent advisory.",
        confidence="medium",
        confidence_explanation="Source mentions but does not characterize the domain as malicious.",
        next_steps=["Pivot on example.com in passive DNS"],
        unknowns=["Whether example.com is the attacker or victim"],
    )

    fake_client = SimpleNamespace(
        messages=SimpleNamespace(
            parse=lambda **kw: _fake_response(parsed, input_tokens=200, output_tokens=150)
        )
    )
    monkeypatch.setattr(summarizer, "_client", lambda: fake_client)

    rec = summarizer.summarize_match(conn, match_id)
    assert rec is not None
    assert rec.summary.confidence == "medium"
    assert rec.input_tokens == 200

    row = conn.execute(
        "SELECT * FROM llm_summaries WHERE match_id = ?", (match_id,)
    ).fetchone()
    assert row is not None
    assert row["summary_text"].startswith("The source mentions example.com")
    assert json.loads(row["entities_json"]) == ["example.com", "CVE-2024-3400"]
    assert row["confidence"] == "medium"
    assert row["input_tokens"] == 200


def test_summarize_skips_existing_summary(conn, monkeypatch):
    match_id = _seed_match(conn)
    parsed = AnalystSummary(
        summary="First", relevant_entities=[], why_it_matters="x",
        confidence="low", confidence_explanation="x", next_steps=[], unknowns=[],
    )
    calls = {"n": 0}

    def fake_parse(**kw):
        calls["n"] += 1
        return _fake_response(parsed)

    monkeypatch.setattr(
        summarizer, "_client",
        lambda: SimpleNamespace(messages=SimpleNamespace(parse=fake_parse)),
    )
    summarizer.summarize_match(conn, match_id)
    second = summarizer.summarize_match(conn, match_id)
    assert second is None
    assert calls["n"] == 1


def test_summarize_force_regenerates(conn, monkeypatch):
    match_id = _seed_match(conn)
    parsed_v1 = AnalystSummary(
        summary="v1", relevant_entities=[], why_it_matters="x",
        confidence="low", confidence_explanation="x", next_steps=[], unknowns=[],
    )
    parsed_v2 = AnalystSummary(
        summary="v2", relevant_entities=["example.com"], why_it_matters="updated",
        confidence="high", confidence_explanation="ok", next_steps=["a"], unknowns=[],
    )
    calls = {"n": 0}

    def fake_parse(**kw):
        calls["n"] += 1
        return _fake_response(parsed_v2 if calls["n"] >= 2 else parsed_v1)

    monkeypatch.setattr(
        summarizer, "_client",
        lambda: SimpleNamespace(messages=SimpleNamespace(parse=fake_parse)),
    )
    summarizer.summarize_match(conn, match_id)
    rec = summarizer.summarize_match(conn, match_id, force=True)
    assert rec is not None
    assert rec.summary.summary == "v2"
    assert calls["n"] == 2


def test_summarize_unknown_match_returns_none(conn):
    assert summarizer.summarize_match(conn, 9999) is None


def test_summarize_uses_cache_control_on_system(conn, monkeypatch):
    match_id = _seed_match(conn)
    captured = {}

    def fake_parse(**kw):
        captured.update(kw)
        return _fake_response(
            AnalystSummary(
                summary="x", relevant_entities=[], why_it_matters="x",
                confidence="low", confidence_explanation="x", next_steps=[], unknowns=[],
            )
        )

    monkeypatch.setattr(
        summarizer, "_client",
        lambda: SimpleNamespace(messages=SimpleNamespace(parse=fake_parse)),
    )
    summarizer.summarize_match(conn, match_id)

    system_blocks = captured["system"]
    assert isinstance(system_blocks, list) and system_blocks
    assert system_blocks[0].get("cache_control") == {"type": "ephemeral"}
    # User text should mention the matched value and source title.
    user_text = captured["messages"][0]["content"]
    assert "example.com" in user_text
    assert "Example Mention" in user_text


def test_summarize_raises_when_unconfigured(conn, monkeypatch):
    match_id = _seed_match(conn)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # _client() raises only when called; trigger it.
    with pytest.raises(summarizer.SummarizerNotConfigured):
        summarizer.summarize_match(conn, match_id)
