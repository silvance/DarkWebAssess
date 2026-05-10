"""Prompt templates for analyst-summary generation.

The system prompt is designed to be **stable across calls** so prompt caching
hits — `cache_control: {"type": "ephemeral"}` is set on the system block in
the summarizer. Per-match content goes in the user turn so the cached prefix
isn't invalidated.
"""
import json
from typing import Iterable, List, Optional

from app.config import LLM_DOC_TEXT_CHARS

SYSTEM_PROMPT = """You are assisting a threat-intelligence analyst working in a small,
self-hosted intel platform. Your job is to summarize a single piece of collected
source material as it pertains to a specific watchlist match, and to draft a
short, factual analyst note in a fixed structured format.

Operating rules
- Use ONLY information supplied in the user turn (source title, source text,
  enrichment data, score reasons, extracted entities). Do not introduce facts
  from training memory.
- Do not invent indicators, attributions, victim names, malware families,
  threat-actor names, dates, or causal links. If the source doesn't say it,
  don't write it.
- Do not state final truth or attempt to validate stolen credentials, leaked
  data, or exploit functionality. Stop at "claimed" / "alleged" / "reported".
- Keep the tone neutral, terse, and analyst-grade. No marketing language, no
  rhetorical questions, no hedging filler.
- The matched entity is given in the user turn. Anchor your summary to that
  entity's mention in the source.
- If the source is foreign-language, summarize in English and note the
  original language.
- If the source contradicts the watchlist match (e.g., the matched value
  appears only in a benign context), say so explicitly in confidence_explanation
  and lower the confidence.

Output rules
- Respond with a single JSON object that conforms to the supplied schema.
- `summary` is one paragraph (3-6 sentences).
- `confidence` is exactly one of: "low", "medium", "high". Use "low" when the
  source barely mentions the matched entity, "high" only when the source
  directly and substantively discusses it.
- `next_steps` should be concrete (e.g., "Check whether 192.0.2.1 appears in
  recent firewall denies"), not vague (e.g., "Investigate further").
- `unknowns` lists material gaps in the source — facts a downstream analyst
  would still need to chase.

Reminder: investigative product, not journalism. Cite only what's in front of
you, flag uncertainty plainly, and surface the gaps.
"""


def _truncate(text: Optional[str], limit: int = None) -> str:
    if not text:
        return ""
    limit = limit or LLM_DOC_TEXT_CHARS
    if len(text) <= limit:
        return text
    return text[:limit] + "\n\n[...truncated]"


def build_user_prompt(
    *,
    matched_value: str,
    match_type: str,
    severity: str,
    score: Optional[int],
    score_reasons: Iterable[str],
    watchlist_description: Optional[str],
    document: dict,
    entities: Iterable[dict],
    enrichments: Iterable[dict],
) -> str:
    """Render the per-match user turn.

    Each call produces a fresh, deterministic block. The structure is:
        # Match
        # Document
        # Extracted entities (sample)
        # Enrichments
        # Source text
    """
    score_lines = list(score_reasons) or []
    ent_lines: List[str] = []
    for e in list(entities)[:40]:
        ent_lines.append(f"- {e['entity_type']}: {e['entity_value']}")
    enrichment_lines: List[str] = []
    for er in enrichments:
        try:
            payload = json.loads(er.get("result_json") or "{}")
        except (TypeError, ValueError):
            payload = {}
        if not er.get("success"):
            continue
        enrichment_lines.append(
            f"- {er['provider']} on ({er['entity_type']}, {er['entity_value']}): "
            + json.dumps(payload, sort_keys=True)
        )

    body = []
    body.append("# Match")
    body.append(f"matched_value: {matched_value}")
    body.append(f"match_type: {match_type}")
    body.append(f"severity: {severity}")
    if score is not None:
        body.append(f"score: {score}")
    if watchlist_description:
        body.append(f"watchlist_description: {watchlist_description}")
    if score_lines:
        body.append("score_reasons:")
        for r in score_lines:
            body.append(f"- {r}")

    body.append("\n# Document")
    body.append(f"source: {document.get('source_name')}")
    body.append(f"title: {document.get('title') or '(no title)'}")
    body.append(f"url: {document.get('source_url')}")
    body.append(f"retrieved_at: {document.get('retrieved_at')}")
    if document.get("published_at"):
        body.append(f"published_at: {document.get('published_at')}")

    if ent_lines:
        body.append("\n# Extracted entities (sample, up to 40)")
        body.extend(ent_lines)

    if enrichment_lines:
        body.append("\n# Enrichment results")
        body.extend(enrichment_lines)
    else:
        body.append("\n# Enrichment results")
        body.append("(none recorded)")

    body.append("\n# Source text")
    body.append(_truncate(document.get("raw_text") or ""))

    return "\n".join(body)
