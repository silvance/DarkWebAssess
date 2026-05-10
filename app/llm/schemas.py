"""Pydantic schema for the analyst summary returned by the LLM."""
from typing import List

from pydantic import BaseModel, Field


class AnalystSummary(BaseModel):
    """Structured analyst note generated from a watchlist match.

    Field semantics are designed to mirror the rubric in `app/llm/prompts.py`.
    Treat every field as analyst-facing: terse, factual, and grounded in the
    supplied source material — the LLM is instructed not to invent indicators,
    attributions, or events that aren't present in the input.
    """

    summary: str = Field(
        description="One-paragraph plain-English summary of the source as it relates to the matched entity."
    )
    relevant_entities: List[str] = Field(
        default_factory=list,
        description="Domains, IPs, CVEs, hashes, URLs, malware families, or actor names explicitly named in the source.",
    )
    why_it_matters: str = Field(
        description="Why this match warrants analyst attention. Tie back to the watchlist entry and any enrichment signals."
    )
    confidence: str = Field(
        description="One of: 'low', 'medium', 'high'. Reflects how confidently the source supports the match."
    )
    confidence_explanation: str = Field(
        description="Short rationale for the confidence level — what supports it, what undermines it."
    )
    next_steps: List[str] = Field(
        default_factory=list,
        description="Concrete investigative or notification steps an analyst should take next.",
    )
    unknowns: List[str] = Field(
        default_factory=list,
        description="Material questions the source does NOT answer. Useful for follow-up research.",
    )
