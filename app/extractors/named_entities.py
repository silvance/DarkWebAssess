"""List-based named-entity extractor for malware family and threat-actor names.

Per the project plan, full NER (e.g., spaCy) is deferred. This module does a
pragmatic case-insensitive word-boundary lookup against curated lists in
`named_entities.yaml`. Multi-word names (e.g., "Cobalt Strike", "Volt Typhoon")
are supported. Returned `entity_type` is `malware` or `actor`.
"""
import re
from functools import lru_cache
from pathlib import Path
from typing import List

import yaml

CONTEXT_WINDOW = 80
LISTS_PATH = Path(__file__).parent / "named_entities.yaml"


@lru_cache(maxsize=1)
def _load_lists() -> dict:
    if not LISTS_PATH.exists():
        return {"malware": [], "threat_actors": []}
    with open(LISTS_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return {
        "malware": list(data.get("malware") or []),
        "threat_actors": list(data.get("threat_actors") or []),
    }


@lru_cache(maxsize=1)
def _compiled() -> dict:
    """Compile a single anchored alternation regex per list, longest-first."""
    out = {}
    for key, names in _load_lists().items():
        if not names:
            out[key] = None
            continue
        # Sort longest-first so "Black Basta" wins over a hypothetical "Black".
        sorted_names = sorted(set(names), key=len, reverse=True)
        # Use word boundaries when the name starts/ends with word chars.
        parts = []
        for n in sorted_names:
            esc = re.escape(n)
            left = r"\b" if n[:1].isalnum() else ""
            right = r"\b" if n[-1:].isalnum() else ""
            parts.append(f"{left}{esc}{right}")
        out[key] = re.compile("|".join(parts), re.IGNORECASE)
    return out


def _context(text: str, start: int, end: int) -> str:
    a = max(0, start - CONTEXT_WINDOW)
    b = min(len(text), end + CONTEXT_WINDOW)
    return re.sub(r"\s+", " ", text[a:b]).strip()


def _extract(text: str, list_key: str, entity_type: str) -> List[dict]:
    regex = _compiled().get(list_key)
    if regex is None:
        return []
    out = []
    seen = set()
    # Build a canonical-case map so we emit the YAML-defined casing rather
    # than whatever the source text used.
    canonical_by_lower = {n.lower(): n for n in _load_lists().get(list_key, [])}
    for m in regex.finditer(text):
        canonical = canonical_by_lower.get(m.group(0).lower(), m.group(0))
        if canonical in seen:
            continue
        seen.add(canonical)
        out.append(
            {
                "entity_type": entity_type,
                "entity_value": canonical,
                "context": _context(text, m.start(), m.end()),
            }
        )
    return out


def extract_malware(text: str) -> List[dict]:
    return _extract(text, "malware", "malware")


def extract_actors(text: str) -> List[dict]:
    return _extract(text, "threat_actors", "actor")


def extract_named_entities(text: str) -> List[dict]:
    return extract_malware(text) + extract_actors(text)
