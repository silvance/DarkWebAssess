"""Tor onion address extractor.

Matches v2 (16 chars) and v3 (56 chars) hostnames over the Tor base32 alphabet
(a-z, 2-7), ending in `.onion`. Returned `entity_type` is `onion`.
"""
import re
from typing import List

ONION_RE = re.compile(
    r"\b(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion\b",
    re.IGNORECASE,
)

CONTEXT_WINDOW = 80


def _context(text: str, start: int, end: int) -> str:
    a = max(0, start - CONTEXT_WINDOW)
    b = min(len(text), end + CONTEXT_WINDOW)
    return re.sub(r"\s+", " ", text[a:b]).strip()


def extract_onions(text: str) -> List[dict]:
    out = []
    seen = set()
    for m in ONION_RE.finditer(text):
        value = m.group(0).lower()
        if value in seen:
            continue
        seen.add(value)
        out.append(
            {
                "entity_type": "onion",
                "entity_value": value,
                "context": _context(text, m.start(), m.end()),
            }
        )
    return out
