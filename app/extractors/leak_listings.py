"""Leak-site indicator extractor.

Recognizes patterns common on ransomware-leak landings (and similar public
dump indices): victim status labels, dataset size mentions, countdown /
deadline lines. Emits these as entities alongside the universal extractors
in `entities.py`, so the existing Entities page, search, watchlist matcher
(via `keyword:` rules), reports, and relationship pivots all just work
against them.

Designed to fail safe: status patterns are multi-word so they don't fire on
ordinary news prose, and `leak_size` only emits when a leak-context word
(data / leak / breach / exfiltrate / dump / ...) sits within 200 chars of
the size mention. A Steam Deck review's "256 GB" doesn't get picked up.

Entity types:
    leak_status   — normalized snake_case (e.g. data_published, auction_ended)
    leak_size     — human-readable size (e.g. "5.2 TB")
    leak_deadline — free-form deadline / countdown string

"""
from __future__ import annotations

import re
from typing import List

CONTEXT_WINDOW = 80
NEAR_LEAK_WINDOW = 200

# --- patterns -----------------------------------------------------------
# Multi-word status phrases. Single tokens like "PUBLISHED" are deliberately
# excluded — they overlap heavily with normal article metadata.
_STATUS_PATTERNS = [
    (
        re.compile(
            r"\bDATA\s+(?P<v>PUBLISHED|LEAKED|RELEASED|AUCTIONED|DELETED|REMOVED|DUMPED)\b",
            re.IGNORECASE,
        ),
        "data_{}",
    ),
    (
        re.compile(
            r"\bAUCTION\s+(?P<v>STARTED|IN\s+PROGRESS|ENDED|EXPIRED|WON|FAILED|LIVE)\b",
            re.IGNORECASE,
        ),
        "auction_{}",
    ),
    (
        re.compile(
            r"\bDEADLINE\s+(?P<v>EXPIRED|EXTENDED|APPROACHING|PAID|PASSED|MET)\b",
            re.IGNORECASE,
        ),
        "deadline_{}",
    ),
    (
        re.compile(
            r"\bNEGOTIATIONS?\s+(?P<v>IN\s+PROGRESS|FAILED|CONCLUDED|STARTED|ENDED|BROKEN\s+OFF)\b",
            re.IGNORECASE,
        ),
        "negotiation_{}",
    ),
    (re.compile(r"\b(?P<v>STAGE\s*[1-9])\b", re.IGNORECASE), "{}"),
    (
        re.compile(
            r"\b(?P<v>FREE\s+DOWNLOAD|FREE\s+LEAK|MIRROR\s+LINK|TORRENT\s+LINK)\b",
            re.IGNORECASE,
        ),
        "{}",
    ),
    (
        re.compile(
            r"\b(?P<v>RANSOM\s+(?:NOT\s+)?PAID|VICTIM\s+(?:PAID|REFUSED))\b",
            re.IGNORECASE,
        ),
        "{}",
    ),
]

_SIZE_RE = re.compile(r"\b(?P<n>\d+(?:\.\d+)?)\s*(?P<u>KB|MB|GB|TB|PB)\b", re.IGNORECASE)
_LEAK_NEAR_WORDS = re.compile(
    r"(?i)\b(?:"
    r"data|leak(?:ed|s)?|breach(?:ed|es)?|exfiltrat\w*|stolen|exposed|"
    r"compromised|dump(?:ed)?|archive|database|files?|records?|victim|payload"
    r")\b"
)

_DEADLINE_PATTERNS = [
    re.compile(
        r"\b(?:DEADLINE|EXPIRES?\s+ON|TIMER\s+ENDS?):\s*(?P<v>[^\n]{1,80})",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:COUNTDOWN|TIME\s+LEFT|REMAINING):\s*(?P<v>[^\n]{1,80})",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?P<v>\d+\s+(?:seconds?|minutes?|hours?|days?|weeks?)\s+"
        r"(?:left|remaining|to\s+go))\b",
        re.IGNORECASE,
    ),
]


# --- helpers ------------------------------------------------------------
def _norm_status(raw: str) -> str:
    """Lowercase + collapse whitespace to underscores."""
    return re.sub(r"\s+", "_", raw.strip().lower())


def _norm_deadline(raw: str) -> str:
    """Trim trailing punctuation, collapse whitespace."""
    cleaned = re.sub(r"\s+", " ", raw.strip())
    cleaned = cleaned.rstrip(".,;:")
    return cleaned[:120]


def _context(text: str, start: int, end: int) -> str:
    a = max(0, start - CONTEXT_WINDOW)
    b = min(len(text), end + CONTEXT_WINDOW)
    return re.sub(r"\s+", " ", text[a:b]).strip()


def _has_leak_word_nearby(text: str, start: int, end: int, *, window: int = NEAR_LEAK_WINDOW) -> bool:
    a = max(0, start - window)
    b = min(len(text), end + window)
    return bool(_LEAK_NEAR_WORDS.search(text[a:b]))


# --- public extractors --------------------------------------------------
def extract_leak_status(text: str) -> List[dict]:
    out = []
    seen = set()
    for pattern, fmt in _STATUS_PATTERNS:
        for m in pattern.finditer(text):
            raw = m.group("v")
            value = fmt.format(_norm_status(raw))
            if value in seen:
                continue
            seen.add(value)
            out.append(
                {
                    "entity_type": "leak_status",
                    "entity_value": value,
                    "context": _context(text, m.start(), m.end()),
                }
            )
    return out


def extract_leak_sizes(text: str) -> List[dict]:
    out = []
    seen = set()
    for m in _SIZE_RE.finditer(text):
        if not _has_leak_word_nearby(text, m.start(), m.end()):
            continue
        size_value = f"{m.group('n')} {m.group('u').upper()}"
        if size_value in seen:
            continue
        seen.add(size_value)
        out.append(
            {
                "entity_type": "leak_size",
                "entity_value": size_value,
                "context": _context(text, m.start(), m.end()),
            }
        )
    return out


def extract_leak_deadlines(text: str) -> List[dict]:
    out = []
    seen = set()
    for pattern in _DEADLINE_PATTERNS:
        for m in pattern.finditer(text):
            value = _norm_deadline(m.group("v"))
            if not value or value in seen:
                continue
            seen.add(value)
            out.append(
                {
                    "entity_type": "leak_deadline",
                    "entity_value": value,
                    "context": _context(text, m.start(), m.end()),
                }
            )
    return out


def extract_leak_indicators(text: str) -> List[dict]:
    if not text:
        return []
    return (
        extract_leak_status(text)
        + extract_leak_sizes(text)
        + extract_leak_deadlines(text)
    )
