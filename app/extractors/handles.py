"""Username/handle extractor (e.g., @attacker_name on Telegram/X/forums).

Matches `@` followed by 3-32 chars of letters/digits/underscores, with a
preceding word boundary and not preceded by a letter/digit/`.` so we don't
accidentally pick up the local part of email addresses.
"""
import re
from typing import List

HANDLE_RE = re.compile(
    r"(?<![A-Za-z0-9._%+\-])@([A-Za-z0-9_]{3,32})\b"
)

CONTEXT_WINDOW = 80


def _context(text: str, start: int, end: int) -> str:
    a = max(0, start - CONTEXT_WINDOW)
    b = min(len(text), end + CONTEXT_WINDOW)
    return re.sub(r"\s+", " ", text[a:b]).strip()


def extract_handles(text: str) -> List[dict]:
    out = []
    seen = set()
    for m in HANDLE_RE.finditer(text):
        handle = m.group(1)
        # Reject all-numeric handles to cut down on noise.
        if handle.isdigit():
            continue
        value = "@" + handle
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "entity_type": "handle",
                "entity_value": value,
                "context": _context(text, m.start(), m.end()),
            }
        )
    return out
