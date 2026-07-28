"""CSV export of indicators. Includes every indicator type."""
from __future__ import annotations

import csv
import io
from typing import List

from app.export.query import Indicator

_COLUMNS = [
    "type", "value", "severity", "score", "first_seen",
    "source_name", "source_url", "document_title", "context",
]


def render_csv(indicators: List[Indicator]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_COLUMNS)
    for i in indicators:
        writer.writerow([
            i.itype, i.value, i.severity,
            "" if i.score is None else i.score,
            i.first_seen, i.source_name or "", i.source_url or "",
            i.doc_title or "", (i.context or "").replace("\n", " ").strip(),
        ])
    return buf.getvalue()
