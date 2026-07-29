"""CSV export of indicators. Includes every indicator type.

Security (CWE-1236, CSV/formula injection): indicator fields (value,
context, document title, source name) originate from ingested documents —
i.e. untrusted, attacker-influenceable content. Spreadsheet applications
(Excel / LibreOffice / Google Sheets) evaluate any cell that begins with a
formula-trigger character as a formula, which can be abused to exfiltrate
data or run commands when the exported file is opened. Every string cell is
therefore run through `sanitize_csv_cell` before writing, so triggering
cells are rendered as literal text instead of being evaluated.
"""
from __future__ import annotations

import csv
import io
from typing import List

from app.export.query import Indicator

_COLUMNS = [
    "type", "value", "severity", "score", "first_seen",
    "source_name", "source_url", "document_title", "context",
]

# Cells starting with any of these are treated as formulas by spreadsheets.
_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv_cell(value):
    """Neutralize spreadsheet formula injection (CWE-1236).

    If a string cell begins with a formula trigger, prefix a single quote so
    Excel / LibreOffice / Sheets render it as literal text instead of
    evaluating it. Non-string values pass through unchanged.
    """
    if isinstance(value, str) and value and value[0] in _FORMULA_TRIGGERS:
        return "'" + value
    return value


def render_csv(indicators: List[Indicator]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_COLUMNS)
    for i in indicators:
        row = [
            i.itype, i.value, i.severity,
            "" if i.score is None else i.score,
            i.first_seen, i.source_name or "", i.source_url or "",
            i.doc_title or "", (i.context or "").replace("\n", " ").strip(),
        ]
        writer.writerow([sanitize_csv_cell(cell) for cell in row])
    return buf.getvalue()
