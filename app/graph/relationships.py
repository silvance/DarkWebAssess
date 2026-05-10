"""Entity relationship helpers.

Relationships are derived on the fly from co-occurrence in `entities`:
two entities are related when they appear in the same document. We don't
materialize a separate relationships table — `idx_entities_doc_type` (added
during the hardening pass) already supports the self-join cheaply, and
on-demand queries always reflect the latest collected docs.

For the graph view in the dashboard, `neighbors()` returns ranked neighbors
(sorted by document overlap) and `entity_summary()` gives the totals shown
alongside the table.
"""
import sqlite3
from typing import Iterable, List, Optional


def neighbors(
    conn: sqlite3.Connection,
    entity_type: str,
    entity_value: str,
    *,
    neighbor_types: Optional[Iterable[str]] = None,
    limit: int = 50,
    min_shared: int = 1,
) -> List[dict]:
    """Return entities that co-occur with `(entity_type, entity_value)`.

    Each row carries (neighbor_type, neighbor_value, shared_docs, last_seen),
    ordered by `shared_docs` desc then most-recent first. Filter the result
    set with `neighbor_types` (e.g. only show CVEs / malware / actors).
    """
    sql = """
        SELECT e2.entity_type AS neighbor_type,
               e2.entity_value AS neighbor_value,
               COUNT(DISTINCT e1.document_id) AS shared_docs,
               MAX(e1.first_seen) AS last_seen
        FROM entities e1
        JOIN entities e2 ON e2.document_id = e1.document_id
        WHERE e1.entity_type = ? AND e1.entity_value = ?
          AND NOT (e2.entity_type = ? AND e2.entity_value = ?)
    """
    params: list = [entity_type, entity_value, entity_type, entity_value]
    if neighbor_types:
        types = list(neighbor_types)
        if types:
            placeholders = ",".join("?" * len(types))
            sql += f" AND e2.entity_type IN ({placeholders})"
            params.extend(types)
    sql += """
        GROUP BY e2.entity_type, e2.entity_value
        HAVING shared_docs >= ?
        ORDER BY shared_docs DESC, last_seen DESC
        LIMIT ?
    """
    params.extend([int(min_shared), int(limit)])
    return [dict(r) for r in conn.execute(sql, tuple(params)).fetchall()]


def related_documents(
    conn: sqlite3.Connection,
    entity_type: str,
    entity_value: str,
    *,
    limit: int = 20,
) -> List[dict]:
    rows = conn.execute(
        """
        SELECT d.id, d.title, d.source_name, d.source_url, d.retrieved_at
        FROM documents d
        WHERE d.id IN (
            SELECT document_id FROM entities
            WHERE entity_type = ? AND entity_value = ?
        )
        ORDER BY d.retrieved_at DESC
        LIMIT ?
        """,
        (entity_type, entity_value, int(limit)),
    ).fetchall()
    return [dict(r) for r in rows]


def entity_summary(
    conn: sqlite3.Connection,
    entity_type: str,
    entity_value: str,
) -> Optional[dict]:
    row = conn.execute(
        """
        SELECT COUNT(DISTINCT document_id) AS sightings,
               MIN(first_seen) AS first_seen,
               MAX(first_seen) AS last_seen
        FROM entities
        WHERE entity_type = ? AND entity_value = ?
        """,
        (entity_type, entity_value),
    ).fetchone()
    if not row or not row["sightings"]:
        return None
    return dict(row)


def list_entity_types(conn: sqlite3.Connection) -> List[str]:
    rows = conn.execute(
        "SELECT DISTINCT entity_type FROM entities ORDER BY entity_type"
    ).fetchall()
    return [r["entity_type"] for r in rows]


# ---- graphviz rendering -------------------------------------------------
# Dashboard uses st.graphviz_chart(...) which takes a DOT source string.

# Type → fill color so the graph reads cleanly across categories.
_TYPE_COLOR = {
    "domain": "lightblue",
    "url": "lightblue",
    "ip": "lightskyblue",
    "ipv6": "lightskyblue",
    "email": "thistle",
    "cve": "lightpink",
    "md5": "wheat",
    "sha1": "wheat",
    "sha256": "wheat",
    "actor": "lightcoral",
    "malware": "salmon",
    "onion": "lightgray",
    "btc": "khaki",
    "eth": "khaki",
    "xmr": "khaki",
    "handle": "plum",
}


def _dot_escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _color_for(entity_type: str) -> str:
    return _TYPE_COLOR.get((entity_type or "").lower(), "white")


def build_graphviz(
    center_type: str,
    center_value: str,
    neighbor_rows: Iterable[dict],
    *,
    max_nodes: int = 25,
) -> str:
    """Build a small Graphviz DOT graph centered on the chosen entity.

    Edges are labeled with the shared-document count; node labels carry the
    type and value, and fill color is keyed on the entity type.
    """
    rows = list(neighbor_rows)[:max_nodes]
    center_label = _dot_escape(center_value)
    center_id = f"{center_type}:{center_value}"
    lines = [
        "digraph G {",
        '  rankdir=LR;',
        '  node [shape=box, style=filled, fontname="Helvetica"];',
        '  edge [fontname="Helvetica", fontsize=10];',
        f'  "{_dot_escape(center_id)}" [label="{center_label}\\n[{_dot_escape(center_type)}]",'
        f' fillcolor="{_color_for(center_type)}", penwidth=2];',
    ]
    for r in rows:
        nid = f"{r['neighbor_type']}:{r['neighbor_value']}"
        lines.append(
            f'  "{_dot_escape(nid)}" [label="{_dot_escape(r["neighbor_value"])}'
            f'\\n[{_dot_escape(r["neighbor_type"])}]",'
            f' fillcolor="{_color_for(r["neighbor_type"])}"];'
        )
        lines.append(
            f'  "{_dot_escape(center_id)}" -> "{_dot_escape(nid)}"'
            f' [label="{int(r["shared_docs"])}"];'
        )
    lines.append("}")
    return "\n".join(lines)
