"""Streamlit dashboard for the mini threat intelligence platform.

Run with:
    streamlit run app/ui/streamlit_app.py
"""
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# Allow `streamlit run app/ui/streamlit_app.py` to import the `app` package.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.database import get_connection, init_db  # noqa: E402

st.set_page_config(page_title="Mini Threat Intel", layout="wide")


@st.cache_resource
def _conn():
    init_db()
    return get_connection()


def _query(sql: str, params: tuple = ()) -> pd.DataFrame:
    return pd.read_sql_query(sql, _conn(), params=params)


def page_overview():
    st.title("Mini Threat Intelligence — Overview")

    c1, c2, c3, c4 = st.columns(4)
    docs = _query("SELECT COUNT(*) AS n FROM documents")["n"].iloc[0]
    entities = _query("SELECT COUNT(*) AS n FROM entities")["n"].iloc[0]
    matches = _query("SELECT COUNT(*) AS n FROM matches")["n"].iloc[0]
    new_high = _query(
        "SELECT COUNT(*) AS n FROM matches WHERE status='new' AND severity IN ('high','critical')"
    )["n"].iloc[0]
    c1.metric("Documents", int(docs))
    c2.metric("Entities", int(entities))
    c3.metric("Matches", int(matches))
    c4.metric("New high/critical", int(new_high))

    st.subheader("Recently collected documents")
    recent = _query(
        """
        SELECT retrieved_at, source_name, title, source_url
        FROM documents
        ORDER BY retrieved_at DESC
        LIMIT 25
        """
    )
    st.dataframe(recent, use_container_width=True)


def page_matches():
    st.title("Watchlist Matches")

    severities = ["low", "medium", "high", "critical"]
    statuses = ["new", "reviewing", "false_positive", "confirmed", "escalated"]

    with st.sidebar:
        st.header("Filters")
        sev_filter = st.multiselect("Severity", severities, default=["high", "critical"])
        status_filter = st.multiselect("Status", statuses, default=["new", "reviewing"])
        search = st.text_input("Search matched value/context")

    sql = """
        SELECT m.id, m.created_at, m.severity, m.status, m.match_type,
               m.matched_value, m.context, d.title, d.source_name, d.source_url
        FROM matches m
        JOIN documents d ON d.id = m.document_id
        WHERE 1=1
    """
    params = []
    if sev_filter:
        placeholders = ",".join("?" * len(sev_filter))
        sql += f" AND m.severity IN ({placeholders})"
        params.extend(sev_filter)
    if status_filter:
        placeholders = ",".join("?" * len(status_filter))
        sql += f" AND m.status IN ({placeholders})"
        params.extend(status_filter)
    if search:
        sql += " AND (m.matched_value LIKE ? OR m.context LIKE ?)"
        like = f"%{search}%"
        params.extend([like, like])
    sql += " ORDER BY m.created_at DESC LIMIT 500"

    df = _query(sql, tuple(params))
    st.write(f"{len(df)} matches")
    st.dataframe(df, use_container_width=True)

    st.subheader("Update match status")
    if not df.empty:
        match_id = st.number_input(
            "Match ID", min_value=int(df["id"].min()), max_value=int(df["id"].max()), step=1
        )
        new_status = st.selectbox("New status", statuses)
        if st.button("Update"):
            with _conn() as conn:
                conn.execute(
                    "UPDATE matches SET status = ? WHERE id = ?", (new_status, int(match_id))
                )
                conn.commit()
            st.success(f"Updated match {int(match_id)} to {new_status}")
            st.rerun()


def page_documents():
    st.title("Document Search")
    q = st.text_input("Search title / text / URL")
    source = st.text_input("Source name (optional)")

    sql = "SELECT id, retrieved_at, source_name, title, source_url FROM documents WHERE 1=1"
    params = []
    if q:
        sql += " AND (title LIKE ? OR raw_text LIKE ? OR source_url LIKE ?)"
        like = f"%{q}%"
        params.extend([like, like, like])
    if source:
        sql += " AND source_name LIKE ?"
        params.append(f"%{source}%")
    sql += " ORDER BY retrieved_at DESC LIMIT 200"

    df = _query(sql, tuple(params))
    st.write(f"{len(df)} documents")
    st.dataframe(df, use_container_width=True)

    if not df.empty:
        doc_id = st.number_input(
            "Open document ID",
            min_value=int(df["id"].min()),
            max_value=int(df["id"].max()),
            step=1,
        )
        if st.button("Show document"):
            row = _query("SELECT * FROM documents WHERE id = ?", (int(doc_id),))
            if not row.empty:
                st.json(row.iloc[0].to_dict())
                ents = _query(
                    "SELECT entity_type, entity_value, context FROM entities WHERE document_id = ?",
                    (int(doc_id),),
                )
                st.subheader(f"Entities ({len(ents)})")
                st.dataframe(ents, use_container_width=True)


def page_entities():
    st.title("Entities")
    etype = st.selectbox(
        "Entity type",
        ["", "domain", "url", "email", "ip", "ipv6", "md5", "sha1", "sha256", "cve"],
    )
    q = st.text_input("Value contains")
    sql = """
        SELECT entity_type, entity_value,
               COUNT(DISTINCT document_id) AS sightings,
               MIN(first_seen) AS first_seen,
               MAX(first_seen) AS last_seen
        FROM entities
        WHERE 1=1
    """
    params = []
    if etype:
        sql += " AND entity_type = ?"
        params.append(etype)
    if q:
        sql += " AND entity_value LIKE ?"
        params.append(f"%{q}%")
    sql += " GROUP BY entity_type, entity_value ORDER BY sightings DESC LIMIT 500"
    df = _query(sql, tuple(params))
    st.write(f"{len(df)} entities")
    st.dataframe(df, use_container_width=True)


def page_sources():
    st.title("Source Health")
    df = _query(
        "SELECT name, type, url, enabled, last_checked_at, last_success_at, last_error, error_count FROM sources ORDER BY name"
    )
    st.dataframe(df, use_container_width=True)


PAGES = {
    "Overview": page_overview,
    "Matches": page_matches,
    "Documents": page_documents,
    "Entities": page_entities,
    "Sources": page_sources,
}

choice = st.sidebar.radio("Page", list(PAGES.keys()))
PAGES[choice]()
