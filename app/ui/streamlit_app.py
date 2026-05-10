"""Streamlit dashboard for the mini threat intelligence platform.

Run with:
    streamlit run app/ui/streamlit_app.py
"""
import os
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# Allow `streamlit run app/ui/streamlit_app.py` to import the `app` package.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.auth.middleware import gate, logout, require_role  # noqa: E402
from app.database import get_connection, init_db  # noqa: E402

st.set_page_config(page_title="Mini Threat Intel", layout="wide")

# Block until logged in (no-op when AUTH_ENABLED=0).
_user = gate()
if _user:
    with st.sidebar:
        if _user.get("auth_disabled"):
            st.caption("Auth disabled (set `AUTH_ENABLED=1` to enable).")
        else:
            st.caption(f"Signed in as **{_user['username']}** ({_user['role']})")
            if st.button("Sign out"):
                logout()


@st.cache_resource
def _conn():
    init_db()
    return get_connection()


def _query(sql: str, params: tuple = ()) -> pd.DataFrame:
    return pd.read_sql_query(sql, _conn(), params=params)


def page_overview():
    st.title("Mini Threat Intelligence — Overview")

    c1, c2, c3, c4, c5 = st.columns(5)
    docs = _query("SELECT COUNT(*) AS n FROM documents")["n"].iloc[0]
    entities = _query("SELECT COUNT(*) AS n FROM entities")["n"].iloc[0]
    matches = _query("SELECT COUNT(*) AS n FROM matches")["n"].iloc[0]
    new_high = _query(
        "SELECT COUNT(*) AS n FROM matches WHERE status='new' AND severity IN ('high','critical')"
    )["n"].iloc[0]
    top_score = _query("SELECT COALESCE(MAX(score), 0) AS n FROM matches WHERE status='new'")[
        "n"
    ].iloc[0]
    c1.metric("Documents", int(docs))
    c2.metric("Entities", int(entities))
    c3.metric("Matches", int(matches))
    c4.metric("New high/critical", int(new_high))
    c5.metric("Top open score", int(top_score))

    st.subheader("Top scored open matches")
    top = _query(
        """
        SELECT m.id, m.score, m.severity, m.matched_value, m.match_type,
               d.source_name, d.title
        FROM matches m
        JOIN documents d ON d.id = m.document_id
        WHERE m.status IN ('new', 'reviewing')
        ORDER BY COALESCE(m.score, -1) DESC, m.created_at DESC
        LIMIT 10
        """
    )
    st.dataframe(top, use_container_width=True)

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
    import json as _json

    st.title("Watchlist Matches")

    severities = ["low", "medium", "high", "critical"]
    statuses = ["new", "reviewing", "false_positive", "confirmed", "escalated"]
    sort_options = ["score (desc)", "created_at (desc)"]

    with st.sidebar:
        st.header("Filters")
        sev_filter = st.multiselect("Severity", severities, default=["high", "critical"])
        status_filter = st.multiselect("Status", statuses, default=["new", "reviewing"])
        min_score = st.slider("Min score", 0, 100, 0, 5)
        sort_by = st.selectbox("Sort", sort_options)
        search = st.text_input("Search matched value/context")

    sql = """
        SELECT m.id, m.created_at, m.score, m.severity, m.status, m.match_type,
               m.matched_value, m.context, m.score_reasons,
               d.title, d.source_name, d.source_url
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
    if min_score > 0:
        sql += " AND COALESCE(m.score, 0) >= ?"
        params.append(int(min_score))
    if search:
        sql += " AND (m.matched_value LIKE ? OR m.context LIKE ?)"
        like = f"%{search}%"
        params.extend([like, like])
    if sort_by.startswith("score"):
        sql += " ORDER BY COALESCE(m.score, -1) DESC, m.created_at DESC"
    else:
        sql += " ORDER BY m.created_at DESC"
    sql += " LIMIT 500"

    df = _query(sql, tuple(params))
    st.write(f"{len(df)} matches")

    table_cols = [c for c in df.columns if c != "score_reasons"]
    st.dataframe(df[table_cols], use_container_width=True)

    st.subheader("Inspect match")
    if not df.empty:
        match_id = st.number_input(
            "Match ID", min_value=int(df["id"].min()), max_value=int(df["id"].max()), step=1
        )
        row = df[df["id"] == int(match_id)]
        if not row.empty:
            r = row.iloc[0]
            st.write(f"**Score:** {r['score']}  |  **Severity:** {r['severity']}  |  **Status:** {r['status']}")
            try:
                reasons = _json.loads(r["score_reasons"]) if r["score_reasons"] else []
            except (TypeError, ValueError):
                reasons = []
            if reasons:
                st.markdown("**Why this score:**")
                for line in reasons:
                    st.markdown(f"- {line}")

        new_status = st.selectbox("New status", statuses)
        if st.button("Update"):
            from app.auth.audit import record_audit
            actor = (_user or {}).get("username")
            with _conn() as conn:
                prev = conn.execute(
                    "SELECT status FROM matches WHERE id = ?", (int(match_id),)
                ).fetchone()
                conn.execute(
                    "UPDATE matches SET status = ? WHERE id = ?",
                    (new_status, int(match_id)),
                )
                record_audit(
                    conn, action="match_status_changed", actor=actor,
                    actor_role=(_user or {}).get("role"),
                    target_type="match", target_id=str(match_id),
                    payload={
                        "from": prev["status"] if prev else None,
                        "to": new_status,
                    },
                )
                conn.commit()
            st.success(f"Updated match {int(match_id)} to {new_status}")
            st.rerun()

        st.markdown("---")
        st.subheader("Analyst summary")
        existing = _query(
            """
            SELECT model, summary_text, entities_json, why_it_matters, confidence,
                   confidence_explanation, next_steps_json, unknowns_json,
                   input_tokens, output_tokens, cache_read_input_tokens,
                   cache_creation_input_tokens, created_at
            FROM llm_summaries
            WHERE match_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (int(match_id),),
        )
        if not existing.empty:
            r = existing.iloc[0]
            try:
                ents = _json.loads(r["entities_json"]) if r["entities_json"] else []
                steps = _json.loads(r["next_steps_json"]) if r["next_steps_json"] else []
                unknowns = _json.loads(r["unknowns_json"]) if r["unknowns_json"] else []
            except (TypeError, ValueError):
                ents, steps, unknowns = [], [], []
            st.caption(
                f"Generated by {r['model']} at {r['created_at']}  ·  "
                f"in_tokens={r['input_tokens']}  out_tokens={r['output_tokens']}  "
                f"cache_read={r['cache_read_input_tokens']}"
            )
            st.markdown(f"**Confidence:** `{r['confidence']}` — {r['confidence_explanation']}")
            st.markdown("**Summary**")
            st.write(r["summary_text"])
            st.markdown("**Why this matters**")
            st.write(r["why_it_matters"])
            if ents:
                st.markdown("**Relevant entities**")
                for e in ents:
                    st.markdown(f"- {e}")
            if steps:
                st.markdown("**Recommended next steps**")
                for s in steps:
                    st.markdown(f"- {s}")
            if unknowns:
                st.markdown("**Unknowns / gaps**")
                for u in unknowns:
                    st.markdown(f"- {u}")
        else:
            st.info("No analyst summary yet for this match.")

        st.markdown("---")
        st.subheader("Case")
        case_owner = st.text_input("Owner (optional)", key="match_to_case_owner")
        if st.button("Create case from this match"):
            try:
                from app.cases.repository import create_case_from_match
            except Exception as exc:  # noqa: BLE001
                st.error(f"Cases module not importable: {exc}")
            else:
                actor = case_owner or (_user or {}).get("username")
                with _conn() as conn:
                    cid = create_case_from_match(conn, int(match_id), owner=actor)
                    if cid is not None:
                        from app.auth.audit import record_audit
                        record_audit(
                            conn, action="case_created_from_match",
                            actor=(_user or {}).get("username"),
                            actor_role=(_user or {}).get("role"),
                            target_type="case", target_id=str(cid),
                            payload={"match_id": int(match_id), "owner": actor},
                        )
                    conn.commit()
                if cid is None:
                    st.error("Match not found.")
                else:
                    st.success(f"Created case #{cid}. Open the Cases page to continue.")

        regen_label = "Regenerate analyst summary" if not existing.empty else "Generate analyst summary"
        if st.button(regen_label):
            try:
                from app.llm.summarizer import SummarizerNotConfigured, summarize_match
            except Exception as exc:  # noqa: BLE001
                st.error(f"LLM module not importable: {exc}")
            else:
                try:
                    with _conn() as conn:
                        with st.spinner("Calling Claude…"):
                            rec = summarize_match(conn, int(match_id), force=True)
                except SummarizerNotConfigured as exc:
                    st.error(str(exc))
                except Exception as exc:  # noqa: BLE001
                    st.error(f"Summarization failed: {exc}")
                else:
                    if rec is None:
                        st.error("Match not found.")
                    else:
                        st.success(f"Summary regenerated (confidence={rec.summary.confidence}).")
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


def page_enrichment():
    import json as _json

    st.title("Enrichment")
    st.caption(
        "Enrichment results from providers (CISA KEV, EPSS, URLhaus, MalwareBazaar, VirusTotal, AbuseIPDB)."
    )

    summary = _query(
        """
        SELECT provider,
               COUNT(*) AS total,
               SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS successful,
               MAX(enriched_at) AS last_run
        FROM enrichments
        GROUP BY provider
        ORDER BY provider
        """
    )
    st.subheader("Provider activity")
    st.dataframe(summary, use_container_width=True)

    st.subheader("Lookup an entity")
    col1, col2 = st.columns([1, 3])
    with col1:
        etype = st.selectbox(
            "Entity type",
            ["cve", "domain", "ip", "url", "md5", "sha1", "sha256"],
        )
    with col2:
        evalue = st.text_input("Entity value")
    if evalue:
        rows = _query(
            """
            SELECT provider, enriched_at, success, result_json, error
            FROM enrichments
            WHERE entity_type = ? AND entity_value = ?
            ORDER BY enriched_at DESC
            """,
            (etype, evalue),
        )
        if rows.empty:
            st.info("No enrichment recorded yet. Try `python -m app.main enrich --type %s --value %s`." % (etype, evalue))
        else:
            for _, r in rows.iterrows():
                badge = "OK" if r["success"] else "ERR"
                with st.expander(f"[{badge}] {r['provider']} — {r['enriched_at']}"):
                    if not r["success"]:
                        st.error(r["error"] or "(no error message)")
                        continue
                    try:
                        st.json(_json.loads(r["result_json"] or "{}"))
                    except (TypeError, ValueError):
                        st.code(r["result_json"] or "")


def page_search():
    from app.search import escape_fts, fts_available, search_documents

    st.title("Full-text Search")
    if not fts_available(_conn()):
        st.error("FTS5 is not enabled in this SQLite build; search is disabled.")
        return

    query = st.text_input("Query", help="Plain words are AND-ed; trailing * means prefix match.")
    col1, col2, col3, col4 = st.columns(4)
    sources = [r[0] for r in _conn().execute(
        "SELECT DISTINCT source_name FROM documents ORDER BY source_name"
    ).fetchall()]
    with col1:
        source = st.selectbox("Source", [""] + sources)
    with col2:
        since = st.text_input("Since (ISO)", "")
    with col3:
        until = st.text_input("Until (ISO)", "")
    with col4:
        limit = st.number_input("Limit", 5, 500, 50, 5)

    if not query:
        st.caption(f"FTS query preview: `{escape_fts('')}`")
        return

    st.caption(f"FTS query preview: `{escape_fts(query)}`")
    results = search_documents(
        _conn(),
        query,
        source_name=source or None,
        since=since or None,
        until=until or None,
        limit=int(limit),
    )
    st.write(f"{len(results)} results")
    if results:
        df = pd.DataFrame(results)
        st.dataframe(df[["retrieved_at", "source_name", "title", "snippet", "source_url"]],
                     use_container_width=True)
        st.download_button(
            "Download CSV",
            df.to_csv(index=False).encode("utf-8"),
            file_name="search_results.csv",
            mime="text/csv",
        )
        st.download_button(
            "Download JSON",
            df.to_json(orient="records", indent=2).encode("utf-8"),
            file_name="search_results.json",
            mime="application/json",
        )


def page_jobs():
    st.title("Jobs")
    summary = _query(
        """
        SELECT job_name,
               COUNT(*) AS runs,
               SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS ok,
               SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS errors,
               MAX(started_at) AS last_run,
               AVG(duration_seconds) AS avg_seconds
        FROM job_runs
        GROUP BY job_name
        ORDER BY job_name
        """
    )
    st.subheader("Per-job summary")
    st.dataframe(summary, use_container_width=True)

    st.subheader("Recent runs")
    recent = _query(
        """
        SELECT id, job_name, started_at, finished_at, success, duration_seconds, message
        FROM job_runs
        ORDER BY started_at DESC
        LIMIT 100
        """
    )
    st.dataframe(recent, use_container_width=True)


def page_cases():
    from app.cases.exporter import export_markdown
    from app.cases.repository import (
        VALID_SEVERITIES,
        VALID_STATUSES,
        add_note,
        attach_evidence,
        create_case,
        get_case_detail,
        update_case_status,
    )

    st.title("Cases")

    with st.sidebar:
        st.header("Filters")
        sev_filter = st.multiselect("Status", list(VALID_STATUSES),
                                    default=["open", "reviewing", "waiting", "escalated"])

    placeholders = ",".join("?" * len(sev_filter)) if sev_filter else None
    if placeholders:
        df = _query(
            f"SELECT id, title, status, severity, owner, created_at, updated_at "
            f"FROM cases WHERE status IN ({placeholders}) ORDER BY updated_at DESC LIMIT 200",
            tuple(sev_filter),
        )
    else:
        df = _query(
            "SELECT id, title, status, severity, owner, created_at, updated_at "
            "FROM cases ORDER BY updated_at DESC LIMIT 200"
        )
    st.write(f"{len(df)} cases")
    st.dataframe(df, use_container_width=True)

    st.markdown("---")
    st.subheader("Create a new case")
    with st.form("new_case"):
        title = st.text_input("Title")
        severity = st.selectbox("Severity", list(VALID_SEVERITIES), index=1)
        owner = st.text_input("Owner")
        summary = st.text_area("Summary")
        if st.form_submit_button("Create"):
            if not title:
                st.error("Title is required.")
            else:
                with _conn() as conn:
                    cid = create_case(conn, title=title, severity=severity,
                                      owner=owner or None, summary=summary or None)
                    conn.commit()
                st.success(f"Created case #{cid}.")
                st.rerun()

    if df.empty:
        return

    st.markdown("---")
    st.subheader("Case detail")
    case_id = st.number_input(
        "Case ID",
        min_value=int(df["id"].min()),
        max_value=int(df["id"].max()),
        step=1,
    )
    with _conn() as conn:
        case = get_case_detail(conn, int(case_id))
    if not case:
        st.error("Case not found.")
        return

    st.markdown(
        f"### Case #{case['id']} — {case['title']}\n"
        f"`{case['status']}` · `{case['severity']}` · "
        f"owner: {case['owner'] or '—'} · "
        f"created {case['created_at']} · updated {case['updated_at']}"
    )
    if case.get("summary"):
        st.markdown("**Summary**")
        st.markdown(case["summary"])

    cols = st.columns(3)
    with cols[0]:
        new_status = st.selectbox("Status", list(VALID_STATUSES),
                                  index=list(VALID_STATUSES).index(case["status"]))
        if st.button("Update status"):
            actor = (_user or {}).get("username") or "dashboard"
            with _conn() as conn:
                update_case_status(conn, int(case_id), new_status, actor=actor)
                conn.commit()
            st.rerun()
    with cols[1]:
        note_body = st.text_area("Add note")
        note_author = st.text_input("Author", key=f"note_author_{case_id}")
        if st.button("Append note"):
            if note_body.strip():
                actor = note_author or (_user or {}).get("username")
                with _conn() as conn:
                    add_note(conn, int(case_id), note_body, author=actor)
                    conn.commit()
                st.rerun()
    with cols[2]:
        if st.button("Export markdown"):
            with _conn() as conn:
                md = export_markdown(conn, int(case_id))
            if md:
                st.download_button(
                    "Download report.md",
                    md.encode("utf-8"),
                    file_name=f"case-{case_id}.md",
                    mime="text/markdown",
                )

    st.markdown("**Evidence**")
    if case["evidence"]:
        ev_df = pd.DataFrame(case["evidence"])
        st.dataframe(ev_df[["id", "kind", "ref", "label", "added_at"]], use_container_width=True)
    else:
        st.caption("No evidence attached yet.")

    with st.expander("Attach text evidence"):
        text_label = st.text_input("Label", key=f"ev_label_{case_id}")
        text_body = st.text_area("Body", key=f"ev_body_{case_id}")
        if st.button("Attach text", key=f"ev_btn_{case_id}"):
            if text_body.strip():
                with _conn() as conn:
                    attach_evidence(conn, int(case_id), "text",
                                    label=text_label or None, body=text_body)
                    conn.commit()
                st.rerun()

    st.markdown("**Notes**")
    for n in case["notes"]:
        st.markdown(f"_{n['created_at']} — {n['author'] or 'anonymous'}_")
        st.markdown(n["body"])

    st.markdown("**Timeline**")
    for ev in case["events"]:
        payload = ev.get("payload") or {}
        bits = ", ".join(f"{k}={v}" for k, v in payload.items()) if payload else ""
        st.markdown(f"- `{ev['created_at']}` **{ev['event_type']}** by {ev['actor'] or 'system'} {bits}")


def page_reports():
    from app.reports.renderers import render_html, render_markdown
    from app.reports.runner import (
        generate_report,
        get_saved,
        list_saved,
        list_templates,
        save_report,
    )

    st.title("Reports")

    st.subheader("Generate")
    templates = list_templates()
    template_names = [t[0] for t in templates]
    description_map = dict(templates)
    with st.form("gen_report"):
        col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
        with col1:
            chosen = st.selectbox("Template", template_names)
        with col2:
            window = st.text_input("Window", value="24h",
                                   help="e.g. 24h, 7d, 30d. Leave blank for all time.")
        with col3:
            fmt = st.selectbox("Format", ["markdown", "html", "json"])
        with col4:
            save = st.checkbox("Save to history", value=True)
        gen = st.form_submit_button("Generate")
    if chosen:
        st.caption(description_map.get(chosen, ""))
    if gen:
        from app.auth.audit import record_audit
        with _conn() as conn:
            report = generate_report(conn, chosen, window=window or None)
            saved_id = save_report(conn, report) if save else None
            record_audit(
                conn,
                action="report_generated",
                actor=(_user or {}).get("username"),
                actor_role=(_user or {}).get("role"),
                target_type="report",
                target_id=str(saved_id) if saved_id else chosen,
                payload={"template": chosen, "window": window, "saved": save},
            )
            conn.commit()
        if fmt == "markdown":
            md = render_markdown(report)
            st.markdown(md)
            st.download_button("Download .md", md.encode("utf-8"),
                               file_name=f"{chosen}.md", mime="text/markdown")
        elif fmt == "html":
            html_body = render_html(report)
            st.components.v1.html(html_body, height=600, scrolling=True)
            st.download_button("Download .html", html_body.encode("utf-8"),
                               file_name=f"{chosen}.html", mime="text/html")
        else:
            import json as _json
            st.code(_json.dumps(report.to_dict(), indent=2, default=str), language="json")

    st.markdown("---")
    st.subheader("History")
    saved = _query(
        "SELECT id, name, title, generated_at, window_start, window_end "
        "FROM reports ORDER BY generated_at DESC LIMIT 100"
    )
    st.dataframe(saved, use_container_width=True)
    if not saved.empty:
        rid = st.number_input("Report ID", min_value=int(saved["id"].min()),
                              max_value=int(saved["id"].max()), step=1)
        view_fmt = st.selectbox("View as", ["markdown", "html", "json"], key="view_saved_fmt")
        if st.button("Open"):
            with _conn() as conn:
                row = get_saved(conn, int(rid))
            if not row:
                st.error("Not found.")
            elif view_fmt == "markdown":
                st.markdown(row["body_markdown"])
            elif view_fmt == "html":
                st.components.v1.html(row["body_html"], height=600, scrolling=True)
            else:
                st.code(row["body_json"], language="json")


def page_admin():
    """Admin-only: user management + audit log + provider key presence."""
    require_role(_user, "admin")
    from app.auth.audit import list_audit
    from app.auth.passwords import WeakPasswordError
    from app.auth.users import (
        create_user, delete_user, list_users, set_enabled,
        set_password, set_role,
    )
    from app.config import AUTH_ROLES

    st.title("Admin")
    actor = (_user or {}).get("username")

    st.subheader("Users")
    users = pd.DataFrame(list_users(_conn()))
    if not users.empty:
        st.dataframe(users, use_container_width=True)
    else:
        st.caption("No users yet.")

    with st.expander("Create user"):
        with st.form("add_user"):
            u_name = st.text_input("Username")
            u_full = st.text_input("Full name (optional)")
            u_role = st.selectbox("Role", list(AUTH_ROLES), index=1)
            u_pw = st.text_input("Password", type="password")
            if st.form_submit_button("Create") and u_name and u_pw:
                try:
                    with _conn() as conn:
                        create_user(conn, u_name, u_pw, role=u_role,
                                    full_name=u_full or None, actor=actor)
                        conn.commit()
                    st.success(f"Created {u_name}.")
                    st.rerun()
                except WeakPasswordError as exc:
                    st.error(str(exc))
                except ValueError as exc:
                    st.error(str(exc))

    if not users.empty:
        with st.expander("Modify user"):
            target = st.selectbox("User", list(users["username"]))
            new_role = st.selectbox("Role", list(AUTH_ROLES), key="modify_role")
            colA, colB, colC, colD = st.columns(4)
            with colA:
                if st.button("Set role"):
                    with _conn() as conn:
                        set_role(conn, target, new_role, actor=actor)
                        conn.commit()
                    st.success("Role updated.")
                    st.rerun()
            with colB:
                if st.button("Disable"):
                    with _conn() as conn:
                        set_enabled(conn, target, False, actor=actor)
                        conn.commit()
                    st.rerun()
            with colC:
                if st.button("Enable"):
                    with _conn() as conn:
                        set_enabled(conn, target, True, actor=actor)
                        conn.commit()
                    st.rerun()
            with colD:
                if st.button("Delete"):
                    with _conn() as conn:
                        delete_user(conn, target, actor=actor)
                        conn.commit()
                    st.rerun()

            new_pw = st.text_input("Reset password", type="password", key="reset_pw")
            if st.button("Set password") and new_pw:
                try:
                    with _conn() as conn:
                        set_password(conn, target, new_pw, actor=actor)
                        conn.commit()
                except WeakPasswordError as exc:
                    st.error(str(exc))
                else:
                    st.success("Password updated.")

    st.markdown("---")
    st.subheader("Provider keys (presence only)")
    key_status = []
    for env_var in [
        "ANTHROPIC_API_KEY",
        "VIRUSTOTAL_API_KEY",
        "ABUSEIPDB_API_KEY",
        "ABUSECH_AUTH_KEY",
        "TELEGRAM_BOT_TOKEN",
    ]:
        key_status.append({"env_var": env_var, "set": bool(os.getenv(env_var))})
    st.dataframe(pd.DataFrame(key_status), use_container_width=True)
    st.caption("Values are never displayed in the dashboard.")

    st.markdown("---")
    st.subheader("Recent audit log")
    audit_rows = list_audit(_conn(), limit=200)
    if audit_rows:
        st.dataframe(pd.DataFrame(audit_rows), use_container_width=True)
    else:
        st.caption("No audit entries yet.")


def page_relationships():
    """Pivot from a chosen entity to its co-occurrence neighbors."""
    from app.graph.relationships import (
        build_graphviz,
        entity_summary,
        list_entity_types,
        neighbors,
        related_documents,
    )

    st.title("Relationships")
    st.caption(
        "Two entities are 'related' when they appear in the same document. "
        "Pick an entity below to see what it co-occurs with, ranked by shared docs."
    )

    types = list_entity_types(_conn())
    if not types:
        st.info("No entities collected yet. Run `python -m app.main collect` to get started.")
        return

    col1, col2 = st.columns([1, 3])
    with col1:
        etype = st.selectbox("Entity type", types)
    with col2:
        rows = _query(
            "SELECT entity_value, COUNT(DISTINCT document_id) AS n "
            "FROM entities WHERE entity_type = ? "
            "GROUP BY entity_value ORDER BY n DESC, entity_value LIMIT 1000",
            (etype,),
        )
        values = rows["entity_value"].tolist() if not rows.empty else []
        evalue = st.selectbox("Entity value", values) if values else None

    if not (etype and evalue):
        return

    summary = entity_summary(_conn(), etype, evalue)
    st.markdown(f"### `{etype}:` **{evalue}**")
    if summary:
        st.markdown(
            f"**Sightings:** {summary['sightings']}  ·  "
            f"**First seen:** {summary['first_seen']}  ·  "
            f"**Last seen:** {summary['last_seen']}"
        )

    st.markdown("---")
    fcol1, fcol2, fcol3 = st.columns(3)
    with fcol1:
        nbr_filter = st.multiselect("Restrict neighbor types", types)
    with fcol2:
        min_shared = st.number_input("Min shared docs", min_value=1, value=1)
    with fcol3:
        limit = st.number_input("Max neighbors", min_value=5, max_value=500, value=50, step=5)

    rows = neighbors(
        _conn(), etype, evalue,
        neighbor_types=nbr_filter or None,
        limit=int(limit),
        min_shared=int(min_shared),
    )
    st.subheader(f"Neighbors ({len(rows)})")
    if rows:
        df = pd.DataFrame(rows)[["neighbor_type", "neighbor_value", "shared_docs", "last_seen"]]
        st.dataframe(df, use_container_width=True)
    else:
        st.caption("No neighbors at the current filter / threshold.")

    if rows and st.checkbox("Show graph", value=True):
        max_nodes = st.slider("Nodes to draw", 5, min(50, len(rows)), value=min(20, len(rows)))
        dot = build_graphviz(etype, evalue, rows, max_nodes=max_nodes)
        st.graphviz_chart(dot, use_container_width=True)

    st.markdown("---")
    st.subheader("Documents where this entity appears")
    docs = related_documents(_conn(), etype, evalue, limit=20)
    if docs:
        st.dataframe(pd.DataFrame(docs), use_container_width=True)
    else:
        st.caption("No documents recorded.")


PAGES = {
    "Overview": page_overview,
    "Matches": page_matches,
    "Cases": page_cases,
    "Reports": page_reports,
    "Relationships": page_relationships,
    "Search": page_search,
    "Documents": page_documents,
    "Entities": page_entities,
    "Enrichment": page_enrichment,
    "Sources": page_sources,
    "Jobs": page_jobs,
    "Admin": page_admin,
}

choice = st.sidebar.radio("Page", list(PAGES.keys()))
PAGES[choice]()
