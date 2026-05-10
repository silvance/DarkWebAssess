# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.1.1 — 2026-05-10

Patch release. Fixes a fatal bug that broke every dashboard page on the
v0.1.0 .exe, silences the `use_container_width` deprecation warnings
that drowned the console, and closes a long-standing UX gap by giving
the watchlist a proper editor in the dashboard.

### Fixed

- **Cross-thread SQLite error** — every Streamlit page raised
  `sqlite3.ProgrammingError: SQLite objects created in a thread can only
  be used in that same thread`. Streamlit reruns each script execution
  on a fresh worker thread, so the connection cached via
  `@st.cache_resource` (and any module-level connection) was created on
  thread A and queried from thread B. `get_connection()` now passes
  `check_same_thread=False`. WAL mode + Python's per-connection lock
  keep concurrent access safe for the dashboard's short-transaction
  workload. Same fix protects the APScheduler workers in the
  `scheduler` service.
- **`use_container_width` deprecation** — every `st.dataframe(...)` and
  `st.graphviz_chart(...)` call switched to `width="stretch"`, which is
  the supported API on Streamlit ≥ 1.40. Removes ~20 deprecation
  warnings per page render.

### Added

- **Watchlist editor page** in the dashboard (analyst+ role). View all
  entries with type/search/enabled filters, add new rules via a form,
  edit severity/enabled/description in place, delete with a "I'm sure"
  confirmation. Every mutation writes a `watchlist_added` /
  `watchlist_updated` / `watchlist_deleted` row to the audit log with
  the actor + role. Closes the "edit-yaml-and-CLI-sync" friction.
- New repository helpers: `list_watchlist(type_filter, search,
  enabled_only)`, `get_watchlist_entry`, `update_watchlist_entry`
  (partial updates: only the fields you pass change), `delete_watchlist_entry`.
- New regression test `tests/test_thread_safety.py`: opens a connection
  on the main thread, queries it from a worker thread (the exact
  Streamlit pattern), and runs 8 concurrent reader threads to verify
  the WAL + busy_timeout config doesn't deadlock.
- 15 new pytest cases in `tests/test_watchlist_repo.py` covering filters,
  partial updates, case-normalization on severity/type, no-op detection,
  and the unknown-id paths on update / delete.

### Changed

- `requirements.txt`: `streamlit>=1.30.0` → `streamlit>=1.40.0` so the
  `width=` parameter is guaranteed to be available.

### Notes on watchlist editing

Edits in the dashboard write to the SQLite DB. The YAML file
(`watchlist.yaml`) remains the source-of-truth for `sync-config`, so
re-running that command will upsert YAML entries on top of dashboard
edits — but it will not delete rules that exist only in the DB. The
page caption surfaces this so the behavior isn't a surprise.

## v0.1.0 — 2026-05-10

First release. The platform now covers ten phases of the original project
plan end-to-end: from RSS + onion collection through extraction, watchlist
matching, scoring, enrichment, full-text search, relationship mapping, LLM
analyst summaries, case management, scheduled reporting, and an opt-in
auth + audit story for production deployments.

(Full v0.1.0 entry preserved in git history; see CHANGELOG.md on
commit 33dc5e8 for the unabbreviated version.)
