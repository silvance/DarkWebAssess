# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.1.1 — 2026-05-10

Patch release. Fixes a fatal bug that broke every dashboard page on the
v0.1.0 .exe and silences the `use_container_width` deprecation warnings
that drowned the console.

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

- New regression test `tests/test_thread_safety.py`: opens a connection
  on the main thread, queries it from a worker thread (the exact
  Streamlit pattern), and runs 8 concurrent reader threads to verify
  the WAL + busy_timeout config doesn't deadlock.

### Changed

- `requirements.txt`: `streamlit>=1.30.0` → `streamlit>=1.40.0` so the
  `width=` parameter is guaranteed to be available.

## v0.1.0 — 2026-05-10

First release. The platform now covers ten phases of the original project
plan end-to-end: from RSS + onion collection through extraction, watchlist
matching, scoring, enrichment, full-text search, relationship mapping, LLM
analyst summaries, case management, scheduled reporting, and an opt-in
auth + audit story for production deployments.

### Added

**Collection**
- RSS collector with feedparser, custom UA, and robust per-source backoff.
- Tor / onion collector — routes through a local SOCKS5h proxy, fetches
  only `*.onion` URLs the operator explicitly configured (no crawling, no
  auto-discovery). Pydantic config validates `type:` ↔ host pairing both
  directions so a `type: rss` source with a `.onion` URL fails at
  config-load instead of leaking the request over the clearweb.
- `tor-check` CLI to smoke-test Tor connectivity.
- Optional Tor sidecar in `docker-compose.yml` (gated on the `tor` profile).

**Extraction**
- Regex-based observable extractors for domain, URL, email, IPv4/IPv6,
  MD5/SHA1/SHA256, CVE — with defang re-fanging for `[.]`, `hxxps://`, `[at]`.
- Onion address extractor (v2 16-char + v3 56-char), crypto wallet
  extractors (BTC P2PKH/P2SH/bech32, ETH, Monero), `@handle` extractor
  with email-local-part avoidance.
- List-based malware family + threat-actor named-entity extractor with
  multi-word support (`Cobalt Strike`, `Volt Typhoon`).
- Leak-listing indicator extractor: `leak_status` (multi-word phrases like
  `DATA PUBLISHED`, `AUCTION IN PROGRESS`, `STAGE 2`), `leak_size`
  (KB/MB/GB/TB/PB, only when a leak-context word sits within 200 chars),
  `leak_deadline` (`DEADLINE: …`, free-form `3 days remaining`).

**Matching, scoring, suppression**
- Watchlist matching: exact + subdomain domain, exact email/IP/CVE/hash,
  onion / wallet / handle / malware / actor types, free-form keyword.
- Rule-based 0-100 priority score per match with reason strings:
  watchlist-severity base, specificity boost, recency, source reliability,
  KEV + tiered EPSS for CVEs, AbuseIPDB confidence bands, URLhaus + VT
  verdicts, co-occurring file hash / CVE / leak indicators, multi-source
  corroboration, false-positive feedback penalty, suppression rule cap.
- YAML-driven suppression rules with optional source-name scoping.

**Enrichment**
- Provider framework with on-disk cache and configurable freshness:
  CISA KEV (no key, with disk-cached catalog), FIRST.org EPSS (no key),
  abuse.ch URLhaus + MalwareBazaar (Auth-Key gated), VirusTotal v3 +
  AbuseIPDB (API-key gated). Providers self-skip when unconfigured.

**Surface area**
- Streamlit dashboard with pages: Overview, Matches, Cases, Reports,
  Relationships, Search, Documents, Entities, Enrichment, Sources, Jobs,
  Admin.
- Cases: turn matches into investigations, attach polymorphic evidence
  (matches / documents / entities / enrichments / summaries / free-form
  text), audit-logged status timeline, self-contained markdown export.
- Reports: `daily_summary`, `weekly_watchlist`, `source_health`,
  `executive` templates rendered to markdown / HTML / JSON, persisted
  history, optional scheduler-driven daily generation.
- LLM analyst summaries via the Anthropic SDK (default `claude-opus-4-7`)
  with structured Pydantic output and prompt-cache-friendly system block.
- Relationship mapping: pivot from any extracted entity to its
  co-occurring neighbors (ranked by shared documents) with a Graphviz
  mini-graph in the dashboard and a `pivot` CLI.
- SQLite FTS5 full-text search with snippets, source/date filters, and
  CSV / JSON export.

**Operations**
- Background scheduler (APScheduler) wraps every cycle with `record_run`
  bookkeeping and per-source exponential backoff.
- Telegram alerts for high/critical matches, gated on
  `ALERT_MIN_SEVERITY` and optional `ALERT_MIN_SCORE`.
- One-shot launcher (`launch.py` / `run.sh` / `run.bat`) handles
  git-pull → venv → deps → init-db in one command.
- SQLite online-backup CLI, restore CLI that flushes WAL and removes
  sidecar `-wal` / `-shm` files before swap.

**Hardening**
- Opt-in dashboard auth (`AUTH_ENABLED=1`) with bcrypt-hashed users,
  three roles (`viewer < analyst < admin`), library-level password length
  enforcement, brute-force lockout (configurable threshold + cooldown),
  first-run admin bootstrap with race-safe re-check.
- `audit_log` table covering login attempts (success / failed / locked /
  disabled), user CRUD, role changes, dashboard match/case mutations,
  report generation, backup/restore.
- Pydantic validation for `sources.yaml` / `watchlist.yaml` /
  `suppression.yaml` (rejects unknown enums and mixed type/host pairings).
- Length caps on case title / note / evidence / summary / label.
- WAL journal mode + `busy_timeout` so the Compose `web` + `scheduler`
  pair doesn't block each other.
- HTML report renderer escapes quotes (defense in depth).

**Packaging & CI**
- PyInstaller spec produces a self-contained Windows `.exe` bundle (or
  macOS / Linux binary) with all hidden imports and bundled YAML configs.
- GitHub Actions workflows: `tests` (Python 3.11 + 3.12 on PRs/pushes)
  and `build-exe` (Windows runner builds the bundle, smoke-tests
  `--help`, uploads zip artifact, attaches to GitHub Release on `v*` tags).
- Docker Compose deployment with `web` + `scheduler` services sharing a
  data volume; optional `tor` profile.

**CLI commands**
- `init-db`, `sync-config`, `collect`, `extract`, `match`, `score`,
  `enrich`, `summarize`, `case` (create/list/show/note/attach/status/export),
  `report` (list/generate/show), `user` (create/list/set-password/set-role/
  enable/disable/delete), `backup`, `restore`, `scheduler`, `search`,
  `reindex`, `pivot`, `tor-check`, `alert-test`, `--version`.

### Out of scope for v0.1.0

Deferred to later releases (and in some cases deliberately so for the
plan's stated safety boundaries):

- Onion crawling / auto-discovery beyond the configured URL list.
- Invite-only forum monitoring, paid-data ingestion, threat-actor
  interaction, automated account creation, malware detonation,
  credential validation.
- Per-site adapters for specific leak sites (the universal heuristic
  extractor ships; per-site parsers are easy to layer on later).
- Telegram channel collector.
- Encrypted secrets-at-rest table (env-var + 0600 `.env` is the
  recommended pattern).
- Email delivery for the daily report (the markdown body is generated;
  any small SMTP / SES wrapper can pipe it).

### Tests

202 pytest cases across collectors, extractors, matching, scoring,
suppression, enrichment, runner, CLI, search, cases, reports, auth,
audit, backup/restore, hardening, relationships, onion collector, and
leak-listings.
