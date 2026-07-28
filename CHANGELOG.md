# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- **Self-monitoring `scrub` command.** `dwa scrub <email|username|domain>`
  checks what's publicly exposed about an identifier you control and
  prints a consolidated report (text / markdown / json). Framed and
  built as a self-monitoring tool — no mass-target mode; providers query
  only public/consented surfaces. Ships three native providers, each
  self-skipping when it can't run:
    - `local_xref` (offline, always on) — surfaces the identifier already
      appearing in sources this tool has collected (watchlist matches,
      extracted entities, document mentions). The highest-signal check
      and unique to this platform.
    - `gravatar` — detects a public Gravatar avatar/profile tied to an
      email, including a leaked display name + linked social accounts.
    - `hibp` — Have I Been Pwned breach lookup (needs `HIBP_API_KEY`);
      raises breaches that exposed passwords or are flagged sensitive to
      high severity.
  Runs persist to new `scrub_runs` / `scrub_findings` tables so exposure
  is trackable over time. Exits non-zero on high-severity findings so it
  is scriptable. New config: `HIBP_API_KEY`, `SCRUB_HTTP_TIMEOUT`,
  `SCRUB_REQUEST_DELAY` (polite inter-request spacing). Native
  username/email-enumeration providers and optional passthrough to
  installed Sherlock / holehe / h8mail land in follow-up changes.

- **Onboarding panel on the dashboard Overview.** On a fresh install the
  Overview page shows a context-aware Getting Started guide instead of a
  wall of zeros: a 3-step walkthrough when the DB is empty, a "run a
  collection" nudge when you have watchlist rules but no documents, and
  an "add watchlist rules" nudge when you have documents but nothing to
  match. Disappears automatically once the tool has both.
- **`demo-seed` / `demo-clear` commands.** Populate the DB with fictional
  sample threat data so a new operator can explore a fully-populated
  dashboard before wiring up real sources. The sample documents run
  through the real pipeline (extract → match → score), so the entities,
  matches, and scores are genuine, not hand-faked. All content is
  unambiguously fake (RFC-2606 `.example` domains, documentation-range
  IPs) and the demo source is disabled so a real `collect` never fetches
  it. `demo-clear` removes only the demo rows, tagged by source name and
  a `[demo]` description marker — it never touches operator-added data.
  Both commands are idempotent.

Feature + hardening release. Real Windows install experience, dark-web
visibility via index-only ingestion, CSAM-defense MIME policy, optional
OPSEC egress preflight, and a Rust extractor accelerator.

### Added

**Windows UX**
- `dwa.cmd` shim — top-level Windows entry point that always invokes the
  project's venv Python. Eliminates the "ran system Python instead of
  venv" foot-gun (the root cause of the v0.1.1 `bs4`-missing reports).
- `run.bat` — pauses on error so a double-click user can read the
  failure before the window closes.
- `launch.py` / frozen `.exe` — auto-opens the browser when the
  dashboard port is listening, plus a `tray` target and `--no-browser`
  flag.
- System-tray launcher (`app/ui/tray.py`, requires `pystray` +
  `Pillow`). Menu: Open Dashboard / Run Collection Now / Open Data
  Folder / About / Quit. Dashboard subprocess is detached
  (`CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP` on Windows) and torn
  down cleanly on Quit.
- `installer/Install-DarkWebAssess.ps1` + `Uninstall-DarkWebAssess.ps1`
  — per-user install (no admin), bundle → `%LOCALAPPDATA%\Programs\…`,
  data → `%APPDATA%\DarkWebAssess`. Creates Start Menu + Desktop
  shortcuts, pre-runs `init-db` + `sync-config`, launches the tray.
- `DWA_DATA_DIR` env var so the data directory can be set independently
  of the install location.

**Dark-web discovery (Option A: index-only)**
- New `discover` CLI subcommand and `onion_directories.yaml` config.
  Fetches operator-curated aggregator pages (Ahmia, dark.fail) and
  extracts the `.onion` URLs they list — but **never** auto-fetches a
  discovered URL. Each becomes a PENDING candidate in a new
  `onion_candidates` table. Triage via `discover list / show / approve
  / reject`; approval prints a `sources.yaml` snippet for the operator
  to paste.
- Repository helpers: `upsert_onion_candidate`, `get_onion_candidate`,
  `list_onion_candidates`, `set_onion_candidate_status`.
- Hard safety boundaries: the discovery collector only fetches the
  seeded directory URLs (never a candidate URL it just discovered),
  validates the host shape against the Tor base32 alphabet for both
  extraction passes (`<a href>` + free-text fallback), caps response
  size at 2 MB and link count at 2k per page, and treats rejected
  status as durable (re-discovery bumps `times_seen` and merges sources
  but never resets status — the operator's NO sticks).

**Binary-content ingestion policy (CSAM defense)**
- `app/collectors/mime_policy.py` — strict textual-only allowlist
  shared across the HTTP-fetching collectors (`onion_collector` and
  `onion_discovery`). Content-Type must be one of `text/html`,
  `text/plain`, `text/xml`, `application/xhtml+xml`, `application/xml`,
  `application/rss+xml`, `application/atom+xml`, `application/json`;
  AND the first 1 KB must look textual (no NUL bytes, no known binary
  magic signatures — JPEG, PNG, GIF, PDF, ZIP, RAR, 7z, gzip, MP4,
  WAV/AVI, OGG, MP3, FLAC, Matroska/WebM, PE/EXE, ELF — and less than
  5% non-printable). A rejected response yields zero documents (no
  placeholder row for an attacker to abuse).
- `onion_collector` no longer stores a hex-elided placeholder for
  binary responses. The fetch is still recorded in source health, but
  no bytes land in the document store.

**OPSEC: egress IP verification**
- `dwa network-check` — calls `https://api.ipify.org`, validates the
  result is a real IP, compares to `EXPECTED_EGRESS_PREFIXES` (a
  comma-separated CIDR allowlist). Exit 0 = in allowlist, 1 = outside,
  2 = lookup failed.
- `STRICT_EGRESS=1` preflight on `collect`, `scheduler`, and
  `discover run`. Refuses to start if the egress IP is outside the
  allowlist or the lookup itself fails. Fail-closed: if
  `STRICT_EGRESS=1` and `EXPECTED_EGRESS_PREFIXES` is empty, the
  preflight refuses immediately rather than fetching with no
  protection.
- The tool does **not** manage WireGuard itself — routing is an OS
  concern (see [`docs/OPSEC.md`](docs/OPSEC.md) for the recommended
  always-on + fail-closed kill-switch setup). The preflight is
  defense-in-depth on top of that.

**Rust extractor accelerator (opt-in)**
- `crates/dwa_extractors/` — PyO3 extension that takes over the
  regex hot path (URL / email / IPv4 / IPv6 / MD5 / SHA1 / SHA256 /
  CVE). One `abi3-py310` wheel works on Python 3.10 through 3.13+.
  Measured ~24× faster on a 100 KB corpus.
- `app/extractors/entities.py` detects the wheel at import time
  (`try: import dwa_extractors`) and routes through it when available.
  Pure Python is the fallback — pip-install-only clones still run
  identically.
- `.github/workflows/build-wheels.yml` — `maturin-action` matrix for
  Linux (x86_64 + aarch64), macOS (x86_64 + arm64), Windows x86_64.
  Wheels attach to releases on `v*` tags.

**Watchlist editor (dashboard)**
- New Watchlist page in the dashboard (analyst+ role). View all
  entries with type/search/enabled filters, add / edit severity /
  enabled / description / delete entries with an "I'm sure"
  confirmation. Every mutation writes a `watchlist_added` /
  `watchlist_updated` / `watchlist_deleted` row to the audit log with
  the actor + role.

**Documentation**
- `docs/TUTORIAL.md` — goal-first walkthrough: install, first
  watchlist entry, first collection cycle, dark-web visibility,
  background-mode options, OPSEC preflight, troubleshooting.
- `docs/OPSEC.md` — WireGuard setup (Windows + Linux), kill-switch
  firewall rules, the `STRICT_EGRESS` workflow, stronger options
  (Linux netns, Windows per-exe firewall rule, Whonix/Tails for
  operational use).
- `crates/dwa_extractors/README.md` — coverage, dict shape, build
  notes, bench notes.

### Changed

- `requirements.txt`: added `pystray>=0.19.5`, `Pillow>=10.0.0` for the
  tray launcher.
- `app/config.py`: honors `DWA_DATA_DIR` and `ONION_DIRECTORIES_PATH`.
- `mini-threat-intel.spec`: bundles `onion_directories.yaml`, the new
  collectors, the tray module, the egress module, and the discovery
  / network / tray CLI commands as hidden imports.
- `app/entry.py`: frozen `.exe` honors `DWA_DATA_DIR`, points
  `ONION_DIRECTORIES_PATH` at the bundled YAML, and dispatches
  `mini-threat-intel.exe tray` to the tray launcher.

### Tests

- New cases (post-v0.1.1):
  - `tests/test_onion_discovery.py` — 19 cases (URL normalization,
    HTML extraction, repo upserts, durable rejection, etc.)
  - `tests/test_mime_policy.py` — 19 cases (MIME allowlist + magic-byte
    sniff)
  - `tests/test_onion_collector.py` — extended for the binary-drop
    semantics (no placeholder row on JPEG / PNG / octet-stream /
    missing Content-Type)
  - `tests/test_egress.py` — 17 cases (CIDR parsing, allowlist match,
    lookup failure, `STRICT_EGRESS` preflight)
  - `tests/test_extractor_bench.py` — 5 cases (Rust↔Python output
    parity, known-corpus signal extraction, ≥1.5× speedup assertion,
    dict shape, end-to-end `extract_all` smoke). Auto-skips when the
    Rust wheel isn't installed.
- 10 pure-Rust unit tests in `crates/dwa_extractors/src/lib.rs`
  (`cargo test --release`).
- Full Python suite: **284 passing** (was 219 at v0.1.1).

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
