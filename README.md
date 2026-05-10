# mini-threat-intel (Milestone 1)

A small self-hosted threat intelligence platform. **Milestone 1** delivers an
RSS + watchlist MVP: collect items from RSS feeds, normalize them, extract
common observables, match against a watchlist, and surface results in a
Streamlit dashboard. Optional Telegram alerts fire on high/critical matches.

## Scope

In scope for Milestone 1:

- RSS collection
- SQLite storage
- Regex-based observable extraction (domain, URL, email, IPv4/IPv6, MD5,
  SHA1, SHA256, CVE)
- Phase 2 observables: onion (v2/v3), crypto wallets (BTC base58/bech32,
  ETH, Monero), `@handles`, malware/threat-actor names via curated lookup
  list (`app/extractors/named_entities.yaml`)
- Defanged-input handling (`evil[.]example[.]com`, `hxxps://`, `[at]`)
- Watchlist matching: exact domain (with subdomain match), email, IP, CVE,
  hash, onion, wallet, handle, malware, actor, free-text keyword
- Streamlit dashboard: overview, matches, documents, entities, enrichment,
  source health
- Telegram alerts for high/critical matches
- Enrichment providers: CISA KEV + EPSS (no key), URLhaus + MalwareBazaar
  (abuse.ch Auth-Key), VirusTotal, AbuseIPDB. Cached results with
  configurable freshness window.
- Rule-based scoring (0–100) with reasons, derived severity, suppression
  rules, and false-positive feedback loop.
- Background scheduler (APScheduler) for collect / enrich / source-health
  with per-source exponential backoff and a `job_runs` history table.
- SQLite FTS5 full-text search over collected documents with snippets,
  source/date filters, and CSV / JSON export.
- LLM analyst summaries via the Anthropic SDK (default `claude-opus-4-7`)
  with structured output (Pydantic), cached system prompt, and a per-match
  panel in the dashboard.
- Case management: turn a match into an investigation, attach evidence
  (matches / documents / entities / enrichments / summaries / free-form
  notes), capture a status timeline, export a self-contained markdown
  report.
- Reports: rule-based templates (`daily_summary`, `weekly_watchlist`,
  `source_health`, `executive`) rendered to markdown / HTML / JSON, with
  a persisted history table, optional scheduler job, and an in-dashboard
  generate-and-browse page.
- Hardening: opt-in dashboard auth (bcrypt + 3 roles), audit log,
  backup/restore CLI using SQLite's online backup, and a Docker Compose
  deployment recipe with web + scheduler services.
- Relationship mapping: pivot from any extracted entity to its
  co-occurring neighbors (ranked by shared documents) with a Graphviz
  mini-graph in the dashboard and a `pivot` CLI command.
- Optional Tor / onion collector: routes through a local SOCKS5h proxy,
  fetches only the `*.onion` URLs you explicitly configure (no crawling),
  with a Compose-profile sidecar and a `tor-check` smoke-test command.
- Leak-listing indicator extractor: emits `leak_status` /
  `leak_size` / `leak_deadline` entities when a document looks like a
  ransomware-leak landing (multi-word status phrases, size-near-leak-word
  co-occurrence, countdown / deadline lines). Gives the scorer a +10
  boost for matches on leak-context pages.

Explicitly **out of scope** here (per the project plan): Tor/onion crawling,
enrichment APIs, scoring, LLM summaries, case management, authentication.

## Repo layout

```
app/
  collectors/rss_collector.py
  extractors/entities.py        # orchestrator + domain/url/email/ip/hash/cve
  extractors/onion.py           # .onion v2/v3
  extractors/wallets.py         # BTC/ETH/XMR
  extractors/handles.py         # @username
  extractors/named_entities.py  # malware + actor lookup
  extractors/named_entities.yaml
  matching/watchlist_matcher.py
  matching/scoring.py           # rule-based 0-100 priority + reasons
  matching/suppression.py       # YAML-driven suppression rules
  enrichment/                   # CISA KEV, EPSS, URLhaus, MalwareBazaar, VT, AbuseIPDB
  jobs/                         # APScheduler scheduler + record_run wrapper
  search.py                     # FTS5 query helpers
  llm/                          # Claude API summarizer (prompts, schema, runner)
  cases/                        # case repository + markdown exporter
  reports/                      # report templates + renderers (md/html/json)
  auth/                         # bcrypt users, role checks, audit log, login gate
  graph/                        # entity co-occurrence relationships
  cli/                          # one module per subcommand group
  pipeline.py                   # process_document + collect/enrich cycles
  entry.py                      # unified entry point used by the .exe build
  alerts/telegram.py
  ui/streamlit_app.py
  config.py
  database.py
  normalizer.py
  repository.py
  main.py            # CLI entrypoint
sources.yaml         # configured RSS feeds
watchlist.yaml       # watched entities
tests/
```

## Quick start

The fastest path: run the one-shot launcher. It pulls the latest commit
(if you're in a git checkout), creates `.venv/`, installs/updates
requirements, initializes the database, syncs `sources.yaml` +
`watchlist.yaml`, and launches the Streamlit dashboard.

```bash
# Linux / macOS
./run.sh                  # default: launch the dashboard
./run.sh collect          # one collection cycle and exit
./run.sh scheduler        # run the scheduler in the foreground
./run.sh setup            # bootstrap only (no launch)

# Windows
run.bat
run.bat collect

# Anywhere
python launch.py [dashboard|collect|scheduler|setup|update]
```

Useful flags: `--no-pull` (skip git pull), `--no-install` (skip pip), `--port 8502`,
`--reinstall` (force pip install even if `requirements.txt` is unchanged).

If you'd rather wire it up by hand:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python -m app.main init-db
python -m app.main sync-config
python -m app.main collect
streamlit run app/ui/streamlit_app.py
```

## CLI

```
python -m app.main init-db        # create SQLite schema
python -m app.main sync-config    # load sources.yaml + watchlist.yaml
python -m app.main collect        # fetch + extract + match + alert
python -m app.main collect --only "Krebs on Security" "BleepingComputer"
python -m app.main extract        # re-extract entities for stored docs
python -m app.main match          # re-run watchlist matching
python -m app.main enrich                      # run enrichment for all stored entities
python -m app.main enrich --type cve           # only CVEs
python -m app.main enrich --type cve --value CVE-2024-3400
python -m app.main enrich --limit 50 --force   # ignore cache, cap to 50 entities
python -m app.main score                       # score matches that have no score yet
python -m app.main score --rescore-all         # re-run scoring across all matches
python -m app.main scheduler                   # foreground job scheduler (ctrl-C to stop)
python -m app.main scheduler --run-now         # also fire every job once on startup
python -m app.main search "lockbit ransomware" # FTS5 search
python -m app.main search "lock*" --source "Krebs on Security" --limit 10
python -m app.main reindex                     # rebuild the FTS index
python -m app.main summarize --match-id 42     # generate analyst summary for one match
python -m app.main summarize --top 10          # summarize top-10 unscored open matches
python -m app.main summarize --all-new --force # regenerate everything
python -m app.main case create --from-match 42 --owner alice
python -m app.main case list --status open
python -m app.main case show 1
python -m app.main case note 1 --body "Looks tied to recent leak claim"
python -m app.main case attach 1 --enrichment 7
python -m app.main case status 1 --to confirmed
python -m app.main case export 1 --output report.md
python -m app.main report list
python -m app.main report generate daily_summary --window 24h --format md
python -m app.main report generate executive --window 30d --format html --output exec.html
python -m app.main report generate weekly_watchlist --save
python -m app.main report list --saved
python -m app.main report show 1 --format md
python -m app.main user create alice --role admin     # interactive password prompt
python -m app.main user list
python -m app.main user set-role alice analyst
python -m app.main user disable alice
python -m app.main backup                              # writes data/backup-<UTC>.db
python -m app.main backup --output /backups/mtl.db
python -m app.main restore /backups/mtl.db --force
python -m app.main pivot domain:example.com            # relationship pivot from CLI
python -m app.main pivot cve:CVE-2024-3400 --neighbor-type domain --limit 10
python -m app.main tor-check                           # smoke-test Tor SOCKS proxy
python -m app.main alert-test     # send a test Telegram alert
```

Scoring is also applied automatically inside `collect` and `match` for newly
created matches, and `severity` is updated to reflect the score band:
0-25 low, 26-50 medium, 51-75 high, 76-100 critical.

## Configuration

`sources.yaml` lists RSS feeds with `name`, `type: rss`, `url`, `enabled`.

`watchlist.yaml` lists watched entries with `type`
(`domain`, `email`, `ip`, `cve`, `hash`, `onion`, `wallet`, `handle`,
`malware`, `actor`, `keyword`), `value`, `severity`
(`low`/`medium`/`high`/`critical`), `description`, `enabled`.

Environment variables (see `.env.example`):

- `DATABASE_PATH` — SQLite path (default `data/threatintel.db`)
- `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` — required for alerts
- `ALERT_MIN_SEVERITY` — `low|medium|high|critical` (default `high`)
- `USER_AGENT`, `HTTP_TIMEOUT`
- `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `ABUSECH_AUTH_KEY` — enrichment
  provider keys (each is optional; the corresponding provider self-skips when
  empty). CISA KEV and EPSS need no key.
- `ENRICHMENT_MAX_AGE_HOURS` — re-enrich cache window (default 168)
- `SUPPRESSION_PATH` — path to `suppression.yaml` (default in repo root)
- `ALERT_MIN_SCORE` — additional score gate for Telegram alerts (default 0,
  meaning the existing severity gate alone determines alerting)
- `COLLECT_INTERVAL_MINUTES` (30), `ENRICH_INTERVAL_MINUTES` (15),
  `ENRICH_BATCH_LIMIT` (100), `SOURCE_HEALTH_INTERVAL_HOURS` (12) — scheduler
  cadences
- `SOURCE_BACKOFF_BASE_MINUTES` (5), `SOURCE_BACKOFF_MAX_EXPONENT` (6) — when a
  source errors, the next attempt is delayed by `BASE * 2^min(error_count, MAX)`
  minutes
- `ANTHROPIC_API_KEY` — required for `summarize`; provider self-skips otherwise
- `LLM_MODEL` (default `claude-opus-4-7`), `LLM_MAX_TOKENS` (2048),
  `LLM_DOC_TEXT_CHARS` (12000) — knobs for analyst summarization
- `DAILY_REPORT_INTERVAL_HOURS` — when > 0, the scheduler also generates
  + persists a `daily_summary` report on this cadence (default 0 = off)

## Tests

```bash
pip install pytest
pytest -q
```

## Dark-web sources (Tor)

The platform can also collect from public Tor hidden services
(`*.onion`). Onion sources are **disabled by default** and routed through
a local Tor SOCKS5 proxy using `socks5h://` so DNS resolution happens at
the Tor exit (a `socks5://` proxy without the `h` would resolve hostnames
locally and leak which onion you're visiting).

### Setting it up

1. **Run a Tor daemon.** Either install locally:

   ```bash
   # Debian/Ubuntu
   sudo apt install tor && sudo systemctl start tor
   # macOS
   brew install tor && brew services start tor
   ```

   …or use the Compose sidecar (gated on a profile so it doesn't pull the
   image for clearweb-only deployments):

   ```bash
   docker compose --profile tor up -d
   # then in .env:
   #   TOR_SOCKS_HOST=tor
   #   TOR_SOCKS_PORT=9050
   ```

2. **Validate connectivity.**

   ```bash
   python -m app.main tor-check
   ```

   Should print `OK: traffic is routed through Tor.` If not, the error message
   tells you whether the proxy is unreachable or returning unexpected content.

3. **Add onion entries to `sources.yaml`.** The shipped file has a disabled
   placeholder showing the expected shape. The Pydantic config refuses
   `type: onion` with a clearweb URL and `type: rss` with an `.onion` URL,
   so a misconfiguration fails on `sync-config` rather than at runtime.

4. **Run a cycle.**

   ```bash
   python -m app.main collect --only "Your Onion Source"
   ```

### What stays in scope

The original project plan drew a clear line that this collector keeps:

- **In scope** — your organization's own leak-site monitoring, public
  ransomware index mirrors, public news mirrors, and any source you have a
  documented authority to fetch.
- **Out of scope** — invite-only criminal forums, buying stolen data,
  interacting with threat actors, automated account creation, exploit
  execution, malware detonation, credential validation. The collector
  **never crawls or auto-discovers** — it only fetches the URLs you put
  in `sources.yaml`.

### Knobs

- `TOR_SOCKS_HOST` (default `127.0.0.1`)
- `TOR_SOCKS_PORT` (default `9050`)
- `ONION_REQUEST_TIMEOUT` (default `60` seconds — Tor is slow)
- `ONION_USER_AGENT` (default a generic Firefox UA)

## Production deployment

The repo ships a `Dockerfile` and `docker-compose.yml` that runs two
services sharing a `data/` volume:

- `web`       — the Streamlit dashboard on port 8501
- `scheduler` — APScheduler background loop (collect / enrich / source-health / optional daily report)

```bash
# 1. Configure
cp .env.example .env
$EDITOR .env                  # set AUTH_ENABLED=1, your API keys, alert thresholds

# 2. Boot
docker compose up -d --build

# 3. First-run bootstrap
open http://localhost:8501    # the gate offers a one-shot admin-creation form

# 4. Backups (run as a cron / systemd timer)
docker compose exec web python -m app.main backup --output /app/data/backup.db
```

Behind a reverse proxy (recommended for TLS):

```nginx
server {
    listen 443 ssl http2;
    server_name intel.example.org;
    ssl_certificate     /etc/letsencrypt/live/intel.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/intel.example.org/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8501;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;     # Streamlit websocket
        proxy_set_header Connection "upgrade";
    }
}
```

### Auth model

- `AUTH_ENABLED=0` (default) → dashboard is open; useful for single-user dev.
- `AUTH_ENABLED=1` → bcrypt-backed login; first hit shows an admin-creation
  form when the `users` table is empty.
- Three roles: `viewer` (read-only), `analyst` (matches/cases/summaries),
  `admin` (everything, including the Admin page for user management +
  audit log).
- All login attempts (success, fail, disabled) and dashboard mutations are
  written to `audit_log` and are visible on the Admin page.

### Backup / restore

- `python -m app.main backup [--output PATH]` uses SQLite's online backup
  API, so you can run it against a live database without stopping the
  scheduler.
- `python -m app.main restore PATH [--force]` validates the input is a
  real SQLite file, saves the current DB to `<db>.bak` first, then
  swaps the file in place.

## Building a standalone executable

A PyInstaller spec is included so the whole platform can be packaged into
a single self-contained `.exe` (Windows) or binary (macOS/Linux). The
build is a "onedir" bundle — `dist/mini-threat-intel/` contains the
executable plus the supporting libs and bundled YAML configs.

CI builds are wired up: every push, PR, and tagged release runs the
[`build-exe`](.github/workflows/build-exe.yml) workflow on a Windows
runner and uploads the resulting bundle as a downloadable artifact.
Tagged releases (`v*`) also attach the zip to the GitHub Release page.

To build locally:

```bash
# 1. Install build deps (adds PyInstaller on top of the runtime requirements)
pip install -r requirements-build.txt

# 2. Build
python scripts/build_exe.py
# or: python -m PyInstaller --clean --noconfirm mini-threat-intel.spec

# 3. Ship dist/mini-threat-intel/ as a zip
```

The frozen executable accepts the same subcommands as the CLI:

```bash
mini-threat-intel.exe                       # launch the dashboard (default)
mini-threat-intel.exe dashboard
mini-threat-intel.exe collect
mini-threat-intel.exe scheduler
mini-threat-intel.exe report generate daily_summary --window 24h
```

Frozen runtime behavior:

- `app/entry.py` is the single entry point; it dispatches to either the
  Streamlit dashboard or `app.main` based on the first argument.
- Bundled YAML configs are unpacked from `sys._MEIPASS`; their paths are
  exposed via `SOURCES_PATH`, `WATCHLIST_PATH`, `SUPPRESSION_PATH` env
  vars so the rest of the code is unaware of the difference.
- The SQLite DB defaults to `./data/threatintel.db` next to the
  executable, so users can run the bundle from any writable directory
  without admin rights. Override with `DATABASE_PATH=…`.
- `launch.py` / `run.sh` / `run.bat` are dev-only — they pull source +
  install deps + invoke `python -m app.main`. End users of the .exe never
  see them.

## Status

Milestones 1, 2, 5 (enrichment), 6 (scoring), 8 (scheduler), 9 (full-text
search), 10 (relationship mapping), 11 (LLM analyst summaries), 12 (case
management), 13 (reporting), and 14 (production hardening) of the larger
phased plan. See *Roadmap* for what comes next.

## Roadmap

The full multi-phase plan (collectors → extractors → matching → enrichment →
scoring → alerting → search → graph → LLM summaries → case management →
reporting → hardening) is the long-term direction. Milestone 1 stops at the
matching/alerting baseline.
