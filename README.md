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

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 1. Initialize the SQLite DB and load sources/watchlist.
python -m app.main init-db
python -m app.main sync-config

# 2. Pull the feeds, store new docs, extract entities, run matches.
python -m app.main collect

# 3. Browse results.
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

## Tests

```bash
pip install pytest
pytest -q
```

## Status

Milestones 1, 2, 5 (enrichment), 6 (scoring), 8 (scheduler), and 9
(full-text search) of the larger phased plan. See *Roadmap* for what comes
next.

## Roadmap

The full multi-phase plan (collectors → extractors → matching → enrichment →
scoring → alerting → search → graph → LLM summaries → case management →
reporting → hardening) is the long-term direction. Milestone 1 stops at the
matching/alerting baseline.
