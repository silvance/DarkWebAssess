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
- Defanged-input handling (`evil[.]example[.]com`, `hxxps://`, `[at]`)
- Watchlist matching: exact domain (with subdomain match), email, IP, CVE,
  hash, free-text keyword
- Streamlit dashboard: overview, matches, documents, entities, source health
- Telegram alerts for high/critical matches

Explicitly **out of scope** here (per the project plan): Tor/onion crawling,
enrichment APIs, scoring, LLM summaries, case management, authentication.

## Repo layout

```
app/
  collectors/rss_collector.py
  extractors/entities.py
  matching/watchlist_matcher.py
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
python -m app.main alert-test     # send a test Telegram alert
```

## Configuration

`sources.yaml` lists RSS feeds with `name`, `type: rss`, `url`, `enabled`.

`watchlist.yaml` lists watched entries with `type`
(`domain`, `email`, `ip`, `cve`, `hash`, `keyword`), `value`, `severity`
(`low`/`medium`/`high`/`critical`), `description`, `enabled`.

Environment variables (see `.env.example`):

- `DATABASE_PATH` — SQLite path (default `data/threatintel.db`)
- `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` — required for alerts
- `ALERT_MIN_SEVERITY` — `low|medium|high|critical` (default `high`)
- `USER_AGENT`, `HTTP_TIMEOUT`

## Tests

```bash
pip install pytest
pytest -q
```

## Status

Milestone 1 of the larger phased plan. See *Roadmap* for what comes next.

## Roadmap

The full multi-phase plan (collectors → extractors → matching → enrichment →
scoring → alerting → search → graph → LLM summaries → case management →
reporting → hardening) is the long-term direction. Milestone 1 stops at the
matching/alerting baseline.
