# Tutorial: from zero to your first match

This walks you through using the tool end-to-end. If you'd rather skim,
each section starts with the one-line goal — find the one that matches
what you actually want to do, and skip the rest.

> **Mental model first.** This tool is **passive**, not a search engine.
> It monitors a list of sources you configure (RSS feeds, onion sites,
> aggregator pages) and flags when one of them mentions something on your
> watchlist. It does *not* go off and look up an email across the web —
> that's a different workflow (deferred to a later release as `scrub`).

---

## 0. Install

### Windows (.exe installer)

1. Download the latest `mini-threat-intel-windows-*.zip` from
   [Releases](https://github.com/silvance/DarkWebAssess/releases) and
   unzip it anywhere (Downloads is fine).
2. From PowerShell in that folder:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\installer\Install-DarkWebAssess.ps1
   ```
3. Done. You'll see a Start Menu folder **DarkWebAssess** with three
   shortcuts (Dashboard, Tray, Uninstall) and a Desktop icon. The
   installer pre-creates the database and launches the tray icon.

Defaults: bundle goes to `%LOCALAPPDATA%\Programs\DarkWebAssess`, data
goes to `%APPDATA%\DarkWebAssess`. No admin rights needed.

### Windows (dev / from source)

```cmd
git clone https://github.com/silvance/DarkWebAssess
cd DarkWebAssess
run.bat setup
run.bat
```

`run.bat setup` creates `.venv\`, installs dependencies, initializes the
DB. `run.bat` (no args) launches the dashboard.

From then on, always use `dwa` for CLI work — it goes through the venv
so you never accidentally hit your system Python:

```cmd
dwa sync-config
dwa collect
dwa user create alice analyst
```

### Linux / macOS

```bash
git clone https://github.com/silvance/DarkWebAssess
cd DarkWebAssess
./run.sh setup
./run.sh
```

---

## 1. First launch — what you should see

After the dashboard opens (`http://localhost:8501/`):

- **Overview** — counts and recent activity. On a fresh install this shows
  a **Getting Started** panel walking you through the first three steps;
  it disappears once you have watchlist rules and collected documents.
- **Matches** — anything that hit your watchlist (empty)
- **Watchlist** — the editor you'll use in a minute
- **Cases** — investigations you've opened
- **Sources** — health/status of every configured collector
- **Discovery** — pending dark-web candidates (empty until you opt in)

> **Want to see it populated before configuring anything?** Run
> `dwa demo-seed` (or `python -m app.main demo-seed`). It loads a handful of
> fictional threat reports through the real pipeline, so Overview, Matches,
> Entities, and Cases all light up with sample data you can click around.
> When you're done exploring, `dwa demo-clear` removes every trace of it —
> it only deletes the demo rows, never anything you added.

If auth is off (default), you're effectively an admin. To turn auth on
for real use:

```bash
dwa user create alice admin    # prompts for password, ≥8 chars
# then set AUTH_ENABLED=1 in your .env and restart
```

---

## 2. Scenario A: "watch my email for leak-site mentions"

**Goal:** get notified if any configured source publishes a post mentioning
your email address.

### 2.1 Add the email to your watchlist

In the dashboard:

1. Sidebar → **Watchlist**
2. Expand **Add new entry**
3. Fill in:
   - Type: `email`
   - Value: `you@example.com`
   - Severity: `high`
   - Description: "personal email — alert me"
   - Enabled: ✓
4. Click **Add**

You can also do this via `watchlist.yaml` if you'd rather edit a file:

```yaml
watchlist:
  - type: email
    value: you@example.com
    severity: high
    description: personal email
    enabled: true
```

Then sync it:

```bash
dwa sync-config
```

### 2.2 Run a collection cycle

Three ways to trigger collection:

| Method | Command |
|---|---|
| Tray icon | Right-click → **Run Collection Now** |
| CLI one-shot | `dwa collect` |
| Background loop | `dwa scheduler` (every 30 minutes by default) |

Expected output from `dwa collect`:

```
Collection done. new=12 dup=0 entities=148 matches=2 alerts=1 errors=0 skipped=0
```

What just happened, in order:
1. Each enabled source in `sources.yaml` was fetched.
2. New documents (12) were stored. Duplicates (by content hash) were skipped.
3. Entities (emails, IPs, CVEs, hashes, domains, URLs, onion addresses,
   wallets, etc.) were extracted — 148 in this run.
4. Each extracted entity was checked against your watchlist. 2 hit.
5. The 2 matches were scored (0–100). The one ≥ `ALERT_MIN_SEVERITY=high`
   triggered 1 Telegram alert (if you configured a bot — see §6.2).

### 2.3 Look at the result

Dashboard → **Matches**. You'll see a row per hit with:
- The source it came from
- The matched value (`you@example.com`)
- A score
- A reason string ("email match, high severity, source X, recent")
- A link to the underlying document

Click into a match to see the surrounding text in the document. From the
match detail you can:
- Mark **false positive** (drops the score, trains the de-prioritizer)
- **Promote to Case** (starts an investigation thread)
- **Add notes**

### 2.4 Promote to a Case (when something looks real)

A Case is your investigation thread. From a Match → **New case from this
match**:

1. Title: "alice email in leak listing"
2. Severity: inherits from the match
3. Status: `open`

Inside the case you can attach more evidence (other matches, documents,
entities, enrichment results), add notes, and export the whole thing as
self-contained markdown when you're ready to share or archive:

```bash
dwa case export <case_id> > alice-leak-2026-05.md
```

---

## 3. Scenario B: "add a new RSS source"

`sources.yaml` is the source-of-truth list. Add an entry:

```yaml
sources:
  - name: "BleepingComputer"
    type: rss
    url: "https://www.bleepingcomputer.com/feed/"
    enabled: true
```

Then sync + collect:

```bash
dwa sync-config
dwa collect --only "BleepingComputer"
```

Pydantic config validation catches the easy mistakes — `type: onion`
with a clearweb URL, or `type: rss` with an `.onion` URL, will both
fail at `sync-config` rather than at runtime.

---

## 4. Scenario C: "I want dark-web visibility"

**Goal:** get visibility into ransomware leak sites and dark-web indexes,
without accidentally cataloguing illegal content.

This is opt-in and has prerequisites. Read [`OPSEC.md`](OPSEC.md) before
you start — at minimum you want a VPN and the tool's egress preflight
enabled.

### 4.1 Stand up Tor

You need a local SOCKS5 proxy on `127.0.0.1:9050`. Two ways:

```bash
# Linux
sudo apt install tor && sudo systemctl enable --now tor

# Docker (any platform)
docker compose --profile tor up -d
```

Verify:

```bash
dwa tor-check
# OK: traffic is routed through Tor.
```

### 4.2 Enable an aggregator

Edit `onion_directories.yaml`. Everything ships disabled. Flip
`enabled: true` on a directory you trust:

```yaml
directories:
  - name: ahmia
    url: https://ahmia.fi/onions/
    transport: clearweb
    enabled: true            # <- was false
```

> Ahmia is the safest starting point: it's clearweb, well-known, and
> has a documented content policy that excludes CSAM/abuse listings.

### 4.3 Discover candidate URLs

```bash
dwa discover run
# [discover] fetching 1 directory ...
# [discover] done. 78 URLs extracted (78 new, 0 re-seen). Review with `dwa discover list`.
```

This **does not** fetch any of the discovered URLs. It only fetches the
aggregator page itself and parses the `.onion` links it lists. Each URL
becomes a PENDING candidate.

### 4.4 Triage candidates

```bash
dwa discover list
#   ID  STATUS     SEEN  URL
# ----------------------------------------------------------------
#    1  pending       1  http://abcdefghijklmnop.onion/
#    2  pending       1  http://qrstuvwxyzabcdef.onion/forum
#    3  pending       1  http://...
```

Look at one in detail:

```bash
dwa discover show 2
# Candidate #2
#   URL:           http://qrstuvwxyzabcdef.onion/forum
#   Host:          qrstuvwxyzabcdef.onion
#   Title:         Some Forum
#   Status:        pending
#   First source:  ahmia
#   ...
```

Decide. For each candidate, you have two choices:

```bash
# Approve: prints a sources.yaml snippet to paste.
dwa discover approve 2 --reviewer alice
# [discover] candidate #2 marked approved.
#
# # Add this entry to sources.yaml, then run: dwa sync-config
#   - name: "Some Forum"
#     type: onion
#     url: "http://qrstuvwxyzabcdef.onion/forum"
#     enabled: true

# Reject: durable. Re-discovery will not re-suggest it.
dwa discover reject 1 --reason "csam-host"
```

### 4.5 Promote approved candidates

Paste the approved snippet into `sources.yaml`, then:

```bash
dwa sync-config
dwa collect --only "Some Forum"
```

The collector goes through Tor for `type: onion` sources automatically.
Content matching, scoring, and alerting work the same as for RSS.

---

## 5. Running it in the background

For day-to-day use you want one of:

### Option A — tray icon (Windows, desktop use)

Just launch `DarkWebAssess (Tray)` from the Start Menu. The tray menu:

- **Open Dashboard** — starts Streamlit and opens your browser
- **Run Collection Now** — one-shot collect
- **Open Data Folder** — explorer to `%APPDATA%\DarkWebAssess`
- **Quit** — stops the dashboard subprocess

### Option B — scheduler (server / always-on)

```bash
dwa scheduler
```

Runs in the foreground; logs to stdout. It fires:
- Collection cycle every `COLLECT_INTERVAL_MINUTES` (default 30)
- Enrichment every `ENRICH_INTERVAL_MINUTES` (default 15)
- Source-health check every `SOURCE_HEALTH_INTERVAL_HOURS` (default 12)
- Daily report if `DAILY_REPORT_INTERVAL_HOURS > 0`

To run as a Linux service:

```ini
# /etc/systemd/system/dwa-scheduler.service
[Unit]
Description=DarkWebAssess scheduler
After=network-online.target

[Service]
Type=simple
User=dwa
WorkingDirectory=/opt/darkwebassess
ExecStart=/opt/darkwebassess/.venv/bin/python -m app.main scheduler
EnvironmentFile=/opt/darkwebassess/.env
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now dwa-scheduler
```

---

## 6. Useful add-ons

### 6.1 Egress preflight (recommended if you go to §4)

See [`OPSEC.md`](OPSEC.md) for the full WireGuard setup. Once that's
done, set:

```bash
export EXPECTED_EGRESS_PREFIXES="<your VPN's CIDR>"
export STRICT_EGRESS=1
dwa network-check         # one-shot verification
```

With `STRICT_EGRESS=1`, `collect`, `scheduler`, and `discover run`
refuse to start if the egress IP is outside your VPN.

### 6.2 Telegram alerts

Create a bot via [@BotFather](https://t.me/BotFather), grab the token,
and message the bot once so you can find your chat ID.

```bash
# .env
TELEGRAM_BOT_TOKEN=12345:abcdef
TELEGRAM_CHAT_ID=987654321
ALERT_MIN_SEVERITY=high
```

Verify:

```bash
dwa alert-test
# OK — test alert sent.
```

From then on, any new match with severity ≥ `ALERT_MIN_SEVERITY` fires
an alert. The `alerts` table records every send for audit.

### 6.3 Enrichment providers

All optional, all skip themselves if not configured.

```bash
# .env
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
ABUSECH_AUTH_KEY=...    # URLhaus + MalwareBazaar
```

KEV (CISA Known Exploited Vulnerabilities) and EPSS (FIRST.org) need no
key — they're enabled by default.

```bash
dwa enrich              # one-shot pass over un-enriched entities
```

### 6.4 LLM analyst summaries

```bash
# .env
ANTHROPIC_API_KEY=sk-ant-...
LLM_MODEL=claude-opus-4-7
```

```bash
dwa summarize           # generate summaries for un-summarized documents
```

Summaries appear in the dashboard on each document / case.

---

## 7. Daily and weekly habits

Once it's running, this is the workflow:

**Daily (5 min):**
- Glance at **Overview** for new matches.
- Triage any **high/critical** matches — promote real ones to cases,
  mark false positives.

**Weekly (15 min):**
- **Discovery** page → review new pending onion candidates → approve or
  reject.
- **Sources** page → look for sources stuck in backoff (red status). Either
  fix the URL, disable, or remove.
- Generate a weekly report: `dwa report generate weekly_watchlist`.

**As needed:**
- Add new watchlist entries when you have new things to monitor (new
  hashes from an IR engagement, new actor handles from threat reports,
  new domains your org owns).
- Add new sources when you encounter a relevant feed.
- Export cases as markdown for archival or hand-off.

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'bs4'` | Ran `python -m app.main` against system Python instead of the venv. | Use `dwa <cmd>` on Windows or activate the venv first. |
| Dashboard pages all crash with `SQLite objects created in a thread can only be used in that same thread` | You're on v0.1.0. | Upgrade to v0.1.1+. |
| `[network-check] FAILED: egress-lookup-failed` | No internet or VPN tunnel down. | Bring WG up; if it's already up, your kill switch is blocking outbound (intended — fix VPN, retry). |
| `STRICT_EGRESS preflight failed` at scheduler start | Egress IP isn't in your allowlist. | Either VPN dropped (fix it) or your allowlist is wrong (check `dwa network-check` output for the actual IP). |
| `tor-check` says `traffic is NOT routed through Tor` | SOCKS proxy isn't running or wrong host/port. | `systemctl status tor` or `docker compose ps`. Verify `TOR_SOCKS_HOST` and `TOR_SOCKS_PORT`. |
| `dwa discover run` says "no enabled directories" | You haven't opted in to any aggregator. | Edit `onion_directories.yaml`, flip `enabled: true` on the ones you trust. |
| Dashboard shows no matches even after collect | Watchlist matchers are case-sensitive on email/handle/wallet types. | Check that the value in `watchlist.yaml` matches the casing in the source. |
| Telegram alerts not arriving | Bot doesn't have your chat ID yet. | Message the bot first; then re-run `alert-test`. |

---

## 9. Where things live

| What | Path (dev / Linux) | Path (Windows installer) |
|---|---|---|
| Config files | repo root | `%LOCALAPPDATA%\Programs\DarkWebAssess\` |
| Database | `data/threatintel.db` | `%APPDATA%\DarkWebAssess\threatintel.db` |
| Logs | stdout | console / scheduler service stdout |
| Backups | `data/backups/` | `%APPDATA%\DarkWebAssess\backups\` |

Online DB backup:

```bash
dwa backup                              # writes to data/backups/
dwa restore data/backups/<file>.db      # flushes WAL, swaps in
```

---

## Where to go next

- **[OPSEC.md](OPSEC.md)** — VPN + kill switch + `STRICT_EGRESS`
- **[crates/dwa_extractors/README.md](../crates/dwa_extractors/README.md)**
  — Rust extraction accelerator (~25× faster, optional)
- **[CHANGELOG.md](../CHANGELOG.md)** — what changed in each release
- **`dwa --help`** — full CLI reference, every subcommand
