import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# DWA_DATA_DIR (set by the Windows installer to %APPDATA%\DarkWebAssess)
# overrides the in-repo data/ directory. Falls back to ROOT/data for dev /
# portable use.
_DWA_DATA_DIR_OVERRIDE = os.getenv("DWA_DATA_DIR")
if _DWA_DATA_DIR_OVERRIDE:
    DATA_DIR = Path(_DWA_DATA_DIR_OVERRIDE)
else:
    DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_PATH = os.getenv("DATABASE_PATH", str(DATA_DIR / "threatintel.db"))
SOURCES_PATH = os.getenv("SOURCES_PATH", str(ROOT / "sources.yaml"))
WATCHLIST_PATH = os.getenv("WATCHLIST_PATH", str(ROOT / "watchlist.yaml"))
ONION_DIRECTORIES_PATH = os.getenv(
    "ONION_DIRECTORIES_PATH", str(ROOT / "onion_directories.yaml")
)

USER_AGENT = os.getenv(
    "USER_AGENT",
    "mini-threat-intel/0.1 (+https://github.com/silvance/darkwebassess)",
)
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "20"))

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# --- Email / SMTP delivery (reports, digests). All optional; stdlib only. ---
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", "")
# Comma-separated recipient list.
SMTP_TO = os.getenv("SMTP_TO", "")
# STARTTLS on a plaintext port (default). Mutually exclusive with SSL.
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "1").lower() in ("1", "true", "yes", "on")
# Implicit TLS (SMTPS, usually port 465).
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "0").lower() in ("1", "true", "yes", "on")
SMTP_TIMEOUT = int(os.getenv("SMTP_TIMEOUT", "30"))

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
ALERT_MIN_SEVERITY = os.getenv("ALERT_MIN_SEVERITY", "high").lower()

# Enrichment provider API keys (all optional — providers self-skip if missing).
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSECH_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY", "")  # URLhaus / MalwareBazaar

# --- Self-monitoring "scrub" (personal exposure checks) ---------------------
# Have I Been Pwned breach API key (paid). When empty, the HIBP scrub
# provider self-skips. https://haveibeenpwned.com/API/Key
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
# Per-request timeout for scrub providers (seconds).
SCRUB_HTTP_TIMEOUT = int(os.getenv("SCRUB_HTTP_TIMEOUT", "15"))
# Polite delay between outbound requests within a scrub run (seconds, float).
# Keeps us courteous to the services we query on behalf of the operator.
SCRUB_REQUEST_DELAY = float(os.getenv("SCRUB_REQUEST_DELAY", "0.5"))
# Username enumeration (Sherlock-style). Site list ships bundled; override
# the path to extend it. 0 = check every bundled site.
SCRUB_USERNAME_SITES_PATH = os.getenv("SCRUB_USERNAME_SITES_PATH", "")
SCRUB_USERNAME_MAX_SITES = int(os.getenv("SCRUB_USERNAME_MAX_SITES", "0"))
# Browser-ish UA so simple existence checks aren't blocked outright.
SCRUB_USER_AGENT = os.getenv(
    "SCRUB_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
)

# Re-enrich an entity at most this often per provider.
ENRICHMENT_MAX_AGE_HOURS = int(os.getenv("ENRICHMENT_MAX_AGE_HOURS", "168"))

# Phase 6 scoring.
SUPPRESSION_PATH = os.getenv("SUPPRESSION_PATH", str(ROOT / "suppression.yaml"))
# Optional alternate gate for Telegram alerts. When set, alerts fire if the
# match score is at or above this value (in addition to the severity gate).
ALERT_MIN_SCORE = int(os.getenv("ALERT_MIN_SCORE", "0"))

# Phase 8 scheduler intervals.
COLLECT_INTERVAL_MINUTES = int(os.getenv("COLLECT_INTERVAL_MINUTES", "30"))
ENRICH_INTERVAL_MINUTES = int(os.getenv("ENRICH_INTERVAL_MINUTES", "15"))
ENRICH_BATCH_LIMIT = int(os.getenv("ENRICH_BATCH_LIMIT", "100"))
SOURCE_HEALTH_INTERVAL_HOURS = int(os.getenv("SOURCE_HEALTH_INTERVAL_HOURS", "12"))
# Per-source backoff: sleep base 5 minutes, doubled per consecutive failure
# (capped at 2^6 * 5 = 320 minutes ~= 5h20m).
SOURCE_BACKOFF_BASE_MINUTES = int(os.getenv("SOURCE_BACKOFF_BASE_MINUTES", "5"))
SOURCE_BACKOFF_MAX_EXPONENT = int(os.getenv("SOURCE_BACKOFF_MAX_EXPONENT", "6"))

# Phase 11 LLM summaries.
LLM_MODEL = os.getenv("LLM_MODEL", "claude-opus-4-7")
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "2048"))
LLM_DOC_TEXT_CHARS = int(os.getenv("LLM_DOC_TEXT_CHARS", "12000"))

# Phase 13 reporting.
DAILY_REPORT_INTERVAL_HOURS = int(os.getenv("DAILY_REPORT_INTERVAL_HOURS", "0"))

# Phase 1 — Tor / onion collection.
TOR_SOCKS_HOST = os.getenv("TOR_SOCKS_HOST", "127.0.0.1")
TOR_SOCKS_PORT = int(os.getenv("TOR_SOCKS_PORT", "9050"))
ONION_REQUEST_TIMEOUT = int(os.getenv("ONION_REQUEST_TIMEOUT", "60"))
# Onion sites should not see the same UA as our clearweb fetcher; default to a
# generic browser-ish string. Operators can override.
ONION_USER_AGENT = os.getenv(
    "ONION_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
)

# Phase 14 hardening: auth defaults to OFF for backwards compatibility.
# Flip AUTH_ENABLED=1 in production (Docker compose sets this for you).
AUTH_ENABLED = os.getenv("AUTH_ENABLED", "0").lower() in ("1", "true", "yes", "on")
AUTH_ROLES = ("viewer", "analyst", "admin")
AUTH_MIN_PASSWORD_LEN = int(os.getenv("AUTH_MIN_PASSWORD_LEN", "8"))
# After AUTH_LOCKOUT_THRESHOLD consecutive failed logins, an account is
# temporarily locked for AUTH_LOCKOUT_MINUTES from the last failure.
AUTH_LOCKOUT_THRESHOLD = int(os.getenv("AUTH_LOCKOUT_THRESHOLD", "10"))
AUTH_LOCKOUT_MINUTES = int(os.getenv("AUTH_LOCKOUT_MINUTES", "15"))
