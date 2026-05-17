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

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
ALERT_MIN_SEVERITY = os.getenv("ALERT_MIN_SEVERITY", "high").lower()

# Enrichment provider API keys (all optional — providers self-skip if missing).
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSECH_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY", "")  # URLhaus / MalwareBazaar

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
