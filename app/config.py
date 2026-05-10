import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)

DATABASE_PATH = os.getenv("DATABASE_PATH", str(DATA_DIR / "threatintel.db"))
SOURCES_PATH = os.getenv("SOURCES_PATH", str(ROOT / "sources.yaml"))
WATCHLIST_PATH = os.getenv("WATCHLIST_PATH", str(ROOT / "watchlist.yaml"))

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
