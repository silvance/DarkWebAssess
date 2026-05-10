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
