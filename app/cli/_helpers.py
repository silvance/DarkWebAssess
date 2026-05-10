"""Helpers shared across CLI command modules."""
import getpass
import sys
from typing import Optional

from app.config import AUTH_MIN_PASSWORD_LEN, SOURCES_PATH, WATCHLIST_PATH


def prompt_password(arg_value: Optional[str]) -> str:
    """Return the password from `--password` or interactively prompt.

    Library-side validation in `app.auth.passwords.assert_strong_password`
    is the source of truth for length; this helper duplicates the rule
    only so the user gets the prompt-time feedback before we hash."""
    if arg_value:
        return arg_value
    p1 = getpass.getpass("Password: ")
    p2 = getpass.getpass("Confirm:  ")
    if p1 != p2:
        print("Passwords do not match.")
        sys.exit(1)
    if len(p1) < AUTH_MIN_PASSWORD_LEN:
        print(f"Password must be at least {AUTH_MIN_PASSWORD_LEN} characters.")
        sys.exit(1)
    return p1


def load_sources_validated() -> list:
    from app.config_models import load_sources

    cfg = load_sources(SOURCES_PATH)
    return [s.model_dump() for s in cfg.sources]


def load_watchlist_validated() -> list:
    from app.config_models import load_watchlist

    cfg = load_watchlist(WATCHLIST_PATH)
    return [w.model_dump() for w in cfg.watchlist]
