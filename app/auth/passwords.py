"""Password hashing helpers (bcrypt) with library-level length enforcement."""
import bcrypt

from app.config import AUTH_MIN_PASSWORD_LEN


class WeakPasswordError(ValueError):
    """Raised when a password is too short for the configured policy."""


def assert_strong_password(plain: str) -> None:
    """Raise WeakPasswordError if `plain` is shorter than AUTH_MIN_PASSWORD_LEN.

    Lifted to the library layer so any caller — CLI, dashboard, or tests —
    enforces the same minimum, instead of depending on each entry point to
    do its own length check.
    """
    if not plain:
        raise WeakPasswordError("Password cannot be empty")
    if len(plain) < AUTH_MIN_PASSWORD_LEN:
        raise WeakPasswordError(
            f"Password must be at least {AUTH_MIN_PASSWORD_LEN} characters."
        )


def hash_password(plain: str) -> str:
    assert_strong_password(plain)
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    if not plain or not hashed:
        return False
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False
