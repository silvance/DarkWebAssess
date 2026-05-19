"""Type stubs for the native dwa_extractors module."""
from typing import TypedDict


class Observable(TypedDict):
    entity_type: str
    entity_value: str
    context: str


def extract_observables(text: str) -> list[Observable]:
    """Extract URLs, emails, IPv4/IPv6, MD5/SHA1/SHA256, and CVEs.

    Returns a list of dicts with the same shape as the existing Python
    extractors. De-duplicates on (entity_type, entity_value), keeping the
    first occurrence's context.

    Caller is expected to have already refanged the text (1.2.3[.]4 →
    1.2.3.4) — refanging stays in Python so the Rust crate has no
    string-manipulation hot path beyond regex.
    """
    ...


def version() -> str:
    """Return the crate version, e.g. '0.1.0'."""
    ...
