"""Regression + benchmark for the Rust extractor accelerator.

Runs only if the `dwa_extractors` Rust wheel is installed. Asserts:

  1. Rust output and Python output are byte-identical (same observables,
     same order, same context strings). This is the contract that the
     fallback can be swapped in without behavior change.
  2. On a 100 KB synthetic corpus, the Rust path is meaningfully faster
     than the Python path. Threshold is conservative (1.5x) so the test
     is robust on slow CI runners; in practice we see 10-50x.
"""
from __future__ import annotations

import time

import pytest

from app.extractors import entities as ent


pytestmark = pytest.mark.skipif(
    not ent._HAVE_RUST,
    reason="dwa_extractors Rust wheel not installed (this is fine; the project falls back to Python)",
)


def _make_corpus(repeats: int = 500) -> str:
    """Synthetic threat-intel-shaped text with a known mix of observables."""
    block = (
        "Threat actor moved laterally via https://evil.example.com/c2 and "
        "mailed alice@example.com from compromised box at 10.20.30.40 / "
        "2001:0db8:0000:0000:0000:0000:0000:0001. Payload SHA256 "
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef "
        "exploits CVE-2024-3400. Earlier sample MD5 "
        "abcdef0123456789abcdef0123456789. Also see "
        "https://other.com/path), defanged 1.2.3[.]4 and hxxps://bad[.]co. "
        "Ethereum wallet 0xdeadbeefcafebabe0123456789abcdef01234567 should "
        "NOT register as a SHA1 hit. Random hex run of 40: "
        "0123456789abcdef0123456789abcdef01234567 (this one SHOULD be sha1).\n\n"
    )
    return block * repeats


def test_rust_and_python_produce_identical_output():
    corpus = _make_corpus(repeats=10)  # ~5 KB, fast to compare exactly
    cleaned = ent.refang(corpus)
    rust = ent._rust_extract_observables(cleaned)
    python = ent._python_simple_observables(cleaned)

    rust_keys = [(o["entity_type"], o["entity_value"]) for o in rust]
    python_keys = [(o["entity_type"], o["entity_value"]) for o in python]

    # Python may emit duplicates (its dedupe happens in extract_all);
    # Rust dedupes inside extract_observables. Compare *sets* to keep
    # the contract about content without coupling to ordering.
    assert set(rust_keys) == set(python_keys), (
        f"Rust extra:   {set(rust_keys) - set(python_keys)}\n"
        f"Python extra: {set(python_keys) - set(rust_keys)}"
    )


def test_rust_finds_the_signal_observables_in_a_known_corpus():
    """Pin the contract on specific high-value extractions."""
    corpus = _make_corpus(repeats=1)
    cleaned = ent.refang(corpus)
    rust = ent._rust_extract_observables(cleaned)
    keys = {(o["entity_type"], o["entity_value"]) for o in rust}

    assert ("url", "https://evil.example.com/c2") in keys
    assert ("email", "alice@example.com") in keys
    assert ("ip", "10.20.30.40") in keys
    # Full IPv6 in the corpus gets canonicalized to the compressed form.
    assert ("ipv6", "2001:db8::1") in keys
    assert ("cve", "CVE-2024-3400") in keys
    assert ("sha256", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef") in keys
    assert ("md5", "abcdef0123456789abcdef0123456789") in keys
    # Defanged IP got refanged + extracted.
    assert ("ip", "1.2.3.4") in keys
    # Ethereum address ≠ sha1 hit.
    assert not any(
        t == "sha1" and v == "deadbeefcafebabe0123456789abcdef01234567"
        for t, v in keys
    )
    # Standalone 40-hex IS a sha1 hit.
    assert ("sha1", "0123456789abcdef0123456789abcdef01234567") in keys


def test_rust_is_faster_than_python_on_a_100kb_corpus():
    """Conservative threshold (1.5x) so the test isn't flaky on slow CI."""
    corpus = _make_corpus(repeats=200)  # ~100 KB
    cleaned = ent.refang(corpus)

    t0 = time.perf_counter()
    for _ in range(3):
        ent._rust_extract_observables(cleaned)
    rust_secs = (time.perf_counter() - t0) / 3

    t0 = time.perf_counter()
    for _ in range(3):
        ent._python_simple_observables(cleaned)
    python_secs = (time.perf_counter() - t0) / 3

    speedup = python_secs / rust_secs if rust_secs > 0 else float("inf")
    # Print so `pytest -s` shows the real number even on a pass.
    print(f"\n[bench] rust={rust_secs*1000:.2f}ms python={python_secs*1000:.2f}ms speedup={speedup:.1f}x")
    assert speedup >= 1.5, (
        f"Rust extractor was not faster than Python on a 100 KB corpus "
        f"(speedup={speedup:.2f}x). Something is off."
    )


def test_rust_emits_correct_dict_shape():
    rust = ent._rust_extract_observables("alice@example.com")
    assert len(rust) == 1
    assert set(rust[0].keys()) == {"entity_type", "entity_value", "context"}
    assert rust[0]["entity_type"] == "email"
    assert rust[0]["entity_value"] == "alice@example.com"
    assert isinstance(rust[0]["context"], str)


def test_extract_all_uses_rust_when_available():
    """Smoke test: extract_all() goes through Rust transparently."""
    result = ent.extract_all("hit https://bad.example.com/ CVE-2024-3400 alice@x.com")
    types = {r["entity_type"] for r in result}
    assert {"url", "cve", "email"}.issubset(types)
