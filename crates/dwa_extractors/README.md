# dwa_extractors

Fast regex-based observable extractors for DarkWebAssess, as a Python
extension module written in Rust.

This crate is an opt-in speedup for the existing Python regex extractors
in `app/extractors/entities.py`. If you don't install it, the project
falls back to pure Python and keeps working — the Rust wheel is purely
a performance accelerator.

## What it covers

`extract_observables(text)` extracts:

- URL (`http://`, `https://`)
- email
- IPv4 (with octet validation + unspecified-IP rejection)
- IPv6 (with `Ipv6Addr::from_str` validation)
- MD5, SHA1, SHA256 (with overlap suppression — a SHA256 hit doesn't
  double-emit as MD5+SHA1+SHA256, and a SHA1 immediately preceded by
  `0x` is treated as an Ethereum address and skipped)
- CVE (`CVE-YYYY-NNNN+`)

Domain, onion, wallet, handle, named-entity, and leak-listing extraction
stay in Python — they require auxiliary data (TLD lists, named-entity
YAML) that doesn't belong in the hot path.

## Returned shape

```python
[
    {"entity_type": "email", "entity_value": "alice@example.com", "context": "..."},
    {"entity_type": "ip",    "entity_value": "1.2.3.4",            "context": "..."},
    ...
]
```

De-duplicated on `(entity_type, entity_value)`. The `context` field is
the ±80-character window around the match, with whitespace collapsed.

## Build (local dev)

```bash
pip install maturin
cd crates/dwa_extractors
maturin develop --release
```

`maturin develop` builds the crate and installs it into your current
virtualenv. After that, `import dwa_extractors` works from any Python
inside the venv.

## Build (wheels)

```bash
maturin build --release --strip
# Wheels land in target/wheels/
```

CI builds wheels for Linux / macOS / Windows on every release tag via
`.github/workflows/build-wheels.yml`.

## Bench

```bash
pytest tests/test_extractor_bench.py -q
# Compares Rust vs. Python on a synthetic 100 KB corpus; asserts identical
# output and Rust speedup.
```
