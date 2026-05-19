//! Fast observable extractors as a PyO3 extension module.
//!
//! Public surface (Python):
//!
//!     extract_observables(text: str) -> list[dict]
//!     version() -> str
//!
//! The returned dict shape matches what the existing Python extractors
//! produce: `{entity_type, entity_value, context}`. De-duplicated on
//! `(entity_type, entity_value)`, keeping the first context.
//!
//! Coverage: URL, email, IPv4 (with octet validation), IPv6 (with parse
//! validation), MD5, SHA1, SHA256 (with overlap suppression and
//! 0x-prefix rejection), CVE. Domain / onion / wallet / handle /
//! named-entity / leak-listing extraction stays in Python.

use once_cell::sync::Lazy;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use regex::Regex;
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::str::FromStr;

// --- Compiled regexes (one-time init) -----------------------------------

static URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\bhttps?://[^\s<>"'`]+"#).unwrap()
});

static EMAIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").unwrap()
});

static IPV4_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b",
    )
    .unwrap()
});

static IPV6_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b").unwrap()
});

static MD5_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[a-fA-F0-9]{32}\b").unwrap());
static SHA1_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[a-fA-F0-9]{40}\b").unwrap());
static SHA256_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[a-fA-F0-9]{64}\b").unwrap());

static CVE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bCVE-\d{4}-\d{4,7}\b").unwrap());

static WS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+").unwrap());

const CONTEXT_WINDOW: usize = 80;
const URL_TRAILING_PUNCT: &[char] = &['.', ',', ')', ';', ':', '\'', '"'];

// --- Internal types -----------------------------------------------------

/// One extracted observable.
struct Observable<'a> {
    entity_type: &'static str,
    entity_value: String,
    text: &'a str,
    start: usize,
    end: usize,
}

// --- Context window -----------------------------------------------------

/// Return the ±80-byte window around the match, with whitespace collapsed.
///
/// We're careful to clamp to UTF-8 char boundaries so we never split a
/// multi-byte character mid-sequence (which would panic on slicing).
fn context_window(text: &str, start: usize, end: usize) -> String {
    let lo = start.saturating_sub(CONTEXT_WINDOW);
    let hi = (end + CONTEXT_WINDOW).min(text.len());
    let lo = clamp_to_char_boundary(text, lo, false);
    let hi = clamp_to_char_boundary(text, hi, true);
    let snippet = &text[lo..hi];
    let trimmed = snippet.trim();
    WS_RE.replace_all(trimmed, " ").into_owned()
}

/// If `idx` is in the middle of a UTF-8 multi-byte char, walk to the
/// nearest boundary. `prefer_higher=true` walks forward; otherwise back.
fn clamp_to_char_boundary(text: &str, mut idx: usize, prefer_higher: bool) -> usize {
    let bytes = text.as_bytes();
    if idx >= bytes.len() {
        return bytes.len();
    }
    while idx > 0 && idx < bytes.len() && (bytes[idx] & 0b1100_0000) == 0b1000_0000 {
        if prefer_higher {
            idx += 1;
        } else {
            idx -= 1;
        }
    }
    idx
}

// --- Per-type extraction ------------------------------------------------

fn extract_urls<'a>(text: &'a str, out: &mut Vec<Observable<'a>>) {
    for m in URL_RE.find_iter(text) {
        let value = m.as_str().trim_end_matches(URL_TRAILING_PUNCT).to_string();
        if value.is_empty() {
            continue;
        }
        out.push(Observable {
            entity_type: "url",
            entity_value: value,
            text,
            start: m.start(),
            end: m.end(),
        });
    }
}

fn extract_emails<'a>(text: &'a str, out: &mut Vec<Observable<'a>>) {
    for m in EMAIL_RE.find_iter(text) {
        out.push(Observable {
            entity_type: "email",
            entity_value: m.as_str().to_ascii_lowercase(),
            text,
            start: m.start(),
            end: m.end(),
        });
    }
}

fn extract_ipv4<'a>(text: &'a str, out: &mut Vec<Observable<'a>>) {
    for m in IPV4_RE.find_iter(text) {
        // Reject 0.0.0.0 (unspecified). Octet bounds are already enforced
        // by the regex itself.
        if m.as_str() == "0.0.0.0" {
            continue;
        }
        out.push(Observable {
            entity_type: "ip",
            entity_value: m.as_str().to_string(),
            text,
            start: m.start(),
            end: m.end(),
        });
    }
}

fn extract_ipv6<'a>(text: &'a str, out: &mut Vec<Observable<'a>>) {
    for m in IPV6_RE.find_iter(text) {
        let raw = m.as_str();
        // Validate by parse — drops false positives like time strings,
        // sha-style hex runs with single colons, etc.
        let addr = match Ipv6Addr::from_str(raw) {
            Ok(addr) => addr,
            Err(_) => continue,
        };
        // Canonicalize (matches what ipaddress.IPv6Address(...) returns
        // when str()'d).
        out.push(Observable {
            entity_type: "ipv6",
            entity_value: addr.to_string(),
            text,
            start: m.start(),
            end: m.end(),
        });
    }
}

/// Extract MD5 / SHA1 / SHA256 in longest-first order, suppressing
/// overlaps. SHA1 matches immediately preceded by `0x` are treated as
/// Ethereum addresses and skipped.
fn extract_hashes<'a>(text: &'a str, out: &mut Vec<Observable<'a>>) {
    let mut consumed: Vec<(usize, usize)> = Vec::new();
    for (entity_type, re) in &[
        ("sha256", &*SHA256_RE),
        ("sha1", &*SHA1_RE),
        ("md5", &*MD5_RE),
    ] {
        for m in re.find_iter(text) {
            let (s, e) = (m.start(), m.end());
            if consumed.iter().any(|(cs, ce)| *cs <= s && s < *ce) {
                continue;
            }
            if *entity_type == "sha1" && s >= 2 {
                let prefix = &text[s - 2..s];
                if prefix.eq_ignore_ascii_case("0x") {
                    continue;
                }
            }
            consumed.push((s, e));
            out.push(Observable {
                entity_type,
                entity_value: m.as_str().to_ascii_lowercase(),
                text,
                start: s,
                end: e,
            });
        }
    }
}

fn extract_cves<'a>(text: &'a str, out: &mut Vec<Observable<'a>>) {
    for m in CVE_RE.find_iter(text) {
        out.push(Observable {
            entity_type: "cve",
            entity_value: m.as_str().to_ascii_uppercase(),
            text,
            start: m.start(),
            end: m.end(),
        });
    }
}

// --- Public entrypoint --------------------------------------------------

/// Materialize an `Observable` into a Python dict.
fn observable_to_dict<'py>(py: Python<'py>, obs: &Observable<'_>) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new_bound(py);
    d.set_item("entity_type", obs.entity_type)?;
    d.set_item("entity_value", &obs.entity_value)?;
    d.set_item("context", context_window(obs.text, obs.start, obs.end))?;
    Ok(d)
}

#[pyfunction]
fn extract_observables<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyList>> {
    let list = PyList::empty_bound(py);
    if text.is_empty() {
        return Ok(list);
    }
    let mut collected: Vec<Observable<'_>> = Vec::new();
    extract_urls(text, &mut collected);
    extract_emails(text, &mut collected);
    extract_ipv4(text, &mut collected);
    extract_ipv6(text, &mut collected);
    extract_hashes(text, &mut collected);
    extract_cves(text, &mut collected);

    let mut seen: HashSet<(&str, String)> = HashSet::new();
    for obs in &collected {
        let key = (obs.entity_type, obs.entity_value.clone());
        if !seen.insert(key) {
            continue;
        }
        list.append(observable_to_dict(py, obs)?)?;
    }
    Ok(list)
}

#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(extract_observables, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}

// --- Pure-Rust unit tests (cargo test) ----------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn types_and_values(text: &str) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        extract_urls(text, &mut out);
        extract_emails(text, &mut out);
        extract_ipv4(text, &mut out);
        extract_ipv6(text, &mut out);
        extract_hashes(text, &mut out);
        extract_cves(text, &mut out);
        out.into_iter()
            .map(|o| (o.entity_type, o.entity_value))
            .collect()
    }

    #[test]
    fn url_strips_trailing_punctuation() {
        let r = types_and_values("see https://example.com/path).");
        assert!(r.contains(&("url", "https://example.com/path".to_string())));
    }

    #[test]
    fn email_lowercased() {
        let r = types_and_values("Mail to Alice@Example.COM.");
        assert!(r.contains(&("email", "alice@example.com".to_string())));
    }

    #[test]
    fn ipv4_rejects_unspecified() {
        let r = types_and_values("default route 0.0.0.0 and gateway 10.1.2.3");
        assert!(r.contains(&("ip", "10.1.2.3".to_string())));
        assert!(!r.contains(&("ip", "0.0.0.0".to_string())));
    }

    #[test]
    fn ipv4_rejects_out_of_range() {
        // 999.1.1.1 doesn't match the regex; verify nothing is extracted.
        let r = types_and_values("999.1.1.1");
        assert!(!r.iter().any(|(t, _)| *t == "ip"));
    }

    #[test]
    fn ipv6_canonicalizes() {
        let r = types_and_values("addr 2001:0db8:0000:0000:0000:0000:0000:0001 done");
        // Canonical form drops leading zeros and collapses long runs of 0.
        assert!(r.contains(&("ipv6", "2001:db8::1".to_string())));
    }

    #[test]
    fn sha256_suppresses_inner_sha1_and_md5() {
        let sha = "a".repeat(64);
        let r = types_and_values(&format!("hash {} end", sha));
        let count_sha1 = r.iter().filter(|(t, _)| *t == "sha1").count();
        let count_md5 = r.iter().filter(|(t, _)| *t == "md5").count();
        let count_sha256 = r.iter().filter(|(t, _)| *t == "sha256").count();
        assert_eq!(count_sha256, 1);
        assert_eq!(count_sha1, 0);
        assert_eq!(count_md5, 0);
    }

    #[test]
    fn sha1_skips_0x_prefix_ethereum_addresses() {
        // 40 hex preceded by 0x — should NOT be emitted as sha1.
        let addr = "f".repeat(40);
        let r = types_and_values(&format!("eth 0x{} done", addr));
        assert!(!r.iter().any(|(t, _)| *t == "sha1"));
    }

    #[test]
    fn cve_uppercased() {
        let r = types_and_values("see cve-2024-3400 advisory");
        assert!(r.contains(&("cve", "CVE-2024-3400".to_string())));
    }

    #[test]
    fn context_window_collapses_whitespace() {
        let text = "before   the   match\n\n  a@b.co  end";
        let mut out = Vec::new();
        extract_emails(text, &mut out);
        assert_eq!(out.len(), 1);
        let ctx = context_window(text, out[0].start, out[0].end);
        assert!(!ctx.contains("  "));
        assert!(!ctx.contains('\n'));
    }

    #[test]
    fn context_window_handles_utf8_boundaries() {
        // Multi-byte chars right at the window edge should not panic.
        let text = "café  a@b.co  ☕".repeat(20);
        let mut out = Vec::new();
        extract_emails(&text, &mut out);
        for obs in &out {
            // Just must not panic.
            let _ = context_window(&text, obs.start, obs.end);
        }
    }
}
