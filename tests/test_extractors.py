from app.extractors.entities import (
    extract_all,
    extract_cves,
    extract_domains,
    extract_emails,
    extract_hashes,
    extract_ipv4,
    extract_urls,
    refang,
)


def values(entities, etype):
    return sorted(e["entity_value"] for e in entities if e["entity_type"] == etype)


def test_refang_dots_and_protocol():
    s = "Visit hxxps://evil[.]example[.]com or email user[at]bad[.]org"
    out = refang(s)
    assert "https://evil.example.com" in out
    assert "user@bad.org" in out


def test_extract_urls():
    text = "See https://example.com/path?x=1, also http://foo.test/."
    urls = [e["entity_value"] for e in extract_urls(text)]
    assert "https://example.com/path?x=1" in urls
    assert "http://foo.test/" in urls or "http://foo.test" in urls


def test_extract_emails_lowercased():
    text = "contact Alice@Example.COM for details"
    emails = [e["entity_value"] for e in extract_emails(text)]
    assert "alice@example.com" in emails


def test_extract_ipv4_filters_invalid():
    text = "valid 192.0.2.1 invalid 999.999.999.999 and 10.0.0.1"
    ips = [e["entity_value"] for e in extract_ipv4(text)]
    assert "192.0.2.1" in ips
    assert "10.0.0.1" in ips
    assert "999.999.999.999" not in ips


def test_extract_domains_skips_file_extensions():
    text = "see report.pdf and the site evil.example.com for malware.exe"
    domains = [e["entity_value"] for e in extract_domains(text)]
    assert "evil.example.com" in domains
    assert "report.pdf" not in domains
    assert "malware.exe" not in domains


def test_extract_hashes_no_overlap():
    sha256 = "a" * 64
    md5 = "b" * 32
    sha1 = "c" * 40
    text = f"hashes: {sha256} {md5} {sha1}"
    hashes = extract_hashes(text)
    by_type = {h["entity_type"]: h["entity_value"] for h in hashes}
    assert by_type.get("sha256") == sha256
    assert by_type.get("md5") == md5
    assert by_type.get("sha1") == sha1


def test_extract_cves_uppercased():
    text = "Affected: cve-2024-3400 and CVE-2023-1234"
    cves = [e["entity_value"] for e in extract_cves(text)]
    assert "CVE-2024-3400" in cves
    assert "CVE-2023-1234" in cves


def test_extract_all_dedupes():
    text = "example.com example.com https://example.com/x"
    ents = extract_all(text)
    keys = [(e["entity_type"], e["entity_value"]) for e in ents]
    assert len(keys) == len(set(keys))


def test_extract_all_handles_empty():
    assert extract_all("") == []
    assert extract_all(None) == []


def test_extract_with_defang():
    text = "C2 at evil[.]example[.]com hosted on 1.2.3[.]4"
    ents = extract_all(text)
    domains = values(ents, "domain")
    ips = values(ents, "ip")
    assert "evil.example.com" in domains
    assert "1.2.3.4" in ips
