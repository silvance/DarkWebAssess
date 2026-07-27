"""Demo data seeding — populate the tool with realistic sample content so a
new operator can explore the dashboard *before* wiring up real sources.

Everything seeded here is fictional and self-contained (RFC-2606
`.example` domains, documentation-range IPs, obviously-fake hashes). It
runs through the exact same pipeline as real collection
(`process_document`), so the entities / matches / scores you see are
produced by the real extractors and scorer — not hand-faked rows.

Seed with:      dwa demo-seed
Remove with:    dwa demo-clear

Both are idempotent. Demo rows are tagged so `demo-clear` can remove them
without touching anything you added yourself:
  - the demo source is named exactly DEMO_SOURCE_NAME
  - demo watchlist entries carry DEMO_TAG in their description
"""
from __future__ import annotations

from typing import List

from app.normalizer import normalize_document
from app.pipeline import process_document
from app.repository import upsert_source, upsert_watchlist_entry

DEMO_SOURCE_NAME = "DEMO — Sample Threat Feed"
DEMO_TAG = "[demo]"


# --- Demo watchlist -----------------------------------------------------
# Fictional "your org" indicators. Descriptions carry DEMO_TAG so
# demo-clear can find them.
_DEMO_WATCHLIST: List[dict] = [
    {
        "type": "domain", "value": "acme-corp.example",
        "description": f"{DEMO_TAG} our primary corporate domain",
        "severity": "high", "enabled": True,
    },
    {
        "type": "email", "value": "jsmith@acme-corp.example",
        "description": f"{DEMO_TAG} CISO — alert on any mention",
        "severity": "high", "enabled": True,
    },
    {
        "type": "cve", "value": "CVE-2024-3400",
        "description": f"{DEMO_TAG} PAN-OS RCE on our perimeter firewall",
        "severity": "critical", "enabled": True,
    },
    {
        "type": "keyword", "value": "acme corp breach",
        "description": f"{DEMO_TAG} brand-monitoring keyword",
        "severity": "high", "enabled": True,
    },
]


# --- Demo documents -----------------------------------------------------
# Each doc's text is written to contain observables that (a) exercise the
# extractors and (b) match the demo watchlist above. Documentation-range
# IPs (192.0.2.0/24, 198.51.100.0/24) and .example domains keep the data
# unambiguously fake.
_DEMO_DOCS: List[dict] = [
    {
        "title": "Ransomware crew claims Acme Corp breach, threatens leak",
        "url": "https://demo.example/news/acme-corp-breach",
        "text": (
            "A ransomware group has claimed responsibility for an intrusion "
            "at Acme Corp (acme-corp.example). The actors say they exploited "
            "CVE-2024-3400 on an unpatched perimeter appliance and exfiltrated "
            "internal mailboxes, including messages from CISO jsmith@acme-corp.example. "
            "Analysts tracking the acme corp breach note a command-and-control "
            "host at 198.51.100.42 and a dropper with SHA256 "
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa. "
            "The group has posted a countdown on its leak site."
        ),
    },
    {
        "title": "PAN-OS CVE-2024-3400 exploited in the wild",
        "url": "https://demo.example/advisories/cve-2024-3400",
        "text": (
            "Widespread exploitation of CVE-2024-3400 continues. Defenders "
            "should patch immediately. Observed scanning from 192.0.2.10 and "
            "192.0.2.11. Indicators include a webshell hash MD5 "
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb and callbacks to evil.example."
        ),
    },
    {
        "title": "Leak listing: ACME CORP — DATA PUBLISHED",
        "url": "https://demo.example/leaks/acme-corp",
        "text": (
            "STATUS: DATA PUBLISHED. Victim: Acme Corp (acme-corp.example). "
            "Size: 240 GB. DEADLINE: passed. Contact the operators for the "
            "full dump. Sample credentials include jsmith@acme-corp.example."
        ),
    },
    {
        "title": "Weekly threat roundup: nothing to see here",
        "url": "https://demo.example/news/weekly-roundup",
        "text": (
            "A quiet week in threat intelligence. Some routine phishing "
            "targeting retail, a few new CVEs in embedded devices, and "
            "continued cleanup from last month's incidents. No indicators "
            "relevant to your watchlist appear in this document."
        ),
    },
]


def seed_demo(conn) -> dict:
    """Seed demo source + watchlist + documents. Idempotent.

    Returns a stats dict: {watchlist, documents_new, documents_dup,
    entities, matches}.
    """
    stats = {"watchlist": 0, "documents_new": 0, "documents_dup": 0,
             "entities": 0, "matches": 0}

    # 1. Demo source (so the Sources page shows where the docs came from).
    upsert_source(conn, {
        "name": DEMO_SOURCE_NAME,
        "type": "rss",
        "url": "https://demo.example/feed",
        "enabled": False,  # disabled so a real `collect` never fetches it
    })

    # 2. Demo watchlist entries.
    for entry in _DEMO_WATCHLIST:
        upsert_watchlist_entry(conn, entry)
        stats["watchlist"] += 1

    # 3. Demo documents through the real pipeline.
    for d in _DEMO_DOCS:
        doc = normalize_document(
            source_name=DEMO_SOURCE_NAME,
            source_type="rss",
            source_url=d["url"],
            title=d["title"],
            raw_text=d["text"],
        )
        result = process_document(conn, doc)
        stats["documents_new"] += result.get("new", 0)
        stats["documents_dup"] += result.get("duplicate", 0)
        stats["entities"] += result.get("entities", 0)
        stats["matches"] += result.get("matches", 0)

    conn.commit()
    return stats


def clear_demo(conn) -> dict:
    """Remove everything seed_demo added. Idempotent.

    Deletes by the demo markers only — never touches operator-added rows.
    Matches/entities cascade via the documents FK (ON DELETE CASCADE),
    but we delete matches/entities explicitly too in case cascade is off.
    """
    stats = {"documents": 0, "watchlist": 0}

    # Document ids from the demo source.
    doc_ids = [r[0] for r in conn.execute(
        "SELECT id FROM documents WHERE source_name = ?", (DEMO_SOURCE_NAME,)
    ).fetchall()]
    if doc_ids:
        placeholders = ",".join("?" * len(doc_ids))
        # Delete dependent rows first (defensive; FK cascade may handle it).
        conn.execute(f"DELETE FROM matches WHERE document_id IN ({placeholders})", doc_ids)
        conn.execute(f"DELETE FROM entities WHERE document_id IN ({placeholders})", doc_ids)
        cur = conn.execute(
            f"DELETE FROM documents WHERE id IN ({placeholders})", doc_ids
        )
        stats["documents"] = cur.rowcount

    # Demo watchlist rows (tagged in description).
    cur = conn.execute(
        "DELETE FROM watchlist WHERE description LIKE ?", (f"%{DEMO_TAG}%",)
    )
    stats["watchlist"] = cur.rowcount

    # Demo source.
    conn.execute("DELETE FROM sources WHERE name = ?", (DEMO_SOURCE_NAME,))

    conn.commit()
    return stats
