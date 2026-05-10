"""Match extracted entities and document text against watchlist entries."""
import re
import sqlite3
from typing import Iterable, List, Optional

from app.extractors.entities import refang


def _norm_domain(value: str) -> str:
    return value.strip().lower().lstrip(".")


def _domain_matches(watch_value: str, candidate: str) -> bool:
    """Match exact domain or any subdomain of watch_value."""
    w = _norm_domain(watch_value)
    c = _norm_domain(candidate)
    return c == w or c.endswith("." + w)


def _keyword_in_text(keyword: str, text: str) -> Optional[re.Match]:
    if not keyword:
        return None
    pattern = re.compile(r"\b" + re.escape(keyword) + r"\b", re.IGNORECASE)
    return pattern.search(text)


def _context_around(text: str, start: int, end: int, window: int = 120) -> str:
    a = max(0, start - window)
    b = min(len(text), end + window)
    return re.sub(r"\s+", " ", text[a:b]).strip()


def load_watchlist(conn: sqlite3.Connection) -> List[sqlite3.Row]:
    return list(
        conn.execute(
            "SELECT id, type, value, description, severity, enabled FROM watchlist WHERE enabled = 1"
        ).fetchall()
    )


def match_document(
    conn: sqlite3.Connection,
    document_id: int,
    title: Optional[str],
    text: Optional[str],
    entities: Iterable[dict],
) -> List[dict]:
    """Return list of matches (not yet inserted) for the given document.

    A match dict contains: watchlist_id, matched_value, match_type, context,
    severity. The caller is responsible for persistence.
    """
    watchlist = load_watchlist(conn)
    if not watchlist:
        return []

    haystack = " ".join(filter(None, [title or "", text or ""]))
    haystack_refanged = refang(haystack)
    entities = list(entities)

    matches: List[dict] = []

    # Bucket entities by type for quick lookup.
    by_type: dict = {}
    for ent in entities:
        by_type.setdefault(ent["entity_type"], []).append(ent)

    for w in watchlist:
        wtype = w["type"].lower()
        wvalue = w["value"]
        severity = w["severity"]
        wid = w["id"]

        if wtype == "domain":
            for ent in by_type.get("domain", []):
                if _domain_matches(wvalue, ent["entity_value"]):
                    matches.append(
                        {
                            "watchlist_id": wid,
                            "matched_value": ent["entity_value"],
                            "match_type": "exact_domain"
                            if _norm_domain(ent["entity_value"]) == _norm_domain(wvalue)
                            else "subdomain",
                            "context": ent.get("context"),
                            "severity": severity,
                        }
                    )

        elif wtype == "email":
            target = wvalue.strip().lower()
            for ent in by_type.get("email", []):
                if ent["entity_value"].lower() == target:
                    matches.append(
                        {
                            "watchlist_id": wid,
                            "matched_value": ent["entity_value"],
                            "match_type": "exact_email",
                            "context": ent.get("context"),
                            "severity": severity,
                        }
                    )

        elif wtype == "ip":
            target = wvalue.strip()
            for ent in by_type.get("ip", []) + by_type.get("ipv6", []):
                if ent["entity_value"] == target:
                    matches.append(
                        {
                            "watchlist_id": wid,
                            "matched_value": ent["entity_value"],
                            "match_type": "exact_ip",
                            "context": ent.get("context"),
                            "severity": severity,
                        }
                    )

        elif wtype == "cve":
            target = wvalue.strip().upper()
            for ent in by_type.get("cve", []):
                if ent["entity_value"].upper() == target:
                    matches.append(
                        {
                            "watchlist_id": wid,
                            "matched_value": ent["entity_value"],
                            "match_type": "exact_cve",
                            "context": ent.get("context"),
                            "severity": severity,
                        }
                    )

        elif wtype == "hash":
            target = wvalue.strip().lower()
            for htype in ("md5", "sha1", "sha256"):
                for ent in by_type.get(htype, []):
                    if ent["entity_value"].lower() == target:
                        matches.append(
                            {
                                "watchlist_id": wid,
                                "matched_value": ent["entity_value"],
                                "match_type": f"exact_{htype}",
                                "context": ent.get("context"),
                                "severity": severity,
                            }
                        )

        elif wtype == "onion":
            target = wvalue.strip().lower()
            for ent in by_type.get("onion", []):
                if ent["entity_value"].lower() == target:
                    matches.append(
                        {
                            "watchlist_id": wid,
                            "matched_value": ent["entity_value"],
                            "match_type": "exact_onion",
                            "context": ent.get("context"),
                            "severity": severity,
                        }
                    )

        elif wtype == "wallet":
            target = wvalue.strip()
            target_l = target.lower()
            for wallet_kind in ("btc", "eth", "xmr"):
                for ent in by_type.get(wallet_kind, []):
                    val = ent["entity_value"]
                    # ETH and BTC bech32 are emitted lowercased; BTC base58
                    # and XMR keep original casing.
                    if val == target or val.lower() == target_l:
                        matches.append(
                            {
                                "watchlist_id": wid,
                                "matched_value": val,
                                "match_type": f"exact_{wallet_kind}",
                                "context": ent.get("context"),
                                "severity": severity,
                            }
                        )

        elif wtype == "handle":
            target = wvalue.strip()
            if not target.startswith("@"):
                target = "@" + target
            target = target.lower()
            for ent in by_type.get("handle", []):
                if ent["entity_value"].lower() == target:
                    matches.append(
                        {
                            "watchlist_id": wid,
                            "matched_value": ent["entity_value"],
                            "match_type": "exact_handle",
                            "context": ent.get("context"),
                            "severity": severity,
                        }
                    )

        elif wtype in ("malware", "actor"):
            target = wvalue.strip().lower()
            for ent in by_type.get(wtype, []):
                if ent["entity_value"].lower() == target:
                    matches.append(
                        {
                            "watchlist_id": wid,
                            "matched_value": ent["entity_value"],
                            "match_type": f"exact_{wtype}",
                            "context": ent.get("context"),
                            "severity": severity,
                        }
                    )

        elif wtype == "keyword":
            m = _keyword_in_text(wvalue, haystack_refanged)
            if m:
                matches.append(
                    {
                        "watchlist_id": wid,
                        "matched_value": wvalue,
                        "match_type": "keyword",
                        "context": _context_around(haystack_refanged, m.start(), m.end()),
                        "severity": severity,
                    }
                )

        else:
            # Unknown type — fall back to keyword search.
            m = _keyword_in_text(wvalue, haystack_refanged)
            if m:
                matches.append(
                    {
                        "watchlist_id": wid,
                        "matched_value": wvalue,
                        "match_type": "keyword",
                        "context": _context_around(haystack_refanged, m.start(), m.end()),
                        "severity": severity,
                    }
                )

    return matches
