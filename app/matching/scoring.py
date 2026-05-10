"""Rule-based prioritization for matches.

Combines watchlist severity, match specificity, document recency, enrichment
verdicts, multi-source corroboration, and false-positive feedback into a
single 0-100 score with a list of reason strings. Severity is re-derived from
the score so downstream alerting/UI naturally pick up the priority.
"""
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from app.matching.suppression import suppression_reason
from app.normalizer import utcnow_iso

# Watchlist severity → starting score.
SEVERITY_BASE = {"low": 10, "medium": 30, "high": 55, "critical": 75}

# Score band → label.
SCORE_BANDS = (
    (76, "critical"),
    (51, "high"),
    (26, "medium"),
    (0, "low"),
)

# Source-name substring → reliability boost.
SOURCE_RELIABILITY = (
    ("CISA", 5),
    ("Krebs", 5),
    ("BleepingComputer", 3),
    ("SANS", 4),
    ("Hacker News", 2),
)


@dataclass
class ScoreResult:
    score: int
    severity: str
    reasons: List[str]


def score_to_severity(score: int) -> str:
    for floor, label in SCORE_BANDS:
        if score >= floor:
            return label
    return "low"


# ---- helpers --------------------------------------------------------------
def _doc_age_days(doc_row) -> Optional[float]:
    for key in ("published_at", "retrieved_at"):
        ts = doc_row[key] if key in doc_row.keys() else None
        if not ts:
            continue
        try:
            dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            continue
        return max(0.0, (datetime.now(timezone.utc) - dt).total_seconds() / 86400)
    return None


def _enrichment(conn: sqlite3.Connection, etype: str, value: str, provider: str) -> Optional[dict]:
    row = conn.execute(
        """
        SELECT result_json, success FROM enrichments
        WHERE entity_type = ? AND entity_value = ? AND provider = ? AND success = 1
        """,
        (etype, value, provider),
    ).fetchone()
    if not row or not row["result_json"]:
        return None
    try:
        return json.loads(row["result_json"])
    except (TypeError, ValueError):
        return None


def _cooccurring_types(conn: sqlite3.Connection, document_id: int) -> Dict[str, int]:
    rows = conn.execute(
        "SELECT entity_type, COUNT(*) AS n FROM entities WHERE document_id = ? GROUP BY entity_type",
        (document_id,),
    ).fetchall()
    return {r["entity_type"]: r["n"] for r in rows}


def _distinct_source_count(conn: sqlite3.Connection, matched_value: str) -> int:
    row = conn.execute(
        """
        SELECT COUNT(DISTINCT d.source_name) AS n
        FROM matches m
        JOIN documents d ON d.id = m.document_id
        WHERE m.matched_value = ?
        """,
        (matched_value,),
    ).fetchone()
    return int(row["n"] or 0)


def _fp_count_for_value(conn: sqlite3.Connection, matched_value: str, exclude_id: Optional[int]) -> int:
    sql = (
        "SELECT COUNT(*) AS n FROM matches WHERE matched_value = ? "
        "AND status = 'false_positive'"
    )
    params: list = [matched_value]
    if exclude_id is not None:
        sql += " AND id != ?"
        params.append(exclude_id)
    return int(conn.execute(sql, tuple(params)).fetchone()["n"] or 0)


def _source_reliability_boost(source_name: Optional[str]) -> int:
    if not source_name:
        return 0
    for needle, boost in SOURCE_RELIABILITY:
        if needle.lower() in source_name.lower():
            return boost
    return 0


# ---- scoring entry point --------------------------------------------------
def score_match(conn: sqlite3.Connection, match_row, doc_row) -> ScoreResult:
    """Compute a 0-100 priority score for a single match.

    `match_row` and `doc_row` should be sqlite3.Row-like objects.
    """
    reasons: List[str] = []
    base_severity = (match_row["severity"] or "medium").lower()
    score = SEVERITY_BASE.get(base_severity, 30)
    reasons.append(f"+{score} watchlist severity={base_severity}")

    # --- Match specificity
    mtype = (match_row["match_type"] or "").lower()
    matched_value = match_row["matched_value"]
    if mtype.startswith("exact_"):
        score += 15
        reasons.append("+15 exact match")
    elif mtype == "subdomain":
        score += 10
        reasons.append("+10 subdomain match")
    elif mtype == "keyword":
        score -= 5
        reasons.append("-5 keyword (less specific)")

    # --- Recency
    age = _doc_age_days(doc_row)
    if age is not None:
        if age < 1:
            score += 10
            reasons.append("+10 very recent (<24h)")
        elif age < 7:
            score += 5
            reasons.append("+5 recent (<7d)")
        elif age > 90:
            score -= 10
            reasons.append("-10 old (>90d)")

    # --- Source reliability
    src_boost = _source_reliability_boost(doc_row["source_name"] if "source_name" in doc_row.keys() else None)
    if src_boost:
        score += src_boost
        reasons.append(f"+{src_boost} high-reliability source")

    # --- CVE enrichment
    if mtype == "exact_cve":
        kev = _enrichment(conn, "cve", matched_value, "cisa_kev")
        if kev and kev.get("in_kev"):
            score += 20
            reasons.append("+20 CVE in CISA KEV")
            if (kev.get("known_ransomware_use") or "").lower() == "known":
                score += 5
                reasons.append("+5 known ransomware exploitation")
        epss = _enrichment(conn, "cve", matched_value, "epss")
        if epss:
            ev = epss.get("epss")
            if isinstance(ev, (int, float)):
                if ev >= 0.7:
                    score += 15
                    reasons.append(f"+15 EPSS={ev:.2f}")
                elif ev >= 0.5:
                    score += 10
                    reasons.append(f"+10 EPSS={ev:.2f}")
                elif ev >= 0.2:
                    score += 5
                    reasons.append(f"+5 EPSS={ev:.2f}")

    # --- IP enrichment
    if mtype == "exact_ip":
        abuse = _enrichment(conn, "ip", matched_value, "abuseipdb")
        if abuse:
            conf = abuse.get("abuse_confidence", 0) or 0
            if conf >= 75:
                score += 15
                reasons.append(f"+15 AbuseIPDB confidence={conf}")
            elif conf >= 25:
                score += 5
                reasons.append(f"+5 AbuseIPDB confidence={conf}")

    # --- Domain / URL / hash enrichment via URLhaus + VT
    type_for_enrichment = {
        "exact_domain": "domain",
        "subdomain": "domain",
        "exact_url": "url",
        "exact_md5": "md5",
        "exact_sha1": "sha1",
        "exact_sha256": "sha256",
    }.get(mtype)
    if type_for_enrichment:
        urlhaus = _enrichment(conn, type_for_enrichment, matched_value, "urlhaus")
        if urlhaus and urlhaus.get("verdict") == "malicious":
            score += 15
            reasons.append("+15 URLhaus: malicious")
        vt = _enrichment(conn, type_for_enrichment, matched_value, "virustotal")
        if vt:
            mal = vt.get("malicious", 0) or 0
            if mal >= 5:
                score += 20
                reasons.append(f"+20 VT: malicious={mal}")
            elif mal >= 1:
                score += 10
                reasons.append(f"+10 VT: malicious={mal}")

    # --- Co-occurrence boosts in the same document
    co = _cooccurring_types(conn, match_row["document_id"])
    has_hash = any(co.get(t, 0) for t in ("md5", "sha1", "sha256"))
    has_cve = co.get("cve", 0) > 0
    has_leak_indicator = co.get("leak_status", 0) > 0
    if has_hash and mtype not in ("exact_md5", "exact_sha1", "exact_sha256"):
        score += 5
        reasons.append("+5 file hash also present")
    if has_cve and mtype != "exact_cve":
        score += 5
        reasons.append("+5 CVE also referenced")
    if has_leak_indicator:
        # Leak-context pages (e.g. ransomware leak landings) make any
        # match more interesting. Stronger signal than a co-occurring CVE
        # because leak_status is filtered to multi-word phrases that
        # don't fire on news prose.
        score += 10
        reasons.append("+10 leak-site indicators present")

    # --- Multi-source corroboration
    sources = _distinct_source_count(conn, matched_value)
    if sources >= 3:
        score += 10
        reasons.append(f"+10 mentioned by {sources} sources")
    elif sources == 2:
        score += 5
        reasons.append("+5 mentioned by 2 sources")

    # --- False-positive feedback penalty
    fp = _fp_count_for_value(conn, matched_value, exclude_id=match_row["id"] if "id" in match_row.keys() else None)
    if fp > 0:
        delta = min(fp * 10, 30)
        score -= delta
        reasons.append(f"-{delta} prior false-positive marks ({fp})")

    # --- Suppression
    src_name = doc_row["source_name"] if "source_name" in doc_row.keys() else None
    sup = suppression_reason(mtype, matched_value, src_name)
    if sup:
        score = min(score, 5)
        reasons.append(f"suppressed: {sup}")

    score = max(0, min(100, score))
    return ScoreResult(score=score, severity=score_to_severity(score), reasons=reasons)


def update_match_score(
    conn: sqlite3.Connection, match_id: int, score: int, severity: str, reasons: List[str]
) -> None:
    """Persist the score, severity, and reasons back onto a match row."""
    conn.execute(
        """
        UPDATE matches
        SET score = ?,
            score_reasons = ?,
            score_updated_at = ?,
            severity = ?
        WHERE id = ?
        """,
        (int(score), json.dumps(reasons), utcnow_iso(), severity, int(match_id)),
    )


def score_and_persist(
    conn: sqlite3.Connection, match_id: int
) -> Optional[Tuple[ScoreResult, dict]]:
    """Look up a match + its document, score it, persist, and return (result, doc)."""
    row = conn.execute(
        """
        SELECT m.id, m.document_id, m.watchlist_id, m.matched_value, m.match_type,
               m.severity, m.status, m.context,
               d.source_name, d.title, d.source_url, d.published_at, d.retrieved_at
        FROM matches m
        JOIN documents d ON d.id = m.document_id
        WHERE m.id = ?
        """,
        (int(match_id),),
    ).fetchone()
    if not row:
        return None
    result = score_match(conn, row, row)
    update_match_score(conn, row["id"], result.score, result.severity, result.reasons)
    return result, dict(row)
