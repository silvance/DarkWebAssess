"""MISP event JSON export (native — no external library).

Emits a single MISP Event with one Attribute per mappable indicator.
MISP attribute type mapping:
  domain->domain, onion->domain, ipv4/ipv6->ip-dst, url->url,
  email->email-src, md5/sha1/sha256->respective, cve->vulnerability,
  wallet->btc (best-effort), handle->github-username? (no) -> skipped.
Unmappable types are skipped and counted.

The event JSON is importable via MISP's "Import from... MISP JSON".
"""
from __future__ import annotations

from typing import List, Tuple

from app.export.query import Indicator
from app.normalizer import utcnow_iso

# itype -> (misp_type, misp_category)
_ATTR_MAP = {
    "domain": ("domain", "Network activity"),
    "onion": ("domain", "Network activity"),
    "ipv4": ("ip-dst", "Network activity"),
    "ipv6": ("ip-dst", "Network activity"),
    "url": ("url", "Network activity"),
    "email": ("email-src", "Payload delivery"),
    "md5": ("md5", "Payload delivery"),
    "sha1": ("sha1", "Payload delivery"),
    "sha256": ("sha256", "Payload delivery"),
    "cve": ("vulnerability", "External analysis"),
}

# MISP threat level: 1 high, 2 medium, 3 low, 4 undefined.
_THREAT_LEVEL = {"critical": "1", "high": "1", "medium": "2", "low": "3"}


def build_event(indicators: List[Indicator], *, info: str = "") -> Tuple[dict, int]:
    now = utcnow_iso()
    date = now[:10]
    attributes = []
    skipped = 0
    worst = "low"
    order = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    for ind in indicators:
        mapping = _ATTR_MAP.get(ind.itype)
        if not mapping:
            skipped += 1
            continue
        misp_type, category = mapping
        if order.get(ind.severity, 1) > order.get(worst, 1):
            worst = ind.severity
        comment_bits = []
        if ind.source_name:
            comment_bits.append(f"source={ind.source_name}")
        if ind.score is not None:
            comment_bits.append(f"score={ind.score}")
        attributes.append({
            "type": misp_type,
            "category": category,
            "value": ind.value,
            "to_ids": ind.itype not in ("cve",),
            "comment": "; ".join(comment_bits),
            "timestamp": ind.first_seen or now,
        })

    event = {
        "Event": {
            "info": info or f"DarkWebAssess export ({len(attributes)} indicators)",
            "date": date,
            "threat_level_id": _THREAT_LEVEL.get(worst, "3"),
            "analysis": "1",
            "distribution": "0",
            "Attribute": attributes,
        }
    }
    return event, skipped


def render_misp(indicators: List[Indicator], *, info: str = "") -> str:
    import json
    event, _skipped = build_event(indicators, info=info)
    return json.dumps(event, indent=2)
