"""STIX 2.1 bundle export (native — no external library).

Maps indicators to STIX 2.1 SDOs:
  - observable types (domain/ip/url/email/hash/onion) -> Indicator with a
    STIX pattern
  - cve      -> Vulnerability
  - malware  -> Malware
  - actor    -> Threat Actor
Types with no clean STIX mapping (keyword, handle, wallet) are skipped and
counted; the caller can surface the skipped count.

Object ids are deterministic (uuid5 of type+value) so re-exporting the
same indicator yields a stable id — friendly to downstream dedupe.
"""
from __future__ import annotations

import uuid
from typing import List, Tuple

from app.export.query import Indicator
from app.normalizer import utcnow_iso

# Stable namespace for deterministic ids (random-looking but fixed).
_NS = uuid.UUID("6b61a1de-6f2e-5f3a-9c2e-2b7c0c0a1d55")

# indicator itype -> (stix observable object type, pattern path)
_PATTERN_MAP = {
    "domain": ("domain-name", "domain-name:value"),
    "onion": ("domain-name", "domain-name:value"),
    "ipv4": ("ipv4-addr", "ipv4-addr:value"),
    "ipv6": ("ipv6-addr", "ipv6-addr:value"),
    "url": ("url", "url:value"),
    "email": ("email-addr", "email-addr:value"),
    "md5": ("file", "file:hashes.'MD5'"),
    "sha1": ("file", "file:hashes.'SHA-1'"),
    "sha256": ("file", "file:hashes.'SHA-256'"),
}

# STIX indicator severity is not standard; we carry it in labels + a custom
# property. Map our severity to a rough confidence.
_CONFIDENCE = {"low": 25, "medium": 50, "high": 75, "critical": 90}


def _det_id(prefix: str, itype: str, value: str) -> str:
    return f"{prefix}--{uuid.uuid5(_NS, f'{itype}:{value.lower()}')}"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def build_bundle(indicators: List[Indicator]) -> Tuple[dict, int]:
    """Return (stix_bundle_dict, skipped_count)."""
    now = utcnow_iso()
    objects = []
    skipped = 0

    for ind in indicators:
        itype = ind.itype
        common = {
            "spec_version": "2.1",
            "created": now,
            "modified": now,
        }
        if itype in _PATTERN_MAP:
            _obj_type, path = _PATTERN_MAP[itype]
            pattern = f"[{path} = '{_escape(ind.value)}']"
            obj = {
                "type": "indicator",
                "id": _det_id("indicator", itype, ind.value),
                **common,
                "name": f"{itype} {ind.value}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": ind.first_seen or now,
                "labels": ["malicious-activity", f"severity:{ind.severity}"],
                "confidence": _CONFIDENCE.get(ind.severity, 50),
            }
            objects.append(obj)
        elif itype == "cve":
            objects.append({
                "type": "vulnerability",
                "id": _det_id("vulnerability", itype, ind.value),
                **common,
                "name": ind.value.upper(),
                "external_references": [
                    {"source_name": "cve", "external_id": ind.value.upper()}
                ],
            })
        elif itype == "malware":
            objects.append({
                "type": "malware",
                "id": _det_id("malware", itype, ind.value),
                **common,
                "name": ind.value,
                "is_family": True,
            })
        elif itype == "actor":
            objects.append({
                "type": "threat-actor",
                "id": _det_id("threat-actor", itype, ind.value),
                **common,
                "name": ind.value,
            })
        else:
            skipped += 1

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
    return bundle, skipped


def render_stix(indicators: List[Indicator]) -> str:
    import json
    bundle, _skipped = build_bundle(indicators)
    return json.dumps(bundle, indent=2)
