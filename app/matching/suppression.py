"""Match suppression rules loaded from suppression.yaml.

Each rule has at minimum `type` (entity/match bucket) and `value` (the matched
value). Optional fields:

- `sources`: list of source names; rule only fires for matches whose document
  came from one of these sources. Omit to apply across all sources.
- `reason`: human-readable explanation, surfaced in score_reasons.
"""
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import yaml

from app.config import SUPPRESSION_PATH


@dataclass(frozen=True)
class SuppressionRule:
    type: str
    value: str
    sources: tuple
    reason: str

    def matches(self, match_type: str, matched_value: str, source_name: Optional[str]) -> bool:
        # `match_type` is "exact_domain" / "subdomain" / "keyword" / etc.;
        # `self.type` is the broad entity bucket like "domain" or "keyword".
        if self.type and not _match_type_in_bucket(match_type, self.type):
            return False
        if self.value.lower() != matched_value.lower():
            return False
        if self.sources and source_name not in self.sources:
            return False
        return True


def _match_type_in_bucket(match_type: str, bucket: str) -> bool:
    bucket = bucket.lower()
    mtype = match_type.lower()
    if bucket == mtype:
        return True
    if mtype == f"exact_{bucket}":
        return True
    if bucket == "domain" and mtype in ("exact_domain", "subdomain"):
        return True
    return False


# Cache the parsed rules. Populated lazily; cleared by `reload_rules()`.
_RULES_CACHE: Optional[List[SuppressionRule]] = None


def reload_rules() -> None:
    """Drop the cached rules so the next call re-reads suppression.yaml."""
    global _RULES_CACHE
    _RULES_CACHE = None


def _load_rules() -> List[SuppressionRule]:
    global _RULES_CACHE
    if _RULES_CACHE is not None:
        return _RULES_CACHE
    # Resolve the path at call time so tests can monkeypatch SUPPRESSION_PATH.
    from app.matching import suppression as _self  # late import for monkeypatch reach

    path = getattr(_self, "SUPPRESSION_PATH", SUPPRESSION_PATH)
    p = Path(path)
    if not p.exists():
        _RULES_CACHE = []
        return _RULES_CACHE
    with open(p, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    out = []
    for entry in data.get("suppress", []) or []:
        out.append(
            SuppressionRule(
                type=str(entry.get("type", "")).lower(),
                value=str(entry.get("value", "")),
                sources=tuple(entry.get("sources") or ()),
                reason=str(entry.get("reason", "")) or "suppressed",
            )
        )
    _RULES_CACHE = out
    return _RULES_CACHE


def suppression_reason(
    match_type: str, matched_value: str, source_name: Optional[str]
) -> Optional[str]:
    """Return the reason string if this match is suppressed, else None."""
    for rule in _load_rules():
        if rule.matches(match_type, matched_value, source_name):
            return rule.reason
    return None
