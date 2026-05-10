"""Cryptocurrency wallet address extractor.

Returns entities with `entity_type` of `btc`, `eth`, or `xmr`. We avoid
checksum validation here (would require extra deps); patterns rely on charset,
length, and word boundaries. False positives are possible for short BTC
base58 strings appearing in random hex-heavy text — callers can dedupe
downstream via overlap detection (see entities.extract_all).
"""
import re
from typing import List

# BTC P2PKH (1...) / P2SH (3...): base58 (no 0, O, I, l), length 26-34 after prefix
BTC_BASE58_RE = re.compile(r"\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b")
# BTC bech32 (bc1...): bech32 charset, length 39-58 after prefix.
BTC_BECH32_RE = re.compile(r"\bbc1[02-9ac-hj-np-z]{39,58}\b")
# Ethereum: 0x followed by 40 hex chars.
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
# Monero: starts with 4 (regular) or 8 (subaddress), 95 chars total, base58.
XMR_RE = re.compile(r"\b[48][1-9A-HJ-NP-Za-km-z]{94}\b")

CONTEXT_WINDOW = 80


def _context(text: str, start: int, end: int) -> str:
    a = max(0, start - CONTEXT_WINDOW)
    b = min(len(text), end + CONTEXT_WINDOW)
    return re.sub(r"\s+", " ", text[a:b]).strip()


def _emit(text: str, regex: re.Pattern, entity_type: str, claimed: list, transform=lambda v: v):
    out = []
    for m in regex.finditer(text):
        if any(s <= m.start() < e for s, e in claimed):
            continue
        claimed.append((m.start(), m.end()))
        out.append(
            {
                "entity_type": entity_type,
                "entity_value": transform(m.group(0)),
                "context": _context(text, m.start(), m.end()),
            }
        )
    return out


def extract_wallets(text: str) -> List[dict]:
    """Extract crypto wallet addresses, longer / more-specific patterns first."""
    claimed: list = []
    out: List[dict] = []
    # Longer / more-specific patterns first so we don't emit a BTC base58
    # substring of a Monero address.
    out.extend(_emit(text, XMR_RE, "xmr", claimed))
    out.extend(_emit(text, BTC_BECH32_RE, "btc", claimed, str.lower))
    out.extend(_emit(text, ETH_RE, "eth", claimed, str.lower))
    out.extend(_emit(text, BTC_BASE58_RE, "btc", claimed))
    return out
