"""Pydantic schemas for the YAML config files.

Validating these on load gives operators an early, specific error message
("severity 'criitical' is not one of: low, medium, high, critical") instead
of silent fall-through to a default — which has caused real misconfigurations
in production tools elsewhere.

Use `load_sources(path)`, `load_watchlist(path)`, `load_suppression(path)`
from `app.config_models` and let exceptions propagate; the CLI layer prints
the validation error and exits non-zero.
"""
from typing import List, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---- entries ------------------------------------------------------------
SeverityLiteral = Literal["low", "medium", "high", "critical"]
WatchlistType = Literal[
    "domain", "email", "ip", "cve", "hash",
    "onion", "wallet", "handle", "malware", "actor", "keyword",
]


class SourceEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    type: Literal["rss"]  # only RSS is wired up today; expand as collectors land
    url: str = Field(min_length=1, max_length=2000)
    enabled: bool = True

    @field_validator("url")
    @classmethod
    def _http_only(cls, v: str) -> str:
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("source url must start with http:// or https://")
        return v


class WatchlistEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: WatchlistType
    value: str = Field(min_length=1, max_length=512)
    description: Optional[str] = Field(default=None, max_length=2000)
    severity: SeverityLiteral = "medium"
    enabled: bool = True


class SuppressionEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = Field(min_length=1, max_length=64)
    value: str = Field(min_length=1, max_length=512)
    sources: Optional[List[str]] = None
    reason: Optional[str] = Field(default=None, max_length=2000)


# ---- containers ---------------------------------------------------------
class SourcesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sources: List[SourceEntry] = Field(default_factory=list)


class WatchlistConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    watchlist: List[WatchlistEntry] = Field(default_factory=list)


class SuppressionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suppress: List[SuppressionEntry] = Field(default_factory=list)


# ---- loaders ------------------------------------------------------------
def _read_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_sources(path: str) -> SourcesConfig:
    return SourcesConfig.model_validate(_read_yaml(path))


def load_watchlist(path: str) -> WatchlistConfig:
    return WatchlistConfig.model_validate(_read_yaml(path))


def load_suppression(path: str) -> SuppressionConfig:
    return SuppressionConfig.model_validate(_read_yaml(path))
