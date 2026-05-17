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
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ---- entries ------------------------------------------------------------
SeverityLiteral = Literal["low", "medium", "high", "critical"]
WatchlistType = Literal[
    "domain", "email", "ip", "cve", "hash",
    "onion", "wallet", "handle", "malware", "actor", "keyword",
]


class SourceEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    # rss = clearweb feed; onion = HTTP fetch routed through Tor SOCKS proxy.
    type: Literal["rss", "onion"]
    url: str = Field(min_length=1, max_length=2000)
    enabled: bool = True

    @field_validator("url")
    @classmethod
    def _http_only(cls, v: str) -> str:
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("source url must start with http:// or https://")
        return v

    @model_validator(mode="after")
    def _onion_type_requires_onion_host(self):
        """An onion-typed source must point at a *.onion hostname, and a
        non-onion source must not. Stops the easy misconfiguration where
        someone marks an https://news/feed source `type: onion` (which would
        force it through Tor for no reason) or vice versa (which would
        leak the .onion fetch over the clearweb)."""
        host = (urlparse(self.url).hostname or "").lower()
        is_onion_host = host.endswith(".onion")
        if self.type == "onion" and not is_onion_host:
            raise ValueError("type=onion sources must use a *.onion URL")
        if self.type == "rss" and is_onion_host:
            raise ValueError(
                "type=rss with a .onion URL would leak the request over the "
                "clearweb — set type=onion to route through Tor."
            )
        return self


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


class OnionDirectoryEntry(BaseModel):
    """A trusted aggregator/index page we'll fetch and parse for onion URLs.

    `transport=clearweb` fetches over plain HTTPS (no Tor). Use this for
    public indexes like ahmia.fi.

    `transport=tor` routes through the local SOCKS5h proxy. Use this for
    onion-hosted aggregators (dark.fail, etc.). Operator must explicitly
    enable each one.
    """
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    url: str = Field(min_length=1, max_length=2000)
    transport: Literal["clearweb", "tor"] = "clearweb"
    enabled: bool = False  # opt-in, even for clearweb indexes

    @field_validator("url")
    @classmethod
    def _http_only(cls, v: str) -> str:
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("directory url must start with http:// or https://")
        return v

    @model_validator(mode="after")
    def _transport_matches_host(self):
        host = (urlparse(self.url).hostname or "").lower()
        is_onion_host = host.endswith(".onion")
        if self.transport == "tor" and not is_onion_host:
            raise ValueError("transport=tor directories must use a *.onion URL")
        if self.transport == "clearweb" and is_onion_host:
            raise ValueError(
                "transport=clearweb with a .onion URL would leak the request "
                "over the clearweb — set transport=tor."
            )
        return self


class OnionDirectoriesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    directories: List[OnionDirectoryEntry] = Field(default_factory=list)


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


def load_onion_directories(path: str) -> OnionDirectoriesConfig:
    return OnionDirectoriesConfig.model_validate(_read_yaml(path))
