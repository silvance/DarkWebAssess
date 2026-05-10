"""Report data model + window helpers + renderer/template registries."""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class ReportSection:
    """One section of a report.

    `rows` + `columns` are for tabular content; `body` is markdown for
    free-form prose; `notes` are bullet items shown after the body. A section
    can contain any combination — renderers drop empty parts.
    """
    title: str
    description: str = ""
    columns: Optional[List[str]] = None
    rows: List[Dict[str, Any]] = field(default_factory=list)
    body: str = ""
    notes: List[str] = field(default_factory=list)


@dataclass
class Report:
    name: str
    title: str
    description: str
    generated_at: str
    window_start: Optional[str] = None
    window_end: Optional[str] = None
    sections: List[ReportSection] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# ---- window parsing ------------------------------------------------------
def parse_window(spec: Optional[str]) -> Optional[timedelta]:
    """Parse strings like '24h', '7d', '30d' into a timedelta. None → None."""
    if not spec:
        return None
    spec = spec.strip().lower()
    if spec.endswith("h"):
        return timedelta(hours=int(spec[:-1]))
    if spec.endswith("d"):
        return timedelta(days=int(spec[:-1]))
    if spec.endswith("m"):
        return timedelta(minutes=int(spec[:-1]))
    raise ValueError(f"Unrecognized window: {spec!r} (use e.g. 24h, 7d, 30d)")


def window_bounds(spec: Optional[str]) -> Tuple[Optional[str], str]:
    """Return (start_iso_or_none, end_iso) for a window spec."""
    end = datetime.now(timezone.utc)
    delta = parse_window(spec)
    if delta is None:
        return None, end.strftime("%Y-%m-%dT%H:%M:%SZ")
    start = end - delta
    return (
        start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        end.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


# ---- registry -----------------------------------------------------------
TEMPLATES: Dict[str, Callable] = {}


def register(name: str):
    """Decorator: register a report template under `name`."""
    def deco(fn: Callable) -> Callable:
        TEMPLATES[name] = fn
        return fn
    return deco


def list_templates() -> List[Tuple[str, str]]:
    """Return [(name, description)] for all registered templates."""
    out = []
    for name, fn in sorted(TEMPLATES.items()):
        out.append((name, (fn.__doc__ or "").strip().splitlines()[0] if fn.__doc__ else ""))
    return out


def get_template(name: str) -> Callable:
    if name not in TEMPLATES:
        raise KeyError(f"Unknown report template: {name!r}. Available: {sorted(TEMPLATES)}")
    return TEMPLATES[name]
