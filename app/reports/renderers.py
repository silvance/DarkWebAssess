"""Render a Report into markdown / HTML / JSON."""
import html as _html
import json
from typing import List

from app.reports.base import Report, ReportSection


def _md_escape_cell(value) -> str:
    if value is None:
        return ""
    s = str(value)
    return s.replace("|", "\\|").replace("\n", " ")


def _section_to_markdown(s: ReportSection) -> List[str]:
    out: List[str] = [f"## {s.title}"]
    if s.description:
        out.append(s.description)
    if s.body:
        out.append(s.body)
    if s.rows and s.columns:
        out.append("")
        out.append("| " + " | ".join(s.columns) + " |")
        out.append("|" + "|".join(["---"] * len(s.columns)) + "|")
        for row in s.rows:
            cells = [_md_escape_cell(row.get(c, "")) for c in s.columns]
            out.append("| " + " | ".join(cells) + " |")
    elif s.rows:
        # rows without explicit columns — render as bullet list of dict reprs
        out.append("")
        for row in s.rows:
            out.append(f"- {row}")
    if s.notes:
        out.append("")
        for note in s.notes:
            out.append(f"- {note}")
    out.append("")
    return out


def render_markdown(report: Report) -> str:
    lines: List[str] = []
    lines.append(f"# {report.title}")
    lines.append("")
    meta = [f"**Generated:** {report.generated_at}"]
    if report.window_start and report.window_end:
        meta.append(f"**Window:** {report.window_start} → {report.window_end}")
    elif report.window_end:
        meta.append(f"**As of:** {report.window_end}")
    if report.metadata:
        for k, v in report.metadata.items():
            meta.append(f"**{k}:** {v}")
    lines.append("  ·  ".join(meta))
    lines.append("")
    if report.description:
        lines.append(f"_{report.description}_")
        lines.append("")
    for section in report.sections:
        lines.extend(_section_to_markdown(section))
    return "\n".join(lines).rstrip() + "\n"


# --- HTML ----------------------------------------------------------------
_HTML_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          max-width: 960px; margin: 2em auto; padding: 0 1em; color: #1f2328; }}
  h1, h2 {{ border-bottom: 1px solid #d0d7de; padding-bottom: 0.3em; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
  th, td {{ border: 1px solid #d0d7de; padding: 6px 10px; text-align: left;
           font-size: 0.9em; vertical-align: top; }}
  th {{ background: #f6f8fa; }}
  tr:nth-child(even) td {{ background: #f9fafc; }}
  .meta {{ color: #57606a; font-size: 0.95em; }}
  code {{ background: #f6f8fa; padding: 0 4px; border-radius: 3px; }}
  ul {{ padding-left: 1.4em; }}
</style>
</head>
<body>
"""

_HTML_TAIL = "</body></html>\n"


def _esc(value) -> str:
    if value is None:
        return ""
    # quote=True escapes both single and double quotes — defense-in-depth
    # in case a value ever lands inside an attribute context.
    return _html.escape(str(value), quote=True)


def _section_to_html(s: ReportSection) -> List[str]:
    out: List[str] = [f"<h2>{_esc(s.title)}</h2>"]
    if s.description:
        out.append(f"<p>{_esc(s.description)}</p>")
    if s.body:
        out.append(f"<pre>{_esc(s.body)}</pre>")
    if s.rows and s.columns:
        out.append("<table><thead><tr>")
        for col in s.columns:
            out.append(f"<th>{_esc(col)}</th>")
        out.append("</tr></thead><tbody>")
        for row in s.rows:
            out.append("<tr>")
            for col in s.columns:
                out.append(f"<td>{_esc(row.get(col, ''))}</td>")
            out.append("</tr>")
        out.append("</tbody></table>")
    elif s.rows:
        out.append("<ul>")
        for row in s.rows:
            out.append(f"<li>{_esc(row)}</li>")
        out.append("</ul>")
    if s.notes:
        out.append("<ul>")
        for n in s.notes:
            out.append(f"<li>{_esc(n)}</li>")
        out.append("</ul>")
    return out


def render_html(report: Report) -> str:
    parts: List[str] = [_HTML_HEAD.format(title=_esc(report.title))]
    parts.append(f"<h1>{_esc(report.title)}</h1>")
    meta_bits: List[str] = [f"Generated: {_esc(report.generated_at)}"]
    if report.window_start and report.window_end:
        meta_bits.append(
            f"Window: {_esc(report.window_start)} → {_esc(report.window_end)}"
        )
    elif report.window_end:
        meta_bits.append(f"As of: {_esc(report.window_end)}")
    for k, v in (report.metadata or {}).items():
        meta_bits.append(f"{_esc(k)}: {_esc(v)}")
    parts.append('<p class="meta">' + " &middot; ".join(meta_bits) + "</p>")
    if report.description:
        parts.append(f"<p><em>{_esc(report.description)}</em></p>")
    for section in report.sections:
        parts.extend(_section_to_html(section))
    parts.append(_HTML_TAIL)
    return "\n".join(parts)


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, default=str)


def render(report: Report, fmt: str) -> str:
    fmt = fmt.lower()
    if fmt in ("md", "markdown"):
        return render_markdown(report)
    if fmt in ("html",):
        return render_html(report)
    if fmt in ("json",):
        return render_json(report)
    raise ValueError(f"Unknown format: {fmt!r} (try md / html / json)")
