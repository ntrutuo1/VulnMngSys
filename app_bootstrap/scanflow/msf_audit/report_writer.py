"""Write IIS MSF audit report to JSON and HTML files."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_REPORTS_DIR = Path(__file__).resolve().parents[3] / "reports"

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IIS MSF Audit Report — {target}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f0f23; color: #e0e0e0; margin: 0; padding: 24px; }}
  h1 {{ color: #60a5fa; margin-bottom: 4px; }}
  .meta {{ color: #9ca3af; font-size: 0.875rem; margin-bottom: 24px; }}
  .score-badge {{ display: inline-block; padding: 8px 20px; border-radius: 9999px;
    font-size: 1.5rem; font-weight: bold; margin-bottom: 16px; }}
  .score-green {{ background: #064e3b; color: #34d399; }}
  .score-orange {{ background: #451a03; color: #fb923c; }}
  .score-red {{ background: #450a0a; color: #f87171; }}
  .summary {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }}
  .pill {{ padding: 4px 14px; border-radius: 9999px; font-size: 0.8rem; font-weight: 600; }}
  .pill-PASS {{ background: #052e16; color: #4ade80; }}
  .pill-FAIL {{ background: #450a0a; color: #f87171; }}
  .pill-WARNING {{ background: #431407; color: #fb923c; }}
  .pill-INFO {{ background: #0c1a3d; color: #60a5fa; }}
  .pill-SKIPPED {{ background: #1f2937; color: #9ca3af; }}
  .pill-ERROR {{ background: #2d0000; color: #ef4444; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
  th {{ background: #1e293b; color: #94a3b8; padding: 10px 12px; text-align: left; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #1e293b; vertical-align: top; }}
  tr:hover td {{ background: #1e293b; }}
  .tag {{ display: inline-block; padding: 2px 10px; border-radius: 4px; font-weight: 600; font-size: 0.8rem; }}
  .tag-PASS {{ background: #052e16; color: #4ade80; }}
  .tag-FAIL {{ background: #450a0a; color: #f87171; }}
  .tag-WARNING {{ background: #431407; color: #fb923c; }}
  .tag-INFO {{ background: #0c1a3d; color: #60a5fa; }}
  .tag-SKIPPED {{ background: #1f2937; color: #9ca3af; }}
  .tag-ERROR {{ background: #2d0000; color: #ef4444; }}
  .evidence {{ color: #d97706; font-size: 0.8rem; }}
  .remediation {{ color: #86efac; font-size: 0.8rem; }}
</style>
</head>
<body>
<h1>IIS MSF Audit Report</h1>
<div class="meta">Target: {target} &nbsp;|&nbsp; Mode: {scan_mode} &nbsp;|&nbsp; {timestamp}</div>
<div class="score-badge {score_class}">Score: {score}/100 — {score_label}</div>
<div class="summary">{summary_pills}</div>
<table>
<thead>
<tr><th>#</th><th>Module</th><th>Category</th><th>Port</th><th>Status</th><th>Evidence</th><th>Remediation</th></tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>
"""

_ROW_TEMPLATE = (
    "<tr>"
    "<td>{id}</td>"
    "<td><strong>{name}</strong><br><small style='color:#6b7280'>{module}</small></td>"
    "<td>{category}</td>"
    "<td>{port}</td>"
    "<td><span class='tag tag-{status}'>{status}</span></td>"
    "<td class='evidence'>{evidence}</td>"
    "<td class='remediation'>{remediation}</td>"
    "</tr>"
)


def write_json_report(payload: dict[str, Any]) -> Path:
    """Write audit payload to JSON file and return path."""
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = _REPORTS_DIR / "iis_msf_audit_report.json"
    report_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return report_path


def write_html_report(payload: dict[str, Any]) -> Path:
    """Write audit payload to HTML file and return path."""
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    html_path = _REPORTS_DIR / "iis_msf_audit_report.html"

    score = payload.get("score", 0)
    if score >= 80:
        score_class = "score-green"
    elif score >= 60:
        score_class = "score-orange"
    else:
        score_class = "score-red"

    summary = payload.get("summary", {})
    pills = "".join(
        f"<span class='pill pill-{k.upper()}'>{k.upper()}: {v}</span>"
        for k, v in summary.items()
        if v > 0
    )

    rows = "\n".join(
        _ROW_TEMPLATE.format(
            id=r.get("id", ""),
            name=_esc(r.get("name", "")),
            module=_esc(r.get("module", "")),
            category=_esc(r.get("category", "").replace("_", " ")),
            port=r.get("port", ""),
            status=r.get("status", ""),
            evidence=_esc(r.get("evidence", "") or ""),
            remediation=_esc(r.get("remediation", "") or ""),
        )
        for r in payload.get("results", [])
    )

    html = _HTML_TEMPLATE.format(
        target=_esc(payload.get("target", "")),
        scan_mode=payload.get("scan_mode", "safe"),
        timestamp=payload.get("timestamp", ""),
        score=score,
        score_label=_esc(payload.get("score_label", "")),
        score_class=score_class,
        summary_pills=pills,
        rows=rows,
    )
    html_path.write_text(html, encoding="utf-8")
    return html_path


def _esc(text: str) -> str:
    """Basic HTML escaping."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
