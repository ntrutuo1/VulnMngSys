"""Write IIS critical CVE audit report to JSON and HTML files."""
from __future__ import annotations

import html
import json
import math
from pathlib import Path
from typing import Any

from vulnmngsys_app.services.scanflow.paths import writable_reports_dir

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IIS Critical CVE Audit Report - {target}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f5f7fb; color: #111827; margin: 0; padding: 24px; }}
  h1 {{ color: #0f766e; margin: 0 0 4px; }}
  h2 {{ color: #1f2937; margin: 28px 0 12px; font-size: 1.05rem; }}
  .meta {{ color: #64748b; font-size: 0.875rem; margin-bottom: 24px; }}
  .score-badge {{ display: inline-block; padding: 8px 18px; border-radius: 8px; font-size: 1.25rem;
    font-weight: 700; margin-bottom: 16px; }}
  .score-green {{ background: #dcfce7; color: #166534; }}
  .score-orange {{ background: #ffedd5; color: #9a3412; }}
  .score-red {{ background: #fee2e2; color: #991b1b; }}
  .summary {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 20px; }}
  .pill {{ padding: 4px 12px; border-radius: 9999px; font-size: 0.8rem; font-weight: 700; }}
  .pill-PASS {{ background: #dcfce7; color: #166534; }}
  .pill-FAIL {{ background: #fee2e2; color: #991b1b; }}
  .pill-WARNING {{ background: #ffedd5; color: #9a3412; }}
  .pill-INFO {{ background: #dbeafe; color: #1d4ed8; }}
  .pill-SKIPPED {{ background: #e5e7eb; color: #374151; }}
  .pill-ERROR {{ background: #fee2e2; color: #b91c1c; }}
  .pill-HIGH {{ background: #fee2e2; color: #991b1b; }}
  .pill-MEDIUM {{ background: #ffedd5; color: #9a3412; }}
  .pill-LOW {{ background: #fef9c3; color: #854d0e; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; background: #fff; border: 1px solid #e5e7eb; }}
  th {{ background: #f8fafc; color: #475569; padding: 10px 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
  .tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 0.78rem; }}
  .tag-PASS {{ background: #dcfce7; color: #166534; }}
  .tag-FAIL {{ background: #fee2e2; color: #991b1b; }}
  .tag-WARNING {{ background: #ffedd5; color: #9a3412; }}
  .tag-INFO {{ background: #dbeafe; color: #1d4ed8; }}
  .tag-SKIPPED {{ background: #e5e7eb; color: #374151; }}
  .tag-ERROR {{ background: #fee2e2; color: #b91c1c; }}
  .tag-HIGH {{ background: #fee2e2; color: #991b1b; }}
  .tag-MEDIUM {{ background: #ffedd5; color: #9a3412; }}
  .tag-LOW {{ background: #fef9c3; color: #854d0e; }}
  .severity-CRITICAL {{ background: #7f1d1d; color: #fff; }}
  .severity-HIGH {{ background: #dc2626; color: #fff; }}
  .severity-MEDIUM {{ background: #f97316; color: #fff; }}
  .severity-LOW {{ background: #eab308; color: #000; }}
  .severity-INFO {{ background: #3b82f6; color: #fff; }}
  .muted {{ color: #64748b; font-size: 0.8rem; }}
  .evidence {{ color: #92400e; font-size: 0.82rem; }}
  .remediation {{ color: #166534; font-size: 0.82rem; }}
</style>
</head>
<body>
<h1>IIS Critical CVE Audit Report</h1>
<div class="meta">Target: {target} | Mode: {scan_mode} | {timestamp}</div>
<div class="score-badge {score_class}">Score: {score}/100 - {score_label}</div>
{pie_chart}
<div class="summary">{summary_pills}</div>
<h2>Findings</h2>
<table>
<thead>
<tr>
  <th>#</th><th>CVE</th><th>Severity</th><th>Module</th><th>Port</th>
  <th>Status</th><th>Local Check</th><th>Evidence</th><th>Remediation</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
<h2>Patch Summary</h2>
<table>
<thead>
<tr>
  <th>CVE</th><th>Severity</th><th>Local Status</th><th>Patch Baseline</th>
  <th>Installed HotFixes</th><th>Required Patch</th>
</tr>
</thead>
<tbody>
{patch_rows}
</tbody>
</table>
</body>
</html>
"""

_ROW_TEMPLATE = (
    "<tr>"
    "<td>{id}</td>"
    "<td>{cve}</td>"
    "<td><span class='tag severity-{severity}'>{severity}</span></td>"
    "<td><strong>{name}</strong><br><span class='muted'>{module}</span></td>"
    "<td>{port}</td>"
    "<td><span class='tag tag-{status}'>{status}</span></td>"
    "<td><span class='tag tag-{local_status}'>{local_status}</span><br><span class='muted'>{local_evidence}</span></td>"
    "<td class='evidence'>{evidence}</td>"
    "<td class='remediation'>{remediation}</td>"
    "</tr>"
)

_PATCH_ROW_TEMPLATE = (
    "<tr>"
    "<td>{cve}</td>"
    "<td><span class='tag severity-{severity}'>{severity}</span></td>"
    "<td><span class='tag tag-{status}'>{status}</span></td>"
    "<td>{patch_after}</td>"
    "<td>{installed_hotfixes}</td>"
    "<td>{required_patch}</td>"
    "</tr>"
)


def write_json_report(payload: dict[str, Any]) -> Path:
    """Write audit payload to JSON file and return path."""
    reports_dir = writable_reports_dir()
    report_path = reports_dir / "iis_msf_audit_report.json"
    report_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return report_path


def generate_svg_donut_chart(summary: dict[str, int]) -> str:
    """Generate self-contained SVG donut chart HTML string."""
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    low = summary.get("low", 0)
    info = summary.get("info", 0)
    total = high + medium + low + info
    
    if total == 0:
        return "<div style='color: #64748b; font-style: italic; margin-bottom: 24px;'>No findings to display.</div>"
        
    r = 40
    stroke_width = 14
    c = 2 * math.pi * r
    
    colors = {
        "high": "#dc2626",
        "medium": "#f97316",
        "low": "#eab308",
        "info": "#3b82f6"
    }
    
    items = [
        {"key": "high", "value": high, "color": colors["high"], "label": "High"},
        {"key": "medium", "value": medium, "color": colors["medium"], "label": "Medium"},
        {"key": "low", "value": low, "color": colors["low"], "label": "Low"},
        {"key": "info", "value": info, "color": colors["info"], "label": "Info"},
    ]
    items = [item for item in items if item["value"] > 0]
    
    svg_circles = []
    accumulated_percent = 0.0
    
    for item in items:
        percent = (item["value"] / total) * 100.0
        stroke_length = (percent / 100.0) * c
        stroke_offset = c - (accumulated_percent / 100.0) * c
        accumulated_percent += percent
        
        svg_circles.append(
            f'<circle cx="50" cy="50" r="{r}" fill="none" stroke="{item["color"]}" '
            f'stroke-width="{stroke_width}" stroke-dasharray="{stroke_length:.3f} {c:.3f}" '
            f'stroke-dashoffset="{stroke_offset:.3f}" transform="rotate(-90 50 50)" />'
        )
        
    circle_elements = "\n      ".join(svg_circles)
    
    legend_items = []
    for item in items:
        pct = round((item["value"] / total) * 100)
        legend_items.append(
            f'<div style="display: flex; align-items: center; gap: 8px; font-size: 0.85rem; margin-bottom: 4px;">'
            f'<span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background-color: {item["color"]};"></span>'
            f'<span style="font-weight: 600; color: #334155; margin-right: 4px;">{item["label"]}:</span>'
            f'<span style="color: #64748b;">{item["value"]} ({pct}%)</span>'
            f'</div>'
        )
    legend_html = "\n    ".join(legend_items)
    
    return f"""\
<div style="display: flex; align-items: center; gap: 24px; margin-top: 16px; margin-bottom: 24px; background: #ffffff; padding: 16px; border: 1px solid #e5e7eb; border-radius: 8px; max-width: 400px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
  <div style="position: relative; width: 100px; height: 100px; flex-shrink: 0;">
    <svg width="100" height="100" viewBox="0 0 100 100" style="display: block;">
      <circle cx="50" cy="50" r="{r}" fill="none" stroke="#e2e8f0" stroke-width="{stroke_width}" />
      {circle_elements}
    </svg>
    <div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; font-family: 'Segoe UI', Arial, sans-serif;">
      <span style="font-size: 16px; font-weight: bold; color: #1e293b; line-height: 1;">{total}</span>
      <span style="font-size: 9px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 2px;">Total</span>
    </div>
  </div>
  <div style="display: flex; flex-direction: column; justify-content: center; font-family: 'Segoe UI', Arial, sans-serif;">
    {legend_html}
  </div>
</div>
"""


def write_html_report(payload: dict[str, Any]) -> Path:
    """Write audit payload to HTML file and return path."""
    reports_dir = writable_reports_dir()
    html_path = reports_dir / "iis_msf_audit_report.html"

    score = int(payload.get("score", 0) or 0)
    if score >= 80:
        score_class = "score-green"
    elif score >= 60:
        score_class = "score-orange"
    else:
        score_class = "score-red"

    summary = payload.get("summary", {})
    pills = "".join(
        f"<span class='pill pill-{html.escape(str(k).upper())}'>{html.escape(str(k).upper())}: {int(v)}</span>"
        for k, v in summary.items()
        if int(v or 0) > 0
    )

    rows = "\n".join(_render_result_row(row) for row in payload.get("results", []))
    patch_rows = "\n".join(_render_patch_row(row) for row in payload.get("kb_patch_summary", []))

    pie_chart_html = generate_svg_donut_chart(summary)

    rendered = _HTML_TEMPLATE.format(
        target=_esc(payload.get("target", "")),
        scan_mode=_esc(payload.get("scan_mode", "focused_cve_local")),
        timestamp=_esc(payload.get("timestamp", "")),
        score=score,
        score_label=_esc(payload.get("score_label", "")),
        score_class=score_class,
        pie_chart=pie_chart_html,
        summary_pills=pills,
        rows=rows,
        patch_rows=patch_rows,
    )
    html_path.write_text(rendered, encoding="utf-8")
    return html_path


def _render_result_row(row: dict[str, Any]) -> str:
    local = row.get("local_check_result") or {}
    severity = str(row.get("severity") or "").upper()
    local_status = str(local.get("status") or "INFO").upper()
    port = row.get("port", "")
    if row.get("ssl"):
        port = f"{port} TLS"
    return _ROW_TEMPLATE.format(
        id=_esc(row.get("id", "")),
        cve=_esc(", ".join(row.get("cve", []) or [])),
        severity=_esc(severity),
        name=_esc(row.get("name", "")),
        module=_esc(row.get("module", "") or row.get("check_method", "")),
        port=_esc(port),
        status=_esc(row.get("status", "")),
        local_status=_esc(local_status),
        local_evidence=_esc(local.get("evidence", "")),
        evidence=_esc(row.get("evidence", "") or ""),
        remediation=_esc(row.get("remediation", "") or ""),
    )


def _render_patch_row(row: dict[str, Any]) -> str:
    hotfixes = row.get("installed_hotfixes") or []
    return _PATCH_ROW_TEMPLATE.format(
        cve=_esc(row.get("cve", "")),
        severity=_esc(str(row.get("severity", "")).upper()),
        status=_esc(str(row.get("status", "")).upper()),
        patch_after=_esc(row.get("patch_after", "")),
        installed_hotfixes=_esc(", ".join(hotfixes) if hotfixes else "-"),
        required_patch=_esc(row.get("required_patch", "")),
    )


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)
