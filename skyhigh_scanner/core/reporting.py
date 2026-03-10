"""
Unified reporting engine for SkyHigh Scanner.

Generates interactive HTML reports with:
  - Dark theme with target-type-specific gradient headers
  - JavaScript filtering by severity, category, target, free-text search
  - CISA KEV badges for actively exploited vulnerabilities
  - Compliance score card and severity distribution
  - Print-friendly CSS media query
"""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone
from typing import List, Optional

from .finding import Finding


# ── Colour themes per target type ────────────────────────────────────
THEME_COLORS = {
    "windows":    ("#0078d4", "#005a9e"),   # Microsoft blue
    "linux":      ("#E95420", "#C34113"),   # Ubuntu orange
    "cisco":      ("#049fd9", "#036fa0"),   # Cisco blue
    "webserver":  ("#2ECC71", "#27AE60"),   # Green
    "middleware": ("#9B59B6", "#8E44AD"),   # Purple
    "database":   ("#E67E22", "#D35400"),   # Orange
    "generic":    ("#34495E", "#2C3E50"),   # Dark grey-blue
}

SEVERITY_BADGE = {
    "CRITICAL": "#dc3545",
    "HIGH":     "#fd7e14",
    "MEDIUM":   "#ffc107",
    "LOW":      "#17a2b8",
    "INFO":     "#6c757d",
}


def generate_html_report(
    scanner_name: str,
    version: str,
    target_type: str,
    findings: List[Finding],
    summary: dict,
    targets_scanned: List[str] = None,
    targets_failed: List[str] = None,
) -> str:
    """Generate a full interactive HTML report.

    Returns:
        HTML string.
    """
    primary, secondary = THEME_COLORS.get(target_type, THEME_COLORS["generic"])
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    total = len(findings)

    # Sort by severity
    sev_order = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
    sorted_findings = sorted(findings, key=lambda f: sev_order.get(f.severity, 99))

    # Build severity stats bar
    sev_counts = summary.get("severity_counts", {})
    crit = sev_counts.get("CRITICAL", 0)
    high = sev_counts.get("HIGH", 0)
    med = sev_counts.get("MEDIUM", 0)
    low = sev_counts.get("LOW", 0)
    info = sev_counts.get("INFO", 0)

    # Build findings HTML rows
    findings_html = []
    for f in sorted_findings:
        badge_color = SEVERITY_BADGE.get(f.severity, "#6c757d")
        kev_badge = ('<span class="kev-badge">ACTIVELY EXPLOITED</span>'
                     if f.cisa_kev else "")
        cve_str = f'<span class="cve-tag">{html.escape(f.cve)}</span>' if f.cve else ""
        cvss_str = f'<span class="cvss-tag">CVSS {f.cvss}</span>' if f.cvss else ""

        findings_html.append(f"""
        <div class="finding-card" data-severity="{f.severity}"
             data-category="{html.escape(f.category)}"
             data-target="{html.escape(f.file_path)}">
          <div class="finding-header">
            <span class="severity-badge" style="background:{badge_color}">
              {f.severity}
            </span>
            <span class="rule-id">{html.escape(f.rule_id)}</span>
            <span class="finding-name">{html.escape(f.name)}</span>
            {cve_str} {cvss_str} {kev_badge}
          </div>
          <div class="finding-body">
            <div class="finding-detail">
              <strong>Target:</strong> {html.escape(f.file_path)}
            </div>
            {"<div class='finding-detail'><strong>Detail:</strong> " +
             html.escape(f.line_content) + "</div>" if f.line_content else ""}
            <div class="finding-detail">
              <strong>Description:</strong> {html.escape(f.description)}
            </div>
            <div class="finding-detail recommendation">
              <strong>Recommendation:</strong> {html.escape(f.recommendation)}
            </div>
            {"<div class='finding-detail'><strong>CWE:</strong> " +
             html.escape(f.cwe) + "</div>" if f.cwe else ""}
          </div>
        </div>""")

    # Targets scanned table
    targets_rows = ""
    if targets_scanned:
        for t in targets_scanned:
            status = "Failed" if t in (targets_failed or []) else "Scanned"
            status_class = "status-fail" if status == "Failed" else "status-ok"
            targets_rows += f'<tr><td>{html.escape(t)}</td><td class="{status_class}">{status}</td></tr>'

    report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(scanner_name)} — Scan Report</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background:#1a1a2e; color:#e0e0e0; }}

  .header {{
    background: linear-gradient(135deg, {primary}, {secondary});
    padding: 30px 40px; color: white;
  }}
  .header h1 {{ font-size: 1.8em; margin-bottom: 5px; }}
  .header .subtitle {{ opacity: 0.9; font-size: 0.95em; }}

  .dashboard {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(150px,1fr));
    gap:15px; padding:20px 40px; }}
  .stat-card {{ background:#16213e; border-radius:10px; padding:20px; text-align:center; }}
  .stat-card .stat-num {{ font-size:2em; font-weight:bold; }}
  .stat-card .stat-label {{ font-size:0.85em; opacity:0.7; margin-top:5px; }}
  .stat-critical .stat-num {{ color:#dc3545; }}
  .stat-high .stat-num {{ color:#fd7e14; }}
  .stat-medium .stat-num {{ color:#ffc107; }}
  .stat-low .stat-num {{ color:#17a2b8; }}
  .stat-kev .stat-num {{ color:#ff4444; }}

  .filters {{ padding:15px 40px; display:flex; gap:10px; flex-wrap:wrap; align-items:center; }}
  .filters select, .filters input {{
    background:#16213e; color:#e0e0e0; border:1px solid #333;
    border-radius:6px; padding:8px 12px; font-size:0.9em;
  }}

  .findings {{ padding:10px 40px 40px; }}
  .finding-card {{
    background:#16213e; border-radius:10px; margin-bottom:12px;
    border-left: 4px solid #333; overflow:hidden;
  }}
  .finding-header {{
    padding:12px 16px; display:flex; align-items:center; gap:10px;
    cursor:pointer; flex-wrap:wrap;
  }}
  .finding-header:hover {{ background:#1a2744; }}
  .finding-body {{ padding:0 16px 14px; display:none; }}
  .finding-card.open .finding-body {{ display:block; }}

  .severity-badge {{
    padding:3px 10px; border-radius:4px; font-size:0.75em;
    font-weight:bold; color:white; min-width:70px; text-align:center;
  }}
  .rule-id {{ font-family:monospace; color:#82aaff; }}
  .finding-name {{ font-weight:600; }}
  .cve-tag {{ background:#5c2d91; padding:2px 8px; border-radius:4px; font-size:0.8em; }}
  .cvss-tag {{ background:#333; padding:2px 8px; border-radius:4px; font-size:0.8em; }}
  .kev-badge {{
    background:#ff4444; padding:2px 8px; border-radius:4px;
    font-size:0.75em; font-weight:bold; animation: pulse 2s infinite;
  }}
  @keyframes pulse {{ 0%,100% {{ opacity:1; }} 50% {{ opacity:0.6; }} }}

  .finding-detail {{ margin-top:8px; font-size:0.9em; line-height:1.5; }}
  .recommendation {{ color:#4CAF50; }}

  .targets-table {{ margin:20px 40px; }}
  .targets-table table {{ width:100%; border-collapse:collapse; background:#16213e; border-radius:10px; overflow:hidden; }}
  .targets-table th {{ background:#0d1b3e; padding:10px; text-align:left; }}
  .targets-table td {{ padding:8px 10px; border-top:1px solid #222; }}
  .status-ok {{ color:#4CAF50; }}
  .status-fail {{ color:#dc3545; }}

  .footer {{ text-align:center; padding:20px; opacity:0.5; font-size:0.85em; }}

  @media print {{
    body {{ background:white; color:black; }}
    .header {{ background:{primary} !important; -webkit-print-color-adjust:exact; }}
    .finding-body {{ display:block !important; }}
    .filters {{ display:none; }}
  }}
</style>
</head>
<body>

<div class="header">
  <h1>{html.escape(scanner_name)} v{html.escape(version)}</h1>
  <div class="subtitle">Scan Report — Generated {timestamp}</div>
  <div class="subtitle">Duration: {summary.get('scan_duration_seconds', 0)}s |
    Targets: {summary.get('targets_scanned', 0)} scanned,
    {summary.get('targets_failed', 0)} failed</div>
</div>

<div class="dashboard">
  <div class="stat-card"><div class="stat-num">{total}</div><div class="stat-label">Total Findings</div></div>
  <div class="stat-card stat-critical"><div class="stat-num">{crit}</div><div class="stat-label">Critical</div></div>
  <div class="stat-card stat-high"><div class="stat-num">{high}</div><div class="stat-label">High</div></div>
  <div class="stat-card stat-medium"><div class="stat-num">{med}</div><div class="stat-label">Medium</div></div>
  <div class="stat-card stat-low"><div class="stat-num">{low}</div><div class="stat-label">Low</div></div>
  <div class="stat-card stat-kev"><div class="stat-num">{summary.get('kev_findings', 0)}</div><div class="stat-label">CISA KEV</div></div>
</div>

<div class="filters">
  <select id="filterSeverity" onchange="filterFindings()">
    <option value="">All Severities</option>
    <option value="CRITICAL">Critical</option>
    <option value="HIGH">High</option>
    <option value="MEDIUM">Medium</option>
    <option value="LOW">Low</option>
  </select>
  <input type="text" id="filterSearch" placeholder="Search findings..."
         oninput="filterFindings()" style="flex:1; min-width:200px;">
</div>

{('<div class="targets-table"><h3 style="margin-bottom:10px;">Targets</h3>'
  '<table><tr><th>Target</th><th>Status</th></tr>'
  + targets_rows + '</table></div>') if targets_rows else ''}

<div class="findings" id="findingsContainer">
  {"".join(findings_html)}
</div>

<div class="footer">
  SkyHigh Scanner v{html.escape(version)} — Comprehensive Active Vulnerability Scanner
</div>

<script>
document.querySelectorAll('.finding-header').forEach(h => {{
  h.addEventListener('click', () => h.parentElement.classList.toggle('open'));
}});

function filterFindings() {{
  const sev = document.getElementById('filterSeverity').value;
  const search = document.getElementById('filterSearch').value.toLowerCase();
  document.querySelectorAll('.finding-card').forEach(card => {{
    const matchSev = !sev || card.dataset.severity === sev;
    const text = card.textContent.toLowerCase();
    const matchSearch = !search || text.includes(search);
    card.style.display = (matchSev && matchSearch) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""
    return report
