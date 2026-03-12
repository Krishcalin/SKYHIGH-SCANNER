"""
Unified reporting engine for SkyHigh Scanner.

Generates interactive HTML reports with:
  - Dark theme with target-type-specific gradient headers
  - Chart.js interactive dashboard (severity, category, targets, EPSS)
  - JavaScript filtering by severity, category, target, free-text search
  - CISA KEV badges for actively exploited vulnerabilities
  - Compliance score card and severity distribution
  - Print-friendly CSS media query

PDF reports via optional ``weasyprint`` dependency:
  - Print-optimised layout (white background, all findings expanded)
  - Executive summary with severity breakdown
  - Same data as HTML but formatted for offline distribution
"""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone

try:
    import weasyprint  # type: ignore[import-untyped]
    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False

from .compliance import FRAMEWORKS, compliance_summary, format_controls
from .finding import Finding

# ── Colour themes per target type ────────────────────────────────────
THEME_COLORS = {
    "windows":    ("#0078d4", "#005a9e"),   # Microsoft blue
    "linux":      ("#E95420", "#C34113"),   # Ubuntu orange
    "cisco":      ("#049fd9", "#036fa0"),   # Cisco blue
    "webserver":  ("#2ECC71", "#27AE60"),   # Green
    "middleware": ("#9B59B6", "#8E44AD"),   # Purple
    "database":   ("#E67E22", "#D35400"),   # Orange
    "dast":       ("#E74C3C", "#C0392B"),   # Red — active attack scanner
    "generic":    ("#34495E", "#2C3E50"),   # Dark grey-blue
}

SEVERITY_BADGE = {
    "CRITICAL": "#dc3545",
    "HIGH":     "#fd7e14",
    "MEDIUM":   "#ffc107",
    "LOW":      "#17a2b8",
    "INFO":     "#6c757d",
}


def _build_evidence_html(evidence: list[dict] | None) -> str:
    """Build HTML for DAST evidence (request/response proof)."""
    if not evidence:
        return ""
    rows = []
    for ev in evidence:
        method = html.escape(str(ev.get("method", "")))
        url = html.escape(str(ev.get("url", "")))
        status = ev.get("status", "")
        payload = html.escape(str(ev.get("payload", "")))
        proof = html.escape(str(ev.get("proof", ""))[:500])
        rows.append(f"""
        <div class="evidence-item">
          <div class="evidence-request">
            <span class="ev-method">{method}</span>
            <span class="ev-url">{url}</span>
            <span class="ev-status">→ {status}</span>
          </div>
          {"<div class='evidence-payload'><strong>Payload:</strong> <code>" + payload + "</code></div>" if payload and payload != "(none — passive check)" else ""}
          <div class="evidence-proof"><strong>Proof:</strong> <pre>{proof}</pre></div>
        </div>""")
    return f"""
    <div class="evidence-section">
      <strong class="evidence-title">Evidence</strong>
      {"".join(rows)}
    </div>"""


def _build_pdf_evidence_html(evidence: list[dict] | None) -> str:
    """Build print-friendly HTML for DAST evidence."""
    if not evidence:
        return ""
    rows = []
    for ev in evidence:
        method = html.escape(str(ev.get("method", "")))
        url = html.escape(str(ev.get("url", "")))
        status = ev.get("status", "")
        payload = html.escape(str(ev.get("payload", "")))
        proof = html.escape(str(ev.get("proof", ""))[:300])
        rows.append(f"""
        <div class="ev-item">
          <div class="ev-req"><strong>{method}</strong> {url} → {status}</div>
          {"<div class='ev-pl'><strong>Payload:</strong> <code>" + payload + "</code></div>" if payload and payload != "(none — passive check)" else ""}
          <div class="ev-pr"><strong>Proof:</strong><pre>{proof}</pre></div>
        </div>""")
    return f"""
    <div class="evidence-section">
      <strong>Evidence</strong>
      {"".join(rows)}
    </div>"""


def _build_charts_data(findings: list[Finding], summary: dict) -> dict:
    """Compute data needed for Chart.js visualisations.

    Returns a dict with serialisable lists/dicts for injection into JS.
    """
    sev_counts = summary.get("severity_counts", {})
    cat_counter: Counter = Counter()
    target_counter: Counter = Counter()
    epss_buckets = {"high": 0, "medium": 0, "low": 0, "none": 0}

    for f in findings:
        cat_counter[f.category] += 1
        target_counter[f.file_path] += 1
        if f.epss is not None:
            if f.epss >= 0.5:
                epss_buckets["high"] += 1
            elif f.epss >= 0.1:
                epss_buckets["medium"] += 1
            else:
                epss_buckets["low"] += 1
        else:
            epss_buckets["none"] += 1

    top_targets = target_counter.most_common(10)
    top_categories = cat_counter.most_common(12)

    return {
        "severity": {
            "labels": ["Critical", "High", "Medium", "Low", "Info"],
            "data": [
                sev_counts.get("CRITICAL", 0),
                sev_counts.get("HIGH", 0),
                sev_counts.get("MEDIUM", 0),
                sev_counts.get("LOW", 0),
                sev_counts.get("INFO", 0),
            ],
            "colors": ["#dc3545", "#fd7e14", "#ffc107", "#17a2b8", "#6c757d"],
        },
        "categories": {
            "labels": [c[0] for c in top_categories],
            "data": [c[1] for c in top_categories],
        },
        "targets": {
            "labels": [t[0] for t in top_targets],
            "data": [t[1] for t in top_targets],
        },
        "epss": {
            "labels": ["\u226550%", "10-49%", "<10%", "No EPSS"],
            "data": [
                epss_buckets["high"],
                epss_buckets["medium"],
                epss_buckets["low"],
                epss_buckets["none"],
            ],
            "colors": ["#dc3545", "#fd7e14", "#28a745", "#6c757d"],
        },
    }


def _build_charts_section(findings: list[Finding], summary: dict) -> str:
    """Build the Chart.js dashboard section HTML + JS."""
    if not findings:
        return ""

    data = _build_charts_data(findings, summary)
    data_json = json.dumps(data)

    return f"""
<div class="charts-section">
  <h3 class="charts-title">Dashboard</h3>
  <div class="charts-grid">
    <div class="chart-card">
      <h4>Severity Distribution</h4>
      <canvas id="chartSeverity"></canvas>
    </div>
    <div class="chart-card">
      <h4>EPSS Risk</h4>
      <canvas id="chartEpss"></canvas>
    </div>
    <div class="chart-card chart-wide">
      <h4>Findings by Category</h4>
      <canvas id="chartCategory"></canvas>
    </div>
    <div class="chart-card chart-wide">
      <h4>Top Targets</h4>
      <canvas id="chartTargets"></canvas>
    </div>
  </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<script>
(function() {{
  const D = {data_json};
  const doughnutOpts = {{
    responsive: true,
    maintainAspectRatio: false,
    plugins: {{
      legend: {{ position: 'bottom', labels: {{ color: '#e0e0e0', padding: 12 }} }},
    }},
  }};
  const barOpts = {{
    responsive: true,
    maintainAspectRatio: false,
    indexAxis: 'y',
    plugins: {{
      legend: {{ display: false }},
    }},
    scales: {{
      x: {{ ticks: {{ color: '#aaa' }}, grid: {{ color: '#333' }} }},
      y: {{ ticks: {{ color: '#e0e0e0' }}, grid: {{ display: false }} }},
    }},
  }};
  new Chart(document.getElementById('chartSeverity'), {{
    type: 'doughnut',
    data: {{
      labels: D.severity.labels,
      datasets: [{{ data: D.severity.data, backgroundColor: D.severity.colors, borderWidth: 0 }}],
    }},
    options: doughnutOpts,
  }});
  new Chart(document.getElementById('chartEpss'), {{
    type: 'doughnut',
    data: {{
      labels: D.epss.labels,
      datasets: [{{ data: D.epss.data, backgroundColor: D.epss.colors, borderWidth: 0 }}],
    }},
    options: doughnutOpts,
  }});
  new Chart(document.getElementById('chartCategory'), {{
    type: 'bar',
    data: {{
      labels: D.categories.labels,
      datasets: [{{ data: D.categories.data, backgroundColor: '#82aaff', borderRadius: 4 }}],
    }},
    options: barOpts,
  }});
  new Chart(document.getElementById('chartTargets'), {{
    type: 'bar',
    data: {{
      labels: D.targets.labels,
      datasets: [{{ data: D.targets.data, backgroundColor: '#4CAF50', borderRadius: 4 }}],
    }},
    options: barOpts,
  }});
}})();
</script>"""


def _build_compliance_section(comp_summary: dict) -> str:
    """Build HTML for the compliance framework mapping summary."""
    if not comp_summary or not any(comp_summary.values()):
        return ""

    sections = []
    for fw_key, controls in comp_summary.items():
        if not controls:
            continue
        fw_label = FRAMEWORKS.get(fw_key, fw_key)
        rows = ""
        for ctrl, count in list(controls.items())[:15]:  # top 15 controls
            rows += (f'<tr><td class="ctrl-id">{html.escape(ctrl)}</td>'
                     f'<td class="ctrl-count">{count}</td></tr>')
        sections.append(f"""
        <div>
          <h4 style="margin:10px 0 6px; color:#82aaff;">{html.escape(fw_label)}</h4>
          <table class="compliance-table">
            <tr><th>Control</th><th>Findings</th></tr>
            {rows}
          </table>
        </div>""")

    return f"""
<div class="compliance-section">
  <h3>Compliance Framework Mapping</h3>
  <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(280px,1fr)); gap:16px;">
    {"".join(sections)}
  </div>
</div>"""


def generate_html_report(
    scanner_name: str,
    version: str,
    target_type: str,
    findings: list[Finding],
    summary: dict,
    targets_scanned: list[str] = None,
    targets_failed: list[str] = None,
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
    sev_counts.get("INFO", 0)

    # EPSS stats
    epss_high_risk = sum(1 for f in findings if f.epss is not None and f.epss >= 0.5)

    # Compliance stats
    compliance_mapped = sum(1 for f in findings if f.compliance)
    comp_summary = compliance_summary(findings) if compliance_mapped else {}

    # Build findings HTML rows
    findings_html = []
    for f in sorted_findings:
        badge_color = SEVERITY_BADGE.get(f.severity, "#6c757d")
        kev_badge = ('<span class="kev-badge">ACTIVELY EXPLOITED</span>'
                     if f.cisa_kev else "")
        cve_str = f'<span class="cve-tag">{html.escape(f.cve)}</span>' if f.cve else ""
        cvss_str = f'<span class="cvss-tag">CVSS {f.cvss}</span>' if f.cvss else ""
        if f.epss is not None:
            epss_pct = f"{f.epss * 100:.1f}%"
            epss_cls = "epss-high" if f.epss >= 0.5 else "epss-med" if f.epss >= 0.1 else "epss-low"
            epss_str = f'<span class="epss-tag {epss_cls}">EPSS {epss_pct}</span>'
        else:
            epss_str = ""

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
            {cve_str} {cvss_str} {epss_str} {kev_badge}
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
            {"<div class='finding-detail compliance-detail'><strong>Compliance:</strong> " +
             html.escape(format_controls(f.compliance)) + "</div>" if f.compliance else ""}
            {_build_evidence_html(f.evidence)}
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
  .stat-epss .stat-num {{ color:#fd7e14; }}

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
  .epss-tag {{ padding:2px 8px; border-radius:4px; font-size:0.8em; font-weight:600; }}
  .epss-high {{ background:#dc3545; color:white; }}
  .epss-med {{ background:#fd7e14; color:white; }}
  .epss-low {{ background:#28a745; color:white; }}
  .kev-badge {{
    background:#ff4444; padding:2px 8px; border-radius:4px;
    font-size:0.75em; font-weight:bold; animation: pulse 2s infinite;
  }}
  @keyframes pulse {{ 0%,100% {{ opacity:1; }} 50% {{ opacity:0.6; }} }}

  .finding-detail {{ margin-top:8px; font-size:0.9em; line-height:1.5; }}
  .recommendation {{ color:#4CAF50; }}
  .compliance-detail {{ color:#82aaff; }}

  .evidence-section {{
    margin-top:12px; padding:10px; background:#0d1b3e;
    border-radius:6px; border-left:3px solid #82aaff;
  }}
  .evidence-title {{ color:#82aaff; font-size:0.9em; display:block; margin-bottom:8px; }}
  .evidence-item {{ margin-bottom:8px; }}
  .evidence-request {{
    font-family:monospace; font-size:0.85em; padding:4px 8px;
    background:#16213e; border-radius:4px; margin-bottom:4px;
  }}
  .ev-method {{ color:#4CAF50; font-weight:bold; }}
  .ev-url {{ color:#e0e0e0; word-break:break-all; }}
  .ev-status {{ color:#fd7e14; }}
  .evidence-payload {{ font-size:0.85em; margin:4px 0; }}
  .evidence-payload code {{
    background:#16213e; padding:2px 6px; border-radius:3px;
    color:#ff6b6b; font-family:monospace;
  }}
  .evidence-proof {{ font-size:0.85em; }}
  .evidence-proof pre {{
    background:#16213e; padding:8px; border-radius:4px;
    overflow-x:auto; white-space:pre-wrap; word-break:break-all;
    color:#aaa; font-size:0.8em; max-height:200px; overflow-y:auto;
    margin-top:4px;
  }}

  .compliance-section {{ padding:20px 40px; }}
  .compliance-section h3 {{ margin-bottom:12px; }}
  .compliance-table {{ width:100%; border-collapse:collapse; background:#16213e; border-radius:10px; overflow:hidden; margin-bottom:16px; }}
  .compliance-table th {{ background:#0d1b3e; padding:10px; text-align:left; }}
  .compliance-table td {{ padding:8px 10px; border-top:1px solid #222; }}
  .compliance-table .ctrl-id {{ font-family:monospace; color:#82aaff; }}
  .compliance-table .ctrl-count {{ color:#4CAF50; font-weight:bold; }}

  .targets-table {{ margin:20px 40px; }}
  .targets-table table {{ width:100%; border-collapse:collapse; background:#16213e; border-radius:10px; overflow:hidden; }}
  .targets-table th {{ background:#0d1b3e; padding:10px; text-align:left; }}
  .targets-table td {{ padding:8px 10px; border-top:1px solid #222; }}
  .status-ok {{ color:#4CAF50; }}
  .status-fail {{ color:#dc3545; }}

  .charts-section {{ padding:20px 40px; }}
  .charts-title {{ margin-bottom:16px; font-size:1.3em; }}
  .charts-grid {{
    display:grid; grid-template-columns:repeat(2, 1fr);
    gap:16px;
  }}
  .chart-card {{
    background:#16213e; border-radius:10px; padding:20px;
    position:relative; min-height:260px;
  }}
  .chart-card h4 {{ margin-bottom:10px; font-size:0.95em; opacity:0.8; }}
  .chart-card canvas {{ max-height:220px; }}
  .chart-wide {{ grid-column: span 1; }}
  @media (max-width:768px) {{
    .charts-grid {{ grid-template-columns:1fr; }}
  }}

  .footer {{ text-align:center; padding:20px; opacity:0.5; font-size:0.85em; }}

  @media print {{
    body {{ background:white; color:black; }}
    .header {{ background:{primary} !important; -webkit-print-color-adjust:exact; }}
    .finding-body {{ display:block !important; }}
    .filters {{ display:none; }}
    .charts-section {{ display:none; }}
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
  <div class="stat-card stat-epss"><div class="stat-num">{epss_high_risk}</div><div class="stat-label">EPSS &ge; 50%</div></div>
  <div class="stat-card" style="border-top:3px solid #82aaff"><div class="stat-num" style="color:#82aaff">{compliance_mapped}</div><div class="stat-label">Compliance Mapped</div></div>
</div>

{_build_charts_section(sorted_findings, summary)}

<div class="filters">
  <select id="filterSeverity" onchange="filterFindings()">
    <option value="">All Severities</option>
    <option value="CRITICAL">Critical</option>
    <option value="HIGH">High</option>
    <option value="MEDIUM">Medium</option>
    <option value="LOW">Low</option>
    <option value="INFO">Info</option>
  </select>
  <select id="filterCategory" onchange="filterFindings()">
    <option value="">All Categories</option>
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

{_build_compliance_section(comp_summary)}

<div class="footer">
  SkyHigh Scanner v{html.escape(version)} — Comprehensive Active Vulnerability Scanner
</div>

<script>
document.querySelectorAll('.finding-header').forEach(h => {{
  h.addEventListener('click', () => h.parentElement.classList.toggle('open'));
}});

/* Populate category filter dropdown */
(function() {{
  const cats = new Set();
  document.querySelectorAll('.finding-card').forEach(c => cats.add(c.dataset.category));
  const sel = document.getElementById('filterCategory');
  [...cats].sort().forEach(cat => {{
    const opt = document.createElement('option');
    opt.value = cat; opt.textContent = cat;
    sel.appendChild(opt);
  }});
}})();

function filterFindings() {{
  const sev = document.getElementById('filterSeverity').value;
  const cat = document.getElementById('filterCategory').value;
  const search = document.getElementById('filterSearch').value.toLowerCase();
  document.querySelectorAll('.finding-card').forEach(card => {{
    const matchSev = !sev || card.dataset.severity === sev;
    const matchCat = !cat || card.dataset.category === cat;
    const text = card.textContent.toLowerCase();
    const matchSearch = !search || text.includes(search);
    card.style.display = (matchSev && matchCat && matchSearch) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""
    return report


# ── PDF Report ────────────────────────────────────────────────────────

def _build_pdf_html(
    scanner_name: str,
    version: str,
    target_type: str,
    findings: list[Finding],
    summary: dict,
    targets_scanned: list[str] = None,
    targets_failed: list[str] = None,
) -> str:
    """Build a print-optimised HTML string suitable for PDF conversion.

    Unlike the interactive HTML report, this version uses a white background,
    all findings are expanded, and there is no JavaScript.
    """
    primary, secondary = THEME_COLORS.get(target_type, THEME_COLORS["generic"])
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    total = len(findings)

    sev_order = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
    sorted_findings = sorted(findings, key=lambda f: sev_order.get(f.severity, 99))

    sev_counts = summary.get("severity_counts", {})
    crit = sev_counts.get("CRITICAL", 0)
    high = sev_counts.get("HIGH", 0)
    med = sev_counts.get("MEDIUM", 0)
    low = sev_counts.get("LOW", 0)

    epss_high_risk = sum(1 for f in findings if f.epss is not None and f.epss >= 0.5)
    compliance_mapped = sum(1 for f in findings if f.compliance)
    comp_summary = compliance_summary(findings) if compliance_mapped else {}

    # ── Build findings rows ───────────────────────────────────────────
    findings_html = []
    for f in sorted_findings:
        badge_color = SEVERITY_BADGE.get(f.severity, "#6c757d")
        kev_badge = ('<span class="kev-badge">ACTIVELY EXPLOITED</span>'
                     if f.cisa_kev else "")
        cve_str = f'<span class="cve-tag">{html.escape(f.cve)}</span>' if f.cve else ""
        cvss_str = f'<span class="cvss-tag">CVSS {f.cvss}</span>' if f.cvss else ""
        if f.epss is not None:
            epss_pct = f"{f.epss * 100:.1f}%"
            epss_cls = "epss-high" if f.epss >= 0.5 else "epss-med" if f.epss >= 0.1 else "epss-low"
            epss_str = f'<span class="epss-tag {epss_cls}">EPSS {epss_pct}</span>'
        else:
            epss_str = ""

        detail_line = (f"<div class='finding-detail'><strong>Detail:</strong> "
                       f"{html.escape(f.line_content)}</div>" if f.line_content else "")
        cwe_line = (f"<div class='finding-detail'><strong>CWE:</strong> "
                    f"{html.escape(f.cwe)}</div>" if f.cwe else "")
        comp_line = (f"<div class='finding-detail compliance-detail'>"
                     f"<strong>Compliance:</strong> "
                     f"{html.escape(format_controls(f.compliance))}</div>"
                     if f.compliance else "")

        findings_html.append(f"""
        <div class="finding-card" style="border-left:4px solid {badge_color};">
          <div class="finding-header">
            <span class="severity-badge" style="background:{badge_color}">
              {f.severity}
            </span>
            <span class="rule-id">{html.escape(f.rule_id)}</span>
            <span class="finding-name">{html.escape(f.name)}</span>
            {cve_str} {cvss_str} {epss_str} {kev_badge}
          </div>
          <div class="finding-body">
            <div class="finding-detail">
              <strong>Target:</strong> {html.escape(f.file_path)}
            </div>
            {detail_line}
            <div class="finding-detail">
              <strong>Description:</strong> {html.escape(f.description)}
            </div>
            <div class="finding-detail recommendation">
              <strong>Recommendation:</strong> {html.escape(f.recommendation)}
            </div>
            {cwe_line}
            {comp_line}
            {_build_pdf_evidence_html(f.evidence)}
          </div>
        </div>""")

    # ── Targets table ─────────────────────────────────────────────────
    targets_rows = ""
    if targets_scanned:
        for t in targets_scanned:
            status = "Failed" if t in (targets_failed or []) else "Scanned"
            status_class = "status-fail" if status == "Failed" else "status-ok"
            targets_rows += (f'<tr><td>{html.escape(t)}</td>'
                             f'<td class="{status_class}">{status}</td></tr>')

    # ── Compliance section ────────────────────────────────────────────
    comp_section = ""
    if comp_summary and any(comp_summary.values()):
        comp_parts = []
        for fw_key, controls in comp_summary.items():
            if not controls:
                continue
            fw_label = FRAMEWORKS.get(fw_key, fw_key)
            rows = ""
            for ctrl, count in list(controls.items())[:15]:
                rows += (f'<tr><td class="ctrl-id">{html.escape(ctrl)}</td>'
                         f'<td class="ctrl-count">{count}</td></tr>')
            comp_parts.append(f"""
            <div class="comp-block">
              <h4>{html.escape(fw_label)}</h4>
              <table class="compliance-table">
                <tr><th>Control</th><th>Findings</th></tr>
                {rows}
              </table>
            </div>""")
        comp_section = f"""
        <div class="compliance-section">
          <h3>Compliance Framework Mapping</h3>
          <div class="comp-grid">{"".join(comp_parts)}</div>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{html.escape(scanner_name)} — PDF Report</title>
<style>
  @page {{
    size: A4;
    margin: 15mm 12mm;
    @bottom-center {{
      content: "Page " counter(page) " of " counter(pages);
      font-size: 8pt; color: #999;
    }}
  }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family: 'Segoe UI', Helvetica, Arial, sans-serif; color:#1a1a1a; font-size:10pt; }}

  .header {{
    background: linear-gradient(135deg, {primary}, {secondary});
    padding: 20px 24px; color: white; margin-bottom:16px;
  }}
  .header h1 {{ font-size: 16pt; margin-bottom: 4px; }}
  .header .subtitle {{ opacity: 0.9; font-size: 9pt; }}

  .dashboard {{
    display: flex; flex-wrap: wrap; gap: 8px;
    margin: 0 0 16px 0; padding: 0;
  }}
  .stat-card {{
    background: #f4f6f9; border-radius: 6px; padding: 10px 14px;
    text-align: center; flex: 1; min-width: 80px;
    border: 1px solid #ddd;
  }}
  .stat-card .stat-num {{ font-size: 18pt; font-weight: bold; }}
  .stat-card .stat-label {{ font-size: 7pt; text-transform: uppercase; color: #666; margin-top: 2px; }}
  .stat-critical .stat-num {{ color: #dc3545; }}
  .stat-high .stat-num {{ color: #e65100; }}
  .stat-medium .stat-num {{ color: #f57f17; }}
  .stat-low .stat-num {{ color: #0277bd; }}

  .findings {{ margin-top: 12px; }}
  .finding-card {{
    background: #fafafa; border-radius: 6px; margin-bottom: 8px;
    padding: 0; overflow: hidden; border: 1px solid #e0e0e0;
    page-break-inside: avoid;
  }}
  .finding-header {{
    padding: 8px 12px; display: flex; align-items: center; gap: 6px;
    flex-wrap: wrap; background: #f4f6f9;
  }}
  .finding-body {{ padding: 6px 12px 10px; }}

  .severity-badge {{
    padding: 2px 8px; border-radius: 3px; font-size: 7pt;
    font-weight: bold; color: white; min-width: 55px; text-align: center;
  }}
  .rule-id {{ font-family: monospace; color: #1565c0; font-size: 9pt; }}
  .finding-name {{ font-weight: 600; font-size: 9.5pt; }}
  .cve-tag {{ background: #5c2d91; color: white; padding: 1px 6px; border-radius: 3px; font-size: 7.5pt; }}
  .cvss-tag {{ background: #555; color: white; padding: 1px 6px; border-radius: 3px; font-size: 7.5pt; }}
  .epss-tag {{ padding: 1px 6px; border-radius: 3px; font-size: 7.5pt; font-weight: 600; }}
  .epss-high {{ background: #dc3545; color: white; }}
  .epss-med {{ background: #fd7e14; color: white; }}
  .epss-low {{ background: #28a745; color: white; }}
  .kev-badge {{ background: #dc3545; color: white; padding: 1px 6px; border-radius: 3px; font-size: 7pt; font-weight: bold; }}

  .finding-detail {{ margin-top: 4px; font-size: 9pt; line-height: 1.4; }}
  .recommendation {{ color: #2e7d32; }}
  .compliance-detail {{ color: #1565c0; }}

  .evidence-section {{
    margin-top: 6px; padding: 6px 8px; background: #f0f4ff;
    border-left: 3px solid #1565c0; border-radius: 4px; font-size: 8pt;
  }}
  .ev-item {{ margin-bottom: 4px; }}
  .ev-req {{ font-family: monospace; font-size: 7.5pt; }}
  .ev-pl {{ margin: 2px 0; }}
  .ev-pl code {{ background: #e8eaf6; padding: 1px 4px; border-radius: 2px; font-size: 7.5pt; }}
  .ev-pr pre {{
    background: #f4f6f9; padding: 4px; border-radius: 3px;
    font-size: 7pt; white-space: pre-wrap; word-break: break-all;
    max-height: 100px; overflow: hidden; margin-top: 2px;
  }}

  .compliance-section {{ margin-top: 20px; page-break-before: auto; }}
  .compliance-section h3 {{ margin-bottom: 8px; font-size: 12pt; }}
  .comp-grid {{ display: flex; flex-wrap: wrap; gap: 12px; }}
  .comp-block {{ flex: 1; min-width: 220px; }}
  .comp-block h4 {{ color: #1565c0; margin-bottom: 4px; font-size: 10pt; }}
  .compliance-table {{ width: 100%; border-collapse: collapse; font-size: 8.5pt; margin-bottom: 8px; }}
  .compliance-table th {{ background: #e8eaf6; padding: 4px 8px; text-align: left; border: 1px solid #ccc; }}
  .compliance-table td {{ padding: 3px 8px; border: 1px solid #ddd; }}
  .compliance-table .ctrl-id {{ font-family: monospace; color: #1565c0; }}
  .compliance-table .ctrl-count {{ color: #2e7d32; font-weight: bold; text-align: center; }}

  .targets-table {{ margin: 12px 0; }}
  .targets-table h3 {{ font-size: 11pt; margin-bottom: 6px; }}
  .targets-table table {{ width: 100%; border-collapse: collapse; font-size: 9pt; }}
  .targets-table th {{ background: #e8eaf6; padding: 4px 8px; text-align: left; border: 1px solid #ccc; }}
  .targets-table td {{ padding: 3px 8px; border: 1px solid #ddd; }}
  .status-ok {{ color: #2e7d32; }}
  .status-fail {{ color: #c62828; }}

  .footer {{ text-align: center; margin-top: 20px; font-size: 8pt; color: #999; }}
</style>
</head>
<body>

<div class="header">
  <h1>{html.escape(scanner_name)} v{html.escape(version)}</h1>
  <div class="subtitle">Security Scan Report — Generated {timestamp}</div>
  <div class="subtitle">Duration: {summary.get('scan_duration_seconds', 0)}s |
    Targets: {summary.get('targets_scanned', 0)} scanned,
    {summary.get('targets_failed', 0)} failed</div>
</div>

<div class="dashboard">
  <div class="stat-card"><div class="stat-num">{total}</div><div class="stat-label">Total</div></div>
  <div class="stat-card stat-critical"><div class="stat-num">{crit}</div><div class="stat-label">Critical</div></div>
  <div class="stat-card stat-high"><div class="stat-num">{high}</div><div class="stat-label">High</div></div>
  <div class="stat-card stat-medium"><div class="stat-num">{med}</div><div class="stat-label">Medium</div></div>
  <div class="stat-card stat-low"><div class="stat-num">{low}</div><div class="stat-label">Low</div></div>
  <div class="stat-card"><div class="stat-num">{summary.get('kev_findings', 0)}</div><div class="stat-label">CISA KEV</div></div>
  <div class="stat-card"><div class="stat-num">{epss_high_risk}</div><div class="stat-label">EPSS &ge; 50%</div></div>
  <div class="stat-card"><div class="stat-num">{compliance_mapped}</div><div class="stat-label">Compliance</div></div>
</div>

{('<div class="targets-table"><h3>Targets</h3>'
  '<table><tr><th>Target</th><th>Status</th></tr>'
  + targets_rows + '</table></div>') if targets_rows else ''}

<div class="findings">
  {"".join(findings_html)}
</div>

{comp_section}

<div class="footer">
  {html.escape(scanner_name)} v{html.escape(version)} — Comprehensive Active Vulnerability Scanner
</div>

</body>
</html>"""


def generate_pdf_report(
    scanner_name: str,
    version: str,
    target_type: str,
    findings: list[Finding],
    summary: dict,
    targets_scanned: list[str] = None,
    targets_failed: list[str] = None,
) -> bytes:
    """Generate a PDF report.

    Requires the optional ``weasyprint`` package::

        pip install weasyprint

    Returns:
        PDF content as bytes.

    Raises:
        RuntimeError: If weasyprint is not installed.
    """
    if not HAS_WEASYPRINT:
        raise RuntimeError(
            "PDF generation requires the 'weasyprint' package.\n"
            "Install it with: pip install weasyprint"
        )

    html_str = _build_pdf_html(
        scanner_name=scanner_name,
        version=version,
        target_type=target_type,
        findings=findings,
        summary=summary,
        targets_scanned=targets_scanned,
        targets_failed=targets_failed,
    )
    pdf_bytes = weasyprint.HTML(string=html_str).write_pdf()
    return pdf_bytes
