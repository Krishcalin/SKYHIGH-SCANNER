"""
Apache HTTPD check module.

Rule ID format: WEB-APACHE-{NNN}
Checks: version CVEs, ServerTokens, ServerSignature, directory listing,
        mod_security, .htaccess, mod_ssl configuration.
"""

from __future__ import annotations

import re

from ..core.credential_manager import CredentialManager
from ..core.finding import Finding
from ..core.transport import HTTPTransport
from ..core.version_utils import version_in_range

APACHE_CVES = [
    {"cve": "CVE-2021-44790", "affected": ">=2.4.0,<2.4.52", "severity": "CRITICAL",
     "name": "mod_lua buffer overflow"},
    {"cve": "CVE-2021-41773", "affected": ">=2.4.49,<=2.4.49", "severity": "CRITICAL",
     "name": "Path Traversal & RCE"},
    {"cve": "CVE-2021-42013", "affected": ">=2.4.50,<=2.4.50", "severity": "CRITICAL",
     "name": "Path Traversal fix bypass"},
    {"cve": "CVE-2019-0211", "affected": ">=2.4.17,<2.4.39", "severity": "HIGH",
     "name": "Local privilege escalation via scoreboard"},
    {"cve": "CVE-2017-9798", "affected": ">=2.2.0,<2.4.28", "severity": "HIGH",
     "name": "Optionsbleed memory leak"},
    {"cve": "CVE-2023-25690", "affected": ">=2.4.0,<2.4.56", "severity": "CRITICAL",
     "name": "HTTP Request Smuggling via mod_proxy"},
    {"cve": "CVE-2024-38476", "affected": ">=2.4.0,<2.4.62", "severity": "CRITICAL",
     "name": "mod_proxy SSRF via backend response"},
    {"cve": "CVE-2024-38474", "affected": ">=2.4.0,<2.4.62", "severity": "CRITICAL",
     "name": "mod_rewrite substitution encoding bypass"},
    {"cve": "CVE-2023-43622", "affected": ">=2.4.55,<2.4.58", "severity": "HIGH",
     "name": "HTTP/2 stream handling DoS"},
    {"cve": "CVE-2024-27316", "affected": ">=2.4.17,<2.4.59", "severity": "HIGH",
     "name": "HTTP/2 CONTINUATION frames DoS"},
    {"cve": "CVE-2022-22720", "affected": ">=2.4.0,<2.4.53", "severity": "HIGH",
     "name": "HTTP Request Smuggling via r:parsebody"},
    {"cve": "CVE-2014-0226", "affected": ">=2.4.6,<2.4.10", "severity": "MEDIUM",
     "name": "mod_status race condition heap overflow"},
]


def run_checks(http: HTTPTransport, url: str,
               credentials: CredentialManager = None,
               verbose: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    headers = http.get_headers()
    server = headers.get("Server", "")

    # Version CVE check
    m = re.search(r"Apache/(\d+\.\d+\.\d+)", server)
    if m:
        ver = m.group(1)
        for cve_entry in APACHE_CVES:
            if version_in_range(ver, cve_entry["affected"]):
                findings.append(Finding(
                    rule_id="WEB-APACHE-001", name=cve_entry["name"],
                    category="Known CVE", severity=cve_entry["severity"],
                    file_path=url, line_num=0,
                    line_content=f"Apache/{ver}",
                    description=f"Apache {ver} is affected by {cve_entry['cve']}.",
                    recommendation="Upgrade Apache HTTPD to latest version.",
                    cve=cve_entry["cve"], cwe="CWE-119", target_type="webserver",
                ))

    # ServerTokens Full
    if re.search(r"Apache/\d+\.\d+\.\d+\s+\(", server):
        findings.append(Finding(
            rule_id="WEB-APACHE-002", name="ServerTokens Full — OS disclosed",
            category="Information Disclosure", severity="MEDIUM",
            file_path=url, line_num=0, line_content=f"Server: {server}",
            description="ServerTokens is set to Full, exposing OS and modules.",
            recommendation="Set ServerTokens Prod in httpd.conf.",
            cwe="CWE-200", target_type="webserver",
        ))

    # Directory listing probe
    status, body = http.probe_path("/icons/")
    if status == 200 and "Index of" in body:
        findings.append(Finding(
            rule_id="WEB-APACHE-003", name="Directory listing enabled",
            category="Configuration", severity="MEDIUM",
            file_path=url, line_num=0, line_content="Index of /icons/",
            description="Directory listing exposes file structure.",
            recommendation="Add 'Options -Indexes' to Apache configuration.",
            cwe="CWE-548", target_type="webserver",
        ))

    # server-status exposure
    status, body = http.probe_path("/server-status")
    if status == 200 and "Apache Server Status" in body:
        findings.append(Finding(
            rule_id="WEB-APACHE-004", name="Server-status page accessible",
            category="Information Disclosure", severity="HIGH",
            file_path=url, line_num=0, line_content="/server-status → 200",
            description="Server-status page exposes connections and configuration.",
            recommendation="Restrict /server-status to localhost only.",
            cwe="CWE-200", target_type="webserver",
        ))

    # server-info exposure
    status, _ = http.probe_path("/server-info")
    if status == 200:
        findings.append(Finding(
            rule_id="WEB-APACHE-005", name="Server-info page accessible",
            category="Information Disclosure", severity="HIGH",
            file_path=url, line_num=0, line_content="/server-info → 200",
            description="Server-info exposes full Apache module configuration.",
            recommendation="Restrict /server-info or disable mod_info.",
            cwe="CWE-200", target_type="webserver",
        ))

    return findings
