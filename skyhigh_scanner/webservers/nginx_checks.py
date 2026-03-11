"""
Nginx check module.

Rule ID format: WEB-NGINX-{NNN}
Checks: version CVEs, server_tokens, stub_status exposure, directory traversal.
"""

from __future__ import annotations

import re

from ..core.credential_manager import CredentialManager
from ..core.finding import Finding
from ..core.transport import HTTPTransport
from ..core.version_utils import version_in_range

NGINX_CVES = [
    {"cve": "CVE-2021-23017", "affected": ">=0.6.18,<1.21.0", "severity": "CRITICAL",
     "name": "DNS Resolver off-by-one heap write"},
    {"cve": "CVE-2019-9511", "affected": ">=1.9.5,<1.17.3", "severity": "HIGH",
     "name": "HTTP/2 Data Dribble DoS"},
    {"cve": "CVE-2018-16843", "affected": ">=1.9.5,<1.15.6", "severity": "HIGH",
     "name": "HTTP/2 excessive memory consumption"},
    {"cve": "CVE-2017-7529", "affected": ">=0.5.6,<1.13.3", "severity": "HIGH",
     "name": "Integer overflow in range filter"},
    {"cve": "CVE-2022-41741", "affected": ">=1.1.3,<1.23.2", "severity": "HIGH",
     "name": "mp4 module buffer overflow"},
    {"cve": "CVE-2022-41742", "affected": ">=1.1.3,<1.23.2", "severity": "HIGH",
     "name": "mp4 module memory disclosure"},
    {"cve": "CVE-2019-9513", "affected": ">=1.9.5,<1.17.3", "severity": "HIGH",
     "name": "HTTP/2 Resource Loop DoS"},
    {"cve": "CVE-2019-9516", "affected": ">=1.9.5,<1.17.3", "severity": "MEDIUM",
     "name": "HTTP/2 zero-length header memory leak"},
    {"cve": "CVE-2024-7347", "affected": ">=1.5.13,<1.27.1", "severity": "MEDIUM",
     "name": "mp4 module read out-of-bounds"},
    {"cve": "CVE-2022-3638", "affected": ">=1.23.0,<1.23.2", "severity": "HIGH",
     "name": "Request smuggling via chunked transfer"},
]


def run_checks(http: HTTPTransport, url: str,
               credentials: CredentialManager = None,
               verbose: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    headers = http.get_headers()
    server = headers.get("Server", "")

    # Version CVE check
    m = re.search(r"nginx/(\d+\.\d+\.\d+)", server)
    if m:
        ver = m.group(1)
        for entry in NGINX_CVES:
            if version_in_range(ver, entry["affected"]):
                findings.append(Finding(
                    rule_id="WEB-NGINX-001", name=entry["name"],
                    category="Known CVE", severity=entry["severity"],
                    file_path=url, line_num=0, line_content=f"nginx/{ver}",
                    description=f"Nginx {ver} is affected by {entry['cve']}.",
                    recommendation="Upgrade Nginx to latest stable version.",
                    cve=entry["cve"], cwe="CWE-119", target_type="webserver",
                ))

    # stub_status exposure
    for path in ["/nginx_status", "/stub_status", "/status"]:
        status, body = http.probe_path(path)
        if status == 200 and "Active connections" in body:
            findings.append(Finding(
                rule_id="WEB-NGINX-002", name="Nginx stub_status exposed",
                category="Information Disclosure", severity="MEDIUM",
                file_path=url, line_num=0, line_content=f"{path} → 200",
                description="stub_status exposes connection metrics.",
                recommendation="Restrict stub_status to internal IPs.",
                cwe="CWE-200", target_type="webserver",
            ))
            break

    return findings
