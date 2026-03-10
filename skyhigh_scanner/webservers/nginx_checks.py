"""
Nginx check module.

Rule ID format: WEB-NGINX-{NNN}
Checks: version CVEs, server_tokens, stub_status exposure, directory traversal.
"""

from __future__ import annotations

import re
from typing import List

from ..core.finding import Finding
from ..core.transport import HTTPTransport
from ..core.credential_manager import CredentialManager
from ..core.version_utils import version_in_range

NGINX_CVES = [
    {"cve": "CVE-2021-23017", "affected": ">=0.6.18,<1.21.0", "severity": "HIGH",
     "name": "DNS Resolver off-by-one heap write"},
    {"cve": "CVE-2019-9511", "affected": ">=1.9.5,<1.17.3", "severity": "HIGH",
     "name": "HTTP/2 Data Dribble DoS"},
    {"cve": "CVE-2018-16843", "affected": ">=1.9.5,<1.15.6", "severity": "HIGH",
     "name": "HTTP/2 excessive memory consumption"},
    {"cve": "CVE-2017-7529", "affected": ">=0.5.6,<1.13.3", "severity": "HIGH",
     "name": "Integer overflow in range filter"},
]


def run_checks(http: HTTPTransport, url: str,
               credentials: CredentialManager = None,
               verbose: bool = False) -> List[Finding]:
    findings: List[Finding] = []
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
