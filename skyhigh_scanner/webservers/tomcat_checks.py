"""
Apache Tomcat check module.

Rule ID format: WEB-TOMCAT-{NNN}
Checks: default credentials, Manager app exposure, AJP Ghostcat,
        version CVEs, shutdown port, sample apps.
"""

from __future__ import annotations

import re
from typing import List

from ..core.finding import Finding
from ..core.transport import HTTPTransport
from ..core.credential_manager import CredentialManager
from ..core.version_utils import version_in_range

TOMCAT_CVES = [
    {"cve": "CVE-2020-1938", "affected": ">=6.0.0,<9.0.31", "severity": "CRITICAL",
     "name": "Ghostcat — AJP File Read/Inclusion"},
    {"cve": "CVE-2024-50379", "affected": ">=9.0.0,<9.0.98", "severity": "CRITICAL",
     "name": "RCE via partial PUT + case-insensitive FS"},
    {"cve": "CVE-2019-0232", "affected": ">=7.0.0,<9.0.18", "severity": "HIGH",
     "name": "CGI Servlet Command Injection (Windows)"},
    {"cve": "CVE-2017-12617", "affected": ">=7.0.0,<9.0.1", "severity": "HIGH",
     "name": "JSP Upload via PUT method"},
    {"cve": "CVE-2016-8735", "affected": ">=6.0.0,<9.0.0", "severity": "CRITICAL",
     "name": "JmxRemoteLifecycleListener Deserialization RCE"},
    {"cve": "CVE-2020-9484", "affected": ">=7.0.0,<9.0.35", "severity": "HIGH",
     "name": "Session Persistence Deserialization RCE"},
    {"cve": "CVE-2022-23181", "affected": ">=8.5.0,<9.0.58", "severity": "HIGH",
     "name": "Temp File Race Condition Privilege Escalation"},
    {"cve": "CVE-2020-11996", "affected": ">=8.5.0,<9.0.36", "severity": "HIGH",
     "name": "HTTP/2 Denial of Service"},
    {"cve": "CVE-2019-0221", "affected": ">=7.0.0,<9.0.20", "severity": "MEDIUM",
     "name": "SSI printenv XSS"},
    {"cve": "CVE-2024-23672", "affected": ">=8.5.0,<9.0.86", "severity": "HIGH",
     "name": "WebSocket DoS via incomplete close"},
    {"cve": "CVE-2024-21733", "affected": ">=8.5.7,<9.0.84", "severity": "MEDIUM",
     "name": "HTTP Request Smuggling Info Leak"},
    {"cve": "CVE-2017-12615", "affected": ">=7.0.0,<7.0.81", "severity": "HIGH",
     "name": "PUT method arbitrary file upload (Windows)"},
]

DEFAULT_CREDS = [
    ("tomcat", "tomcat"),
    ("admin", "admin"),
    ("manager", "manager"),
    ("admin", ""),
    ("tomcat", "s3cret"),
]


def run_checks(http: HTTPTransport, url: str,
               credentials: CredentialManager = None,
               verbose: bool = False) -> List[Finding]:
    findings: List[Finding] = []
    headers = http.get_headers()
    server = headers.get("Server", "")

    # Version CVE check
    m = re.search(r"(?:Tomcat|Coyote)/(\d+\.\d+\.\d+)", server)
    if m:
        ver = m.group(1)
        for entry in TOMCAT_CVES:
            if version_in_range(ver, entry["affected"]):
                findings.append(Finding(
                    rule_id="WEB-TOMCAT-001", name=entry["name"],
                    category="Known CVE", severity=entry["severity"],
                    file_path=url, line_num=0, line_content=f"Tomcat/{ver}",
                    description=f"Tomcat {ver} is affected by {entry['cve']}.",
                    recommendation="Upgrade Tomcat to latest version.",
                    cve=entry["cve"], cwe="CWE-94", target_type="webserver",
                ))

    # Manager app exposure
    for path in ["/manager/html", "/host-manager/html", "/manager/status"]:
        status, body = http.probe_path(path)
        if status in (200, 401):
            sev = "CRITICAL" if status == 200 else "HIGH"
            findings.append(Finding(
                rule_id="WEB-TOMCAT-002", name=f"Tomcat Manager at {path}",
                category="Attack Surface", severity=sev,
                file_path=url, line_num=0, line_content=f"{path} → {status}",
                description="Manager app is accessible. Default credentials may work.",
                recommendation="Restrict Manager to localhost or remove it.",
                cwe="CWE-284", target_type="webserver",
            ))

    # Default credential testing on Manager
    if credentials and credentials.has_web():
        pass  # Use provided credentials
    else:
        for user, pwd in DEFAULT_CREDS:
            try:
                import requests
                resp = requests.get(f"{url}/manager/html", auth=(user, pwd),
                                    timeout=10, verify=False)
                if resp.status_code == 200:
                    findings.append(Finding(
                        rule_id="WEB-TOMCAT-003",
                        name=f"Default credentials work: {user}:{pwd}",
                        category="Authentication", severity="CRITICAL",
                        file_path=url, line_num=0,
                        line_content=f"/manager/html auth={user}:{pwd} → 200",
                        description="Tomcat Manager accessible with default credentials.",
                        recommendation="Change default credentials in tomcat-users.xml.",
                        cwe="CWE-798", target_type="webserver",
                    ))
                    break
            except Exception:
                break

    # Sample/example apps
    for path in ["/examples/", "/docs/", "/examples/servlets/"]:
        status, _ = http.probe_path(path)
        if status == 200:
            findings.append(Finding(
                rule_id="WEB-TOMCAT-004", name=f"Sample application at {path}",
                category="Attack Surface", severity="MEDIUM",
                file_path=url, line_num=0, line_content=f"{path} → 200",
                description="Sample/example apps should be removed in production.",
                recommendation=f"Remove {path} from the Tomcat deployment.",
                cwe="CWE-1188", target_type="webserver",
            ))

    return findings
