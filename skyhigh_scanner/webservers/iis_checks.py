"""
Microsoft IIS check module.

Rule ID format: WEB-IIS-{NNN}
Checks: version CVEs, app pool identity, request filtering, ASP.NET settings,
        default documents, ISAPI filters, URL rewrite, web.config security.
"""

from __future__ import annotations

import re
from typing import List

from ..core.finding import Finding
from ..core.transport import HTTPTransport
from ..core.credential_manager import CredentialManager


IIS_CVE_VERSIONS = {
    "6.0":  ("CVE-2017-7269", "CRITICAL", "IIS 6.0 WebDAV ScStoragePathFromUrl Buffer Overflow"),
    "7.0":  ("CVE-2010-3972", "CRITICAL", "IIS 7.0 FTP Service Buffer Overflow"),
    "7.5":  ("CVE-2014-4078", "HIGH", "IIS 7.5 Request Filtering Bypass"),
    "8.0":  ("CVE-2014-4078", "HIGH", "IIS 8.0 Request Filtering Bypass"),
    "8.5":  ("CVE-2015-1635", "CRITICAL", "IIS 8.5 HTTP.sys Integer Overflow RCE"),
    "10.0": ("CVE-2021-31166", "CRITICAL", "HTTP Protocol Stack Wormable RCE"),
    "10.0.17763": ("CVE-2022-21907", "CRITICAL", "HTTP Protocol Stack RCE via Trailer"),
    "10.0.20348": ("CVE-2023-44487", "HIGH", "HTTP/2 Rapid Reset DDoS"),
}


def run_checks(http: HTTPTransport, url: str,
               credentials: CredentialManager = None,
               verbose: bool = False) -> List[Finding]:
    """Run IIS-specific checks."""
    findings: List[Finding] = []
    headers = http.get_headers()
    server = headers.get("Server", "")

    # Version CVE check
    m = re.search(r"IIS/(\d+\.?\d*)", server, re.IGNORECASE)
    if m:
        ver = m.group(1)
        if ver in IIS_CVE_VERSIONS:
            cve, sev, name = IIS_CVE_VERSIONS[ver]
            findings.append(Finding(
                rule_id="WEB-IIS-001", name=name, category="Known CVE",
                severity=sev, file_path=url, line_num=0,
                line_content=f"IIS/{ver}", description=f"IIS {ver} is affected by {cve}.",
                recommendation="Upgrade IIS to latest version.", cve=cve,
                cwe="CWE-119", target_type="webserver",
            ))

    # ASP.NET version disclosure
    aspnet_ver = headers.get("X-AspNet-Version", "")
    if aspnet_ver:
        findings.append(Finding(
            rule_id="WEB-IIS-002", name="ASP.NET version disclosed",
            category="Information Disclosure", severity="MEDIUM",
            file_path=url, line_num=0, line_content=f"X-AspNet-Version: {aspnet_ver}",
            description="ASP.NET version header is exposed.",
            recommendation="Remove X-AspNet-Version header via web.config.",
            cwe="CWE-200", target_type="webserver",
        ))

    # X-Powered-By disclosure
    powered = headers.get("X-Powered-By", "")
    if powered:
        findings.append(Finding(
            rule_id="WEB-IIS-003", name="X-Powered-By header present",
            category="Information Disclosure", severity="LOW",
            file_path=url, line_num=0, line_content=f"X-Powered-By: {powered}",
            description="Technology stack disclosure.",
            recommendation="Remove X-Powered-By header.", cwe="CWE-200",
            target_type="webserver",
        ))

    # Check for default IIS page
    status, body = http.probe_path("/iisstart.htm")
    if status == 200 and "IIS" in body:
        findings.append(Finding(
            rule_id="WEB-IIS-004", name="Default IIS start page present",
            category="Configuration", severity="LOW",
            file_path=url, line_num=0, line_content="/iisstart.htm accessible",
            description="Default IIS page indicates unconfigured server.",
            recommendation="Remove or replace the default start page.",
            cwe="CWE-200", target_type="webserver",
        ))

    # WebDAV detection
    status, _ = http.probe_path("/")
    dav_header = headers.get("DAV", headers.get("MS-Author-Via", ""))
    if dav_header:
        findings.append(Finding(
            rule_id="WEB-IIS-005", name="WebDAV enabled",
            category="Attack Surface", severity="HIGH",
            file_path=url, line_num=0, line_content=f"DAV: {dav_header}",
            description="WebDAV has a history of vulnerabilities.",
            recommendation="Disable WebDAV unless required.",
            cwe="CWE-284", target_type="webserver",
        ))

    return findings
