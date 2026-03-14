"""
Oracle WebLogic check module.

Rule ID format: WEB-WEBLOGIC-{NNN}
Checks: console exposure, T3/IIOP deserialization CVEs, SSRF, version CVEs.
"""

from __future__ import annotations

import re

from ..core.credential_manager import CredentialManager
from ..core.finding import Finding
from ..core.transport import HTTPTransport
from ..core.version_utils import version_in_range

WEBLOGIC_CVES = [
    {"cve": "CVE-2023-21839", "affected": ">=12.2.1.3,<=14.1.1.0", "severity": "CRITICAL",
     "name": "Remote Code Execution via T3/IIOP"},
    {"cve": "CVE-2020-14882", "affected": ">=10.3.6,<=14.1.1.0", "severity": "CRITICAL",
     "name": "Unauthenticated Console Takeover"},
    {"cve": "CVE-2020-14883", "affected": ">=10.3.6,<=14.1.1.0", "severity": "CRITICAL",
     "name": "Authenticated RCE via Console"},
    {"cve": "CVE-2019-2725", "affected": ">=10.3.6,<=12.2.1.3", "severity": "CRITICAL",
     "name": "wls-wsat Deserialization RCE"},
    {"cve": "CVE-2018-2628", "affected": ">=10.3.6,<=12.2.1.3", "severity": "CRITICAL",
     "name": "T3 Protocol Deserialization RCE"},
    {"cve": "CVE-2017-10271", "affected": ">=10.3.6,<=12.2.1.2", "severity": "CRITICAL",
     "name": "wls-wsat XMLDecoder RCE"},
    {"cve": "CVE-2020-2555", "affected": ">=12.1.3,<=12.2.1.4", "severity": "CRITICAL",
     "name": "Coherence T3 Deserialization RCE"},
    {"cve": "CVE-2020-2883", "affected": ">=10.3.6,<=12.2.1.4", "severity": "CRITICAL",
     "name": "Coherence T3 Deserialization Bypass"},
    {"cve": "CVE-2021-2109", "affected": ">=10.3.6,<=14.1.1.0", "severity": "CRITICAL",
     "name": "IIOP JNDI Injection RCE"},
    {"cve": "CVE-2018-2893", "affected": ">=10.3.6,<=12.2.1.3", "severity": "CRITICAL",
     "name": "T3 Protocol Deserialization Bypass"},
    {"cve": "CVE-2018-2894", "affected": ">=12.1.3,<=12.2.1.3", "severity": "CRITICAL",
     "name": "Web Services File Upload RCE"},
    {"cve": "CVE-2017-3506", "affected": ">=10.3.6,<=12.2.1.2", "severity": "CRITICAL",
     "name": "wls-wsat XMLDecoder RCE (Original)"},
    {"cve": "CVE-2019-2729", "affected": ">=10.3.6,<=12.2.1.3", "severity": "CRITICAL",
     "name": "XMLDecoder Deserialization Bypass"},
    {"cve": "CVE-2022-21371", "affected": ">=12.1.3,<=14.1.1.0", "severity": "HIGH",
     "name": "Local File Inclusion / Path Traversal"},
    {"cve": "CVE-2023-21931", "affected": ">=12.2.1.3,<=14.1.1.0", "severity": "CRITICAL",
     "name": "IIOP Remote Code Execution"},
]


def run_checks(http: HTTPTransport, url: str,
               credentials: CredentialManager = None,
               verbose: bool = False) -> list[Finding]:
    findings: list[Finding] = []

    # Console exposure
    for path in ["/console", "/console/login/LoginForm.jsp"]:
        status, body = http.probe_path(path)
        if status in (200, 302) and ("WebLogic" in body or "console" in body.lower()):
            # Try to extract version
            m = re.search(r"WebLogic Server.*?(\d+\.\d+\.\d+\.\d+)", body)
            ver = m.group(1) if m else ""

            findings.append(Finding(
                rule_id="WEB-WEBLOGIC-001", name="WebLogic Console accessible",
                category="Attack Surface", severity="HIGH",
                file_path=url, line_num=0,
                line_content=f"/console → {status}" + (f" (v{ver})" if ver else ""),
                description="WebLogic admin console is publicly accessible.",
                recommendation="Restrict console access to management network.",
                cwe="CWE-284", target_type="webserver",
            ))

            # Version CVE matching
            if ver:
                for entry in WEBLOGIC_CVES:
                    if version_in_range(ver, entry["affected"]):
                        findings.append(Finding(
                            rule_id="WEB-WEBLOGIC-002", name=entry["name"],
                            category="Known CVE", severity=entry["severity"],
                            file_path=url, line_num=0,
                            line_content=f"WebLogic {ver}",
                            description=f"WebLogic {ver} is affected by {entry['cve']}.",
                            recommendation="Apply Oracle CPU patches.",
                            cve=entry["cve"], cwe="CWE-502", target_type="webserver",
                        ))
            break

    # wls-wsat endpoint (deserialization target)
    status, _ = http.probe_path("/wls-wsat/CoordinatorPortType")
    if status in (200, 500):
        findings.append(Finding(
            rule_id="WEB-WEBLOGIC-003", name="wls-wsat endpoint accessible",
            category="Attack Surface", severity="CRITICAL",
            file_path=url, line_num=0,
            line_content=f"/wls-wsat/CoordinatorPortType → {status}",
            description="wls-wsat is targeted by multiple deserialization CVEs.",
            recommendation="Remove wls-wsat.war or restrict access.",
            cwe="CWE-502", target_type="webserver",
        ))

    # SSRF via UDDI
    status, _ = http.probe_path("/uddiexplorer/")
    if status == 200:
        findings.append(Finding(
            rule_id="WEB-WEBLOGIC-004", name="UDDI Explorer accessible",
            category="Attack Surface", severity="HIGH",
            file_path=url, line_num=0,
            line_content="/uddiexplorer/ → 200",
            description="UDDI Explorer can be used for SSRF attacks.",
            recommendation="Remove or restrict UDDI Explorer.",
            cwe="CWE-918", target_type="webserver",
        ))

    return findings
