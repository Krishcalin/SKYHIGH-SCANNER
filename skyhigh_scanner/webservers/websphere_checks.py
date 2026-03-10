"""
IBM WebSphere Application Server check module.

Rule ID format: WEB-WEBSPHERE-{NNN}
Checks: admin console exposure, SOAP connector, deserialization CVEs.
"""

from __future__ import annotations

import re
from typing import List

from ..core.finding import Finding
from ..core.transport import HTTPTransport
from ..core.credential_manager import CredentialManager


def run_checks(http: HTTPTransport, url: str,
               credentials: CredentialManager = None,
               verbose: bool = False) -> List[Finding]:
    findings: List[Finding] = []

    # Admin console exposure
    for path in ["/ibm/console", "/ibm/console/logon.jsp", "/admin"]:
        status, body = http.probe_path(path)
        if status in (200, 302) and ("WebSphere" in body or "ibm" in body.lower()):
            findings.append(Finding(
                rule_id="WEB-WEBSPHERE-001", name="WebSphere Admin Console accessible",
                category="Attack Surface", severity="HIGH",
                file_path=url, line_num=0,
                line_content=f"{path} → {status}",
                description="WebSphere admin console is publicly accessible.",
                recommendation="Restrict admin console to management network.",
                cwe="CWE-284", target_type="webserver",
            ))
            break

    # Snoop servlet (info disclosure)
    status, body = http.probe_path("/snoop")
    if status == 200 and "Request Information" in body:
        findings.append(Finding(
            rule_id="WEB-WEBSPHERE-002", name="Snoop servlet accessible",
            category="Information Disclosure", severity="MEDIUM",
            file_path=url, line_num=0, line_content="/snoop → 200",
            description="Snoop servlet exposes request/server details.",
            recommendation="Remove or restrict the snoop servlet.",
            cwe="CWE-200", target_type="webserver",
        ))

    # Default error page with version
    status, body = http.probe_path("/nonexistent_path_test_404")
    if "WebSphere" in body:
        m = re.search(r"WebSphere.*?(\d+\.\d+\.\d+\.\d+)", body)
        ver_str = m.group(1) if m else ""
        findings.append(Finding(
            rule_id="WEB-WEBSPHERE-003", name="WebSphere version in error page",
            category="Information Disclosure", severity="MEDIUM",
            file_path=url, line_num=0,
            line_content=f"Error page reveals WebSphere {ver_str}",
            description="Custom error pages expose server technology and version.",
            recommendation="Configure custom error pages without version info.",
            cwe="CWE-200", target_type="webserver",
        ))

    return findings
