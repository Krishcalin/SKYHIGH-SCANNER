"""
Oracle client/DB detection check module (middleware-side).

Rule ID format: MW-ORA-{CATEGORY}-{NNN}
Checks: Oracle version, TNS listener probing, OEM console exposure.
Database-specific deep checks are in databases/oracle_db_checks.py.
"""

from __future__ import annotations

import re
import socket
from typing import List

from ..core.finding import Finding
from ..core.credential_manager import CredentialManager
from ..core.version_utils import version_in_range

ORACLE_CVES = [
    {"cve": "CVE-2012-1675", "affected": ">=10.0,<12.2", "severity": "HIGH",
     "name": "TNS Poison — Remote Registration Hijacking"},
    {"cve": "CVE-2018-3110", "affected": ">=12.1,<=12.2.0.1", "severity": "CRITICAL",
     "name": "Oracle DB Remote Code Execution"},
    {"cve": "CVE-2020-14882", "affected": ">=19.0,<19.9", "severity": "HIGH",
     "name": "Oracle DB Privilege Escalation"},
]


def run_checks(transport, host_ip: str, version_info: str,
               credentials: CredentialManager = None,
               verbose: bool = False) -> List[Finding]:
    findings: List[Finding] = []

    # Parse Oracle version
    m = re.search(r"Release\s+(\d+\.\d+\.\d+\.\d+)", version_info)
    ora_ver = m.group(1) if m else ""

    if ora_ver:
        # CVE checks
        for entry in ORACLE_CVES:
            if version_in_range(ora_ver, entry["affected"]):
                findings.append(Finding(
                    rule_id="MW-ORA-CVE-001", name=entry["name"],
                    category="Known CVE", severity=entry["severity"],
                    file_path=host_ip, line_num=0,
                    line_content=f"Oracle {ora_ver}",
                    description=f"Oracle {ora_ver} is affected by {entry['cve']}.",
                    recommendation="Apply Oracle Critical Patch Update.",
                    cve=entry["cve"], cwe="CWE-269", target_type="middleware",
                ))

    # TNS Listener probe
    try:
        with socket.create_connection((host_ip, 1521), timeout=5) as s:
            s.settimeout(3)
            banner = s.recv(1024).decode("utf-8", errors="replace")
            if banner:
                findings.append(Finding(
                    rule_id="MW-ORA-TNS-001", name="TNS Listener version disclosed",
                    category="Oracle TNS", severity="MEDIUM",
                    file_path=host_ip, line_num=0,
                    line_content=f"TNS banner: {banner[:100]}",
                    description="TNS Listener banner reveals version information.",
                    recommendation="Set SECURE_REGISTER_LISTENER in listener.ora.",
                    cwe="CWE-200", target_type="middleware",
                ))
    except Exception:
        pass

    # OEM Console exposure
    try:
        from ..core.transport import HTTPTransport, HAS_REQUESTS
        if HAS_REQUESTS:
            for port in (5500, 1158):
                try:
                    http = HTTPTransport(f"https://{host_ip}:{port}", timeout=5)
                    status, body = http.probe_path("/em")
                    if status in (200, 302):
                        findings.append(Finding(
                            rule_id="MW-ORA-OEM-001",
                            name=f"Oracle Enterprise Manager on port {port}",
                            category="Attack Surface", severity="HIGH",
                            file_path=host_ip, line_num=0,
                            line_content=f"https://{host_ip}:{port}/em → {status}",
                            description="OEM console is accessible.",
                            recommendation="Restrict OEM access to management network.",
                            cwe="CWE-284", target_type="middleware",
                        ))
                    http.disconnect()
                except Exception:
                    pass
    except ImportError:
        pass

    return findings
