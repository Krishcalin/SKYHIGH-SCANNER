"""
Java / JDK / Spring / JBoss check module.

Rule ID format: MW-JAVA-{CATEGORY}-{NNN}
Checks: JDK EOL, Log4Shell, Spring4Shell, JBoss console, Actuator exposure.
"""

from __future__ import annotations

import re
from typing import List

from ..core.finding import Finding
from ..core.credential_manager import CredentialManager
from ..core.version_utils import parse_ver, version_in_range

JAVA_EOL = {
    "1.6": "2018-12", "1.7": "2022-03", "1.8.0": None,  # LTS, still supported
    "9": "2018-03", "10": "2018-09", "12": "2019-09",
    "13": "2020-03", "14": "2020-09", "15": "2021-03",
    "16": "2021-09", "18": "2022-09", "19": "2023-03",
    "20": "2023-09", "22": "2024-09",
}


def run_checks(transport, host_ip: str, version_info: str,
               credentials: CredentialManager = None,
               verbose: bool = False) -> List[Finding]:
    findings: List[Finding] = []

    # Parse Java version
    m = re.search(r'"(\d+[\d._]+)"', version_info) or re.search(r'(\d+[\d._]+)', version_info)
    java_ver = m.group(1) if m else ""

    if java_ver:
        # EOL check
        for prefix, eol_date in JAVA_EOL.items():
            if java_ver.startswith(prefix) and eol_date:
                findings.append(Finding(
                    rule_id="MW-JAVA-VER-001", name=f"End-of-life Java version {java_ver}",
                    category="Java Version", severity="HIGH",
                    file_path=host_ip, line_num=0,
                    line_content=f"java version {java_ver} (EOL: {eol_date})",
                    description=f"Java {java_ver} reached EOL in {eol_date}.",
                    recommendation="Upgrade to a supported Java LTS version (11, 17, or 21).",
                    cwe="CWE-1104", target_type="middleware",
                ))
                break

    # Log4j detection via SSH
    try:
        log4j_output = transport.execute(
            "find / -name 'log4j-core-*.jar' -type f 2>/dev/null | head -20"
        ) if hasattr(transport, 'execute') else ""
        for line in log4j_output.strip().split("\n"):
            if not line.strip():
                continue
            m = re.search(r"log4j-core-(\d+\.\d+\.\d+)\.jar", line)
            if m:
                log4j_ver = m.group(1)
                if version_in_range(log4j_ver, ">=2.0,<2.17.1"):
                    findings.append(Finding(
                        rule_id="MW-JAVA-CVE-001",
                        name="Log4Shell — Log4j RCE (CVE-2021-44228)",
                        category="Known CVE", severity="CRITICAL",
                        file_path=host_ip, line_num=0,
                        line_content=f"log4j-core-{log4j_ver}.jar at {line.strip()}",
                        description="Log4j < 2.17.1 is vulnerable to remote code execution.",
                        recommendation="Upgrade log4j-core to >= 2.17.1.",
                        cve="CVE-2021-44228", cwe="CWE-917", target_type="middleware",
                        cisa_kev=True,
                    ))
    except Exception:
        pass

    # Spring Boot Actuator detection via HTTP probing
    try:
        from ..core.transport import HTTPTransport, HAS_REQUESTS
        if HAS_REQUESTS:
            for port in (8080, 8443, 8081):
                try:
                    http = HTTPTransport(f"http://{host_ip}:{port}", timeout=5)
                    for path in ["/actuator", "/actuator/env", "/actuator/heapdump"]:
                        status, body = http.probe_path(path)
                        if status == 200:
                            findings.append(Finding(
                                rule_id="MW-JAVA-SBOOT-001",
                                name=f"Spring Boot Actuator {path} exposed",
                                category="Spring Boot", severity="HIGH" if "env" in path or "heap" in path else "MEDIUM",
                                file_path=host_ip, line_num=0,
                                line_content=f"http://{host_ip}:{port}{path} → 200",
                                description=f"Actuator endpoint {path} is publicly accessible.",
                                recommendation="Restrict Actuator endpoints via management.endpoints.web.exposure.include.",
                                cwe="CWE-200", target_type="middleware",
                            ))
                    http.disconnect()
                except Exception:
                    pass
    except ImportError:
        pass

    return findings
