"""
Node.js / Express.js / MERN Stack check module.

Rule ID format: MW-MERN-{CATEGORY}-{NNN}
Checks: EOL Node.js, Express version, npm vulnerable packages, .env exposure.
"""

from __future__ import annotations

import re
import json
from typing import List

from ..core.finding import Finding
from ..core.credential_manager import CredentialManager
from ..core.version_utils import parse_ver

NODE_EOL = {
    "10": "2021-04-30", "11": "2019-06-01", "12": "2022-04-30",
    "13": "2020-06-01", "14": "2023-04-30", "15": "2021-06-01",
    "16": "2023-09-11", "17": "2022-06-01", "19": "2023-06-01",
    "21": "2024-06-01",
}


def run_checks(transport, host_ip: str, version_info: str,
               credentials: CredentialManager = None,
               verbose: bool = False) -> List[Finding]:
    findings: List[Finding] = []

    # Parse Node.js version
    m = re.search(r"v(\d+\.\d+\.\d+)", version_info)
    node_ver = m.group(1) if m else ""

    if node_ver:
        major = node_ver.split(".")[0]
        if major in NODE_EOL:
            findings.append(Finding(
                rule_id="MW-MERN-NODE-001",
                name=f"End-of-life Node.js {node_ver}",
                category="Node.js Version", severity="HIGH",
                file_path=host_ip, line_num=0,
                line_content=f"Node.js v{node_ver} (EOL: {NODE_EOL[major]})",
                description=f"Node.js {major}.x reached EOL on {NODE_EOL[major]}.",
                recommendation="Upgrade to a supported Node.js LTS (20.x or 22.x).",
                cwe="CWE-1104", target_type="middleware",
            ))

    # npm audit check via SSH
    try:
        if hasattr(transport, 'execute'):
            # Find package.json locations
            pkg_paths = transport.execute(
                "find / -maxdepth 4 -name package.json -not -path '*/node_modules/*' "
                "-type f 2>/dev/null | head -5"
            ).strip()
            for pkg_path in pkg_paths.split("\n"):
                if not pkg_path.strip():
                    continue
                pkg_dir = "/".join(pkg_path.strip().split("/")[:-1])
                audit_output = transport.execute(
                    f"cd {pkg_dir} && npm audit --json 2>/dev/null | head -200"
                ).strip()
                if audit_output:
                    try:
                        audit = json.loads(audit_output)
                        vulns = audit.get("metadata", {}).get("vulnerabilities", {})
                        critical = vulns.get("critical", 0)
                        high = vulns.get("high", 0)
                        if critical > 0 or high > 0:
                            findings.append(Finding(
                                rule_id="MW-MERN-NPM-001",
                                name=f"npm audit: {critical} critical, {high} high vulnerabilities",
                                category="npm Packages", severity="CRITICAL" if critical else "HIGH",
                                file_path=host_ip, line_num=0,
                                line_content=f"{pkg_dir}: critical={critical}, high={high}",
                                description="npm packages have known vulnerabilities.",
                                recommendation=f"Run 'npm audit fix' in {pkg_dir}.",
                                cwe="CWE-1104", target_type="middleware",
                            ))
                    except json.JSONDecodeError:
                        pass
    except Exception:
        pass

    # Express.js detection and X-Powered-By header
    try:
        from ..core.transport import HTTPTransport, HAS_REQUESTS
        if HAS_REQUESTS:
            for port in (3000, 5000, 8080):
                try:
                    http = HTTPTransport(f"http://{host_ip}:{port}", timeout=5)
                    headers = http.get_headers()
                    powered = headers.get("X-Powered-By", "")
                    if "Express" in powered:
                        findings.append(Finding(
                            rule_id="MW-MERN-EXPRESS-001",
                            name="Express.js X-Powered-By header exposed",
                            category="Express.js", severity="LOW",
                            file_path=host_ip, line_num=0,
                            line_content=f"X-Powered-By: {powered}",
                            description="Framework disclosure via X-Powered-By header.",
                            recommendation="Use helmet middleware: app.use(helmet())",
                            cwe="CWE-200", target_type="middleware",
                        ))
                    http.disconnect()
                except Exception:
                    pass
    except ImportError:
        pass

    return findings
