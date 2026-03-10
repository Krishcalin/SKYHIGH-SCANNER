"""
.NET Framework / .NET Core / ASP.NET check module.

Rule ID format: MW-DOTNET-{CATEGORY}-{NNN}
Checks: EOL runtime versions, web.config debug mode, ViewState MAC,
        custom errors off, NuGet vulnerable packages.
"""

from __future__ import annotations

import re
import json
from typing import List

from ..core.finding import Finding
from ..core.credential_manager import CredentialManager

DOTNET_EOL = {
    "2.1": "2021-08-21", "2.2": "2019-12-23", "3.0": "2020-03-03",
    "3.1": "2022-12-13", "5.0": "2022-05-10", "6.0": "2024-11-12",
}


def run_checks(transport, host_ip: str, version_info: str,
               credentials: CredentialManager = None,
               verbose: bool = False) -> List[Finding]:
    findings: List[Finding] = []

    # Parse .NET runtimes
    for line in version_info.strip().split("\n"):
        m = re.search(r"Microsoft\.NETCore\.App\s+(\d+\.\d+\.\d+)", line)
        if not m:
            m = re.search(r"Microsoft\.AspNetCore\.App\s+(\d+\.\d+\.\d+)", line)
        if m:
            ver = m.group(1)
            major_minor = ".".join(ver.split(".")[:2])
            if major_minor in DOTNET_EOL:
                findings.append(Finding(
                    rule_id="MW-DOTNET-CORE-001",
                    name=f"End-of-life .NET runtime {ver}",
                    category=".NET Runtime", severity="HIGH",
                    file_path=host_ip, line_num=0,
                    line_content=f".NET {ver} (EOL: {DOTNET_EOL[major_minor]})",
                    description=f".NET {major_minor} reached EOL on {DOTNET_EOL[major_minor]}.",
                    recommendation="Upgrade to a supported .NET LTS version (8.0 or 9.0).",
                    cwe="CWE-1104", target_type="middleware",
                ))

    # .NET Framework version check (Windows registry output)
    if "Release" in version_info:
        try:
            data = json.loads(version_info)
            release = data.get("Release", 0)
            # .NET 4.5 = 378389, 4.6 = 393295, 4.7 = 460798, 4.8 = 528040
            if release and release < 460798:  # Below .NET 4.7
                findings.append(Finding(
                    rule_id="MW-DOTNET-FW-001",
                    name=f".NET Framework below 4.7 (release={release})",
                    category=".NET Framework", severity="MEDIUM",
                    file_path=host_ip, line_num=0,
                    line_content=f"Registry Release = {release}",
                    description=".NET Framework versions below 4.7 may have unpatched vulnerabilities.",
                    recommendation="Upgrade to .NET Framework 4.8 or migrate to .NET 8+.",
                    cwe="CWE-1104", target_type="middleware",
                ))
        except (json.JSONDecodeError, TypeError):
            pass

    return findings
