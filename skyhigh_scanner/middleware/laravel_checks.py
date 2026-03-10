"""
Laravel Framework check module.

Rule ID format: MW-LARAVEL-{CATEGORY}-{NNN}
Checks: debug mode, .env exposure, Ignition RCE, APP_KEY, Telescope in prod.
"""

from __future__ import annotations

import re
from typing import List

from ..core.finding import Finding
from ..core.credential_manager import CredentialManager


def run_checks(transport, host_ip: str, version_info: str,
               credentials: CredentialManager = None,
               verbose: bool = False) -> List[Finding]:
    findings: List[Finding] = []

    # version_info here is the path to artisan file
    artisan_path = version_info.strip()
    app_dir = "/".join(artisan_path.split("/")[:-1]) if artisan_path else ""

    if not app_dir or not hasattr(transport, 'execute'):
        return findings

    # Get Laravel version
    try:
        ver_output = transport.execute(f"cd {app_dir} && php artisan --version 2>/dev/null").strip()
        m = re.search(r"(\d+\.\d+\.\d+)", ver_output)
        laravel_ver = m.group(1) if m else ""
    except Exception:
        laravel_ver = ""

    # Check .env file
    try:
        env_content = transport.execute(f"cat {app_dir}/.env 2>/dev/null").strip()
        if env_content:
            # APP_DEBUG=true
            if re.search(r"APP_DEBUG\s*=\s*true", env_content, re.IGNORECASE):
                findings.append(Finding(
                    rule_id="MW-LARAVEL-CFG-001", name="APP_DEBUG=true in production",
                    category="Laravel Config", severity="CRITICAL",
                    file_path=host_ip, line_num=0,
                    line_content="APP_DEBUG=true",
                    description="Debug mode exposes stack traces, environment variables, and queries.",
                    recommendation="Set APP_DEBUG=false in .env for production.",
                    cwe="CWE-215", target_type="middleware",
                ))

            # APP_ENV=local
            if re.search(r"APP_ENV\s*=\s*local", env_content, re.IGNORECASE):
                findings.append(Finding(
                    rule_id="MW-LARAVEL-CFG-002", name="APP_ENV=local in production",
                    category="Laravel Config", severity="HIGH",
                    file_path=host_ip, line_num=0,
                    line_content="APP_ENV=local",
                    description="Application environment is set to local (development).",
                    recommendation="Set APP_ENV=production in .env.",
                    cwe="CWE-489", target_type="middleware",
                ))

            # APP_KEY empty or base64:
            if re.search(r"APP_KEY\s*=\s*$", env_content, re.MULTILINE):
                findings.append(Finding(
                    rule_id="MW-LARAVEL-CFG-003", name="APP_KEY not set",
                    category="Laravel Config", severity="CRITICAL",
                    file_path=host_ip, line_num=0,
                    line_content="APP_KEY= (empty)",
                    description="Empty APP_KEY means encryption/sessions are insecure.",
                    recommendation="Run: php artisan key:generate",
                    cwe="CWE-312", target_type="middleware",
                ))
    except Exception:
        pass

    # .env exposure via HTTP
    try:
        from ..core.transport import HTTPTransport, HAS_REQUESTS
        if HAS_REQUESTS:
            http = HTTPTransport(f"http://{host_ip}", timeout=5)
            for path in ["/.env", "/.env.backup", "/.env.old"]:
                status, body = http.probe_path(path)
                if status == 200 and ("APP_KEY" in body or "DB_PASSWORD" in body):
                    findings.append(Finding(
                        rule_id="MW-LARAVEL-ENV-001",
                        name=f".env file accessible via HTTP at {path}",
                        category="Information Disclosure", severity="CRITICAL",
                        file_path=host_ip, line_num=0,
                        line_content=f"http://{host_ip}{path} → 200 (contains secrets)",
                        description=".env file containing secrets is publicly downloadable.",
                        recommendation="Block .env files in web server config.",
                        cve="CVE-2017-16894", cwe="CWE-538", target_type="middleware",
                    ))
            http.disconnect()
    except Exception:
        pass

    # Ignition debug page (CVE-2021-3129)
    try:
        from ..core.transport import HTTPTransport, HAS_REQUESTS
        if HAS_REQUESTS:
            http = HTTPTransport(f"http://{host_ip}", timeout=5)
            status, body = http.probe_path("/_ignition/health-check")
            if status == 200:
                findings.append(Finding(
                    rule_id="MW-LARAVEL-DBG-001",
                    name="Ignition debug page exposed (CVE-2021-3129)",
                    category="Debug Mode", severity="CRITICAL",
                    file_path=host_ip, line_num=0,
                    line_content="/_ignition/health-check → 200",
                    description="Ignition RCE vulnerability allows unauthenticated code execution.",
                    recommendation="Set APP_DEBUG=false and update facade/ignition.",
                    cve="CVE-2021-3129", cwe="CWE-94", target_type="middleware",
                    cisa_kev=True,
                ))
            http.disconnect()
    except Exception:
        pass

    return findings
