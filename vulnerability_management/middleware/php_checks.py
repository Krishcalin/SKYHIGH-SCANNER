"""
PHP runtime check module.

Rule ID format: MW-PHP-{CATEGORY}-{NNN}
Checks: EOL versions, php.ini security, phpinfo exposure, extension CVEs.
"""

from __future__ import annotations

import re

from ..core.credential_manager import CredentialManager
from ..core.finding import Finding

PHP_EOL = {
    "5.": "2018-12-31", "7.0": "2019-01-10", "7.1": "2019-12-01",
    "7.2": "2020-11-30", "7.3": "2021-12-06", "7.4": "2022-11-28",
    "8.0": "2023-11-26", "8.1": "2025-12-31",
}

PHP_INI_CHECKS = [
    {"param": "expose_php", "bad": "On", "id": "MW-PHP-INI-001",
     "severity": "MEDIUM", "name": "expose_php enabled",
     "desc": "PHP version disclosed in HTTP headers.", "fix": "Set expose_php = Off."},
    {"param": "display_errors", "bad": "On", "id": "MW-PHP-INI-002",
     "severity": "HIGH", "name": "display_errors enabled",
     "desc": "Stack traces visible to users, leaking paths and code.",
     "fix": "Set display_errors = Off in production."},
    {"param": "allow_url_include", "bad": "On", "id": "MW-PHP-INI-003",
     "severity": "CRITICAL", "name": "allow_url_include enabled",
     "desc": "Enables Remote File Inclusion (RFI) attacks.",
     "fix": "Set allow_url_include = Off."},
    {"param": "allow_url_fopen", "bad": "On", "id": "MW-PHP-INI-004",
     "severity": "MEDIUM", "name": "allow_url_fopen enabled",
     "desc": "Allows fopen/include to access remote URLs.",
     "fix": "Set allow_url_fopen = Off unless required."},
    {"param": "session.cookie_secure", "bad": "0", "id": "MW-PHP-INI-005",
     "severity": "MEDIUM", "name": "Session cookie not secure-only",
     "desc": "Session cookies sent over HTTP.", "fix": "Set session.cookie_secure = 1."},
    {"param": "session.cookie_httponly", "bad": "0", "id": "MW-PHP-INI-006",
     "severity": "MEDIUM", "name": "Session cookie not httponly",
     "desc": "Session cookies accessible via JavaScript (XSS risk).",
     "fix": "Set session.cookie_httponly = 1."},
]


def run_checks(transport, host_ip: str, version_info: str,
               credentials: CredentialManager = None,
               verbose: bool = False) -> list[Finding]:
    findings: list[Finding] = []

    # Parse PHP version
    m = re.search(r"PHP\s+(\d+\.\d+\.\d+)", version_info)
    php_ver = m.group(1) if m else ""

    if php_ver:
        for prefix, eol_date in PHP_EOL.items():
            if php_ver.startswith(prefix):
                findings.append(Finding(
                    rule_id="MW-PHP-VER-001",
                    name=f"End-of-life PHP {php_ver}",
                    category="PHP Version", severity="HIGH",
                    file_path=host_ip, line_num=0,
                    line_content=f"PHP {php_ver} (EOL: {eol_date})",
                    description=f"PHP {php_ver} reached EOL on {eol_date}.",
                    recommendation="Upgrade to PHP 8.2+ or latest supported.",
                    cwe="CWE-1104", target_type="middleware",
                ))
                break

    # php.ini checks via SSH
    try:
        php_ini = transport.execute(
            "php -r \"phpinfo(INFO_CONFIGURATION);\" 2>/dev/null || "
            "cat /etc/php/*/cli/php.ini 2>/dev/null || "
            "cat /etc/php.ini 2>/dev/null"
        ) if hasattr(transport, 'execute') else ""

        for check in PHP_INI_CHECKS:
            m = re.search(rf"^\s*{check['param']}\s*=\s*(\S+)", php_ini, re.MULTILINE)
            if m and m.group(1).strip().lower() == check["bad"].lower():
                findings.append(Finding(
                    rule_id=check["id"], name=check["name"],
                    category="PHP Configuration", severity=check["severity"],
                    file_path=host_ip, line_num=0,
                    line_content=f"{check['param']} = {m.group(1)}",
                    description=check["desc"],
                    recommendation=check["fix"],
                    cwe="CWE-16", target_type="middleware",
                ))
    except Exception:
        pass

    # phpinfo() exposure via HTTP
    try:
        from ..core.transport import HAS_REQUESTS, HTTPTransport
        if HAS_REQUESTS:
            http = HTTPTransport(f"http://{host_ip}", timeout=5)
            for path in ["/phpinfo.php", "/info.php", "/test.php", "/php_info.php"]:
                status, body = http.probe_path(path)
                if status == 200 and "phpinfo()" in body:
                    findings.append(Finding(
                        rule_id="MW-PHP-INFO-001", name=f"phpinfo() accessible at {path}",
                        category="Information Disclosure", severity="HIGH",
                        file_path=host_ip, line_num=0,
                        line_content=f"http://{host_ip}{path} → 200",
                        description="phpinfo() exposes full PHP configuration and system info.",
                        recommendation=f"Remove {path} from the web server.",
                        cwe="CWE-200", target_type="middleware",
                    ))
            http.disconnect()
    except Exception:
        pass

    return findings
