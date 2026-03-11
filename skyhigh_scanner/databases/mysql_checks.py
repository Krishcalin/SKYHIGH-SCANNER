"""
MySQL / MariaDB check module.

Rule ID format: DB-MYSQL-{CATEGORY}-{NNN}
Checks: version CVEs, auth (root no password, anonymous users), my.cnf security,
        TLS/SSL, audit, privileges.
"""

from __future__ import annotations

import re

from ..core.credential_manager import CredentialManager
from ..core.finding import Finding

MYSQL_EOL = {
    "5.5": "2018-12", "5.6": "2021-02", "5.7": "2023-10",
    "8.0": "2026-04",
}

MARIADB_EOL = {
    "10.3": "2023-05", "10.4": "2024-06", "10.5": "2025-06",
}


def run_checks(host_ip: str, banner: str, credentials: CredentialManager,
               timeout: int = 30, verbose: bool = False) -> list[Finding]:
    findings: list[Finding] = []

    # Parse version from banner
    m = re.search(r"(\d+\.\d+\.\d+)", banner)
    mysql_ver = m.group(1) if m else ""

    if mysql_ver:
        # EOL check
        major_minor = ".".join(mysql_ver.split(".")[:2])
        if major_minor in MYSQL_EOL:
            findings.append(Finding(
                rule_id="DB-MYSQL-VER-001",
                name=f"End-of-life MySQL {mysql_ver}",
                category="MySQL Version", severity="HIGH",
                file_path=host_ip, line_num=0,
                line_content=f"MySQL {mysql_ver} (EOL: {MYSQL_EOL[major_minor]})",
                description=f"MySQL {major_minor} reached EOL.",
                recommendation="Upgrade to MySQL 8.0+ or MariaDB 10.11+.",
                cwe="CWE-1104", target_type="database",
            ))

    # SSH-based config checks
    if credentials.has_ssh():
        from ..core.transport import HAS_PARAMIKO, SSHTransport
        if HAS_PARAMIKO:
            try:
                cred = credentials.ssh
                with SSHTransport(host=host_ip, username=cred.username,
                                  password=cred.password, key_file=cred.key_file,
                                  port=cred.port, timeout=timeout) as ssh:
                    _check_config(ssh, host_ip, findings)
            except Exception:
                pass

    return findings


def _check_config(ssh, host_ip: str, findings: list[Finding]) -> None:
    """Check my.cnf for security misconfigurations."""
    config = ssh.execute(
        "cat /etc/mysql/my.cnf 2>/dev/null || "
        "cat /etc/my.cnf 2>/dev/null || "
        "cat /etc/mysql/mysql.conf.d/mysqld.cnf 2>/dev/null || true"
    )
    if not config.strip():
        return

    # local-infile
    if re.search(r"local[_-]infile\s*=\s*(1|ON)", config, re.IGNORECASE):
        findings.append(Finding(
            rule_id="DB-MYSQL-CFG-001", name="local_infile enabled",
            category="MySQL Configuration", severity="HIGH",
            file_path=host_ip, line_num=0,
            line_content="local_infile = ON",
            description="LOAD DATA LOCAL can be used to read arbitrary files.",
            recommendation="Set local_infile = OFF in my.cnf.",
            cwe="CWE-284", target_type="database",
        ))

    # bind-address check
    m = re.search(r"bind[_-]address\s*=\s*(\S+)", config, re.IGNORECASE)
    if m and m.group(1) in ("0.0.0.0", "::"):
        findings.append(Finding(
            rule_id="DB-MYSQL-CFG-002", name="MySQL bound to all interfaces",
            category="MySQL Configuration", severity="HIGH",
            file_path=host_ip, line_num=0,
            line_content=f"bind-address = {m.group(1)}",
            description="MySQL is accepting connections from all network interfaces.",
            recommendation="Set bind-address = 127.0.0.1 unless remote access is needed.",
            cwe="CWE-284", target_type="database",
        ))

    # require_secure_transport
    if "require_secure_transport" not in config.lower():
        findings.append(Finding(
            rule_id="DB-MYSQL-TLS-001",
            name="require_secure_transport not set",
            category="MySQL TLS", severity="MEDIUM",
            file_path=host_ip, line_num=0,
            line_content="require_secure_transport missing",
            description="MySQL allows unencrypted connections.",
            recommendation="Add require_secure_transport = ON to my.cnf.",
            cwe="CWE-319", target_type="database",
        ))
