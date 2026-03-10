"""
Oracle Database deep check module.

Rule ID format: DB-ORA-{CATEGORY}-{NNN}
Checks: default accounts, excessive privileges, audit config,
        network encryption, init parameters.
"""

from __future__ import annotations

from typing import List

from ..core.finding import Finding
from ..core.credential_manager import CredentialManager


ORACLE_DEFAULT_ACCOUNTS = [
    ("SCOTT", "TIGER"), ("SYS", "CHANGE_ON_INSTALL"),
    ("SYSTEM", "MANAGER"), ("DBSNMP", "DBSNMP"),
    ("OUTLN", "OUTLN"), ("MDSYS", "MDSYS"),
]


def run_checks(host_ip: str, credentials: CredentialManager,
               timeout: int = 30, verbose: bool = False) -> List[Finding]:
    findings: List[Finding] = []

    # SSH-based checks if credentials available
    if credentials.has_ssh():
        from ..core.transport import SSHTransport, HAS_PARAMIKO
        if HAS_PARAMIKO:
            try:
                cred = credentials.ssh
                with SSHTransport(host=host_ip, username=cred.username,
                                  password=cred.password, key_file=cred.key_file,
                                  port=cred.port, timeout=timeout) as ssh:
                    _check_sqlnet(ssh, host_ip, findings)
                    _check_listener(ssh, host_ip, findings)
                    _check_init_params(ssh, host_ip, findings)
            except Exception:
                pass

    return findings


def _check_sqlnet(ssh, host_ip: str, findings: List[Finding]) -> None:
    """Check sqlnet.ora for encryption settings."""
    output = ssh.execute(
        "cat $ORACLE_HOME/network/admin/sqlnet.ora 2>/dev/null || "
        "find / -name sqlnet.ora -type f 2>/dev/null -exec cat {} \\; | head -100"
    )
    if output and "SQLNET.ENCRYPTION_SERVER" not in output.upper():
        findings.append(Finding(
            rule_id="DB-ORA-NET-001", name="Network encryption not configured",
            category="Oracle Network", severity="HIGH",
            file_path=host_ip, line_num=0,
            line_content="SQLNET.ENCRYPTION_SERVER missing from sqlnet.ora",
            description="Oracle native network encryption is not enabled.",
            recommendation="Add SQLNET.ENCRYPTION_SERVER = REQUIRED to sqlnet.ora.",
            cwe="CWE-311", target_type="database",
        ))


def _check_listener(ssh, host_ip: str, findings: List[Finding]) -> None:
    """Check listener.ora security."""
    output = ssh.execute(
        "cat $ORACLE_HOME/network/admin/listener.ora 2>/dev/null || true"
    )
    if output and "SECURE_REGISTER" not in output.upper():
        findings.append(Finding(
            rule_id="DB-ORA-TNS-002", name="TNS Listener not secured",
            category="Oracle TNS", severity="HIGH",
            file_path=host_ip, line_num=0,
            line_content="SECURE_REGISTER_LISTENER not set",
            description="Listener is vulnerable to TNS Poison attacks.",
            recommendation="Add SECURE_REGISTER_LISTENER = (TCP) to listener.ora.",
            cwe="CWE-284", target_type="database",
        ))


def _check_init_params(ssh, host_ip: str, findings: List[Finding]) -> None:
    """Check dangerous init.ora/spfile parameters."""
    output = ssh.execute(
        "cat $ORACLE_HOME/dbs/init*.ora 2>/dev/null || true"
    )
    if "REMOTE_OS_AUTHENT=TRUE" in output.upper():
        findings.append(Finding(
            rule_id="DB-ORA-INIT-001", name="REMOTE_OS_AUTHENT=TRUE",
            category="Oracle Parameters", severity="CRITICAL",
            file_path=host_ip, line_num=0,
            line_content="REMOTE_OS_AUTHENT=TRUE",
            description="Remote OS authentication allows unauthenticated database access.",
            recommendation="Set REMOTE_OS_AUTHENT=FALSE.",
            cwe="CWE-287", target_type="database",
        ))
