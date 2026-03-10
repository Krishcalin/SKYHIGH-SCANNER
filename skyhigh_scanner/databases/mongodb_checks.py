"""
MongoDB check module.

Rule ID format: DB-MONGO-{CATEGORY}-{NNN}
Checks: auth disabled, bind to 0.0.0.0, no TLS, version CVEs, audit.
"""

from __future__ import annotations

import re
import socket
from typing import List

from ..core.finding import Finding
from ..core.credential_manager import CredentialManager


def run_checks(host_ip: str, credentials: CredentialManager,
               timeout: int = 30, verbose: bool = False) -> List[Finding]:
    findings: List[Finding] = []

    # Banner grab for version
    try:
        with socket.create_connection((host_ip, 27017), timeout=5) as s:
            s.settimeout(3)
            # MongoDB responds to isMaster command but also has a banner
            s.recv(1024)
    except Exception:
        pass

    # SSH-based config checks
    if credentials.has_ssh():
        from ..core.transport import SSHTransport, HAS_PARAMIKO
        if HAS_PARAMIKO:
            try:
                cred = credentials.ssh
                with SSHTransport(host=host_ip, username=cred.username,
                                  password=cred.password, key_file=cred.key_file,
                                  port=cred.port, timeout=timeout) as ssh:
                    _check_config(ssh, host_ip, findings)
                    _check_version(ssh, host_ip, findings)
            except Exception:
                pass

    # Unauthenticated access check
    _check_unauth_access(host_ip, findings)

    return findings


def _check_config(ssh, host_ip: str, findings: List[Finding]) -> None:
    """Check mongod.conf for security settings."""
    config = ssh.execute(
        "cat /etc/mongod.conf 2>/dev/null || "
        "cat /etc/mongodb.conf 2>/dev/null || true"
    )
    if not config.strip():
        return

    # Authorization disabled
    if re.search(r"authorization\s*:\s*disabled", config, re.IGNORECASE):
        findings.append(Finding(
            rule_id="DB-MONGO-AUTH-001", name="MongoDB authorization disabled",
            category="MongoDB Authentication", severity="CRITICAL",
            file_path=host_ip, line_num=0,
            line_content="security.authorization: disabled",
            description="MongoDB has no authentication — anyone can read/write data.",
            recommendation="Set security.authorization: enabled in mongod.conf.",
            cwe="CWE-306", target_type="database",
        ))
    elif "authorization" not in config.lower():
        findings.append(Finding(
            rule_id="DB-MONGO-AUTH-002", name="MongoDB authorization not configured",
            category="MongoDB Authentication", severity="CRITICAL",
            file_path=host_ip, line_num=0,
            line_content="security.authorization not set",
            description="Authorization is not explicitly enabled.",
            recommendation="Add security.authorization: enabled to mongod.conf.",
            cwe="CWE-306", target_type="database",
        ))

    # Bind IP
    m = re.search(r"bindIp\s*:\s*(\S+)", config)
    if m and "0.0.0.0" in m.group(1):
        findings.append(Finding(
            rule_id="DB-MONGO-NET-001", name="MongoDB bound to all interfaces",
            category="MongoDB Network", severity="HIGH",
            file_path=host_ip, line_num=0,
            line_content=f"bindIp: {m.group(1)}",
            description="MongoDB accepts connections from all network interfaces.",
            recommendation="Set bindIp to 127.0.0.1 or specific trusted IPs.",
            cwe="CWE-284", target_type="database",
        ))

    # TLS
    if "tls" not in config.lower() and "ssl" not in config.lower():
        findings.append(Finding(
            rule_id="DB-MONGO-NET-002", name="MongoDB TLS/SSL not configured",
            category="MongoDB Network", severity="HIGH",
            file_path=host_ip, line_num=0,
            line_content="No TLS/SSL configuration found",
            description="MongoDB connections are unencrypted.",
            recommendation="Enable TLS in net.tls section of mongod.conf.",
            cwe="CWE-319", target_type="database",
        ))

    # Audit log
    if "auditlog" not in config.lower() and "auditLog" not in config:
        findings.append(Finding(
            rule_id="DB-MONGO-AUDIT-001", name="MongoDB audit log not enabled",
            category="MongoDB Audit", severity="MEDIUM",
            file_path=host_ip, line_num=0,
            line_content="auditLog not configured",
            description="Database operations are not being audited.",
            recommendation="Enable auditLog in mongod.conf (Enterprise feature).",
            cwe="CWE-778", target_type="database",
        ))


def _check_version(ssh, host_ip: str, findings: List[Finding]) -> None:
    """Check MongoDB version for EOL."""
    output = ssh.execute("mongod --version 2>/dev/null || true").strip()
    m = re.search(r"v(\d+\.\d+\.\d+)", output)
    if m:
        ver = m.group(1)
        major_minor = ".".join(ver.split(".")[:2])
        eol = {"3.6": "2021-04", "4.0": "2022-04", "4.2": "2023-04",
               "4.4": "2024-02", "5.0": "2024-10"}
        if major_minor in eol:
            findings.append(Finding(
                rule_id="DB-MONGO-VER-001",
                name=f"End-of-life MongoDB {ver}",
                category="MongoDB Version", severity="HIGH",
                file_path=host_ip, line_num=0,
                line_content=f"MongoDB {ver} (EOL: {eol[major_minor]})",
                description=f"MongoDB {major_minor} is end-of-life.",
                recommendation="Upgrade to MongoDB 7.0+ or latest supported.",
                cwe="CWE-1104", target_type="database",
            ))


def _check_unauth_access(host_ip: str, findings: List[Finding]) -> None:
    """Test if MongoDB allows unauthenticated access."""
    try:
        with socket.create_connection((host_ip, 27017), timeout=5) as s:
            # Send isMaster command (minimal wire protocol)
            # This is a simplified check — a full implementation would
            # use pymongo or construct the wire protocol message
            s.settimeout(5)
            # If we can connect and get data back without auth, it's open
            # For now, just flag that port 27017 is reachable
            findings.append(Finding(
                rule_id="DB-MONGO-NET-003",
                name="MongoDB port 27017 accessible",
                category="MongoDB Network", severity="MEDIUM",
                file_path=host_ip, line_num=0,
                line_content=f"{host_ip}:27017 — TCP open",
                description="MongoDB port is reachable. Verify authentication is enforced.",
                recommendation="Ensure authorization is enabled and firewall restricts access.",
                cwe="CWE-284", target_type="database",
            ))
    except Exception:
        pass
