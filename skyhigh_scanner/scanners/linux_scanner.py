"""
Linux Active Vulnerability Scanner.

Connects via SSH to scan Linux systems for:
  - Kernel CVEs and package vulnerabilities
  - CIS benchmark compliance
  - SSH hardening (sshd_config)
  - File permissions
  - Network security (sysctl)
  - Unnecessary services
  - Audit/logging configuration

Rule ID format: LNX-{CATEGORY}-{NNN}
"""

from __future__ import annotations

import re

from ..core.scanner_base import ScannerBase
from ..core.credential_manager import CredentialManager
from ..core.ip_utils import expand_ip_range
from ..core.transport import SSHTransport, HAS_PARAMIKO
from ..core.version_utils import parse_ver

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SSH hardening rules (CIS 5.2.x)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SSH_CHECKS = [
    {"id": "LNX-SSH-001", "param": "PermitRootLogin", "bad": ["yes"],
     "severity": "CRITICAL", "name": "SSH root login permitted",
     "desc": "CIS 5.2.10: Direct root SSH login should be disabled.",
     "fix": "Set PermitRootLogin to no in /etc/ssh/sshd_config.", "cwe": "CWE-250"},
    {"id": "LNX-SSH-002", "param": "Protocol", "bad": ["1"],
     "severity": "CRITICAL", "name": "SSH Protocol 1 enabled",
     "desc": "SSH v1 has known cryptographic weaknesses.",
     "fix": "Set Protocol 2 in sshd_config.", "cwe": "CWE-327"},
    {"id": "LNX-SSH-003", "param": "PasswordAuthentication", "bad": ["yes"],
     "severity": "MEDIUM", "name": "SSH password authentication enabled",
     "desc": "Key-based auth is more secure than password auth.",
     "fix": "Set PasswordAuthentication no in sshd_config.", "cwe": "CWE-287"},
    {"id": "LNX-SSH-004", "param": "PermitEmptyPasswords", "bad": ["yes"],
     "severity": "CRITICAL", "name": "SSH empty passwords permitted",
     "desc": "CIS 5.2.11: Empty passwords must be disabled.",
     "fix": "Set PermitEmptyPasswords no.", "cwe": "CWE-521"},
    {"id": "LNX-SSH-005", "param": "X11Forwarding", "bad": ["yes"],
     "severity": "LOW", "name": "SSH X11 forwarding enabled",
     "desc": "CIS 5.2.6: X11 forwarding increases attack surface.",
     "fix": "Set X11Forwarding no.", "cwe": "CWE-284"},
    {"id": "LNX-SSH-006", "param": "MaxAuthTries", "bad_fn": "gt:4",
     "severity": "MEDIUM", "name": "SSH MaxAuthTries too high",
     "desc": "CIS 5.2.7: MaxAuthTries should be 4 or fewer.",
     "fix": "Set MaxAuthTries 4.", "cwe": "CWE-307"},
    {"id": "LNX-SSH-007", "param": "ClientAliveInterval", "bad_fn": "eq:0",
     "severity": "MEDIUM", "name": "SSH ClientAliveInterval not set",
     "desc": "CIS 5.2.16: Idle timeout should be configured.",
     "fix": "Set ClientAliveInterval 300.", "cwe": "CWE-613"},
    {"id": "LNX-SSH-008", "param": "LoginGraceTime", "bad_fn": "gt:60",
     "severity": "LOW", "name": "SSH LoginGraceTime too long",
     "desc": "CIS 5.2.17: Grace time should be 60 seconds or less.",
     "fix": "Set LoginGraceTime 60.", "cwe": "CWE-613"},
    {"id": "LNX-SSH-009", "param": "AllowTcpForwarding", "bad": ["yes"],
     "severity": "MEDIUM", "name": "SSH TCP forwarding enabled",
     "desc": "TCP forwarding can be used for lateral movement.",
     "fix": "Set AllowTcpForwarding no.", "cwe": "CWE-284"},
    {"id": "LNX-SSH-010", "param": "LogLevel", "bad": ["QUIET"],
     "severity": "MEDIUM", "name": "SSH logging level too low",
     "desc": "CIS 5.2.5: LogLevel should be INFO or VERBOSE.",
     "fix": "Set LogLevel INFO in sshd_config.", "cwe": "CWE-778"},
]


class LinuxScanner(ScannerBase):
    """Active vulnerability scanner for Linux systems."""

    SCANNER_NAME = "SkyHigh Linux Scanner"
    SCANNER_VERSION = "1.0.0"
    TARGET_TYPE = "linux"

    def __init__(self, target: str, credentials: CredentialManager,
                 max_hosts: int = 256, timeout: int = 30,
                 verbose: bool = False, profile=None):
        super().__init__(verbose=verbose, profile=profile)
        self.target = target
        self.credentials = credentials
        self.max_hosts = max_hosts
        self.timeout = timeout

    def scan(self) -> None:
        if not HAS_PARAMIKO:
            self._error("paramiko not installed. Run: pip install paramiko")
            return
        if not self.credentials.has_ssh():
            self._error("SSH credentials required (--ssh-user / --ssh-password or --ssh-key)")
            return

        self._start_timer()
        hosts = expand_ip_range(self.target)[:self.max_hosts]

        for host_ip in hosts:
            self._info(f"Scanning Linux host: {host_ip}")
            try:
                self._scan_host(host_ip)
                self.targets_scanned.append(host_ip)
            except Exception as e:
                self._warn(f"Failed to scan {host_ip}: {e}")
                self.targets_failed.append(host_ip)

        self._stop_timer()

    def _scan_host(self, host_ip: str) -> None:
        cred = self.credentials.ssh
        with SSHTransport(host=host_ip, username=cred.username,
                          password=cred.password, key_file=cred.key_file,
                          port=cred.port, timeout=self.timeout) as ssh:
            # Collect system info
            kernel = ssh.execute("uname -r").strip()
            os_release = ssh.execute("cat /etc/os-release 2>/dev/null").strip()
            distro = self._detect_distro(os_release)
            self._vprint(f"  Kernel: {kernel}, Distro: {distro}")

            # Run check modules (gated by scan profile)
            if self._check_enabled("crypto"):
                self._check_ssh_config(ssh, host_ip)
            if self._check_enabled("auth"):
                self._check_account_security(ssh, host_ip)
            if self._check_enabled("permissions"):
                self._check_file_permissions(ssh, host_ip)
            if self._check_enabled("network"):
                self._check_network_security(ssh, host_ip)
            if self._check_enabled("services"):
                self._check_services(ssh, host_ip)
            if self._check_enabled("filesystem"):
                self._check_filesystem(ssh, host_ip)
            if self._check_enabled("logging"):
                self._check_logging(ssh, host_ip)
            if self._check_enabled("kernel"):
                self._check_kernel_params(ssh, host_ip)
            if self._check_enabled("patches"):
                self._check_packages(ssh, host_ip, distro)
            if self._check_enabled("cve"):
                self._check_cves(host_ip, kernel)

    def _detect_distro(self, os_release: str) -> str:
        if "ubuntu" in os_release.lower():
            return "ubuntu"
        if "rhel" in os_release.lower() or "red hat" in os_release.lower():
            return "rhel"
        if "centos" in os_release.lower():
            return "centos"
        if "debian" in os_release.lower():
            return "debian"
        if "suse" in os_release.lower():
            return "suse"
        if "amazon" in os_release.lower():
            return "amazon"
        return "unknown"

    def _check_ssh_config(self, ssh: SSHTransport, host: str) -> None:
        """Check sshd_config against CIS benchmarks."""
        self._vprint(f"  Checking SSH config on {host}")
        try:
            config = ssh.get_file("/etc/ssh/sshd_config")
        except Exception:
            return

        for check in SSH_CHECKS:
            param = check["param"]
            m = re.search(rf"^\s*{param}\s+(\S+)", config, re.MULTILINE | re.IGNORECASE)
            if not m:
                continue
            value = m.group(1).lower()

            matched = False
            if "bad" in check:
                matched = value in [b.lower() for b in check["bad"]]
            elif "bad_fn" in check:
                fn, threshold = check["bad_fn"].split(":")
                try:
                    val_int = int(value)
                    thr_int = int(threshold)
                    if fn == "gt":
                        matched = val_int > thr_int
                    elif fn == "eq":
                        matched = val_int == thr_int
                    elif fn == "lt":
                        matched = val_int < thr_int
                except ValueError:
                    pass

            if matched:
                self._add(
                    rule_id=check["id"], category="SSH Hardening",
                    name=check["name"], severity=check["severity"],
                    file_path=host, line_num=0,
                    line_content=f"{param} = {m.group(1)}",
                    description=check["desc"],
                    recommendation=check["fix"],
                    cwe=check.get("cwe"),
                )

    def _check_account_security(self, ssh: SSHTransport, host: str) -> None:
        """Check password policies and account security."""
        self._vprint(f"  Checking account security on {host}")
        try:
            shadow = ssh.execute("cat /etc/shadow 2>/dev/null")
            for line in shadow.strip().split("\n"):
                parts = line.split(":")
                if len(parts) < 2:
                    continue
                username, password_hash = parts[0], parts[1]
                if password_hash == "" or password_hash == "!":
                    continue
                if password_hash == "!!":
                    continue  # locked
                # Empty password hash
                if password_hash in ("", "*"):
                    self._add(
                        rule_id="LNX-ACCT-001", category="Account Security",
                        name="Account with empty password",
                        severity="CRITICAL", file_path=host, line_num=0,
                        line_content=f"User: {username}",
                        description="Account has no password set.",
                        recommendation=f"Set a strong password for {username} or lock the account.",
                        cwe="CWE-521",
                    )
        except Exception:
            pass

        # Login.defs checks
        try:
            login_defs = ssh.get_file("/etc/login.defs")
            m = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", login_defs, re.MULTILINE)
            if m and int(m.group(1)) > 365:
                self._add(
                    rule_id="LNX-ACCT-002", category="Account Security",
                    name="Password max age exceeds 365 days",
                    severity="MEDIUM", file_path=host, line_num=0,
                    line_content=f"PASS_MAX_DAYS = {m.group(1)}",
                    description="CIS 5.5.1.1: Password should expire within 365 days.",
                    recommendation="Set PASS_MAX_DAYS to 365 in /etc/login.defs.",
                    cwe="CWE-262",
                )
            m = re.search(r"^\s*PASS_MIN_LEN\s+(\d+)", login_defs, re.MULTILINE)
            if m and int(m.group(1)) < 14:
                self._add(
                    rule_id="LNX-ACCT-003", category="Account Security",
                    name="Minimum password length below 14",
                    severity="HIGH", file_path=host, line_num=0,
                    line_content=f"PASS_MIN_LEN = {m.group(1)}",
                    description="CIS 5.5.1.4: Minimum password length should be 14+.",
                    recommendation="Set PASS_MIN_LEN to 14 in /etc/login.defs.",
                    cwe="CWE-521",
                )
        except Exception:
            pass

    def _check_file_permissions(self, ssh: SSHTransport, host: str) -> None:
        """Check permissions on sensitive files."""
        self._vprint(f"  Checking file permissions on {host}")
        sensitive_files = {
            "/etc/passwd":  ("LNX-PERM-001", "644"),
            "/etc/shadow":  ("LNX-PERM-002", "640"),
            "/etc/group":   ("LNX-PERM-003", "644"),
            "/etc/gshadow": ("LNX-PERM-004", "640"),
            "/etc/crontab": ("LNX-PERM-005", "600"),
        }
        for filepath, (rule_id, expected_max) in sensitive_files.items():
            try:
                result = ssh.execute(f"stat -c '%a' {filepath} 2>/dev/null").strip()
                if result and int(result, 8) > int(expected_max, 8):
                    self._add(
                        rule_id=rule_id, category="File Permissions",
                        name=f"Overly permissive {filepath}",
                        severity="HIGH", file_path=host, line_num=0,
                        line_content=f"permissions={result} (expected <={expected_max})",
                        description=f"{filepath} has permissions {result}, max should be {expected_max}.",
                        recommendation=f"chmod {expected_max} {filepath}",
                        cwe="CWE-732",
                    )
            except Exception:
                pass

    def _check_network_security(self, ssh: SSHTransport, host: str) -> None:
        """Check sysctl network security parameters."""
        self._vprint(f"  Checking network security on {host}")
        sysctl_checks = [
            {"param": "net.ipv4.ip_forward", "expected": "0", "id": "LNX-NET-001",
             "name": "IP forwarding enabled", "severity": "HIGH",
             "desc": "CIS 3.1.1: IP forwarding should be disabled unless router.",
             "fix": "Set net.ipv4.ip_forward = 0 in /etc/sysctl.conf."},
            {"param": "net.ipv4.conf.all.accept_redirects", "expected": "0", "id": "LNX-NET-002",
             "name": "ICMP redirects accepted", "severity": "MEDIUM",
             "desc": "CIS 3.3.2: ICMP redirects can be used for MITM.",
             "fix": "Set net.ipv4.conf.all.accept_redirects = 0."},
            {"param": "net.ipv4.tcp_syncookies", "expected": "1", "id": "LNX-NET-003",
             "name": "SYN cookies disabled", "severity": "MEDIUM",
             "desc": "CIS 3.3.8: SYN cookies protect against SYN flood.",
             "fix": "Set net.ipv4.tcp_syncookies = 1."},
        ]
        for check in sysctl_checks:
            try:
                result = ssh.execute(f"sysctl -n {check['param']} 2>/dev/null").strip()
                if result and result != check["expected"]:
                    self._add(
                        rule_id=check["id"], category="Network Security",
                        name=check["name"], severity=check["severity"],
                        file_path=host, line_num=0,
                        line_content=f"{check['param']} = {result}",
                        description=check["desc"],
                        recommendation=check["fix"],
                        cwe="CWE-284",
                    )
            except Exception:
                pass

    def _check_services(self, ssh: SSHTransport, host: str) -> None:
        """Check for unnecessary/risky services."""
        self._vprint(f"  Checking services on {host}")
        risky_services = {
            "telnet.socket": ("LNX-SVC-001", "CRITICAL", "Telnet service enabled",
                              "Telnet transmits credentials in cleartext."),
            "avahi-daemon": ("LNX-SVC-002", "LOW", "Avahi mDNS daemon running",
                             "CIS 2.2.3: mDNS increases attack surface."),
            "cups": ("LNX-SVC-003", "LOW", "CUPS print service running",
                     "CIS 2.2.4: Disable CUPS on servers."),
            "rpcbind": ("LNX-SVC-004", "MEDIUM", "RPC portmapper running",
                        "CIS 2.2.6: Disable rpcbind unless NFS is needed."),
        }
        try:
            result = ssh.execute("systemctl list-unit-files --state=enabled --type=service 2>/dev/null")
            for svc, (rule_id, severity, name, desc) in risky_services.items():
                if svc in result:
                    self._add(
                        rule_id=rule_id, category="Services",
                        name=name, severity=severity,
                        file_path=host, line_num=0,
                        line_content=f"{svc} = enabled",
                        description=desc,
                        recommendation=f"systemctl disable --now {svc}",
                        cwe="CWE-284",
                    )
        except Exception:
            pass

    def _check_filesystem(self, ssh: SSHTransport, host: str) -> None:
        """Check mount options for security."""
        self._vprint(f"  Checking filesystem on {host}")
        try:
            fstab = ssh.get_file("/etc/fstab")
            mounts = ssh.execute("mount")
            # Check /tmp noexec
            if "/tmp" in mounts and "noexec" not in mounts.split("/tmp")[1].split("\n")[0]:
                self._add(
                    rule_id="LNX-FS-001", category="Filesystem",
                    name="/tmp not mounted with noexec",
                    severity="MEDIUM", file_path=host, line_num=0,
                    line_content="/tmp missing noexec option",
                    description="CIS 1.1.4: /tmp should be mounted with noexec.",
                    recommendation="Add noexec to /tmp mount options in /etc/fstab.",
                    cwe="CWE-732",
                )
        except Exception:
            pass

    def _check_logging(self, ssh: SSHTransport, host: str) -> None:
        """Check logging configuration."""
        self._vprint(f"  Checking logging on {host}")
        try:
            result = ssh.execute("systemctl is-active rsyslog 2>/dev/null").strip()
            if result != "active":
                result2 = ssh.execute("systemctl is-active systemd-journald 2>/dev/null").strip()
                if result2 != "active":
                    self._add(
                        rule_id="LNX-LOG-001", category="Logging",
                        name="No logging daemon running",
                        severity="HIGH", file_path=host, line_num=0,
                        line_content="rsyslog=inactive, journald=inactive",
                        description="CIS 4.2.1: rsyslog or journald must be running.",
                        recommendation="Enable rsyslog: systemctl enable --now rsyslog.",
                        cwe="CWE-778",
                    )
        except Exception:
            pass

    def _check_kernel_params(self, ssh: SSHTransport, host: str) -> None:
        """Check kernel security parameters."""
        self._vprint(f"  Checking kernel parameters on {host}")
        try:
            aslr = ssh.execute("sysctl -n kernel.randomize_va_space 2>/dev/null").strip()
            if aslr and aslr != "2":
                self._add(
                    rule_id="LNX-KERN-001", category="Kernel Parameters",
                    name="ASLR not fully enabled",
                    severity="HIGH", file_path=host, line_num=0,
                    line_content=f"kernel.randomize_va_space = {aslr}",
                    description="CIS 1.5.2: ASLR should be set to 2 (full).",
                    recommendation="Set kernel.randomize_va_space = 2.",
                    cwe="CWE-119",
                )
        except Exception:
            pass

    def _check_packages(self, ssh: SSHTransport, host: str, distro: str) -> None:
        """Check for pending security updates."""
        self._vprint(f"  Checking packages on {host}")
        try:
            if distro in ("ubuntu", "debian"):
                result = ssh.execute(
                    "apt list --upgradable 2>/dev/null | grep -i security | wc -l"
                ).strip()
                if result and int(result) > 0:
                    self._add(
                        rule_id="LNX-PATCH-001", category="Patch Management",
                        name=f"{result} pending security updates",
                        severity="HIGH", file_path=host, line_num=0,
                        line_content=f"{result} security updates available",
                        description="System has pending security patches.",
                        recommendation="Run: apt update && apt upgrade -y",
                        cwe="CWE-1104",
                    )
            elif distro in ("rhel", "centos", "amazon"):
                result = ssh.execute(
                    "yum check-update --security 2>/dev/null | grep -c '^[a-zA-Z]'"
                ).strip()
                if result and int(result) > 0:
                    self._add(
                        rule_id="LNX-PATCH-001", category="Patch Management",
                        name=f"{result} pending security updates",
                        severity="HIGH", file_path=host, line_num=0,
                        line_content=f"{result} security updates available",
                        description="System has pending security patches.",
                        recommendation="Run: yum update --security -y",
                        cwe="CWE-1104",
                    )
        except Exception:
            pass

    def _check_cves(self, host: str, kernel_version: str) -> None:
        """Check kernel version against CVE database."""
        if not kernel_version:
            return
        try:
            from ..core.cve_database import CVEDatabase
            with CVEDatabase() as db:
                cve_findings = db.check_version("linux_kernel", kernel_version)
                for f in cve_findings:
                    f.file_path = host
                    self._add_finding(f)
        except Exception:
            pass
