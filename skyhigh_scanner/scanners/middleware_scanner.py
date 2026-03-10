"""
Middleware / Runtime Meta-Scanner.

Detects installed middleware and runtimes on target hosts via SSH or WinRM,
then dispatches to specific check modules:
  - Java (JDK/JRE, JBoss/WildFly, Spring Framework/Boot)
  - .NET Framework / .NET Core / ASP.NET
  - PHP runtime + extensions
  - Node.js + Express.js
  - Laravel Framework
  - Oracle DB client

Rule ID format: MW-{PLATFORM}-{CATEGORY}-{NNN}
"""

from __future__ import annotations

import re

from ..core.scanner_base import ScannerBase
from ..core.credential_manager import CredentialManager
from ..core.ip_utils import expand_ip_range
from ..core.transport import SSHTransport, WinRMTransport, HAS_PARAMIKO, HAS_WINRM


class MiddlewareScanner(ScannerBase):
    """Meta-scanner for middleware and runtime environments."""

    SCANNER_NAME = "SkyHigh Middleware Scanner"
    SCANNER_VERSION = "1.0.0"
    TARGET_TYPE = "middleware"

    def __init__(self, target: str, credentials: CredentialManager,
                 max_hosts: int = 256, timeout: int = 30,
                 verbose: bool = False):
        super().__init__(verbose=verbose)
        self.target = target
        self.credentials = credentials
        self.max_hosts = max_hosts
        self.timeout = timeout

    def scan(self) -> None:
        self._start_timer()
        hosts = expand_ip_range(self.target)[:self.max_hosts]

        for host_ip in hosts:
            self._info(f"Scanning middleware on: {host_ip}")
            try:
                self._scan_host(host_ip)
                self.targets_scanned.append(host_ip)
            except Exception as e:
                self._warn(f"Failed to scan {host_ip}: {e}")
                self.targets_failed.append(host_ip)

        self._stop_timer()

    def _scan_host(self, host_ip: str) -> None:
        """Detect and scan middleware on a single host."""
        # Try SSH first, then WinRM
        if self.credentials.has_ssh() and HAS_PARAMIKO:
            self._scan_via_ssh(host_ip)
        elif self.credentials.has_winrm() and HAS_WINRM:
            self._scan_via_winrm(host_ip)
        else:
            self._warn(f"No SSH or WinRM credentials for {host_ip}")

    def _scan_via_ssh(self, host_ip: str) -> None:
        cred = self.credentials.ssh
        with SSHTransport(host=host_ip, username=cred.username,
                          password=cred.password, key_file=cred.key_file,
                          port=cred.port, timeout=self.timeout) as ssh:
            # Detect Java
            java_ver = ssh.execute("java -version 2>&1 || true").strip()
            if "version" in java_ver.lower():
                self._vprint(f"  Java detected: {java_ver.split(chr(10))[0]}")
                self._dispatch_check("java", ssh, host_ip, java_ver)

            # Detect .NET Core
            dotnet_ver = ssh.execute("dotnet --list-runtimes 2>/dev/null || true").strip()
            if "Microsoft" in dotnet_ver:
                self._vprint(f"  .NET detected")
                self._dispatch_check("dotnet", ssh, host_ip, dotnet_ver)

            # Detect PHP
            php_ver = ssh.execute("php -v 2>/dev/null || true").strip()
            if "PHP" in php_ver:
                self._vprint(f"  PHP detected: {php_ver.split(chr(10))[0]}")
                self._dispatch_check("php", ssh, host_ip, php_ver)

            # Detect Node.js
            node_ver = ssh.execute("node -v 2>/dev/null || true").strip()
            if node_ver.startswith("v"):
                self._vprint(f"  Node.js detected: {node_ver}")
                self._dispatch_check("nodejs", ssh, host_ip, node_ver)

            # Detect Laravel
            laravel_ver = ssh.execute(
                "find / -maxdepth 4 -name artisan -type f 2>/dev/null | head -1"
            ).strip()
            if laravel_ver:
                self._vprint(f"  Laravel detected at: {laravel_ver}")
                self._dispatch_check("laravel", ssh, host_ip, laravel_ver)

            # Detect Oracle
            oracle_ver = ssh.execute(
                "echo $ORACLE_HOME && "
                "$ORACLE_HOME/bin/sqlplus -V 2>/dev/null || true"
            ).strip()
            if "Release" in oracle_ver or "Oracle" in oracle_ver:
                self._vprint(f"  Oracle detected")
                self._dispatch_check("oracle", ssh, host_ip, oracle_ver)

    def _scan_via_winrm(self, host_ip: str) -> None:
        cred = self.credentials.winrm
        transport = WinRMTransport(
            host=host_ip, username=cred.username,
            password=cred.password, domain=cred.domain,
            port=cred.port, use_ssl=cred.use_ssl,
            timeout=self.timeout,
        )
        transport.connect()
        try:
            # Detect Java
            java_ver = transport.run_cmd("java -version 2>&1").strip()
            if "version" in java_ver.lower():
                self._dispatch_check("java", transport, host_ip, java_ver)

            # Detect .NET Framework (Windows registry)
            dotnet_ver = transport.run_ps(
                "Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full' "
                "| Get-ItemProperty | Select-Object Release, Version | ConvertTo-Json"
            ).strip()
            if dotnet_ver:
                self._dispatch_check("dotnet", transport, host_ip, dotnet_ver)

            # Detect PHP
            php_ver = transport.run_cmd("php -v 2>&1").strip()
            if "PHP" in php_ver:
                self._dispatch_check("php", transport, host_ip, php_ver)

            # Detect Node.js
            node_ver = transport.run_cmd("node -v 2>&1").strip()
            if node_ver.startswith("v"):
                self._dispatch_check("nodejs", transport, host_ip, node_ver)
        finally:
            transport.disconnect()

    def _dispatch_check(self, platform: str, transport, host_ip: str,
                        version_info: str) -> None:
        """Dispatch to platform-specific check module."""
        try:
            if platform == "java":
                from ..middleware.java_checks import run_checks
            elif platform == "dotnet":
                from ..middleware.dotnet_checks import run_checks
            elif platform == "php":
                from ..middleware.php_checks import run_checks
            elif platform == "nodejs":
                from ..middleware.nodejs_checks import run_checks
            elif platform == "laravel":
                from ..middleware.laravel_checks import run_checks
            elif platform == "oracle":
                from ..middleware.oracle_checks import run_checks
            else:
                return
            findings = run_checks(transport, host_ip, version_info,
                                  self.credentials, self.verbose)
            for f in findings:
                self._add_finding(f)
        except ImportError:
            self._vprint(f"  {platform} check module not available")
        except Exception as e:
            self._warn(f"  {platform} checks failed: {e}")
