"""
Auto-discovery scanner — detects target types and dispatches to specific scanners.

Runs the full pipeline:
  1. Network discovery (host probe + port scan + fingerprinting)
  2. Target classification
  3. Dispatch to Windows/Linux/Cisco/WebServer/Middleware/Database scanners
  4. Aggregate findings
"""

from __future__ import annotations

from typing import List

from ..core.scanner_base import ScannerBase
from ..core.credential_manager import CredentialManager
from ..core.discovery import NetworkDiscovery, HostInfo


class AutoScanner(ScannerBase):
    """Auto-discovery meta-scanner."""

    SCANNER_NAME = "SkyHigh Auto Scanner"
    SCANNER_VERSION = "1.0.0"
    TARGET_TYPE = "auto"

    def __init__(self, target: str, credentials: CredentialManager,
                 max_hosts: int = 256, timeout: int = 30,
                 threads: int = 10, verbose: bool = False,
                 no_discovery: bool = False):
        super().__init__(verbose=verbose)
        self.target = target
        self.credentials = credentials
        self.max_hosts = max_hosts
        self.timeout = timeout
        self.threads = threads
        self.no_discovery = no_discovery

    def scan(self) -> None:
        self._start_timer()
        self._info("Starting auto-discovery scan...")

        # Phase 1: Discovery
        discovery = NetworkDiscovery(
            ip_range=self.target,
            max_hosts=self.max_hosts,
            timeout=self.timeout,
            workers=self.threads,
            verbose=self.verbose,
        )
        hosts = discovery.discover()
        self._info(f"Discovered {len(hosts)} targets")

        # Phase 2: Dispatch to specific scanners per host
        for host in hosts:
            self.targets_scanned.append(host.ip)

            for scan_type in host.scan_types:
                try:
                    self._dispatch(scan_type, host)
                except Exception as e:
                    self._warn(f"Scanner {scan_type} failed on {host.ip}: {e}")
                    if host.ip not in self.targets_failed:
                        self.targets_failed.append(host.ip)

        self._stop_timer()
        self._info(f"Auto scan complete: {len(self.findings)} findings "
                   f"across {len(self.targets_scanned)} targets")

    def _dispatch(self, scan_type: str, host: HostInfo) -> None:
        """Dispatch to a specific scanner for one host."""
        self._vprint(f"Dispatching {scan_type} scanner for {host.ip}")

        if scan_type == "windows" and self.credentials.has_winrm():
            from .windows_scanner import WindowsScanner
            scanner = WindowsScanner(
                target=host.ip, credentials=self.credentials,
                timeout=self.timeout, verbose=self.verbose,
            )
            scanner.scan()
            self.findings.extend(scanner.findings)

        elif scan_type == "linux" and self.credentials.has_ssh():
            from .linux_scanner import LinuxScanner
            scanner = LinuxScanner(
                target=host.ip, credentials=self.credentials,
                timeout=self.timeout, verbose=self.verbose,
            )
            scanner.scan()
            self.findings.extend(scanner.findings)

        elif scan_type == "cisco" and (self.credentials.has_ssh() or self.credentials.has_snmp()):
            from .cisco_scanner import CiscoScanner
            scanner = CiscoScanner(
                target=host.ip, credentials=self.credentials,
                timeout=self.timeout, verbose=self.verbose,
            )
            scanner.scan()
            self.findings.extend(scanner.findings)

        elif scan_type == "webserver":
            from .webserver_scanner import WebServerScanner
            scanner = WebServerScanner(
                target=host.ip, credentials=self.credentials,
                timeout=self.timeout, verbose=self.verbose,
            )
            scanner.scan()
            self.findings.extend(scanner.findings)

        elif scan_type == "middleware" and self.credentials.has_ssh():
            from .middleware_scanner import MiddlewareScanner
            scanner = MiddlewareScanner(
                target=host.ip, credentials=self.credentials,
                timeout=self.timeout, verbose=self.verbose,
            )
            scanner.scan()
            self.findings.extend(scanner.findings)

        elif scan_type == "database":
            from .database_scanner import DatabaseScanner
            scanner = DatabaseScanner(
                target=host.ip, credentials=self.credentials,
                timeout=self.timeout, verbose=self.verbose,
            )
            scanner.scan()
            self.findings.extend(scanner.findings)
