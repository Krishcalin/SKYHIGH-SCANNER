"""
Database Active Vulnerability Scanner.

Detects and scans databases on target hosts:
  - Oracle Database (TNS on 1521, OEM on 5500)
  - MySQL / MariaDB (port 3306)
  - MongoDB (port 27017)

Rule ID format: DB-{PLATFORM}-{CATEGORY}-{NNN}
"""

from __future__ import annotations

import socket

from ..core.credential_manager import CredentialManager
from ..core.ip_utils import expand_ip_range
from ..core.scanner_base import ScannerBase


class DatabaseScanner(ScannerBase):
    """Active vulnerability scanner for databases."""

    SCANNER_NAME = "SkyHigh Database Scanner"
    SCANNER_VERSION = "1.0.0"
    TARGET_TYPE = "database"

    def __init__(self, target: str, credentials: CredentialManager,
                 max_hosts: int = 256, timeout: int = 30,
                 verbose: bool = False, profile=None):
        super().__init__(verbose=verbose, profile=profile)
        self.target = target
        self.credentials = credentials
        self.max_hosts = max_hosts
        self.timeout = timeout

    def scan(self) -> None:
        self._start_timer()
        hosts = expand_ip_range(self.target)[:self.max_hosts]

        for host_ip in hosts:
            self._info(f"Scanning databases on: {host_ip}")
            try:
                self._scan_host(host_ip)
                self.targets_scanned.append(host_ip)
            except Exception as e:
                self._warn(f"Failed to scan {host_ip}: {e}")
                self.targets_failed.append(host_ip)

        self._stop_timer()

    def _scan_host(self, host_ip: str) -> None:
        """Detect running databases by port probing and run checks."""
        if not self._check_enabled("database"):
            return

        # Oracle TNS (1521)
        if self._port_open(host_ip, 1521):
            self._vprint(f"  Oracle TNS detected on {host_ip}:1521")
            self._run_oracle_checks(host_ip)

        # MySQL/MariaDB (3306)
        if self._port_open(host_ip, 3306):
            banner = self._grab_banner(host_ip, 3306)
            self._vprint(f"  MySQL/MariaDB detected on {host_ip}:3306 — {banner}")
            self._run_mysql_checks(host_ip, banner)

        # MongoDB (27017)
        if self._port_open(host_ip, 27017):
            self._vprint(f"  MongoDB detected on {host_ip}:27017")
            self._run_mongodb_checks(host_ip)

    def _port_open(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=3):
                return True
        except (OSError, socket.timeout):
            return False

    def _grab_banner(self, host: str, port: int) -> str:
        try:
            with socket.create_connection((host, port), timeout=5) as s:
                s.settimeout(3)
                return s.recv(1024).decode("utf-8", errors="replace").strip()
        except Exception:
            return ""

    def _run_oracle_checks(self, host_ip: str) -> None:
        try:
            from ..databases.oracle_db_checks import run_checks
            findings = run_checks(host_ip, self.credentials, self.timeout, self.verbose)
            for f in findings:
                self._add_finding(f)
        except ImportError:
            self._vprint("  Oracle check module not available")
        except Exception as e:
            self._warn(f"  Oracle checks failed: {e}")

    def _run_mysql_checks(self, host_ip: str, banner: str) -> None:
        try:
            from ..databases.mysql_checks import run_checks
            findings = run_checks(host_ip, banner, self.credentials,
                                  self.timeout, self.verbose)
            for f in findings:
                self._add_finding(f)
        except ImportError:
            self._vprint("  MySQL check module not available")
        except Exception as e:
            self._warn(f"  MySQL checks failed: {e}")

    def _run_mongodb_checks(self, host_ip: str) -> None:
        try:
            from ..databases.mongodb_checks import run_checks
            findings = run_checks(host_ip, self.credentials, self.timeout, self.verbose)
            for f in findings:
                self._add_finding(f)
        except ImportError:
            self._vprint("  MongoDB check module not available")
        except Exception as e:
            self._warn(f"  MongoDB checks failed: {e}")
