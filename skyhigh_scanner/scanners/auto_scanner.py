"""
Auto-discovery scanner — detects target types and dispatches to specific scanners.

Runs the full pipeline:
  1. Network discovery (host probe + port scan + fingerprinting)
  2. Target classification (TTL, banners, HTTP headers, SNMP sysDescr)
  3. Discovery summary table
  4. Parallel dispatch to Windows/Linux/Cisco/WebServer/Middleware/Database scanners
  5. Aggregate findings with progress reporting
"""

from __future__ import annotations

import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.credential_manager import CredentialManager
from ..core.discovery import HostInfo, NetworkDiscovery
from ..core.scanner_base import ScannerBase

# ── Credential requirements per scan type ─────────────────────────
_CRED_REQUIREMENTS: dict[str, str] = {
    "windows":    "WinRM (--win-user / --win-password)",
    "linux":      "SSH (--ssh-user / --ssh-password or --ssh-key)",
    "cisco":      "SSH or SNMP (--ssh-user or --snmp-community)",
    "middleware":  "SSH (--ssh-user / --ssh-password or --ssh-key)",
}


class AutoScanner(ScannerBase):
    """Auto-discovery meta-scanner with parallel dispatch."""

    SCANNER_NAME = "SkyHigh Auto Scanner"
    SCANNER_VERSION = "1.2.0"
    TARGET_TYPE = "auto"

    def __init__(self, target: str, credentials: CredentialManager,
                 max_hosts: int = 256, timeout: int = 30,
                 threads: int = 10, verbose: bool = False,
                 no_discovery: bool = False, profile=None):
        super().__init__(verbose=verbose, profile=profile)
        self.target = target
        self.credentials = credentials
        self.max_hosts = max_hosts
        self.timeout = timeout
        self.threads = threads
        self.no_discovery = no_discovery
        self._skipped_types: dict[str, set[str]] = {}  # scan_type → {ips}
        self._lock = threading.Lock()

    # ── Main scan pipeline ────────────────────────────────────────────
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

        if not hosts:
            self._stop_timer()
            return

        # Phase 2: Discovery summary
        self._print_discovery_summary(hosts)

        # Collect targets
        for host in hosts:
            self.targets_scanned.append(host.ip)

        # Phase 3: Parallel dispatch to specific scanners
        tasks = [(scan_type, host)
                 for host in hosts
                 for scan_type in host.scan_types]
        total_dispatches = len(tasks)

        if self.threads <= 1 or total_dispatches <= 1:
            # Sequential fallback
            for i, (scan_type, host) in enumerate(tasks, 1):
                self._print_progress(i, total_dispatches, host.ip, scan_type)
                try:
                    self._dispatch(scan_type, host)
                except Exception as e:
                    self._warn(f"Scanner {scan_type} failed on {host.ip}: {e}")
                    if host.ip not in self.targets_failed:
                        self.targets_failed.append(host.ip)
        else:
            self._info(f"Dispatching {total_dispatches} scans across "
                       f"{min(self.threads, total_dispatches)} threads")
            self._dispatch_parallel(tasks, total_dispatches)

        # Phase 4: Report skipped scans
        self._report_skipped()

        self._stop_timer()
        self._info(f"Auto scan complete: {len(self.findings)} findings "
                   f"across {len(self.targets_scanned)} targets")

    # ── Parallel dispatch ────────────────────────────────────────────
    def _dispatch_parallel(self, tasks: list, total: int) -> None:
        """Run scanner dispatches in parallel using ThreadPoolExecutor."""
        done_count = 0

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {
                pool.submit(self._dispatch_one, scan_type, host): (host.ip, scan_type)
                for scan_type, host in tasks
            }
            for future in as_completed(futures):
                ip, scan_type = futures[future]
                done_count += 1
                self._print_progress(done_count, total, ip, scan_type)
                try:
                    findings, skipped = future.result()
                    with self._lock:
                        self.findings.extend(findings)
                        if skipped:
                            self._track_skipped(skipped[0], skipped[1])
                except Exception as e:
                    with self._lock:
                        self._warn(f"Scanner {scan_type} failed on {ip}: {e}")
                        if ip not in self.targets_failed:
                            self.targets_failed.append(ip)

    def _dispatch_one(self, scan_type: str, host: HostInfo):
        """Execute a single scanner dispatch, returning (findings, skip_info).

        Returns:
            tuple: (list[Finding], tuple[str,str]|None) — findings and
                   optional (scan_type, ip) if skipped.
        """
        scanner = self._create_scanner(scan_type, host)
        if scanner is None:
            return [], (scan_type, host.ip) if scan_type in _CRED_REQUIREMENTS else None
        scanner.scan()
        return scanner.findings, None

    # ── Discovery summary ─────────────────────────────────────────────
    def _print_discovery_summary(self, hosts: list[HostInfo]) -> None:
        """Print a table summarising discovered hosts."""
        print(f"\n{'─' * 78}", file=sys.stderr)
        print(f"  {'IP Address':<18} {'Hostname':<22} {'OS Guess':<14} "
              f"{'Ports':<6} {'Scan Types'}", file=sys.stderr)
        print(f"{'─' * 78}", file=sys.stderr)

        for host in hosts:
            hostname = (host.hostname[:20] + "..") if len(host.hostname) > 22 else host.hostname
            ports = len(host.services)
            scan_types = ", ".join(host.scan_types) or "none"
            print(f"  {host.ip:<18} {hostname:<22} {host.os_guess:<14} "
                  f"{ports:<6} {scan_types}", file=sys.stderr)

        print(f"{'─' * 78}\n", file=sys.stderr)

    # ── Progress reporting ────────────────────────────────────────────
    def _print_progress(self, current: int, total: int,
                        ip: str, scan_type: str) -> None:
        """Print progress indicator for current dispatch."""
        pct = round(current / total * 100) if total else 0
        self._info(f"[{current}/{total} {pct}%] Scanning {ip} → {scan_type}")

    # ── Scanner creation ─────────────────────────────────────────────
    def _create_scanner(self, scan_type: str, host: HostInfo):
        """Create a scanner instance for a given type, or None if creds missing."""

        if scan_type == "windows":
            if not self.credentials.has_winrm():
                return None
            from .windows_scanner import WindowsScanner
            return WindowsScanner(
                target=host.ip, credentials=self.credentials,
                timeout=self.timeout, verbose=self.verbose,
                profile=self.profile,
            )

        elif scan_type == "linux":
            if not self.credentials.has_ssh():
                return None
            from .linux_scanner import LinuxScanner
            return LinuxScanner(
                target=host.ip, credentials=self.credentials,
                timeout=self.timeout, verbose=self.verbose,
                profile=self.profile,
            )

        elif scan_type == "cisco":
            if not (self.credentials.has_ssh() or self.credentials.has_snmp()):
                return None
            from .cisco_scanner import CiscoScanner
            return CiscoScanner(
                target=host.ip, credentials=self.credentials,
                timeout=self.timeout, verbose=self.verbose,
                profile=self.profile,
            )

        elif scan_type == "webserver":
            from .webserver_scanner import WebServerScanner
            return WebServerScanner(
                target=host.ip, credentials=self.credentials,
                timeout=self.timeout, verbose=self.verbose,
                profile=self.profile,
            )

        elif scan_type == "middleware":
            if not self.credentials.has_ssh():
                return None
            from .middleware_scanner import MiddlewareScanner
            return MiddlewareScanner(
                target=host.ip, credentials=self.credentials,
                timeout=self.timeout, verbose=self.verbose,
                profile=self.profile,
            )

        elif scan_type == "database":
            from .database_scanner import DatabaseScanner
            return DatabaseScanner(
                target=host.ip, credentials=self.credentials,
                timeout=self.timeout, verbose=self.verbose,
                profile=self.profile,
            )

        else:
            self._vprint(f"Unknown scan type '{scan_type}' for {host.ip}")
            return None

    # ── Sequential dispatch (backward-compat) ────────────────────────
    def _dispatch(self, scan_type: str, host: HostInfo) -> None:
        """Dispatch to a specific scanner for one host (sequential mode)."""
        scanner = self._create_scanner(scan_type, host)
        if scanner is None:
            if scan_type in _CRED_REQUIREMENTS:
                self._track_skipped(scan_type, host.ip)
            return
        scanner.scan()
        self.findings.extend(scanner.findings)

    # ── Skipped scan tracking ─────────────────────────────────────────
    def _track_skipped(self, scan_type: str, ip: str) -> None:
        """Record that a scan was skipped due to missing credentials."""
        self._skipped_types.setdefault(scan_type, set()).add(ip)

    def _report_skipped(self) -> None:
        """Print summary of skipped scans due to missing credentials."""
        for scan_type, ips in sorted(self._skipped_types.items()):
            cred_hint = _CRED_REQUIREMENTS.get(scan_type, "credentials")
            self._warn(
                f"Skipped {scan_type} scan on {len(ips)} host(s) — "
                f"missing {cred_hint}"
            )

    # ── Summary override ──────────────────────────────────────────────
    def summary(self) -> dict:
        """Extend base summary with auto-scanner specific data."""
        s = super().summary()
        s["skipped_scans"] = {
            st: sorted(ips) for st, ips in self._skipped_types.items()
        }
        return s
