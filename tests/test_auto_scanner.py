"""Tests for the auto scanner and discovery enhancements."""

import pytest
from unittest.mock import patch, MagicMock

from skyhigh_scanner.core.discovery import (
    HostInfo,
    NetworkDiscovery,
    ServiceInfo,
    guess_os_from_ttl,
    _resolve_os,
    _os_confidence,
)
from skyhigh_scanner.core.credential_manager import CredentialManager
from skyhigh_scanner.scanners.auto_scanner import AutoScanner, _CRED_REQUIREMENTS


# ── TTL fingerprinting ───────────────────────────────────────────────

class TestGuessOsFromTtl:
    def test_linux_ttl_64(self):
        assert guess_os_from_ttl(64) == "Linux"

    def test_linux_ttl_lower(self):
        assert guess_os_from_ttl(50) == "Linux"

    def test_windows_ttl_128(self):
        assert guess_os_from_ttl(128) == "Windows"

    def test_windows_ttl_lower(self):
        assert guess_os_from_ttl(100) == "Windows"

    def test_network_device_ttl_255(self):
        assert guess_os_from_ttl(255) == "Network Device"

    def test_network_device_ttl_200(self):
        assert guess_os_from_ttl(200) == "Network Device"

    def test_zero_ttl(self):
        assert guess_os_from_ttl(0) == ""

    def test_negative_ttl(self):
        assert guess_os_from_ttl(-1) == ""


# ── OS signal resolution ─────────────────────────────────────────────

class TestResolveOs:
    def test_empty_signals(self):
        assert _resolve_os([]) == ""

    def test_single_linux(self):
        assert _resolve_os(["Linux"]) == "Linux"

    def test_single_windows(self):
        assert _resolve_os(["Windows"]) == "Windows"

    def test_majority_vote_linux(self):
        signals = ["Linux", "Linux", "Windows"]
        assert _resolve_os(signals) == "Linux"

    def test_majority_vote_windows(self):
        signals = ["Windows", "Windows", "Linux"]
        assert _resolve_os(signals) == "Windows"

    def test_cisco_normalisation(self):
        signals = ["Cisco IOS", "cisco ssh"]
        assert _resolve_os(signals) == "Cisco IOS"

    def test_ubuntu_maps_to_linux(self):
        signals = ["Linux (Ubuntu/Debian)", "Linux"]
        assert _resolve_os(signals) == "Linux"

    def test_network_device(self):
        assert _resolve_os(["Network Device"]) == "Network Device"


class TestOsConfidence:
    def test_empty_low(self):
        assert _os_confidence([]) == "low"

    def test_single_signal_low(self):
        assert _os_confidence(["Linux"]) == "low"

    def test_two_signals_medium(self):
        assert _os_confidence(["Linux", "Windows"]) == "medium"

    def test_two_same_signals_high(self):
        assert _os_confidence(["Linux", "Linux"]) == "high"

    def test_three_signals_high(self):
        assert _os_confidence(["Linux", "Windows", "Linux"]) == "high"


# ── HostInfo ─────────────────────────────────────────────────────────

class TestHostInfo:
    def test_ttl_default(self):
        h = HostInfo(ip="10.0.0.1")
        assert h.ttl == 0
        assert h.os_confidence == "low"

    def test_has_port(self):
        h = HostInfo(ip="10.0.0.1", services=[ServiceInfo(port=22)])
        assert h.has_port(22)
        assert not h.has_port(80)

    def test_get_service(self):
        svc = ServiceInfo(port=80, banner="nginx/1.20")
        h = HostInfo(ip="10.0.0.1", services=[svc])
        assert h.get_service(80) is svc
        assert h.get_service(443) is None


# ── classify_host ────────────────────────────────────────────────────

class TestClassifyHost:
    def _discovery(self):
        return NetworkDiscovery(ip_range="10.0.0.1", timeout=1)

    def test_windows_by_ports(self):
        d = self._discovery()
        h = HostInfo(ip="10.0.0.1", services=[
            ServiceInfo(port=445, service="microsoft-ds"),
            ServiceInfo(port=135, service="msrpc"),
            ServiceInfo(port=3389, service="ms-wbt-server"),
        ])
        d.classify_host(h)
        assert "windows" in h.scan_types
        assert "Windows" in h.os_guess

    def test_linux_by_ssh(self):
        d = self._discovery()
        h = HostInfo(ip="10.0.0.1", services=[
            ServiceInfo(port=22, service="ssh", banner="SSH-2.0-OpenSSH_8.9p1"),
        ])
        d.classify_host(h)
        assert "linux" in h.scan_types
        assert "Linux" in h.os_guess

    def test_cisco_by_ssh_banner(self):
        d = self._discovery()
        h = HostInfo(ip="10.0.0.1", services=[
            ServiceInfo(port=22, service="ssh", banner="SSH-2.0-Cisco-1.25"),
        ])
        d.classify_host(h)
        assert "cisco" in h.scan_types
        assert "Cisco" in h.os_guess

    def test_cisco_by_telnet_banner(self):
        d = self._discovery()
        h = HostInfo(ip="10.0.0.1", services=[
            ServiceInfo(port=23, service="telnet",
                        banner="User Access Verification\r\nUsername:"),
        ])
        d.classify_host(h)
        assert "cisco" in h.scan_types

    def test_webserver_apache(self):
        d = self._discovery()
        h = HostInfo(ip="10.0.0.1", services=[
            ServiceInfo(port=80, service="http", banner="Apache/2.4.52 (Ubuntu)"),
        ])
        d.classify_host(h)
        assert "webserver" in h.scan_types
        svc = h.get_service(80)
        assert svc.service == "apache-httpd"
        assert "Linux" in h.os_guess

    def test_webserver_nginx(self):
        d = self._discovery()
        h = HostInfo(ip="10.0.0.1", services=[
            ServiceInfo(port=443, service="https", banner="nginx/1.24.0"),
        ])
        d.classify_host(h)
        assert "webserver" in h.scan_types
        svc = h.get_service(443)
        assert svc.service == "nginx"

    def test_webserver_iis_marks_windows(self):
        d = self._discovery()
        h = HostInfo(ip="10.0.0.1", services=[
            ServiceInfo(port=80, service="http",
                        banner="Microsoft-IIS/10.0"),
        ])
        d.classify_host(h)
        assert "webserver" in h.scan_types
        assert "windows" in h.scan_types
        assert "Windows" in h.os_guess

    def test_webserver_tomcat(self):
        d = self._discovery()
        h = HostInfo(ip="10.0.0.1", services=[
            ServiceInfo(port=8080, service="http-proxy",
                        banner="Apache-Coyote/1.1 Tomcat"),
        ])
        d.classify_host(h)
        svc = h.get_service(8080)
        assert svc.service == "tomcat"

    def test_database_mysql(self):
        d = self._discovery()
        h = HostInfo(ip="10.0.0.1", services=[
            ServiceInfo(port=3306, service="mysql"),
        ])
        d.classify_host(h)
        assert "database" in h.scan_types

    def test_database_oracle(self):
        d = self._discovery()
        h = HostInfo(ip="10.0.0.1", services=[
            ServiceInfo(port=1521, service="oracle-tns"),
        ])
        d.classify_host(h)
        assert "database" in h.scan_types

    def test_middleware_nodejs(self):
        d = self._discovery()
        h = HostInfo(ip="10.0.0.1", services=[
            ServiceInfo(port=3000, service="nodejs"),
        ])
        d.classify_host(h)
        assert "middleware" in h.scan_types

    def test_snmp_adds_cisco(self):
        d = self._discovery()
        h = HostInfo(ip="10.0.0.1", services=[
            ServiceInfo(port=161, service="snmp"),
        ])
        d.classify_host(h)
        assert "cisco" in h.scan_types

    def test_ttl_contributes_to_os_guess(self):
        d = self._discovery()
        h = HostInfo(ip="10.0.0.1", ttl=128, services=[
            ServiceInfo(port=445, service="microsoft-ds"),
        ])
        d.classify_host(h)
        assert "Windows" in h.os_guess
        # Two signals: port + TTL → high confidence
        assert h.os_confidence in ("medium", "high")

    def test_ttl_linux_with_ssh(self):
        d = self._discovery()
        h = HostInfo(ip="10.0.0.1", ttl=64, services=[
            ServiceInfo(port=22, service="ssh", banner="SSH-2.0-OpenSSH_9.0"),
        ])
        d.classify_host(h)
        assert "Linux" in h.os_guess
        assert h.os_confidence in ("medium", "high")

    def test_multi_service_host(self):
        """Host with SSH + HTTP + MySQL gets linux + webserver + database."""
        d = self._discovery()
        h = HostInfo(ip="10.0.0.1", services=[
            ServiceInfo(port=22, service="ssh", banner="SSH-2.0-OpenSSH_8.9"),
            ServiceInfo(port=80, service="http", banner="Apache/2.4.52"),
            ServiceInfo(port=3306, service="mysql"),
        ])
        d.classify_host(h)
        assert "linux" in h.scan_types
        assert "webserver" in h.scan_types
        assert "database" in h.scan_types

    def test_empty_services_no_crash(self):
        d = self._discovery()
        h = HostInfo(ip="10.0.0.1", services=[])
        d.classify_host(h)
        assert h.scan_types == []
        assert h.os_guess == ""

    def test_os_confidence_high_with_multiple_signals(self):
        d = self._discovery()
        h = HostInfo(ip="10.0.0.1", ttl=64, services=[
            ServiceInfo(port=22, service="ssh", banner="SSH-2.0-OpenSSH_8.9"),
            ServiceInfo(port=80, service="http", banner="Apache/2.4.52"),
        ])
        d.classify_host(h)
        assert h.os_confidence == "high"

    def test_ubuntu_ssh_banner(self):
        d = self._discovery()
        h = HostInfo(ip="10.0.0.1", services=[
            ServiceInfo(port=22, service="ssh",
                        banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"),
        ])
        d.classify_host(h)
        assert "Linux" in h.os_guess


# ── AutoScanner ──────────────────────────────────────────────────────

class TestAutoScannerInit:
    def test_default_attributes(self):
        creds = CredentialManager()
        s = AutoScanner(target="10.0.0.0/24", credentials=creds)
        assert s.target == "10.0.0.0/24"
        assert s.max_hosts == 256
        assert s.threads == 10
        assert s.no_discovery is False
        assert s._skipped_types == {}
        assert s.profile.name == "standard"

    def test_custom_profile(self):
        from skyhigh_scanner.core.scan_profiles import get_profile
        creds = CredentialManager()
        p = get_profile("quick")
        s = AutoScanner(target="10.0.0.1", credentials=creds, profile=p)
        assert s.profile.name == "quick"

    def test_version_bumped(self):
        creds = CredentialManager()
        s = AutoScanner(target="10.0.0.1", credentials=creds)
        assert s.SCANNER_VERSION == "1.2.0"


class TestAutoScannerDispatch:
    def _scanner(self, **cred_kwargs):
        creds = CredentialManager()
        for k, v in cred_kwargs.items():
            setattr(creds, k, v)
        return AutoScanner(target="10.0.0.1", credentials=creds)

    def test_skipped_windows_no_creds(self):
        s = self._scanner()
        host = HostInfo(ip="10.0.0.1", scan_types=["windows"])
        s._dispatch("windows", host)
        assert "windows" in s._skipped_types
        assert "10.0.0.1" in s._skipped_types["windows"]

    def test_skipped_linux_no_creds(self):
        s = self._scanner()
        host = HostInfo(ip="10.0.0.1", scan_types=["linux"])
        s._dispatch("linux", host)
        assert "linux" in s._skipped_types

    def test_skipped_cisco_no_creds(self):
        s = self._scanner()
        host = HostInfo(ip="10.0.0.1", scan_types=["cisco"])
        s._dispatch("cisco", host)
        assert "cisco" in s._skipped_types

    def test_skipped_middleware_no_creds(self):
        s = self._scanner()
        host = HostInfo(ip="10.0.0.1", scan_types=["middleware"])
        s._dispatch("middleware", host)
        assert "middleware" in s._skipped_types

    def test_unknown_scan_type(self):
        s = self._scanner()
        host = HostInfo(ip="10.0.0.1")
        # Should not crash
        s._dispatch("unknown_type", host)
        assert len(s.findings) == 0

    def test_report_skipped_produces_warnings(self, capsys):
        s = self._scanner()
        s._skipped_types = {"windows": {"10.0.0.1", "10.0.0.2"}}
        s._report_skipped()
        captured = capsys.readouterr()
        assert "Skipped windows scan" in captured.err
        assert "2 host(s)" in captured.err
        assert "WinRM" in captured.err


class TestAutoScannerSummary:
    def test_summary_includes_skipped(self):
        creds = CredentialManager()
        s = AutoScanner(target="10.0.0.1", credentials=creds)
        s._skipped_types = {"linux": {"10.0.0.1"}, "windows": {"10.0.0.2"}}
        summary = s.summary()
        assert "skipped_scans" in summary
        assert "linux" in summary["skipped_scans"]
        assert "10.0.0.1" in summary["skipped_scans"]["linux"]

    def test_summary_empty_skipped(self):
        creds = CredentialManager()
        s = AutoScanner(target="10.0.0.1", credentials=creds)
        summary = s.summary()
        assert summary["skipped_scans"] == {}

    def test_summary_profile(self):
        from skyhigh_scanner.core.scan_profiles import get_profile
        creds = CredentialManager()
        p = get_profile("full")
        s = AutoScanner(target="10.0.0.1", credentials=creds, profile=p)
        assert s.summary()["profile"] == "full"


class TestAutoScannerDiscoverySummary:
    def test_print_discovery_summary(self, capsys):
        creds = CredentialManager()
        s = AutoScanner(target="10.0.0.1", credentials=creds)
        hosts = [
            HostInfo(ip="10.0.0.1", hostname="web01.local",
                     os_guess="Linux", scan_types=["linux", "webserver"],
                     services=[ServiceInfo(port=22), ServiceInfo(port=80)]),
            HostInfo(ip="10.0.0.2", hostname="dc01.corp.local",
                     os_guess="Windows", scan_types=["windows"],
                     services=[ServiceInfo(port=445)]),
        ]
        s._print_discovery_summary(hosts)
        captured = capsys.readouterr()
        assert "10.0.0.1" in captured.err
        assert "10.0.0.2" in captured.err
        assert "Linux" in captured.err
        assert "Windows" in captured.err
        assert "web01.local" in captured.err

    def test_progress_output(self, capsys):
        creds = CredentialManager()
        s = AutoScanner(target="10.0.0.1", credentials=creds)
        s._print_progress(3, 10, "10.0.0.1", "linux")
        captured = capsys.readouterr()
        assert "3/10" in captured.err
        assert "30%" in captured.err
        assert "linux" in captured.err


class TestCredRequirements:
    def test_all_cred_scan_types_covered(self):
        """Ensure all scan types that need creds have hints."""
        for scan_type in ("windows", "linux", "cisco", "middleware"):
            assert scan_type in _CRED_REQUIREMENTS

    def test_webserver_no_creds_needed(self):
        assert "webserver" not in _CRED_REQUIREMENTS

    def test_database_no_creds_needed(self):
        assert "database" not in _CRED_REQUIREMENTS


# ── Parallel dispatch ─────────────────────────────────────────────

class TestParallelDispatch:
    def _scanner(self, threads=4, **cred_kwargs):
        creds = CredentialManager()
        for k, v in cred_kwargs.items():
            setattr(creds, k, v)
        return AutoScanner(target="10.0.0.1", credentials=creds, threads=threads)

    def test_has_lock(self):
        s = self._scanner()
        assert hasattr(s, "_lock")

    def test_dispatch_one_returns_tuple(self):
        """_dispatch_one returns (findings, skip_info) tuple."""
        s = self._scanner()
        host = HostInfo(ip="10.0.0.1", scan_types=["windows"])
        findings, skipped = s._dispatch_one("windows", host)
        assert isinstance(findings, list)
        # No winrm creds → skipped
        assert skipped == ("windows", "10.0.0.1")

    def test_dispatch_one_unknown_returns_none_skip(self):
        s = self._scanner()
        host = HostInfo(ip="10.0.0.1")
        findings, skipped = s._dispatch_one("unknown_type", host)
        assert findings == []
        assert skipped is None

    def test_dispatch_one_webserver_no_skip(self):
        """Webserver doesn't need creds so skip_info should be None."""
        s = self._scanner()
        host = HostInfo(ip="10.0.0.1", scan_types=["webserver"])
        # _create_scanner will succeed (returns a scanner), but
        # scanner.scan() would try to connect. Just test _create_scanner.
        scanner = s._create_scanner("webserver", host)
        assert scanner is not None

    def test_create_scanner_returns_none_without_creds(self):
        s = self._scanner()
        host = HostInfo(ip="10.0.0.1")
        for scan_type in ("windows", "linux", "cisco", "middleware"):
            assert s._create_scanner(scan_type, host) is None

    def test_sequential_fallback_with_one_thread(self):
        """threads=1 should use sequential path (no ThreadPoolExecutor)."""
        s = self._scanner(threads=1)
        host = HostInfo(ip="10.0.0.1", scan_types=["windows"])
        # dispatch should still track skipped
        s._dispatch("windows", host)
        assert "windows" in s._skipped_types

    def test_dispatch_parallel_skipped_tracking(self):
        """_dispatch_parallel collects skip info from _dispatch_one."""
        s = self._scanner(threads=2)
        tasks = [
            ("windows", HostInfo(ip="10.0.0.1", scan_types=["windows"])),
            ("linux", HostInfo(ip="10.0.0.2", scan_types=["linux"])),
        ]
        s._dispatch_parallel(tasks, total=2)
        assert "windows" in s._skipped_types
        assert "10.0.0.1" in s._skipped_types["windows"]
        assert "linux" in s._skipped_types
        assert "10.0.0.2" in s._skipped_types["linux"]

    def test_dispatch_parallel_progress_output(self, capsys):
        s = self._scanner(threads=2)
        tasks = [
            ("windows", HostInfo(ip="10.0.0.1", scan_types=["windows"])),
        ]
        s._dispatch_parallel(tasks, total=1)
        captured = capsys.readouterr()
        assert "1/1" in captured.err
        assert "100%" in captured.err
