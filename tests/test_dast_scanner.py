"""Tests for the DastScanner orchestrator."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from vulnerability_management.dast.config import DastConfig, ScopePolicy
from vulnerability_management.dast.crawler import SiteMap
from vulnerability_management.scanners.dast_scanner import DastScanner

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Initialization
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestDastScannerInit:
    def test_basic_init(self):
        scanner = DastScanner(target="https://app.example.com")
        assert scanner.SCANNER_NAME == "VulnMgmt DAST Scanner"
        assert scanner.TARGET_TYPE == "dast"
        assert scanner.target == "https://app.example.com"

    def test_target_url_property_with_scheme(self):
        scanner = DastScanner(target="https://app.example.com")
        assert scanner._target_url == "https://app.example.com"

    def test_target_url_property_without_scheme(self):
        scanner = DastScanner(target="app.example.com")
        assert scanner._target_url == "https://app.example.com"

    def test_auto_scope_from_target(self):
        scanner = DastScanner(target="https://app.example.com")
        assert scanner.dast_config.scope.is_host_allowed("app.example.com")

    def test_explicit_config(self):
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["custom.com"]),
            rate_limit_rps=5.0,
        )
        scanner = DastScanner(
            target="https://custom.com",
            dast_config=config,
        )
        assert scanner.dast_config.rate_limit_rps == 5.0

    def test_http_target(self):
        scanner = DastScanner(target="http://insecure.example.com")
        assert scanner._target_url == "http://insecure.example.com"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Check dispatch
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestDastScannerDispatch:
    def test_check_dispatch_map(self):
        """All DAST check categories should be in the dispatch map."""
        expected = {
            "injection", "xss", "auth_session", "access_control",
            "api_security", "file_inclusion", "info_disclosure",
            "config_misconfig", "ssrf", "xxe", "jwt",
        }
        assert set(DastScanner.CHECK_DISPATCH.keys()) == expected

    def test_passive_mode_skips_injection(self):
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["example.com"]),
            passive_only=True,
            accept_risk=True,
        )
        scanner = DastScanner(
            target="https://example.com",
            dast_config=config,
        )
        # In passive mode, injection/xss/file_inclusion/access_control
        # should be skipped
        mock_client = MagicMock()
        sitemap = SiteMap()
        sitemap.urls.add("https://example.com")

        # Patch _run_check_module to track which categories are called
        called_categories = []

        def track_run(module_name, *args, **kwargs):
            called_categories.append(module_name)
            return []

        scanner._run_check_module = track_run
        scanner._dispatch_checks(mock_client, "https://example.com", sitemap)

        # Injection checks should NOT be called in passive mode
        assert "injection" not in called_categories
        assert "xss" not in called_categories
        assert "file_inclusion" not in called_categories
        assert "access_control" not in called_categories

    def test_check_module_import_error_handled(self):
        """ImportError from missing check modules should be handled gracefully."""
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["example.com"]),
            accept_risk=True,
        )
        scanner = DastScanner(
            target="https://example.com",
            dast_config=config,
        )
        mock_client = MagicMock()
        sitemap = SiteMap()

        # This should not raise — check modules don't exist yet
        scanner._dispatch_checks(mock_client, "https://example.com", sitemap)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Scan execution
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestDastScannerScan:
    def test_scan_no_requests_library(self):
        """Scan should error gracefully if requests is not installed."""
        scanner = DastScanner(target="https://example.com")
        with patch("vulnerability_management.core.transport.HAS_REQUESTS", False):
            scanner.scan()
        assert len(scanner.findings) == 0
        assert len(scanner.targets_failed) == 0

    def test_scan_with_crawl_disabled(self):
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["example.com"]),
            crawl_enabled=False,
            accept_risk=True,
            rate_limit_rps=1000.0,
        )
        scanner = DastScanner(
            target="https://example.com",
            dast_config=config,
        )

        # Mock the HTTP client
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html>OK</html>"
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.request = MagicMock()
        mock_response.request.headers = {}

        with patch("vulnerability_management.dast.http_client.requests") as mock_requests:
            mock_session = MagicMock()
            mock_requests.Session.return_value = mock_session
            mock_session.request.return_value = mock_response

            scanner.scan()

        # Should have scanned just the seed URL
        assert "https://example.com" in scanner.targets_scanned

    def test_scan_exception_records_failure(self):
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["example.com"]),
            accept_risk=True,
        )
        scanner = DastScanner(
            target="https://example.com",
            dast_config=config,
        )

        with patch(
            "vulnerability_management.dast.http_client.requests",
        ) as mock_requests:
            mock_requests.Session.side_effect = Exception("Connection refused")
            scanner.scan()

        assert "https://example.com" in scanner.targets_failed


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Warning banner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestWarningBanner:
    def test_banner_printed_by_default(self, capsys):
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["example.com"]),
            accept_risk=False,
        )
        scanner = DastScanner(
            target="https://example.com",
            dast_config=config,
        )
        scanner._print_warning_banner()
        captured = capsys.readouterr()
        assert "WARNING" in captured.err
        assert "example.com" in captured.err

    def test_passive_only_shows_in_banner(self, capsys):
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["example.com"]),
            passive_only=True,
        )
        scanner = DastScanner(
            target="https://example.com",
            dast_config=config,
        )
        scanner._print_warning_banner()
        captured = capsys.readouterr()
        assert "PASSIVE ONLY" in captured.err


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CLI integration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestDastCLI:
    def test_dast_command_parses(self):
        from vulnerability_management.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args([
            "dast", "--target", "https://app.example.com",
            "--dast-rate-limit", "20",
            "--dast-passive-only",
        ])
        assert args.command == "dast"
        assert args.target == "https://app.example.com"
        assert args.dast_rate_limit == 20.0
        assert args.dast_passive_only is True

    def test_dast_auth_mode_parses(self):
        from vulnerability_management.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args([
            "dast", "--target", "https://app.example.com",
            "--dast-auth-mode", "bearer",
            "--dast-auth-token", "mytoken",
        ])
        assert args.dast_auth_mode == "bearer"
        assert args.dast_auth_token == "mytoken"

    def test_dast_defaults(self):
        from vulnerability_management.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args([
            "dast", "--target", "https://example.com",
        ])
        assert args.dast_rate_limit == 10.0
        assert args.dast_max_requests == 10000
        assert args.dast_crawl_depth == 5
        assert args.dast_auth_mode == "none"
        assert args.dast_passive_only is False
        assert args.dast_no_crawl is False
        assert args.dast_accept_risk is False

    def test_dast_all_flags(self):
        from vulnerability_management.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args([
            "dast", "--target", "https://example.com",
            "--dast-max-requests", "5000",
            "--dast-crawl-depth", "3",
            "--dast-no-crawl",
            "--dast-accept-risk",
            "--dast-follow-subdomains",
        ])
        assert args.dast_max_requests == 5000
        assert args.dast_crawl_depth == 3
        assert args.dast_no_crawl is True
        assert args.dast_accept_risk is True
        assert args.dast_follow_subdomains is True


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Concurrent dispatch & perf metrics (Phase 6)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestConcurrentDispatch:
    def test_dispatch_calls_all_enabled_modules(self):
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["example.com"]),
            accept_risk=True,
        )
        scanner = DastScanner(
            target="https://example.com",
            dast_config=config,
        )
        mock_client = MagicMock()
        sitemap = SiteMap()
        sitemap.urls.add("https://example.com")

        called = []

        def track_run(module_name, *args, **kwargs):
            called.append(module_name)
            return []

        scanner._run_check_module = track_run
        scanner._dispatch_checks(mock_client, "https://example.com", sitemap)

        # All 11 check modules should be called
        assert len(called) == 11

    def test_dispatch_handles_import_errors(self):
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["example.com"]),
            accept_risk=True,
        )
        scanner = DastScanner(
            target="https://example.com",
            dast_config=config,
        )
        mock_client = MagicMock()
        sitemap = SiteMap()

        # Should not raise even with missing modules
        scanner._dispatch_checks(mock_client, "https://example.com", sitemap)


class TestPerfMetrics:
    def test_summary_includes_performance(self):
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["example.com"]),
            accept_risk=True,
        )
        scanner = DastScanner(
            target="https://example.com",
            dast_config=config,
        )
        scanner._perf_metrics = {
            "avg_response_time_ms": 42.5,
            "p95_response_time_ms": 120.3,
        }
        s = scanner.summary()
        assert "performance" in s["dast_metadata"]
        assert s["dast_metadata"]["performance"]["avg_response_time_ms"] == 42.5
        assert s["dast_metadata"]["performance"]["p95_response_time_ms"] == 120.3

    def test_perf_metrics_default_empty(self):
        scanner = DastScanner(target="https://example.com")
        s = scanner.summary()
        assert s["dast_metadata"]["performance"] == {}
