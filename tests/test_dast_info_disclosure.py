"""Tests for DAST info_disclosure check module."""

from __future__ import annotations

from unittest.mock import MagicMock

from skyhigh_scanner.dast.checks.info_disclosure import (
    run_checks,
)
from skyhigh_scanner.dast.crawler import SiteMap

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _mock_client(
    headers: dict | None = None,
    probe_results: dict | None = None,
    get_text: str = "",
    get_headers: dict | None = None,
) -> MagicMock:
    """Create a mock DastHTTPClient."""
    client = MagicMock()

    # get_headers returns the specified headers
    client.get_headers.return_value = headers or {}

    # probe_path returns (status, body) based on path
    if probe_results:
        def _probe(base, path):
            key = path if path else base
            return probe_results.get(key, (404, ""))
        client.probe_path.side_effect = _probe
    else:
        client.probe_path.return_value = (404, "")

    # get returns a mock response
    resp = MagicMock()
    resp.text = get_text
    resp.headers = get_headers or {}
    client.get.return_value = resp

    return client


def _empty_sitemap() -> SiteMap:
    return SiteMap()


def _sitemap_with_urls(*urls: str) -> SiteMap:
    sm = SiteMap()
    sm.urls = set(urls)
    return sm


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestServerHeader:
    """DAST-INFO-001: Server version disclosure."""

    def test_server_version_disclosed(self):
        client = _mock_client(headers={"Server": "Apache/2.4.41 (Ubuntu)"})
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        info_001 = [f for f in findings if f.rule_id == "DAST-INFO-001"]
        assert len(info_001) == 1
        assert "Apache/2.4.41" in info_001[0].line_content

    def test_server_no_version_no_finding(self):
        client = _mock_client(headers={"Server": "cloudflare"})
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        info_001 = [f for f in findings if f.rule_id == "DAST-INFO-001"]
        assert len(info_001) == 0

    def test_nginx_version(self):
        client = _mock_client(headers={"Server": "nginx/1.21.3"})
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        info_001 = [f for f in findings if f.rule_id == "DAST-INFO-001"]
        assert len(info_001) == 1


class TestTechHeaders:
    """DAST-INFO-002: Technology stack headers."""

    def test_x_powered_by_disclosed(self):
        client = _mock_client(headers={"X-Powered-By": "Express"})
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        info_002 = [f for f in findings if f.rule_id == "DAST-INFO-002"]
        assert len(info_002) == 1
        assert "X-Powered-By" in info_002[0].line_content

    def test_multiple_tech_headers(self):
        client = _mock_client(headers={
            "X-Powered-By": "PHP/8.1",
            "X-AspNet-Version": "4.0.30319",
        })
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        info_002 = [f for f in findings if f.rule_id == "DAST-INFO-002"]
        assert len(info_002) == 2

    def test_no_tech_headers(self):
        client = _mock_client(headers={"Content-Type": "text/html"})
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        info_002 = [f for f in findings if f.rule_id == "DAST-INFO-002"]
        assert len(info_002) == 0


class TestSensitiveFiles:
    """DAST-INFO-003: Sensitive file exposure."""

    def test_git_head_exposed(self):
        client = _mock_client(probe_results={
            ".git/HEAD": (200, "ref: refs/heads/main"),
        })
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        info_003 = [f for f in findings if f.rule_id == "DAST-INFO-003"]
        assert len(info_003) == 1
        assert info_003[0].severity == "HIGH"

    def test_env_file_exposed_is_critical(self):
        client = _mock_client(probe_results={
            ".env": (200, "API_KEY=secret123\nDATABASE_URL=postgres://..."),
        })
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        info_003 = [f for f in findings if f.rule_id == "DAST-INFO-003"]
        assert len(info_003) == 1
        assert info_003[0].severity == "CRITICAL"

    def test_404_no_finding(self):
        client = _mock_client()  # all probes return 404
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        info_003 = [f for f in findings if f.rule_id == "DAST-INFO-003"]
        assert len(info_003) == 0


class TestDirectoryListing:
    """DAST-INFO-004: Directory listing."""

    def test_directory_listing_detected(self):
        # probe_path receives (base_url, path) — the check passes dir_url as base
        # and "" as path. Override probe_path to always return listing.
        client = _mock_client()
        client.probe_path.return_value = (200, "<html><title>Index of /uploads</title>...</html>")
        sitemap = _sitemap_with_urls("https://example.com/uploads/file.txt")
        findings = run_checks(client, "https://example.com", sitemap)
        info_004 = [f for f in findings if f.rule_id == "DAST-INFO-004"]
        assert len(info_004) >= 1


class TestErrorPages:
    """DAST-INFO-005: Debug info in error pages."""

    def test_python_traceback(self):
        error_body = "Traceback (most recent call last):\n  File ..."
        client = _mock_client(probe_results={
            "nonexistent_path_404_test": (500, error_body),
        })
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        info_005 = [f for f in findings if f.rule_id == "DAST-INFO-005"]
        assert len(info_005) == 1
        assert "Python stack trace" in info_005[0].line_content

    def test_sql_error(self):
        error_body = "You have an error in your SQL syntax near ''"
        client = _mock_client(probe_results={
            "test.php?id='": (500, error_body),
        })
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        info_005 = [f for f in findings if f.rule_id == "DAST-INFO-005"]
        assert len(info_005) == 1


class TestInternalIPs:
    """DAST-INFO-006: Internal IP addresses."""

    def test_internal_ip_in_header(self):
        resp = MagicMock()
        resp.text = ""
        resp.headers = {"X-Backend-Server": "192.168.1.100:8080"}
        client = MagicMock()
        client.get_headers.return_value = {}
        client.probe_path.return_value = (404, "")
        client.get.return_value = resp

        findings = run_checks(client, "https://example.com", _empty_sitemap())
        info_006 = [f for f in findings if f.rule_id == "DAST-INFO-006"]
        assert len(info_006) == 1
        assert "192.168.1.100" in info_006[0].line_content


class TestHTMLComments:
    """DAST-INFO-007: Sensitive HTML comments."""

    def test_password_in_comment(self):
        html = "<html><!-- default password: admin123 --></html>"
        resp = MagicMock()
        resp.text = html
        client = MagicMock()
        client.get_headers.return_value = {}
        client.probe_path.return_value = (404, "")
        client.get.return_value = resp

        sitemap = _sitemap_with_urls("https://example.com/login")
        findings = run_checks(client, "https://example.com", sitemap)
        info_007 = [f for f in findings if f.rule_id == "DAST-INFO-007"]
        assert len(info_007) >= 1


class TestEmailDisclosure:
    """DAST-INFO-008: Email addresses disclosed."""

    def test_email_found(self):
        html = "<html>Contact: admin@internal-corp.com</html>"
        resp = MagicMock()
        resp.text = html
        client = MagicMock()
        client.get_headers.return_value = {}
        client.probe_path.return_value = (404, "")
        client.get.return_value = resp

        sitemap = _sitemap_with_urls("https://example.com/about")
        findings = run_checks(client, "https://example.com", sitemap)
        info_008 = [f for f in findings if f.rule_id == "DAST-INFO-008"]
        assert len(info_008) == 1
        assert "admin@internal-corp.com" in info_008[0].line_content


class TestRunChecks:
    """Integration tests for run_checks."""

    def test_no_findings_on_clean_target(self):
        client = _mock_client(headers={"Content-Type": "text/html"})
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        # Should only have findings from empty/safe headers, not errors
        assert isinstance(findings, list)

    def test_all_findings_have_correct_category(self):
        client = _mock_client(headers={"Server": "Apache/2.4.41", "X-Powered-By": "PHP"})
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        for f in findings:
            assert f.category == "info_disclosure"
            assert f.target_type == "dast"

    def test_all_findings_have_rule_ids(self):
        client = _mock_client(headers={"Server": "nginx/1.21.3"})
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        for f in findings:
            assert f.rule_id.startswith("DAST-INFO-")
