"""Tests for DAST SSRF check module."""

from __future__ import annotations

from unittest.mock import MagicMock

from skyhigh_scanner.dast.checks.ssrf import run_checks
from skyhigh_scanner.dast.crawler import FormField, FormInfo, SiteMap

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _mock_client(
    get_text: str = "",
    get_status: int = 200,
    post_text: str = "",
    post_status: int = 200,
    headers: dict | None = None,
) -> MagicMock:
    client = MagicMock()

    get_resp = MagicMock()
    get_resp.text = get_text
    get_resp.status_code = get_status
    get_resp.headers = headers or {}
    client.get.return_value = get_resp

    post_resp = MagicMock()
    post_resp.text = post_text
    post_resp.status_code = post_status
    post_resp.headers = headers or {}
    client.post.return_value = post_resp

    return client


def _url_sitemap(*urls: str) -> SiteMap:
    sm = SiteMap()
    sm.urls = set(urls)
    return sm


def _empty_sitemap() -> SiteMap:
    return SiteMap()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DAST-SSRF-001: SSRF via URL parameters
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestSSRFUrlParams:
    """DAST-SSRF-001: SSRF via URL parameters."""

    def test_aws_metadata_detected(self):
        """Detect SSRF when AWS metadata content is in response."""
        client = _mock_client(
            get_text="ami-0abcdef1234567890\ninstance-id: i-1234567890abcdef0",
        )
        sm = _url_sitemap("https://example.com/fetch?url=https://example.com")
        findings = run_checks(client, "https://example.com", sm)
        ssrf_001 = [f for f in findings if f.rule_id == "DAST-SSRF-001"]
        assert len(ssrf_001) >= 1
        assert ssrf_001[0].severity == "CRITICAL"

    def test_passwd_detected(self):
        """Detect SSRF when /etc/passwd content leaks."""
        client = _mock_client(
            get_text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:",
        )
        sm = _url_sitemap("https://example.com/proxy?url=https://google.com")
        findings = run_checks(client, "https://example.com", sm)
        ssrf_001 = [f for f in findings if f.rule_id == "DAST-SSRF-001"]
        assert len(ssrf_001) >= 1

    def test_no_ssrf_normal_response(self):
        """No finding for normal response content."""
        client = _mock_client(get_text="<html>Normal page content</html>")
        sm = _url_sitemap("https://example.com/fetch?url=https://example.com")
        findings = run_checks(client, "https://example.com", sm)
        ssrf_001 = [f for f in findings if f.rule_id == "DAST-SSRF-001"]
        assert len(ssrf_001) == 0

    def test_non_ssrf_param_skipped(self):
        """Params not in SSRF_PARAM_NAMES are skipped."""
        client = _mock_client(get_text="ami-0abcdef1234567890")
        sm = _url_sitemap("https://example.com/search?q=test")
        findings = run_checks(client, "https://example.com", sm)
        ssrf_001 = [f for f in findings if f.rule_id == "DAST-SSRF-001"]
        assert len(ssrf_001) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DAST-SSRF-002: SSRF via form inputs
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestSSRFFormInputs:
    """DAST-SSRF-002: SSRF via form inputs."""

    def test_form_ssrf_detected(self):
        client = _mock_client(
            post_text="ami-0abcdef1234567890\nlatest/meta-data",
        )
        sm = SiteMap()
        sm.forms = [FormInfo(
            url="https://example.com/webhook",
            action="https://example.com/webhook",
            method="POST",
            fields=[FormField(name="callback", field_type="text")],
        )]
        findings = run_checks(client, "https://example.com", sm)
        ssrf_002 = [f for f in findings if f.rule_id == "DAST-SSRF-002"]
        assert len(ssrf_002) >= 1

    def test_form_non_ssrf_field_skipped(self):
        client = _mock_client(post_text="ami-0abcdef1234567890")
        sm = SiteMap()
        sm.forms = [FormInfo(
            url="https://example.com/search",
            action="https://example.com/search",
            method="POST",
            fields=[FormField(name="q", field_type="text")],
        )]
        findings = run_checks(client, "https://example.com", sm)
        ssrf_002 = [f for f in findings if f.rule_id == "DAST-SSRF-002"]
        assert len(ssrf_002) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DAST-SSRF-003: SSRF via redirect parameters
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestSSRFRedirectParams:
    """DAST-SSRF-003: SSRF via redirect parameters."""

    def test_redirect_to_internal(self):
        client = _mock_client(
            get_status=302,
            headers={"Location": "http://127.0.0.1/admin"},
        )
        sm = _url_sitemap("https://example.com/redirect?next=https://example.com")
        findings = run_checks(client, "https://example.com", sm)
        ssrf_003 = [f for f in findings if f.rule_id == "DAST-SSRF-003"]
        assert len(ssrf_003) >= 1

    def test_no_redirect_to_external(self):
        client = _mock_client(
            get_status=302,
            headers={"Location": "https://example.com/dashboard"},
        )
        sm = _url_sitemap("https://example.com/redirect?next=https://example.com")
        findings = run_checks(client, "https://example.com", sm)
        ssrf_003 = [f for f in findings if f.rule_id == "DAST-SSRF-003"]
        assert len(ssrf_003) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DAST-SSRF-005: Open redirect to internal network
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestOpenRedirectInternal:
    """DAST-SSRF-005: Open redirect to internal network."""

    def test_redirect_to_metadata(self):
        client = _mock_client(
            get_status=302,
            headers={"Location": "http://169.254.169.254/latest/meta-data"},
        )
        sm = _url_sitemap("https://example.com/go?redirect=https://example.com")
        findings = run_checks(client, "https://example.com", sm)
        ssrf_005 = [f for f in findings if f.rule_id == "DAST-SSRF-005"]
        assert len(ssrf_005) >= 1


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Integration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestSSRFIntegration:
    """Integration tests."""

    def test_all_findings_correct_category(self):
        client = _mock_client(
            get_text="ami-0abcdef1234567890",
        )
        sm = _url_sitemap("https://example.com/fetch?url=https://example.com")
        findings = run_checks(client, "https://example.com", sm)
        for f in findings:
            assert f.category == "ssrf"
            assert f.target_type == "dast"

    def test_empty_sitemap(self):
        client = _mock_client()
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        assert isinstance(findings, list)

    def test_exception_handling(self):
        """Check that exceptions in HTTP calls are handled gracefully."""
        client = MagicMock()
        client.get.side_effect = Exception("Connection refused")
        client.post.side_effect = Exception("Connection refused")
        sm = _url_sitemap("https://example.com/fetch?url=test")
        findings = run_checks(client, "https://example.com", sm)
        assert isinstance(findings, list)
