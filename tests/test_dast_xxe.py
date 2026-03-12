"""Tests for DAST XXE check module."""

from __future__ import annotations

from unittest.mock import MagicMock

from skyhigh_scanner.dast.checks.xxe import run_checks
from skyhigh_scanner.dast.crawler import APIEndpoint, FormField, FormInfo, SiteMap

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _mock_client(
    get_text: str = "",
    get_status: int = 200,
    post_text: str = "",
    post_status: int = 200,
) -> MagicMock:
    client = MagicMock()

    get_resp = MagicMock()
    get_resp.text = get_text
    get_resp.status_code = get_status
    get_resp.headers = {"Content-Type": "text/html"}
    client.get.return_value = get_resp

    post_resp = MagicMock()
    post_resp.text = post_text
    post_resp.status_code = post_status
    post_resp.headers = {"Content-Type": "application/xml"}
    client.post.return_value = post_resp

    client.probe_path.return_value = (404, "")

    return client


def _xml_sitemap() -> SiteMap:
    """Create a sitemap with XML-accepting endpoints."""
    sm = SiteMap()
    sm.urls = {"https://example.com/api/data"}
    sm.api_endpoints = [
        APIEndpoint(url="https://example.com/api/data", method="POST"),
    ]
    return sm


def _empty_sitemap() -> SiteMap:
    return SiteMap()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DAST-XXE-001: XXE via XML content-type endpoints
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestXXEXmlEndpoints:
    """DAST-XXE-001: XXE via XML endpoints."""

    def test_passwd_in_response(self):
        """Detect XXE when /etc/passwd content appears in response."""
        client = _mock_client(
            post_text="<response>root:x:0:0:root:/root:/bin/bash</response>",
        )
        sm = _xml_sitemap()
        findings = run_checks(client, "https://example.com", sm)
        xxe_001 = [f for f in findings if f.rule_id == "DAST-XXE-001"]
        assert len(xxe_001) >= 1
        assert xxe_001[0].severity == "CRITICAL"
        assert xxe_001[0].cwe == "CWE-611"

    def test_winini_in_response(self):
        """Detect XXE when win.ini content appears."""
        client = _mock_client(
            post_text="<data>[fonts]\nCourier=something</data>",
        )
        sm = _xml_sitemap()
        findings = run_checks(client, "https://example.com", sm)
        xxe_001 = [f for f in findings if f.rule_id == "DAST-XXE-001"]
        assert len(xxe_001) >= 1

    def test_no_xxe_normal_response(self):
        """No finding for normal XML response."""
        client = _mock_client(post_text="<response><status>ok</status></response>")
        sm = _xml_sitemap()
        findings = run_checks(client, "https://example.com", sm)
        xxe_001 = [f for f in findings if f.rule_id == "DAST-XXE-001"]
        assert len(xxe_001) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DAST-XXE-002: XXE via file upload (SVG)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestXXEFileUpload:
    """DAST-XXE-002: XXE via SVG file upload."""

    def test_svn_xxe_detected(self):
        """Detect XXE when file upload form processes SVG with XXE."""
        client = _mock_client(
            post_text="root:x:0:0:root:/root:/bin/bash",
        )
        sm = SiteMap()
        sm.forms = [FormInfo(
            url="https://example.com/upload",
            action="https://example.com/upload",
            method="POST",
            fields=[FormField(name="file", field_type="file")],
            has_file_upload=True,
        )]
        findings = run_checks(client, "https://example.com", sm)
        xxe_002 = [f for f in findings if f.rule_id == "DAST-XXE-002"]
        assert len(xxe_002) >= 1
        assert xxe_002[0].severity == "HIGH"

    def test_no_file_upload_forms(self):
        """No finding when there are no file upload forms."""
        client = _mock_client()
        sm = SiteMap()
        sm.forms = [FormInfo(
            url="https://example.com/search",
            action="https://example.com/search",
            method="POST",
            fields=[FormField(name="q", field_type="text")],
        )]
        findings = run_checks(client, "https://example.com", sm)
        xxe_002 = [f for f in findings if f.rule_id == "DAST-XXE-002"]
        assert len(xxe_002) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DAST-XXE-003: XXE entity expansion (DoS detection)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestXXEEntityExpansion:
    """DAST-XXE-003: XXE entity expansion."""

    def test_parser_error_detected(self):
        """Detect when entity expansion causes parser error."""
        client = _mock_client(
            post_text="XML parser error: entity expansion limit exceeded",
        )
        sm = _xml_sitemap()
        findings = run_checks(client, "https://example.com", sm)
        xxe_003 = [f for f in findings if f.rule_id == "DAST-XXE-003"]
        assert len(xxe_003) >= 1
        assert xxe_003[0].severity == "MEDIUM"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DAST-XXE-004: SOAP endpoint XXE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestXXESoapEndpoints:
    """DAST-XXE-004: SOAP endpoint XXE."""

    def test_soap_xxe_detected(self):
        """Detect XXE in SOAP endpoint."""
        # GET returns 200 for WSDL probe, POST returns passwd content
        get_resp = MagicMock()
        get_resp.text = '<definitions xmlns="http://schemas.xmlsoap.org/wsdl/">'
        get_resp.status_code = 200
        get_resp.headers = {"Content-Type": "text/xml"}

        post_resp = MagicMock()
        post_resp.text = "root:x:0:0:root:/root:/bin/bash"
        post_resp.status_code = 200
        post_resp.headers = {"Content-Type": "text/xml"}

        client = MagicMock()
        client.get.return_value = get_resp
        client.post.return_value = post_resp

        sm = _empty_sitemap()
        findings = run_checks(client, "https://example.com", sm)
        xxe_004 = [f for f in findings if f.rule_id == "DAST-XXE-004"]
        assert len(xxe_004) >= 1
        assert xxe_004[0].severity == "HIGH"

    def test_no_soap_endpoints(self):
        """No finding when no SOAP endpoints are found."""
        get_resp = MagicMock()
        get_resp.text = "Not Found"
        get_resp.status_code = 404
        get_resp.headers = {}

        client = MagicMock()
        client.get.return_value = get_resp
        client.post.return_value = MagicMock(text="", status_code=200, headers={})

        sm = _empty_sitemap()
        findings = run_checks(client, "https://example.com", sm)
        xxe_004 = [f for f in findings if f.rule_id == "DAST-XXE-004"]
        assert len(xxe_004) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Integration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestXXEIntegration:
    """Integration tests."""

    def test_all_findings_correct_category(self):
        client = _mock_client(
            post_text="root:x:0:0:root:/root:/bin/bash",
        )
        sm = _xml_sitemap()
        findings = run_checks(client, "https://example.com", sm)
        for f in findings:
            assert f.category == "xxe"
            assert f.target_type == "dast"

    def test_empty_sitemap(self):
        client = _mock_client()
        client.probe_path.return_value = (404, "")
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        assert isinstance(findings, list)

    def test_exception_handling(self):
        """Exceptions in HTTP calls are handled gracefully."""
        client = MagicMock()
        client.get.side_effect = Exception("Connection refused")
        client.post.side_effect = Exception("Connection refused")
        client.probe_path.side_effect = Exception("Connection refused")
        sm = _xml_sitemap()
        findings = run_checks(client, "https://example.com", sm)
        assert isinstance(findings, list)
