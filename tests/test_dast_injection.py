"""Tests for DAST injection check module."""

from __future__ import annotations

from unittest.mock import MagicMock

from skyhigh_scanner.dast.checks.injection import run_checks
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
    get_resp.headers = {}
    client.get.return_value = get_resp

    post_resp = MagicMock()
    post_resp.text = post_text
    post_resp.status_code = post_status
    post_resp.headers = {}
    client.post.return_value = post_resp

    client.probe_path.return_value = (404, "")

    return client


def _url_sitemap(*urls: str) -> SiteMap:
    sm = SiteMap()
    sm.urls = set(urls)
    return sm


def _empty_sitemap() -> SiteMap:
    return SiteMap()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestSQLInjectionURL:
    """DAST-INJ-001: SQL injection via URL parameters."""

    def test_sql_error_detected(self):
        client = _mock_client(
            get_text="You have an error in your SQL syntax near 'test'",
        )
        sm = _url_sitemap("https://example.com/search?q=test")
        findings = run_checks(client, "https://example.com", sm)
        inj_001 = [f for f in findings if f.rule_id == "DAST-INJ-001"]
        assert len(inj_001) == 1
        assert inj_001[0].severity == "CRITICAL"

    def test_no_sql_error(self):
        client = _mock_client(get_text="<html>Normal page</html>")
        sm = _url_sitemap("https://example.com/search?q=test")
        findings = run_checks(client, "https://example.com", sm)
        inj_001 = [f for f in findings if f.rule_id == "DAST-INJ-001"]
        assert len(inj_001) == 0

    def test_no_params_no_test(self):
        client = _mock_client()
        sm = _url_sitemap("https://example.com/page")
        findings = run_checks(client, "https://example.com", sm)
        inj_001 = [f for f in findings if f.rule_id == "DAST-INJ-001"]
        assert len(inj_001) == 0

    def test_oracle_error(self):
        client = _mock_client(get_text="ORA-01756: quoted string not properly terminated")
        sm = _url_sitemap("https://example.com/data?id=1")
        findings = run_checks(client, "https://example.com", sm)
        inj_001 = [f for f in findings if f.rule_id == "DAST-INJ-001"]
        assert len(inj_001) == 1


class TestSQLInjectionForms:
    """DAST-INJ-002: SQL injection via forms."""

    def test_form_sql_injection(self):
        client = _mock_client(
            post_text="MySQL error: mysql_query() failed",
        )
        sm = SiteMap()
        sm.forms = [FormInfo(
            url="https://example.com/search",
            action="https://example.com/search",
            method="POST",
            fields=[FormField(name="q", field_type="text")],
        )]
        findings = run_checks(client, "https://example.com", sm)
        inj_002 = [f for f in findings if f.rule_id == "DAST-INJ-002"]
        assert len(inj_002) == 1


class TestCommandInjection:
    """DAST-INJ-003: Command injection."""

    def test_command_echo_reflected(self):
        client = _mock_client(get_text="output: SKYHIGH_CMD_TEST")
        sm = _url_sitemap("https://example.com/ping?host=127.0.0.1")
        findings = run_checks(client, "https://example.com", sm)
        inj_003 = [f for f in findings if f.rule_id == "DAST-INJ-003"]
        assert len(inj_003) == 1
        assert inj_003[0].severity == "CRITICAL"

    def test_no_command_injection(self):
        client = _mock_client(get_text="<html>Normal output</html>")
        sm = _url_sitemap("https://example.com/ping?host=127.0.0.1")
        findings = run_checks(client, "https://example.com", sm)
        inj_003 = [f for f in findings if f.rule_id == "DAST-INJ-003"]
        assert len(inj_003) == 0


class TestSSTI:
    """DAST-INJ-004: Server-Side Template Injection."""

    def test_ssti_detected(self):
        # Response contains 49 (7*7 evaluated) but not the raw payload
        client = _mock_client(get_text="<html>Result: 49</html>")
        sm = _url_sitemap("https://example.com/render?name=test")
        findings = run_checks(client, "https://example.com", sm)
        inj_004 = [f for f in findings if f.rule_id == "DAST-INJ-004"]
        assert len(inj_004) == 1

    def test_ssti_not_detected_raw_payload(self):
        # If the raw payload is in the response, it wasn't evaluated
        client = _mock_client(get_text="<html>Input: {{7*7}}</html>")
        sm = _url_sitemap("https://example.com/render?name=test")
        findings = run_checks(client, "https://example.com", sm)
        inj_004 = [f for f in findings if f.rule_id == "DAST-INJ-004"]
        assert len(inj_004) == 0


class TestCRLFInjection:
    """DAST-INJ-005: CRLF injection."""

    def test_crlf_in_body(self):
        client = _mock_client(get_text="X-SKYHIGH-CRLF-Test:injected")
        get_resp = client.get.return_value
        get_resp.headers = {}
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        inj_005 = [f for f in findings if f.rule_id == "DAST-INJ-005"]
        assert len(inj_005) == 1


class TestHostHeaderInjection:
    """DAST-INJ-006: Host header injection."""

    def test_host_reflected(self):
        client = _mock_client(get_text="<a href='https://evil.skyhigh-test.com/reset'>Reset</a>")
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        inj_006 = [f for f in findings if f.rule_id == "DAST-INJ-006"]
        assert len(inj_006) == 1


class TestNoSQLInjection:
    """DAST-INJ-007: NoSQL injection."""

    def test_nosql_operator_accepted(self):
        post_resp = MagicMock()
        post_resp.status_code = 200
        nosql_data = {"username": "admin", "email": "admin@example.com", "role": "admin", "id": 1, "name": "Administrator", "status": "active"}
        post_resp.text = '{"username": "admin", "email": "admin@example.com", "role": "admin", "id": 1, "name": "Administrator", "status": "active"}'
        post_resp.json.return_value = nosql_data
        post_resp.headers = {}

        client = MagicMock()
        client.get.return_value = MagicMock(text="", status_code=200, headers={})
        client.post.return_value = post_resp
        client.probe_path.return_value = (404, "")

        sm = SiteMap()
        sm.api_endpoints = [APIEndpoint(url="https://api.example.com/login", method="POST")]
        findings = run_checks(client, "https://api.example.com", sm)
        inj_007 = [f for f in findings if f.rule_id == "DAST-INJ-007"]
        assert len(inj_007) == 1


class TestXPathInjection:
    """DAST-INJ-008: XPath injection."""

    def test_xpath_error(self):
        client = _mock_client(get_text="XPathException: Invalid predicate")
        sm = _url_sitemap("https://example.com/xml?query=test")
        findings = run_checks(client, "https://example.com", sm)
        inj_008 = [f for f in findings if f.rule_id == "DAST-INJ-008"]
        assert len(inj_008) == 1


class TestRunChecks:
    """Integration tests."""

    def test_all_findings_correct_category(self):
        client = _mock_client(get_text="SQL syntax error near")
        sm = _url_sitemap("https://example.com/search?q=test")
        findings = run_checks(client, "https://example.com", sm)
        for f in findings:
            assert f.category == "injection"
            assert f.target_type == "dast"

    def test_empty_sitemap(self):
        client = _mock_client()
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        assert isinstance(findings, list)
