"""Tests for DAST api_security check module."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from vulnerability_management.dast.checks.api_security import (
    _check_graphql_alias_dos,
    _check_graphql_batch_dos,
    _check_graphql_deep_nesting_dos,
    run_checks,
)
from vulnerability_management.dast.crawler import APIEndpoint, SiteMap

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _mock_client(
    probe_results: dict | None = None,
    post_json_resp: str = "{}",
    post_status: int = 200,
    get_text: str = "",
    get_status: int = 200,
    get_resp_headers: dict | None = None,
) -> MagicMock:
    client = MagicMock()
    client.get_headers.return_value = {}

    if probe_results:
        def _probe(base, path):
            return probe_results.get(path, (404, ""))
        client.probe_path.side_effect = _probe
    else:
        client.probe_path.return_value = (404, "")

    get_resp = MagicMock()
    get_resp.text = get_text
    get_resp.status_code = get_status
    get_resp.headers = get_resp_headers or {}
    get_resp.json.return_value = {}
    client.get.return_value = get_resp

    post_resp = MagicMock()
    post_resp.text = post_json_resp
    post_resp.status_code = post_status
    post_resp.json.return_value = {}
    post_resp.headers = {}
    client.post.return_value = post_resp

    return client


def _empty_sitemap() -> SiteMap:
    return SiteMap()


def _api_sitemap(*urls: str) -> SiteMap:
    sm = SiteMap()
    sm.api_endpoints = [APIEndpoint(url=u, source="test") for u in urls]
    return sm


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestAPIKeyInURL:
    """DAST-API-001: API keys in URLs."""

    def test_api_key_in_url(self):
        sm = SiteMap()
        sm.urls = {"https://api.example.com/data?api_key=supersecretkey123"}
        client = _mock_client()
        findings = run_checks(client, "https://api.example.com", sm)
        api_001 = [f for f in findings if f.rule_id == "DAST-API-001"]
        assert len(api_001) == 1

    def test_no_api_key(self):
        sm = SiteMap()
        sm.urls = {"https://api.example.com/data?page=1"}
        client = _mock_client()
        findings = run_checks(client, "https://api.example.com", sm)
        api_001 = [f for f in findings if f.rule_id == "DAST-API-001"]
        assert len(api_001) == 0


class TestGraphQLIntrospection:
    """DAST-API-002: GraphQL introspection."""

    def test_introspection_enabled(self):
        post_resp = MagicMock()
        post_resp.status_code = 200
        post_resp.json.return_value = {"data": {"__schema": {"types": []}}}
        post_resp.text = '{"data":{"__schema":{"types":[]}}}'

        client = MagicMock()
        client.get_headers.return_value = {}
        client.probe_path.return_value = (404, "")
        client.get.return_value = MagicMock(text="", status_code=200, headers={}, json=lambda: {})
        client.post.return_value = post_resp

        findings = run_checks(client, "https://example.com", _empty_sitemap())
        api_002 = [f for f in findings if f.rule_id == "DAST-API-002"]
        assert len(api_002) == 1

    def test_introspection_disabled(self):
        post_resp = MagicMock()
        post_resp.status_code = 400
        post_resp.json.return_value = {"errors": [{"message": "Forbidden"}]}

        client = MagicMock()
        client.get_headers.return_value = {}
        client.probe_path.return_value = (404, "")
        client.get.return_value = MagicMock(text="", status_code=200, headers={}, json=lambda: {})
        client.post.return_value = post_resp

        findings = run_checks(client, "https://example.com", _empty_sitemap())
        api_002 = [f for f in findings if f.rule_id == "DAST-API-002"]
        assert len(api_002) == 0


class TestAPIDocsExposed:
    """DAST-API-003: API documentation exposed."""

    def test_swagger_exposed(self):
        swagger_body = '{"swagger": "2.0", "info": {"title": "Test API"}, "paths": {"/api/users": {}, "/api/orders": {}, "/api/products": {}, "/api/settings": {}}}'
        client = _mock_client(probe_results={
            "swagger.json": (200, swagger_body),
        })
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        api_003 = [f for f in findings if f.rule_id == "DAST-API-003"]
        assert len(api_003) == 1

    def test_no_api_docs(self):
        client = _mock_client()
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        api_003 = [f for f in findings if f.rule_id == "DAST-API-003"]
        assert len(api_003) == 0


class TestVerboseErrors:
    """DAST-API-004: Verbose API errors."""

    def test_stack_trace_in_api(self):
        resp = MagicMock()
        resp.text = '{"error": "fail", "stackTrace": "at com.app.Main.run"}'
        resp.status_code = 500
        resp.headers = {}

        client = MagicMock()
        client.get_headers.return_value = {}
        client.probe_path.return_value = (404, "")
        client.get.return_value = resp
        client.post.return_value = MagicMock(text="{}", status_code=200, json=lambda: {}, headers={})

        sm = _api_sitemap("https://api.example.com/v1/data")
        findings = run_checks(client, "https://api.example.com", sm)
        api_004 = [f for f in findings if f.rule_id == "DAST-API-004"]
        assert len(api_004) == 1


class TestRateLimiting:
    """DAST-API-005: Missing rate limiting."""

    def test_no_rate_limit_headers(self):
        resp = MagicMock()
        resp.text = '{"data": "ok"}'
        resp.status_code = 200
        resp.headers = {"Content-Type": "application/json"}

        client = MagicMock()
        client.get_headers.return_value = {}
        client.probe_path.return_value = (404, "")
        client.get.return_value = resp
        client.post.return_value = MagicMock(text="{}", status_code=200, json=lambda: {}, headers={})

        sm = _api_sitemap("https://api.example.com/v1/data")
        findings = run_checks(client, "https://api.example.com", sm)
        api_005 = [f for f in findings if f.rule_id == "DAST-API-005"]
        assert len(api_005) == 1

    def test_rate_limit_present(self):
        resp = MagicMock()
        resp.text = '{"data": "ok"}'
        resp.status_code = 200
        resp.headers = {
            "Content-Type": "application/json",
            "X-RateLimit-Limit": "100",
        }

        client = MagicMock()
        client.get_headers.return_value = {}
        client.probe_path.return_value = (404, "")
        client.get.return_value = resp
        client.post.return_value = MagicMock(text="{}", status_code=200, json=lambda: {}, headers={})

        sm = _api_sitemap("https://api.example.com/v1/data")
        findings = run_checks(client, "https://api.example.com", sm)
        api_005 = [f for f in findings if f.rule_id == "DAST-API-005"]
        assert len(api_005) == 0


class TestAPICORS:
    """DAST-API-007: CORS on API endpoints."""

    def test_api_cors_wildcard(self):
        resp = MagicMock()
        resp.text = '{"data": "ok"}'
        resp.status_code = 200
        resp.headers = {"Access-Control-Allow-Origin": "*"}

        client = MagicMock()
        client.get_headers.return_value = {}
        client.probe_path.return_value = (404, "")
        client.get.return_value = resp
        client.post.return_value = MagicMock(text="{}", status_code=200, json=lambda: {}, headers={})

        sm = _api_sitemap("https://api.example.com/v1/data")
        findings = run_checks(client, "https://api.example.com", sm)
        api_007 = [f for f in findings if f.rule_id == "DAST-API-007"]
        assert len(api_007) == 1


class TestRunChecks:
    """Integration tests."""

    def test_all_findings_correct_category(self):
        client = _mock_client()
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        for f in findings:
            assert f.category == "api_security"
            assert f.target_type == "dast"

    def test_empty_sitemap_no_crash(self):
        client = _mock_client()
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        assert isinstance(findings, list)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# GraphQL DoS (DAST-API-009 / 010 / 011)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestGraphQLBatchDoS:
    """DAST-API-009: GraphQL query batching DoS."""

    def test_batch_accepted(self):
        """Detect when batch of 100 queries all execute."""
        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        batch_result = [{"data": {"__typename": "Query"}}] * 100
        resp.text = json.dumps(batch_result)
        resp.json.return_value = batch_result
        client.post.return_value = resp
        findings = []
        _check_graphql_batch_dos(client, "https://example.com", findings)
        api_009 = [f for f in findings if f.rule_id == "DAST-API-009"]
        assert len(api_009) >= 1
        assert api_009[0].severity == "MEDIUM"
        assert api_009[0].cwe == "CWE-400"

    def test_batch_rejected(self):
        """No finding when batch is rejected."""
        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 400
        resp.headers = {}
        resp.text = '{"errors": [{"message": "batch limit exceeded"}]}'
        client.post.return_value = resp
        findings = []
        _check_graphql_batch_dos(client, "https://example.com", findings)
        api_009 = [f for f in findings if f.rule_id == "DAST-API-009"]
        assert len(api_009) == 0


class TestGraphQLAliasDoS:
    """DAST-API-010: GraphQL field aliasing DoS."""

    def test_alias_accepted(self):
        """Detect when 100 aliases are all returned."""
        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        alias_data = {f"a{i}": "Query" for i in range(100)}
        resp.text = json.dumps({"data": alias_data})
        resp.json.return_value = {"data": alias_data}
        client.post.return_value = resp
        findings = []
        _check_graphql_alias_dos(client, "https://example.com", findings)
        api_010 = [f for f in findings if f.rule_id == "DAST-API-010"]
        assert len(api_010) >= 1

    def test_alias_rejected(self):
        """No finding when aliases are limited."""
        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        alias_data = {f"a{i}": "Query" for i in range(5)}
        resp.text = json.dumps({"data": alias_data})
        resp.json.return_value = {"data": alias_data}
        client.post.return_value = resp
        findings = []
        _check_graphql_alias_dos(client, "https://example.com", findings)
        api_010 = [f for f in findings if f.rule_id == "DAST-API-010"]
        assert len(api_010) == 0


class TestGraphQLDeepNesting:
    """DAST-API-011: GraphQL deep nesting DoS."""

    def test_nesting_causes_error(self):
        """Detect when deep nesting causes 5xx."""
        client = MagicMock()

        call_idx = [0]

        def fake_post(*args, **kwargs):
            call_idx[0] += 1
            resp = MagicMock()
            resp.headers = {}
            if call_idx[0] == 1:
                # Baseline introspection query - OK
                resp.status_code = 200
                resp.text = '{"data": {}}'
            else:
                # Deep nesting query - server error
                resp.status_code = 500
                resp.text = "Internal Server Error"
            return resp

        client.post.side_effect = fake_post
        findings = []
        _check_graphql_deep_nesting_dos(client, "https://example.com", findings)
        api_011 = [f for f in findings if f.rule_id == "DAST-API-011"]
        assert len(api_011) >= 1

    def test_nesting_handled(self):
        """No finding when nesting is properly limited."""
        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        resp.text = '{"errors": [{"message": "max depth exceeded"}]}'
        client.post.return_value = resp
        findings = []
        _check_graphql_deep_nesting_dos(client, "https://example.com", findings)
        api_011 = [f for f in findings if f.rule_id == "DAST-API-011"]
        assert len(api_011) == 0
