"""Tests for the DAST HTTP client with scope enforcement and rate limiting."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from skyhigh_scanner.dast.config import (
    DastConfig,
    RequestLimitExceeded,
    ScopePolicy,
    ScopeViolation,
)
from skyhigh_scanner.dast.http_client import DastHTTPClient, RequestEvidence

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# RequestEvidence
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestRequestEvidence:
    def test_summary_basic(self):
        ev = RequestEvidence(
            method="GET",
            url="https://example.com/api",
            status_code=200,
        )
        assert ev.summary() == "GET https://example.com/api → 200"

    def test_summary_with_body(self):
        ev = RequestEvidence(
            method="POST",
            url="https://example.com/login",
            status_code=302,
            request_body="username=admin&password=test",
        )
        assert "POST" in ev.summary()
        assert "302" in ev.summary()
        assert "username=admin" in ev.summary()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DastHTTPClient
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@pytest.fixture
def dast_config():
    """Config with scope locked to example.com."""
    return DastConfig(
        scope=ScopePolicy(allowed_hosts=["example.com"]),
        rate_limit_rps=1000.0,  # High rate to avoid blocking in tests
        max_requests=100,
    )


@pytest.fixture
def mock_response():
    """Create a mock requests.Response."""
    resp = MagicMock()
    resp.status_code = 200
    resp.text = "<html>Hello</html>"
    resp.headers = {"Content-Type": "text/html"}
    resp.request = MagicMock()
    resp.request.headers = {"User-Agent": "test"}
    return resp


class TestDastHTTPClientScope:
    def test_in_scope_request_succeeds(self, dast_config, mock_response):
        client = DastHTTPClient(config=dast_config)
        with patch.object(client._session, "request", return_value=mock_response):
            resp = client.get("https://example.com/page")
        assert resp.status_code == 200

    def test_out_of_scope_raises(self, dast_config):
        client = DastHTTPClient(config=dast_config)
        with pytest.raises(ScopeViolation):
            client.get("https://evil.com/attack")

    def test_scope_enforced_on_all_methods(self, dast_config):
        client = DastHTTPClient(config=dast_config)
        for method in ("get", "post", "put", "delete", "head", "options"):
            with pytest.raises(ScopeViolation):
                getattr(client, method)("https://evil.com/x")


class TestDastHTTPClientRequestCounting:
    def test_request_count_tracks(self, dast_config, mock_response):
        client = DastHTTPClient(config=dast_config)
        with patch.object(client._session, "request", return_value=mock_response):
            client.get("https://example.com/1")
            client.get("https://example.com/2")
        assert client.request_count == 2

    def test_request_limit_enforced(self, mock_response):
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["example.com"]),
            rate_limit_rps=1000.0,
            max_requests=3,
        )
        client = DastHTTPClient(config=config)
        with patch.object(client._session, "request", return_value=mock_response):
            client.get("https://example.com/1")
            client.get("https://example.com/2")
            client.get("https://example.com/3")
            with pytest.raises(RequestLimitExceeded):
                client.get("https://example.com/4")


class TestDastHTTPClientEvidence:
    def test_evidence_captured(self, dast_config, mock_response):
        client = DastHTTPClient(config=dast_config)
        with patch.object(client._session, "request", return_value=mock_response):
            client.get("https://example.com/page")
        assert len(client.evidence) == 1
        ev = client.evidence[0]
        assert ev.method == "GET"
        assert ev.url == "https://example.com/page"
        assert ev.status_code == 200

    def test_evidence_not_captured_when_disabled(self, dast_config, mock_response):
        client = DastHTTPClient(config=dast_config)
        with patch.object(client._session, "request", return_value=mock_response):
            client.get("https://example.com/page", capture_evidence=False)
        assert len(client.evidence) == 0

    def test_head_does_not_capture_by_default(self, dast_config, mock_response):
        client = DastHTTPClient(config=dast_config)
        with patch.object(client._session, "request", return_value=mock_response):
            client.head("https://example.com/page")
        assert len(client.evidence) == 0


class TestDastHTTPClientAuth:
    def test_bearer_auth(self):
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["example.com"]),
            auth_mode="bearer",
            auth_token="mytoken123",
        )
        client = DastHTTPClient(config=config)
        assert client._session.headers.get("Authorization") == "Bearer mytoken123"

    def test_cookie_auth_name_value(self):
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["example.com"]),
            auth_mode="cookie",
            auth_token="session_id=abc123",
        )
        client = DastHTTPClient(config=config)
        assert client._session.cookies.get("session_id") == "abc123"

    def test_cookie_auth_value_only(self):
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["example.com"]),
            auth_mode="cookie",
            auth_token="abc123",
        )
        client = DastHTTPClient(config=config)
        assert client._session.cookies.get("session") == "abc123"

    def test_basic_auth(self):
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["example.com"]),
            auth_mode="basic",
            auth_token="admin:secret",
        )
        client = DastHTTPClient(config=config)
        assert client._session.auth == ("admin", "secret")

    def test_custom_headers(self):
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["example.com"]),
            custom_headers={"X-Custom": "test-value"},
        )
        client = DastHTTPClient(config=config)
        assert client._session.headers.get("X-Custom") == "test-value"


class TestDastHTTPClientConvenience:
    def test_post_form(self, dast_config, mock_response):
        client = DastHTTPClient(config=dast_config)
        with patch.object(client._session, "request", return_value=mock_response) as mock_req:
            client.post_form("https://example.com/submit", {"name": "test"})
        mock_req.assert_called_once()
        _, kwargs = mock_req.call_args
        assert kwargs.get("data") == {"name": "test"}

    def test_post_json(self, dast_config, mock_response):
        client = DastHTTPClient(config=dast_config)
        with patch.object(client._session, "request", return_value=mock_response) as mock_req:
            client.post_json("https://example.com/api", {"key": "val"})
        mock_req.assert_called_once()
        _, kwargs = mock_req.call_args
        assert kwargs.get("json") == {"key": "val"}

    def test_probe_path(self, dast_config, mock_response):
        mock_response.text = "probe response body"
        client = DastHTTPClient(config=dast_config)
        with patch.object(client._session, "request", return_value=mock_response):
            status, body = client.probe_path("https://example.com", "/test")
        assert status == 200
        assert "probe response" in body

    def test_probe_path_out_of_scope(self, dast_config):
        client = DastHTTPClient(config=dast_config)
        status, body = client.probe_path("https://evil.com", "/test")
        assert status == 0
        assert body == ""

    def test_get_headers(self, dast_config, mock_response):
        mock_response.headers = {"Server": "nginx", "X-Custom": "yes"}
        client = DastHTTPClient(config=dast_config)
        with patch.object(client._session, "request", return_value=mock_response):
            headers = client.get_headers("https://example.com")
        assert headers.get("Server") == "nginx"

    def test_context_manager(self, dast_config):
        with DastHTTPClient(config=dast_config) as client:
            assert client is not None

    def test_login_form(self, dast_config, mock_response):
        mock_response.status_code = 302
        client = DastHTTPClient(config=dast_config)
        with patch.object(client._session, "request", return_value=mock_response):
            result = client.login_form(
                "https://example.com/login",
                {"user": "admin", "pass": "secret"},
            )
        assert result is True
