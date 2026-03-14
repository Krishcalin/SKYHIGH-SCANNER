"""
Tests for Phase 6 — Performance & Safety features.

Verifies:
  - CircuitBreaker: state transitions, threshold, half-open recovery
  - RateLimiter.adapt: adaptive rate reduction/recovery
  - Retry logic: retries on 5xx/connection errors, no retry on 4xx
  - Response time tracking: avg, p95
  - Connection pooling: adapter mounted
  - New DastConfig fields: verify_ssl, user_agent, proxy, max_pages, max_retries
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from vulnerability_management.dast.config import (
    CircuitBreaker,
    CircuitBreakerOpen,
    DastConfig,
    RateLimiter,
    ScopePolicy,
)
from vulnerability_management.dast.http_client import DastHTTPClient

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CircuitBreaker
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestCircuitBreaker:
    def test_initial_state_closed(self):
        cb = CircuitBreaker()
        assert cb.state == "closed"

    def test_stays_closed_under_threshold(self):
        cb = CircuitBreaker(threshold=5)
        for _ in range(4):
            cb.record_failure()
        assert cb.state == "closed"
        cb.check()  # Should not raise

    def test_trips_at_threshold(self):
        cb = CircuitBreaker(threshold=3)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == "open"
        with pytest.raises(CircuitBreakerOpen):
            cb.check()

    def test_success_resets_to_closed(self):
        cb = CircuitBreaker(threshold=3)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == "open"

        # Simulate reset_timeout elapsed
        cb._opened_at = time.monotonic() - 100.0
        assert cb.state == "half-open"

        cb.record_success()
        assert cb.state == "closed"
        assert cb.failure_count == 0

    def test_half_open_after_timeout(self):
        cb = CircuitBreaker(threshold=2, reset_timeout=0.1)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "open"

        time.sleep(0.15)
        assert cb.state == "half-open"
        cb.check()  # Should not raise in half-open

    def test_failure_count_property(self):
        cb = CircuitBreaker()
        assert cb.failure_count == 0
        cb.record_failure()
        cb.record_failure()
        assert cb.failure_count == 2


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Adaptive RateLimiter
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestAdaptiveRateLimiter:
    def test_adapt_halves_on_429(self):
        rl = RateLimiter(rate=10.0)
        rl.adapt(429)
        assert rl.rate == 5.0

    def test_adapt_halves_on_500(self):
        rl = RateLimiter(rate=10.0)
        rl.adapt(500)
        assert rl.rate == 5.0

    def test_adapt_halves_on_503(self):
        rl = RateLimiter(rate=10.0)
        rl.adapt(503)
        assert rl.rate == 5.0

    def test_adapt_floor_at_0_5(self):
        rl = RateLimiter(rate=1.0)
        rl.adapt(500)  # → 0.5
        assert rl.rate == 0.5
        rl.adapt(500)  # Should stay at 0.5
        assert rl.rate == 0.5

    def test_adapt_recovery_after_backoff(self):
        rl = RateLimiter(rate=10.0)
        rl.adapt(500)  # → 5.0
        assert rl.rate == 5.0

        # Simulate backoff period elapsed
        rl._backoff_until = time.monotonic() - 1.0
        rl.adapt(200)  # → 7.5
        assert rl.rate == 7.5

    def test_adapt_no_recovery_during_backoff(self):
        rl = RateLimiter(rate=10.0)
        rl.adapt(500)  # → 5.0
        # Still in backoff period
        rl.adapt(200)  # Should not recover
        assert rl.rate == 5.0

    def test_adapt_capped_at_base_rate(self):
        rl = RateLimiter(rate=10.0)
        rl.adapt(500)  # → 5.0
        rl._backoff_until = time.monotonic() - 1.0
        rl.adapt(200)  # → 7.5
        rl.adapt(200)  # → 10.0
        rl.adapt(200)  # Should stay at 10.0
        assert rl.rate == 10.0

    def test_no_change_on_normal_200(self):
        rl = RateLimiter(rate=10.0)
        rl.adapt(200)
        assert rl.rate == 10.0

    def test_no_change_on_404(self):
        rl = RateLimiter(rate=10.0)
        rl.adapt(404)
        assert rl.rate == 10.0

    def test_base_rate_preserved(self):
        rl = RateLimiter(rate=20.0)
        assert rl._base_rate == 20.0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# New DastConfig fields
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestDastConfigNewFields:
    def test_defaults(self):
        config = DastConfig()
        assert config.verify_ssl is False
        assert config.user_agent == "VulnMgmt-DAST/1.0"
        assert config.proxy is None
        assert config.max_pages == 500
        assert config.max_retries == 3

    def test_custom_values(self):
        config = DastConfig(
            verify_ssl=True,
            user_agent="CustomBot/2.0",
            proxy="http://127.0.0.1:8080",
            max_pages=100,
            max_retries=5,
        )
        assert config.verify_ssl is True
        assert config.user_agent == "CustomBot/2.0"
        assert config.proxy == "http://127.0.0.1:8080"
        assert config.max_pages == 100
        assert config.max_retries == 5

    def test_from_cli_args_new_fields(self):
        from argparse import Namespace
        args = Namespace(
            target="https://example.com",
            ip_range=None,
            dast_scope=None,
            dast_rate_limit=10.0,
            dast_max_requests=10000,
            dast_crawl_depth=5,
            dast_auth_mode="none",
            dast_auth_token=None,
            dast_login_url=None,
            dast_login_user=None,
            dast_login_password=None,
            dast_no_crawl=False,
            dast_passive_only=False,
            dast_accept_risk=False,
            dast_follow_subdomains=False,
            dast_request_timeout=20,
            dast_verify_ssl=True,
            dast_max_pages=200,
            dast_user_agent="MyBot/1.0",
            dast_proxy="http://proxy:8080",
            dast_retries=5,
            timeout=30,
        )
        config = DastConfig.from_cli_args(args)
        assert config.request_timeout == 20
        assert config.verify_ssl is True
        assert config.max_pages == 200
        assert config.user_agent == "MyBot/1.0"
        assert config.proxy == "http://proxy:8080"
        assert config.max_retries == 5


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Retry Logic
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def _make_client(**overrides):
    defaults = dict(
        scope=ScopePolicy(allowed_hosts=["example.com"]),
        rate_limit_rps=1000.0,
        max_requests=5000,
        max_retries=3,
    )
    defaults.update(overrides)
    config = DastConfig(**defaults)
    return DastHTTPClient(config=config)


def _mock_resp(status=200, text="OK", headers=None):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.headers = headers or {"Content-Type": "text/html"}
    resp.request = MagicMock()
    resp.request.headers = {}
    return resp


class TestRetryLogic:
    def test_no_retry_on_200(self):
        client = _make_client()
        mock_resp = _mock_resp(200)
        with patch.object(client._session, "request", return_value=mock_resp) as m:
            resp = client.request("GET", "https://example.com/ok")
        assert resp.status_code == 200
        assert m.call_count == 1

    def test_no_retry_on_404(self):
        client = _make_client()
        mock_resp = _mock_resp(404)
        with patch.object(client._session, "request", return_value=mock_resp) as m:
            resp = client.request("GET", "https://example.com/missing")
        assert resp.status_code == 404
        assert m.call_count == 1

    def test_retry_on_500(self):
        client = _make_client()
        fail_resp = _mock_resp(500)
        ok_resp = _mock_resp(200)

        with patch.object(
            client._session, "request",
            side_effect=[fail_resp, ok_resp],
        ) as m, patch("vulnerability_management.dast.http_client.time.sleep"):
            resp = client.request("GET", "https://example.com/flaky")

        assert resp.status_code == 200
        assert m.call_count == 2

    def test_retry_exhausted_on_persistent_500(self):
        client = _make_client(max_retries=2)
        fail_resp = _mock_resp(500)

        with patch.object(
            client._session, "request",
            return_value=fail_resp,
        ) as m, patch("vulnerability_management.dast.http_client.time.sleep"):
            # Should return the 500 response after exhausting retries
            resp = client.request("GET", "https://example.com/down")

        assert resp.status_code == 500
        assert m.call_count == 2

    def test_retry_on_connection_error(self):
        import requests as req
        client = _make_client(max_retries=3)
        ok_resp = _mock_resp(200)

        with patch.object(
            client._session, "request",
            side_effect=[req.ConnectionError("refused"), ok_resp],
        ) as m, patch("vulnerability_management.dast.http_client.time.sleep"):
            resp = client.request("GET", "https://example.com/retry")

        assert resp.status_code == 200
        assert m.call_count == 2

    def test_retry_on_timeout(self):
        import requests as req
        client = _make_client(max_retries=3)
        ok_resp = _mock_resp(200)

        with patch.object(
            client._session, "request",
            side_effect=[req.Timeout("timed out"), ok_resp],
        ) as m, patch("vulnerability_management.dast.http_client.time.sleep"):
            resp = client.request("GET", "https://example.com/slow")

        assert resp.status_code == 200
        assert m.call_count == 2

    def test_all_retries_exhausted_raises(self):
        import requests as req
        client = _make_client(max_retries=2)

        with patch.object(
            client._session, "request",
            side_effect=req.ConnectionError("refused"),
        ), patch("vulnerability_management.dast.http_client.time.sleep"), pytest.raises(req.ConnectionError):
            client.request("GET", "https://example.com/dead")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Response Time Tracking
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestResponseTimeTracking:
    def test_avg_response_time(self):
        client = _make_client()
        resp = _mock_resp(200)

        with patch.object(client._session, "request", return_value=resp):
            for _ in range(5):
                client.request("GET", "https://example.com/page")

        assert client.avg_response_time_ms >= 0
        assert len(client._response_times) == 5

    def test_p95_response_time(self):
        client = _make_client()
        resp = _mock_resp(200)

        with patch.object(client._session, "request", return_value=resp):
            for _ in range(20):
                client.request("GET", "https://example.com/page")

        assert client.p95_response_time_ms >= client.avg_response_time_ms * 0.5

    def test_no_requests_returns_zero(self):
        client = _make_client()
        assert client.avg_response_time_ms == 0.0
        assert client.p95_response_time_ms == 0.0

    def test_evidence_includes_response_time(self):
        client = _make_client()
        resp = _mock_resp(200)

        with patch.object(client._session, "request", return_value=resp):
            client.request("GET", "https://example.com/timed")

        assert len(client.evidence) == 1
        assert client.evidence[0].response_time_ms >= 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Connection Pooling & Client Config
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestClientConfig:
    def test_user_agent_set(self):
        client = _make_client(user_agent="TestBot/3.0")
        assert client._session.headers["User-Agent"] == "TestBot/3.0"

    def test_proxy_set(self):
        client = _make_client(proxy="http://proxy:8080")
        assert client._session.proxies["http"] == "http://proxy:8080"
        assert client._session.proxies["https"] == "http://proxy:8080"

    def test_no_proxy_by_default(self):
        client = _make_client()
        assert not getattr(client._session, "proxies", None) or \
            client._session.proxies == {}

    def test_verify_ssl_from_config(self):
        client = _make_client(verify_ssl=True)
        assert client._session.verify is True

    def test_verify_ssl_param_overrides_config(self):
        config = DastConfig(
            scope=ScopePolicy(allowed_hosts=["example.com"]),
            rate_limit_rps=1000.0,
            max_requests=5000,
            verify_ssl=True,
        )
        client = DastHTTPClient(config=config, verify_ssl=False)
        assert client._session.verify is False

    def test_connection_pool_adapter_mounted(self):
        client = _make_client()
        # Check that adapters are mounted
        assert len(client._session.adapters) >= 2

    def test_circuit_breaker_blocks_request(self):
        client = _make_client()
        # Trip the circuit breaker
        for _ in range(10):
            client._circuit_breaker.record_failure()

        with pytest.raises(CircuitBreakerOpen):
            client.request("GET", "https://example.com/blocked")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CLI new arguments
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestDastCLINewArgs:
    def test_new_args_parse(self):
        from vulnerability_management.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args([
            "dast", "--target", "https://example.com",
            "--dast-request-timeout", "25",
            "--dast-verify-ssl",
            "--dast-max-pages", "300",
            "--dast-user-agent", "CustomAgent/1.0",
            "--dast-proxy", "http://127.0.0.1:8080",
            "--dast-retries", "5",
        ])
        assert args.dast_request_timeout == 25
        assert args.dast_verify_ssl is True
        assert args.dast_max_pages == 300
        assert args.dast_user_agent == "CustomAgent/1.0"
        assert args.dast_proxy == "http://127.0.0.1:8080"
        assert args.dast_retries == 5

    def test_new_args_defaults(self):
        from vulnerability_management.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args([
            "dast", "--target", "https://example.com",
        ])
        assert args.dast_request_timeout == 15
        assert args.dast_verify_ssl is False
        assert args.dast_max_pages == 500
        assert args.dast_user_agent == "VulnMgmt-DAST/1.0"
        assert args.dast_proxy is None
        assert args.dast_retries == 3
