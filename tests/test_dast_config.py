"""Tests for DAST configuration, scope policy, and rate limiter."""

from __future__ import annotations

import json
import threading
import time

import pytest

from skyhigh_scanner.dast.config import (
    CircuitBreaker,
    CircuitBreakerOpen,
    DastConfig,
    RateLimiter,
    RequestCounter,
    RequestLimitExceeded,
    ScopePolicy,
    _load_scope_file,
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ScopePolicy
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestScopePolicy:
    def test_host_allowed_exact(self):
        scope = ScopePolicy(allowed_hosts=["example.com"])
        assert scope.is_host_allowed("example.com")
        assert not scope.is_host_allowed("evil.com")

    def test_host_allowed_case_insensitive(self):
        scope = ScopePolicy(allowed_hosts=["Example.COM"])
        assert scope.is_host_allowed("example.com")
        assert scope.is_host_allowed("EXAMPLE.COM")

    def test_host_allowed_subdomain_disabled(self):
        scope = ScopePolicy(allowed_hosts=["example.com"], follow_subdomains=False)
        assert not scope.is_host_allowed("sub.example.com")

    def test_host_allowed_subdomain_enabled(self):
        scope = ScopePolicy(allowed_hosts=["example.com"], follow_subdomains=True)
        assert scope.is_host_allowed("sub.example.com")
        assert scope.is_host_allowed("deep.sub.example.com")
        assert not scope.is_host_allowed("evil.com")

    def test_empty_hosts_denies_all(self):
        scope = ScopePolicy(allowed_hosts=[])
        assert not scope.is_host_allowed("example.com")

    def test_path_allowed_no_prefixes(self):
        scope = ScopePolicy()
        assert scope.is_path_allowed("/any/path")

    def test_path_allowed_with_prefixes(self):
        scope = ScopePolicy(allowed_path_prefixes=["/app/", "/api/v1/"])
        assert scope.is_path_allowed("/app/dashboard")
        assert scope.is_path_allowed("/api/v1/users")
        assert not scope.is_path_allowed("/admin/panel")

    def test_path_excluded(self):
        scope = ScopePolicy(excluded_paths=["/logout"])
        assert not scope.is_path_allowed("/logout")
        assert scope.is_path_allowed("/login")

    def test_path_excluded_extension(self):
        scope = ScopePolicy()
        assert not scope.is_path_allowed("/files/report.pdf")
        assert not scope.is_path_allowed("/images/logo.png")
        assert scope.is_path_allowed("/api/data")

    def test_url_in_scope(self):
        scope = ScopePolicy(allowed_hosts=["app.example.com"])
        assert scope.is_url_in_scope("https://app.example.com/dashboard")
        assert not scope.is_url_in_scope("https://evil.com/attack")

    def test_url_in_scope_excluded_path(self):
        scope = ScopePolicy(
            allowed_hosts=["app.example.com"],
            excluded_paths=["/logout"],
        )
        assert not scope.is_url_in_scope("https://app.example.com/logout")

    def test_from_target(self):
        scope = ScopePolicy.from_target("https://app.example.com/path")
        assert scope.is_host_allowed("app.example.com")

    def test_from_target_preserves_extra_hosts(self):
        scope = ScopePolicy.from_target(
            "https://app.example.com",
            allowed_hosts=["api.example.com"],
        )
        assert scope.is_host_allowed("app.example.com")
        assert scope.is_host_allowed("api.example.com")

    def test_localhost_factory(self):
        scope = ScopePolicy.localhost()
        assert scope.is_host_allowed("localhost")
        assert scope.is_host_allowed("127.0.0.1")
        assert scope.max_depth == 10

    def test_max_depth_default(self):
        scope = ScopePolicy()
        assert scope.max_depth == 5


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# RateLimiter
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestRateLimiter:
    def test_acquire_immediate(self):
        limiter = RateLimiter(rate=1000.0)
        start = time.monotonic()
        limiter.acquire()
        elapsed = time.monotonic() - start
        assert elapsed < 0.1

    def test_burst(self):
        limiter = RateLimiter(rate=100.0, burst=5)
        # Should be able to acquire 5 tokens without blocking
        start = time.monotonic()
        for _ in range(5):
            limiter.acquire()
        elapsed = time.monotonic() - start
        assert elapsed < 0.1

    def test_minimum_rate(self):
        limiter = RateLimiter(rate=0.01)
        assert limiter.rate == 0.1  # Clamped to minimum


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# RequestCounter
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestRequestCounter:
    def test_increment(self):
        counter = RequestCounter(max_requests=100)
        assert counter.increment() == 1
        assert counter.increment() == 2
        assert counter.count == 2

    def test_limit_exceeded(self):
        counter = RequestCounter(max_requests=2)
        counter.increment()
        counter.increment()
        with pytest.raises(RequestLimitExceeded):
            counter.increment()

    def test_reset(self):
        counter = RequestCounter(max_requests=5)
        counter.increment()
        counter.increment()
        counter.reset()
        assert counter.count == 0
        counter.increment()  # Should not raise

    def test_thread_safe(self):
        counter = RequestCounter(max_requests=1000)
        errors = []

        def increment_many():
            try:
                for _ in range(100):
                    counter.increment()
            except RequestLimitExceeded:
                errors.append("limit exceeded")

        threads = [threading.Thread(target=increment_many) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert counter.count == 500
        assert not errors


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DastConfig
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestDastConfig:
    def test_defaults(self):
        config = DastConfig()
        assert config.rate_limit_rps == 10.0
        assert config.max_requests == 10000
        assert config.auth_mode == "none"
        assert config.crawl_enabled is True
        assert config.passive_only is False

    def test_invalid_auth_mode(self):
        with pytest.raises(ValueError, match="Invalid auth_mode"):
            DastConfig(auth_mode="oauth")

    def test_valid_auth_modes(self):
        for mode in ("none", "cookie", "bearer", "basic", "form"):
            config = DastConfig(auth_mode=mode)
            assert config.auth_mode == mode

    def test_from_cli_args_basic(self):
        from argparse import Namespace
        args = Namespace(
            target="https://app.example.com",
            ip_range=None,
            dast_scope=None,
            dast_rate_limit=20.0,
            dast_max_requests=5000,
            dast_crawl_depth=3,
            dast_auth_mode="bearer",
            dast_auth_token="mytoken123",
            dast_login_url=None,
            dast_no_crawl=False,
            dast_passive_only=True,
            dast_accept_risk=True,
            dast_follow_subdomains=False,
            timeout=15,
        )
        config = DastConfig.from_cli_args(args)
        assert config.rate_limit_rps == 20.0
        assert config.max_requests == 5000
        assert config.auth_mode == "bearer"
        assert config.auth_token == "mytoken123"
        assert config.passive_only is True
        assert config.accept_risk is True
        assert config.scope.is_host_allowed("app.example.com")

    def test_from_cli_args_non_url_target(self):
        from argparse import Namespace
        args = Namespace(
            target=None,
            ip_range="192.168.1.1",
            dast_scope=None,
            dast_rate_limit=10.0,
            dast_max_requests=10000,
            dast_crawl_depth=5,
            dast_auth_mode="none",
            dast_auth_token=None,
            dast_login_url=None,
            dast_no_crawl=False,
            dast_passive_only=False,
            dast_accept_risk=False,
            dast_follow_subdomains=False,
            timeout=30,
        )
        config = DastConfig.from_cli_args(args)
        assert config.scope.is_host_allowed("192.168.1.1")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Scope file loading
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestScopeFileLoading:
    def test_load_scope_file(self, tmp_path):
        scope_data = {
            "allowed_hosts": ["app.example.com", "api.example.com"],
            "allowed_path_prefixes": ["/app/"],
            "max_depth": 3,
            "follow_subdomains": True,
        }
        scope_file = tmp_path / "scope.json"
        scope_file.write_text(json.dumps(scope_data))

        scope = _load_scope_file(str(scope_file))
        assert scope.is_host_allowed("app.example.com")
        assert scope.is_host_allowed("api.example.com")
        assert scope.max_depth == 3
        assert scope.follow_subdomains is True
        assert scope.is_path_allowed("/app/dashboard")
        assert not scope.is_path_allowed("/admin/")

    def test_load_scope_file_minimal(self, tmp_path):
        scope_data = {"allowed_hosts": ["test.com"]}
        scope_file = tmp_path / "scope.json"
        scope_file.write_text(json.dumps(scope_data))

        scope = _load_scope_file(str(scope_file))
        assert scope.is_host_allowed("test.com")
        assert scope.max_depth == 5  # default


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Adaptive RateLimiter (Phase 6)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestRateLimiterAdaptive:
    def test_base_rate_stored(self):
        rl = RateLimiter(rate=15.0)
        assert rl._base_rate == 15.0

    def test_adapt_reduces_on_server_error(self):
        rl = RateLimiter(rate=20.0)
        rl.adapt(500)
        assert rl.rate == 10.0

    def test_adapt_reduces_on_429(self):
        rl = RateLimiter(rate=20.0)
        rl.adapt(429)
        assert rl.rate == 10.0

    def test_adapt_ignores_client_errors(self):
        rl = RateLimiter(rate=20.0)
        rl.adapt(400)
        assert rl.rate == 20.0
        rl.adapt(403)
        assert rl.rate == 20.0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CircuitBreaker (Phase 6)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestCircuitBreakerConfig:
    def test_default_threshold(self):
        cb = CircuitBreaker()
        assert cb.threshold == 10

    def test_custom_threshold(self):
        cb = CircuitBreaker(threshold=5, reset_timeout=30.0)
        assert cb.threshold == 5
        assert cb.reset_timeout == 30.0

    def test_check_passes_when_closed(self):
        cb = CircuitBreaker()
        cb.check()  # Should not raise

    def test_check_raises_when_open(self):
        cb = CircuitBreaker(threshold=1)
        cb.record_failure()
        with pytest.raises(CircuitBreakerOpen):
            cb.check()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# New DastConfig fields (Phase 6)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestDastConfigPhase6:
    def test_new_field_defaults(self):
        config = DastConfig()
        assert config.verify_ssl is False
        assert config.user_agent == "SkyHigh-DAST/1.0"
        assert config.proxy is None
        assert config.max_pages == 500
        assert config.max_retries == 3

    def test_from_cli_args_maps_new_fields(self):
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
            dast_request_timeout=25,
            dast_verify_ssl=True,
            dast_max_pages=100,
            dast_user_agent="Test/1.0",
            dast_proxy="http://proxy:9090",
            dast_retries=2,
            timeout=30,
        )
        config = DastConfig.from_cli_args(args)
        assert config.request_timeout == 25
        assert config.verify_ssl is True
        assert config.max_pages == 100
        assert config.user_agent == "Test/1.0"
        assert config.proxy == "http://proxy:9090"
        assert config.max_retries == 2
