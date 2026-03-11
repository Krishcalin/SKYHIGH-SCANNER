"""
Scope-enforced, rate-limited HTTP client for DAST scanning.

Wraps the ``requests`` library with:
  - Scope enforcement — every URL is checked against ``ScopePolicy``
  - Rate limiting — token bucket algorithm
  - Request counting — hard cap on total requests
  - Evidence logging — stores request/response pairs for findings
  - Authentication — auto-applies auth headers based on config
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .config import (
    DastConfig,
    RateLimiter,
    RequestCounter,
    RequestLimitExceeded,
    ScopeViolation,
)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Evidence record
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class RequestEvidence:
    """Captured request/response pair for finding evidence."""

    method: str
    url: str
    status_code: int
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body_snippet: str = ""

    def summary(self) -> str:
        """One-line summary for Finding.line_content."""
        body_hint = ""
        if self.request_body:
            body_hint = f" | Body: {self.request_body[:80]}"
        return (
            f"{self.method} {self.url} → {self.status_code}"
            f"{body_hint}"
        )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DAST HTTP Client
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class DastHTTPClient:
    """HTTP client with scope enforcement, rate limiting, and evidence capture.

    Args:
        config: DAST configuration (scope, rate limits, auth, etc.).
        verify_ssl: Whether to verify SSL certificates.
    """

    def __init__(self, config: DastConfig, verify_ssl: bool = False):
        if not HAS_REQUESTS:
            raise ImportError(
                "DAST scanner requires 'requests'. Install with: pip install requests"
            )

        self.config = config
        self._session = requests.Session()
        self._session.verify = verify_ssl

        # Rate limiter and request counter
        self._rate_limiter = RateLimiter(rate=config.rate_limit_rps)
        self._counter = RequestCounter(max_requests=config.max_requests)

        # Evidence log
        self.evidence: list[RequestEvidence] = []

        # Apply authentication
        self._setup_auth()

        # Apply custom headers
        if config.custom_headers:
            self._session.headers.update(config.custom_headers)

        # Suppress SSL warnings when not verifying
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ── Auth setup ────────────────────────────────────────────────────

    def _setup_auth(self) -> None:
        """Configure session authentication based on config."""
        mode = self.config.auth_mode

        if mode == "bearer" and self.config.auth_token:
            self._session.headers["Authorization"] = f"Bearer {self.config.auth_token}"

        elif mode == "cookie" and self.config.auth_token:
            # auth_token is expected to be "name=value" or just the cookie value
            if "=" in self.config.auth_token:
                name, _, value = self.config.auth_token.partition("=")
                self._session.cookies.set(name.strip(), value.strip())
            else:
                self._session.cookies.set("session", self.config.auth_token)

        elif mode == "basic" and self.config.auth_token and ":" in self.config.auth_token:
            user, _, pw = self.config.auth_token.partition(":")
            self._session.auth = (user, pw)

    # ── Scope check ───────────────────────────────────────────────────

    def _check_scope(self, url: str) -> None:
        """Raise ScopeViolation if URL is not in scope."""
        if not self.config.scope.is_url_in_scope(url):
            raise ScopeViolation(f"URL is out of scope: {url}")

    # ── Core request method ───────────────────────────────────────────

    def request(
        self,
        method: str,
        url: str,
        capture_evidence: bool = True,
        **kwargs,
    ) -> requests.Response:
        """Send an HTTP request with scope enforcement and rate limiting.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.).
            url: Full URL to request.
            capture_evidence: Whether to log request/response evidence.
            **kwargs: Passed to ``requests.Session.request()``.

        Returns:
            The HTTP response.

        Raises:
            ScopeViolation: If the URL is out of scope.
            RequestLimitExceeded: If the max request cap is reached.
        """
        self._check_scope(url)
        self._counter.increment()
        self._rate_limiter.acquire()

        kwargs.setdefault("timeout", self.config.request_timeout)
        kwargs.setdefault("allow_redirects", True)

        resp = self._session.request(method, url, **kwargs)

        if capture_evidence:
            body = kwargs.get("data") or kwargs.get("json")
            body_str = str(body)[:500] if body else None
            ev = RequestEvidence(
                method=method.upper(),
                url=url,
                status_code=resp.status_code,
                request_headers=dict(resp.request.headers),
                request_body=body_str,
                response_headers=dict(resp.headers),
                response_body_snippet=resp.text[:2000] if resp.text else "",
            )
            self.evidence.append(ev)

        return resp

    # ── Convenience methods ───────────────────────────────────────────

    def get(self, url: str, **kwargs) -> requests.Response:
        """Send a GET request."""
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        """Send a POST request."""
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> requests.Response:
        """Send a PUT request."""
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs) -> requests.Response:
        """Send a DELETE request."""
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response:
        """Send a HEAD request."""
        kwargs.setdefault("capture_evidence", False)
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> requests.Response:
        """Send an OPTIONS request."""
        return self.request("OPTIONS", url, **kwargs)

    def post_form(self, url: str, data: dict[str, Any], **kwargs) -> requests.Response:
        """Submit a form via POST."""
        return self.post(url, data=data, **kwargs)

    def post_json(self, url: str, json_data: dict[str, Any], **kwargs) -> requests.Response:
        """Send JSON payload via POST."""
        return self.post(url, json=json_data, **kwargs)

    # ── Form-based login ──────────────────────────────────────────────

    def login_form(self, login_url: str, form_data: dict[str, str]) -> bool:
        """Perform form-based login and capture the session.

        Returns:
            True if login appeared successful (non-error redirect or 200).
        """
        try:
            resp = self.post(login_url, data=form_data)
            # Consider login successful if we got 200 or a redirect
            return resp.status_code in (200, 301, 302, 303)
        except Exception as e:
            logger.warning("Form login failed: %s", e)
            return False

    # ── Utility ───────────────────────────────────────────────────────

    def get_headers(self, url: str) -> dict[str, str]:
        """Fetch response headers for a URL."""
        try:
            resp = self.head(url)
            return dict(resp.headers)
        except Exception:
            return {}

    def probe_path(self, base_url: str, path: str) -> tuple[int, str]:
        """Probe a path relative to base URL. Returns (status, body_snippet)."""
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            resp = self.get(url, capture_evidence=False)
            return resp.status_code, resp.text[:2000] if resp.text else ""
        except (ScopeViolation, RequestLimitExceeded):
            return 0, ""
        except Exception:
            return 0, ""

    @property
    def request_count(self) -> int:
        """Number of requests sent so far."""
        return self._counter.count

    def close(self) -> None:
        """Close the underlying session."""
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
