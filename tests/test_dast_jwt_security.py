"""Tests for DAST JWT security check module."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from unittest.mock import MagicMock

from skyhigh_scanner.dast.checks.jwt_security import (
    _collect_jwts,
    run_checks,
)
from skyhigh_scanner.dast.crawler import APIEndpoint, SiteMap

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _make_jwt(
    header: dict | None = None,
    payload: dict | None = None,
    secret: str = "secret",
) -> str:
    """Create a valid HS256-signed JWT for testing."""
    h = header or {"alg": "HS256", "typ": "JWT"}
    p = payload or {"sub": "1234", "name": "Test", "iat": 1000000000}

    def b64(d: dict) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(d).encode(),
        ).rstrip(b"=").decode()

    hdr = b64(h)
    pld = b64(p)
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), f"{hdr}.{pld}".encode(), hashlib.sha256).digest(),
    ).rstrip(b"=").decode()
    return f"{hdr}.{pld}.{sig}"


def _mock_headers(
    extra: dict | None = None,
    cookies: list[str] | None = None,
) -> MagicMock:
    """Build a mock headers object that supports .get() and .get_all()."""
    hdr = MagicMock()
    store = dict(extra or {})

    def _get(key, default=None):
        return store.get(key, default)

    def _get_all(key, default=None):
        if key == "Set-Cookie" and cookies:
            return list(cookies)
        return default if default is not None else []

    hdr.get = _get
    hdr.get_all = _get_all
    return hdr


def _mock_client(
    get_text: str = "",
    get_status: int = 200,
    post_text: str = "",
    post_status: int = 200,
    headers: MagicMock | None = None,
) -> MagicMock:
    """Standard mock HTTP client with get/post responses."""
    client = MagicMock()

    get_resp = MagicMock()
    get_resp.text = get_text
    get_resp.status_code = get_status
    get_resp.headers = headers or _mock_headers()
    client.get.return_value = get_resp

    post_resp = MagicMock()
    post_resp.text = post_text
    post_resp.status_code = post_status
    post_resp.headers = headers or _mock_headers()
    client.post.return_value = post_resp

    return client


def _empty_sitemap() -> SiteMap:
    return SiteMap()


def _api_sitemap(*urls: str) -> SiteMap:
    sm = SiteMap()
    for url in urls:
        sm.api_endpoints.append(APIEndpoint(url=url, source="test"))
    return sm


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TestJWTCollection
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestJWTCollection:
    """Tests for JWT token collection from responses."""

    def test_jwt_from_auth_header(self):
        """API endpoint response body contains a JWT token -> collected."""
        token = _make_jwt()
        # _collect_jwts searches response body text for eyJ... patterns
        client = _mock_client(
            get_text=f'{{"access_token": "{token}"}}',
            headers=_mock_headers(),
        )
        sm = _api_sitemap("https://api.example.com/auth/token")
        tokens = _collect_jwts(client, sm, "https://example.com")
        assert len(tokens) >= 1
        found_tokens = [t for t, _url in tokens]
        assert token in found_tokens

    def test_jwt_from_cookie(self):
        """Response Set-Cookie contains JWT -> token collected."""
        token = _make_jwt()
        client = _mock_client(
            headers=_mock_headers(
                cookies=[f"session={token}; Path=/; HttpOnly"],
            ),
        )
        sm = _api_sitemap("https://api.example.com/login")
        tokens = _collect_jwts(client, sm, "https://example.com")
        assert len(tokens) >= 1
        found_tokens = [t for t, _url in tokens]
        assert token in found_tokens

    def test_no_jwt_found(self):
        """No JWT in any response -> run_checks returns empty list."""
        client = _mock_client(
            get_text="<html>No tokens here</html>",
            headers=_mock_headers(),
        )
        sm = _empty_sitemap()
        findings = run_checks(client, "https://example.com", sm)
        assert findings == []


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TestAlgNone
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestAlgNone:
    """DAST-JWT-001: Algorithm confusion (none algorithm)."""

    def test_alg_none_accepted(self):
        """Server returns 200 when sent alg:none token -> DAST-JWT-001."""
        token = _make_jwt()
        # Collection phase returns 200 with token in body,
        # then check phase also returns 200 (accepts alg:none).
        client = _mock_client(
            get_text=f'{{"token": "{token}"}}',
            get_status=200,
            headers=_mock_headers(),
        )
        sm = _api_sitemap("https://api.example.com/data")
        findings = run_checks(client, "https://example.com", sm)
        jwt_001 = [f for f in findings if f.rule_id == "DAST-JWT-001"]
        assert len(jwt_001) >= 1
        assert jwt_001[0].severity == "CRITICAL"

    def test_alg_none_rejected(self):
        """Server returns 401 for alg:none token -> no finding."""
        token = _make_jwt()
        call_count = 0

        def _get_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.headers = _mock_headers()
            if call_count <= 1:
                # Collection phase: return token in body
                resp.text = f'{{"token": "{token}"}}'
                resp.status_code = 200
            else:
                # Check phase: reject
                resp.text = '{"error": "unauthorized"}'
                resp.status_code = 401
            return resp

        client = MagicMock()
        client.get.side_effect = _get_side_effect
        sm = _empty_sitemap()
        findings = run_checks(client, "https://example.com", sm)
        jwt_001 = [f for f in findings if f.rule_id == "DAST-JWT-001"]
        assert len(jwt_001) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TestSignatureStripping
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestSignatureStripping:
    """DAST-JWT-002: Signature stripping."""

    def test_stripped_accepted(self):
        """Server returns 200 with stripped signature -> DAST-JWT-002."""
        token = _make_jwt()
        client = _mock_client(
            get_text=f'{{"token": "{token}"}}',
            get_status=200,
            headers=_mock_headers(),
        )
        sm = _api_sitemap("https://api.example.com/data")
        findings = run_checks(client, "https://example.com", sm)
        jwt_002 = [f for f in findings if f.rule_id == "DAST-JWT-002"]
        assert len(jwt_002) >= 1
        assert jwt_002[0].severity == "CRITICAL"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TestExpiredTokens
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestExpiredTokens:
    """DAST-JWT-003: Expired token accepted."""

    def test_expired_accepted(self):
        """Token has past exp claim, server returns 200 -> DAST-JWT-003."""
        expired_payload = {
            "sub": "1234",
            "name": "Test",
            "iat": 1000000000,
            "exp": 1000000001,  # Far in the past
        }
        token = _make_jwt(payload=expired_payload)
        client = _mock_client(
            get_text=f'{{"token": "{token}"}}',
            get_status=200,
            headers=_mock_headers(),
        )
        sm = _api_sitemap("https://api.example.com/data")
        findings = run_checks(client, "https://example.com", sm)
        jwt_003 = [f for f in findings if f.rule_id == "DAST-JWT-003"]
        assert len(jwt_003) >= 1
        assert jwt_003[0].severity == "HIGH"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TestClaimTampering
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestClaimTampering:
    """DAST-JWT-004: Claim tampering."""

    def test_admin_claim_accepted(self):
        """Token with role=admin via alg:none accepted -> DAST-JWT-004."""
        token = _make_jwt()
        client = _mock_client(
            get_text=f'{{"token": "{token}"}}',
            get_status=200,
            headers=_mock_headers(),
        )
        sm = _api_sitemap("https://api.example.com/data")
        findings = run_checks(client, "https://example.com", sm)
        jwt_004 = [f for f in findings if f.rule_id == "DAST-JWT-004"]
        assert len(jwt_004) >= 1
        assert jwt_004[0].severity == "CRITICAL"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TestWeakSecret
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestWeakSecret:
    """DAST-JWT-005: Weak signing secret (local check, no HTTP needed)."""

    def test_common_secret_matches(self):
        """Token signed with HS256 using 'secret' as key -> DAST-JWT-005."""
        token = _make_jwt(secret="secret")
        # For collection, embed the token in the response body
        client = _mock_client(
            get_text=f'{{"token": "{token}"}}',
            get_status=200,
            headers=_mock_headers(),
        )
        sm = _empty_sitemap()
        findings = run_checks(client, "https://example.com", sm)
        jwt_005 = [f for f in findings if f.rule_id == "DAST-JWT-005"]
        assert len(jwt_005) >= 1
        assert jwt_005[0].severity == "HIGH"
        assert "secret" in jwt_005[0].line_content


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TestJWTIntegration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestJWTIntegration:
    """Integration tests for JWT security checks."""

    def test_all_findings_correct_category(self):
        """All findings have category='jwt' and target_type='dast'."""
        token = _make_jwt()
        client = _mock_client(
            get_text=f'{{"token": "{token}"}}',
            get_status=200,
            headers=_mock_headers(),
        )
        sm = _api_sitemap("https://api.example.com/data")
        findings = run_checks(client, "https://example.com", sm)
        assert len(findings) > 0, "Expected at least one finding"
        for f in findings:
            assert f.category == "jwt"
            assert f.target_type == "dast"
