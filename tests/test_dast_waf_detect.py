"""Tests for DAST WAF detection module."""

from __future__ import annotations

from unittest.mock import MagicMock

from vulnerability_management.dast.waf_detect import WAFInfo, detect_waf

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _mock_client(
    get_text: str = "",
    get_status: int = 200,
    headers: dict | None = None,
    cookies: dict | None = None,
) -> MagicMock:
    """Build a MagicMock HTTP client whose ``get()`` returns a canned response.

    Parameters
    ----------
    get_text:
        Value for ``resp.text``.
    get_status:
        Value for ``resp.status_code``.
    headers:
        Response headers dict.  Cookie values that need to appear in the
        ``set-cookie`` header should be passed via the *cookies* parameter
        instead for convenience — they will be merged into headers
        automatically.
    cookies:
        Convenience dict whose values are joined and injected as the
        ``set-cookie`` header so that ``_probe_waf_headers`` picks them up.
    """
    client = MagicMock()

    merged_headers = dict(headers or {})
    if cookies:
        # Combine cookie entries into a single set-cookie header value.
        cookie_parts = [f"{k}={v}" for k, v in cookies.items()]
        existing = merged_headers.get("set-cookie", "")
        if existing:
            cookie_parts.insert(0, existing)
        merged_headers["set-cookie"] = "; ".join(cookie_parts)

    resp = MagicMock()
    resp.text = get_text
    resp.status_code = get_status
    resp.headers = merged_headers
    client.get.return_value = resp

    return client


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# WAF Detection Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestWAFDetection:
    """Tests for ``detect_waf`` across various WAF signatures."""

    def test_no_waf_detected(self):
        """Clean response with no WAF signatures returns WAFInfo(detected=False)."""
        client = _mock_client(
            get_text="<html><body>Hello, World!</body></html>",
            get_status=200,
            headers={"server": "nginx/1.25.3", "content-type": "text/html"},
        )
        info = detect_waf(client, "https://example.com")
        assert isinstance(info, WAFInfo)
        assert info.detected is False
        assert info.name == ""

    def test_cloudflare_detected(self):
        """Cloudflare WAF is detected via cf-ray header and server header."""
        client = _mock_client(
            get_text="<html>OK</html>",
            get_status=200,
            headers={
                "cf-ray": "8a1b2c3d4e5f-IAD",
                "server": "cloudflare",
                "content-type": "text/html",
            },
        )
        info = detect_waf(client, "https://example.com")
        assert info.detected is True
        assert "Cloudflare" in info.name
        assert info.confidence == "high"
        assert len(info.evidence) >= 1

    def test_aws_waf_detected(self):
        """AWS WAF is detected via x-amzn-waf-action header."""
        client = _mock_client(
            get_text="<html>OK</html>",
            get_status=200,
            headers={
                "x-amzn-waf-action": "block",
                "content-type": "text/html",
            },
        )
        info = detect_waf(client, "https://example.com")
        assert info.detected is True
        assert "AWS" in info.name
        assert len(info.evidence) >= 1

    def test_modsecurity_detected(self):
        """ModSecurity is detected via body pattern on a 403 response.

        ModSecurity has no header signatures, so detection relies on the
        block-probe path: the XSS probe GET returns 403 with 'ModSecurity'
        in the response body.
        """
        # The header probe GET returns a clean 200 (no WAF fingerprint).
        # The block probe GET (with XSS payload) returns 403 + body match.
        call_count = {"n": 0}
        client = MagicMock()

        def _side_effect(url, **kwargs):
            call_count["n"] += 1
            resp = MagicMock()
            resp.headers = {}
            if "skyhigh_waf_test" in url:
                # Block probe response
                resp.status_code = 403
                resp.text = (
                    "<html><head><title>403 Forbidden</title></head>"
                    "<body>ModSecurity: Access denied with code 403</body></html>"
                )
            else:
                # Normal header probe
                resp.status_code = 200
                resp.text = "<html>OK</html>"
            return resp

        client.get.side_effect = _side_effect

        info = detect_waf(client, "https://example.com")
        assert info.detected is True
        assert "ModSecurity" in info.name
        assert len(info.evidence) >= 1

    def test_imperva_detected(self):
        """Imperva/Incapsula is detected via X-CDN header or incap_ses cookie."""
        client = _mock_client(
            get_text="<html>OK</html>",
            get_status=200,
            headers={"x-cdn": "Imperva", "content-type": "text/html"},
            cookies={"incap_ses_123": "abc123"},
        )
        info = detect_waf(client, "https://example.com")
        assert info.detected is True
        assert "Imperva" in info.name or "Incapsula" in info.name
        assert info.confidence == "high"
        assert len(info.evidence) >= 1

    def test_block_probe_detection(self):
        """XSS probe payload triggers a 403 with WAF block page pattern.

        Simulates a scenario where headers are clean but the block probe
        (with ``<script>alert(1)</script>`` payload) gets a 403 response
        containing a Sucuri WAF block page.
        """
        call_count = {"n": 0}
        client = MagicMock()

        def _side_effect(url, **kwargs):
            call_count["n"] += 1
            resp = MagicMock()
            resp.headers = {}
            if "skyhigh_waf_test" in url:
                resp.status_code = 403
                resp.text = (
                    "<html><body>Access Denied - Sucuri WebSite Firewall"
                    "<br>Your request was blocked.</body></html>"
                )
            else:
                resp.status_code = 200
                resp.text = "<html>OK</html>"
            return resp

        client.get.side_effect = _side_effect

        info = detect_waf(client, "https://example.com")
        assert info.detected is True
        assert "Sucuri" in info.name
        assert any("block page" in ev for ev in info.evidence)
