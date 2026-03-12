"""
DAST Check Module — Configuration & Misconfiguration.

Passive checks that detect security misconfigurations:
  - Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
  - Cookie security flags (HttpOnly, Secure, SameSite)
  - CORS misconfiguration
  - Allowed HTTP methods
  - Mixed content indicators
  - Cache-Control for sensitive pages

Rule IDs: DAST-CFG-001 through DAST-CFG-010
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from ...core.finding import Finding

if TYPE_CHECKING:
    from ...core.credential_manager import CredentialManager
    from ..crawler import SiteMap
    from ..http_client import DastHTTPClient

logger = logging.getLogger(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Constants
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

REQUIRED_SECURITY_HEADERS: list[tuple[str, str, str, str]] = [
    # (header_name, rule_id, severity, cwe)
    ("Content-Security-Policy", "DAST-CFG-001", "MEDIUM", "CWE-693"),
    ("X-Frame-Options", "DAST-CFG-001", "MEDIUM", "CWE-1021"),
    ("X-Content-Type-Options", "DAST-CFG-001", "LOW", "CWE-16"),
    ("Referrer-Policy", "DAST-CFG-001", "LOW", "CWE-200"),
    ("Permissions-Policy", "DAST-CFG-001", "LOW", "CWE-16"),
]

# Dangerous HTTP methods
DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}

# Weak CSP directives
WEAK_CSP_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"'unsafe-inline'"), "allows unsafe-inline scripts"),
    (re.compile(r"'unsafe-eval'"), "allows unsafe-eval"),
    (re.compile(r"default-src\s+[^;]*\*"), "uses wildcard in default-src"),
    (re.compile(r"script-src\s+[^;]*\*"), "uses wildcard in script-src"),
    (re.compile(r"script-src\s+[^;]*data:"), "allows data: URIs in script-src"),
]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helper
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _finding(
    rule_id: str,
    name: str,
    severity: str,
    file_path: str,
    line_content: str,
    description: str,
    recommendation: str,
    cwe: str | None = None,
    evidence: list[dict] | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        name=name,
        category="config_misconfig",
        severity=severity,
        file_path=file_path,
        line_num=0,
        line_content=line_content,
        description=description,
        recommendation=recommendation,
        cwe=cwe,
        target_type="dast",
        evidence=evidence,
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Checks
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _check_security_headers(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-CFG-001: Missing security headers."""
    headers = client.get_headers(target_url)
    if not headers:
        return

    for header_name, rule_id, severity, cwe in REQUIRED_SECURITY_HEADERS:
        if not headers.get(header_name):
            findings.append(_finding(
                rule_id=rule_id,
                name=f"Missing security header: {header_name}",
                severity=severity,
                file_path=target_url,
                line_content=f"{header_name}: (missing)",
                description=(
                    f"The {header_name} response header is missing. "
                    "Security headers provide defense-in-depth against "
                    "common web attacks."
                ),
                recommendation=f"Add the {header_name} response header with an appropriate value.",
                cwe=cwe,
            ))


def _check_hsts(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-CFG-002: Missing or weak HSTS."""
    headers = client.get_headers(target_url)
    hsts = headers.get("Strict-Transport-Security", "")

    if not hsts:
        findings.append(_finding(
            rule_id="DAST-CFG-002",
            name="Missing HSTS header",
            severity="MEDIUM",
            file_path=target_url,
            line_content="Strict-Transport-Security: (missing)",
            description=(
                "The Strict-Transport-Security header is missing. "
                "Without HSTS, users are vulnerable to SSL stripping attacks "
                "on their first visit."
            ),
            recommendation=(
                "Add Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains; preload"
            ),
            cwe="CWE-319",
        ))
    else:
        # Check max-age value
        max_age_match = re.search(r"max-age=(\d+)", hsts)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 15768000:  # Less than 6 months
                findings.append(_finding(
                    rule_id="DAST-CFG-002",
                    name="Weak HSTS max-age",
                    severity="LOW",
                    file_path=target_url,
                    line_content=f"Strict-Transport-Security: {hsts}",
                    description=(
                        f"HSTS max-age is {max_age} seconds "
                        f"({max_age // 86400} days), which is less than "
                        "the recommended 6 months (15768000 seconds)."
                    ),
                    recommendation="Set HSTS max-age to at least 31536000 (1 year).",
                    cwe="CWE-319",
                ))


def _check_cookie_security(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-CFG-003: Insecure cookie configuration."""
    try:
        resp = client.get(target_url, capture_evidence=False)
    except Exception as exc:
        logger.debug("Check %s failed for %s: %s", "DAST-CFG-003", target_url, exc)
        return

    set_cookie_headers = resp.headers.get("Set-Cookie", "")
    if not set_cookie_headers:
        return

    # Parse each cookie from the Set-Cookie header(s)
    # requests merges multiple Set-Cookie into one with comma separation
    cookies = [c.strip() for c in set_cookie_headers.split(",") if "=" in c]

    for cookie in cookies:
        cookie_name = cookie.split("=")[0].strip()
        cookie_lower = cookie.lower()

        if "httponly" not in cookie_lower:
            findings.append(_finding(
                rule_id="DAST-CFG-003",
                name=f"Cookie missing HttpOnly flag: {cookie_name}",
                severity="MEDIUM",
                file_path=target_url,
                line_content=f"Set-Cookie: {cookie_name}=... (no HttpOnly)",
                description=(
                    f"Cookie '{cookie_name}' does not have the HttpOnly flag. "
                    "Without HttpOnly, JavaScript can access the cookie, "
                    "making it vulnerable to XSS-based theft."
                ),
                recommendation=f"Set the HttpOnly flag on cookie '{cookie_name}'.",
                cwe="CWE-1004",
            ))

        if "secure" not in cookie_lower:
            findings.append(_finding(
                rule_id="DAST-CFG-003",
                name=f"Cookie missing Secure flag: {cookie_name}",
                severity="MEDIUM",
                file_path=target_url,
                line_content=f"Set-Cookie: {cookie_name}=... (no Secure)",
                description=(
                    f"Cookie '{cookie_name}' does not have the Secure flag. "
                    "Without Secure, the cookie may be sent over unencrypted "
                    "HTTP connections."
                ),
                recommendation=f"Set the Secure flag on cookie '{cookie_name}'.",
                cwe="CWE-614",
            ))

        if "samesite" not in cookie_lower:
            findings.append(_finding(
                rule_id="DAST-CFG-003",
                name=f"Cookie missing SameSite attribute: {cookie_name}",
                severity="LOW",
                file_path=target_url,
                line_content=f"Set-Cookie: {cookie_name}=... (no SameSite)",
                description=(
                    f"Cookie '{cookie_name}' does not have the SameSite attribute. "
                    "Without SameSite, the cookie is vulnerable to CSRF attacks."
                ),
                recommendation=f"Set SameSite=Strict or SameSite=Lax on cookie '{cookie_name}'.",
                cwe="CWE-1275",
            ))


def _check_cors(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-CFG-004: CORS misconfiguration."""
    try:
        resp = client.get(
            target_url,
            headers={"Origin": "https://evil.attacker.com"},
            capture_evidence=False,
        )
    except Exception as exc:
        logger.debug("Check %s failed for %s: %s", "DAST-CFG-004", target_url, exc)
        return

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

    if acao == "*":
        severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
        findings.append(_finding(
            rule_id="DAST-CFG-004",
            name="CORS allows all origins",
            severity=severity,
            file_path=target_url,
            line_content=f"Access-Control-Allow-Origin: {acao}",
            description=(
                "The server allows CORS requests from any origin (wildcard *). "
                "This allows any website to make cross-origin requests to "
                "the application."
            ),
            recommendation=(
                "Restrict Access-Control-Allow-Origin to specific trusted "
                "domains. Never use wildcard with credentials."
            ),
            cwe="CWE-942",
            evidence=[{
                "method": "GET",
                "url": target_url,
                "status": resp.status_code,
                "payload": "Origin: https://evil.attacker.com",
                "proof": f"ACAO: {acao}, ACAC: {acac}",
            }],
        ))
    elif acao == "https://evil.attacker.com":
        findings.append(_finding(
            rule_id="DAST-CFG-004",
            name="CORS reflects arbitrary origin",
            severity="HIGH",
            file_path=target_url,
            line_content=f"Access-Control-Allow-Origin: {acao}",
            description=(
                "The server reflects the Origin header back in "
                "Access-Control-Allow-Origin, accepting any origin. "
                "This is effectively the same as a wildcard but bypasses "
                "browser restrictions on credentials."
            ),
            recommendation=(
                "Validate the Origin header against a whitelist of "
                "trusted domains."
            ),
            cwe="CWE-942",
            evidence=[{
                "method": "GET",
                "url": target_url,
                "status": resp.status_code,
                "payload": "Origin: https://evil.attacker.com",
                "proof": f"ACAO: {acao} (reflected)",
            }],
        ))


def _check_http_methods(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-CFG-005: Dangerous HTTP methods enabled."""
    try:
        resp = client.options(target_url, capture_evidence=False)
    except Exception as exc:
        logger.debug("Check %s failed for %s: %s", "DAST-CFG-005", target_url, exc)
        return

    allow = resp.headers.get("Allow", "")
    if not allow:
        return

    methods = {m.strip().upper() for m in allow.split(",")}
    dangerous = methods & DANGEROUS_METHODS

    if "TRACE" in dangerous:
        findings.append(_finding(
            rule_id="DAST-CFG-005",
            name="TRACE method enabled",
            severity="MEDIUM",
            file_path=target_url,
            line_content=f"Allow: {allow}",
            description=(
                "The TRACE HTTP method is enabled. TRACE can be used in "
                "Cross-Site Tracing (XST) attacks to steal credentials "
                "and session tokens."
            ),
            recommendation="Disable the TRACE method on the web server.",
            cwe="CWE-693",
            evidence=[{
                "method": "OPTIONS",
                "url": target_url,
                "status": resp.status_code,
                "payload": "(none — passive check)",
                "proof": f"Allow: {allow}",
            }],
        ))

    other_dangerous = dangerous - {"TRACE"}
    if other_dangerous:
        findings.append(_finding(
            rule_id="DAST-CFG-005",
            name=f"Potentially dangerous HTTP methods enabled: {', '.join(sorted(other_dangerous))}",
            severity="LOW",
            file_path=target_url,
            line_content=f"Allow: {allow}",
            description=(
                f"The following HTTP methods are enabled: "
                f"{', '.join(sorted(other_dangerous))}. "
                "These methods may allow unauthorized modification "
                "or deletion of resources if not properly secured."
            ),
            recommendation=(
                "Disable unnecessary HTTP methods. Only allow GET, POST, "
                "and HEAD unless other methods are explicitly needed."
            ),
            cwe="CWE-16",
        ))


def _check_csp_quality(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-CFG-006: Weak Content Security Policy."""
    headers = client.get_headers(target_url)
    csp = headers.get("Content-Security-Policy", "")
    if not csp:
        return  # Missing CSP already reported by _check_security_headers

    for pattern, weakness in WEAK_CSP_PATTERNS:
        if pattern.search(csp):
            findings.append(_finding(
                rule_id="DAST-CFG-006",
                name=f"Weak CSP: {weakness}",
                severity="MEDIUM",
                file_path=target_url,
                line_content=f"CSP: {csp[:200]}",
                description=(
                    f"The Content-Security-Policy {weakness}. "
                    "This weakens the protection CSP provides against "
                    "XSS and code injection attacks."
                ),
                recommendation=(
                    "Strengthen the CSP by removing 'unsafe-inline', "
                    "'unsafe-eval', and wildcards. Use nonces or hashes "
                    "for inline scripts."
                ),
                cwe="CWE-693",
            ))


def _check_mixed_content(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-CFG-007: Mixed content (HTTP resources on HTTPS pages)."""
    checked = 0
    mixed_re = re.compile(
        r"""(?:src|href|action)\s*=\s*["']http://""",
        re.IGNORECASE,
    )

    for url in sitemap.urls:
        if not url.startswith("https://"):
            continue
        if checked >= 20:
            break
        try:
            resp = client.get(url, capture_evidence=False)
        except Exception as exc:
            logger.debug("Check %s failed for %s: %s", "DAST-CFG-007", url, exc)
            continue
        checked += 1

        if mixed_re.search(resp.text):
            findings.append(_finding(
                rule_id="DAST-CFG-007",
                name="Mixed content detected",
                severity="LOW",
                file_path=url,
                line_content="HTTP resource loaded on HTTPS page",
                description=(
                    f"The HTTPS page at {url} includes resources loaded "
                    "over plain HTTP. This creates a mixed content warning "
                    "and may allow MitM attacks on those resources."
                ),
                recommendation=(
                    "Load all resources over HTTPS. Use protocol-relative "
                    "URLs or update references to use https://."
                ),
                cwe="CWE-319",
            ))


def _check_cache_control(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-CFG-008: Missing cache-control for sensitive pages."""
    headers = client.get_headers(target_url)
    cache_control = headers.get("Cache-Control", "").lower()
    pragma = headers.get("Pragma", "").lower()

    # Only flag if the page likely has sensitive content
    # (login pages, authenticated areas)
    if not cache_control or (
        "no-store" not in cache_control
        and "no-cache" not in cache_control
        and "no-cache" not in pragma
    ):
        findings.append(_finding(
            rule_id="DAST-CFG-008",
            name="Missing cache-control directives",
            severity="LOW",
            file_path=target_url,
            line_content=f"Cache-Control: {cache_control or '(missing)'}",
            description=(
                "The response does not include no-store or no-cache "
                "cache-control directives. Sensitive data may be cached "
                "by browsers or proxy servers."
            ),
            recommendation=(
                "Add Cache-Control: no-store, no-cache, must-revalidate "
                "and Pragma: no-cache for pages with sensitive data."
            ),
            cwe="CWE-525",
        ))


def _check_clickjacking(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-CFG-009: Clickjacking — X-Frame-Options and CSP frame-ancestors."""
    headers = client.get_headers(target_url)
    xfo = headers.get("X-Frame-Options", "")
    csp = headers.get("Content-Security-Policy", "")

    has_xfo = bool(xfo)
    has_frame_ancestors = "frame-ancestors" in csp if csp else False

    if not has_xfo and not has_frame_ancestors:
        # Already captured by missing headers check, but provide specific guidance
        return

    if has_xfo:
        xfo_upper = xfo.upper()
        if xfo_upper not in ("DENY", "SAMEORIGIN") and not xfo_upper.startswith("ALLOW-FROM"):
            findings.append(_finding(
                rule_id="DAST-CFG-009",
                name=f"Invalid X-Frame-Options value: {xfo}",
                severity="MEDIUM",
                file_path=target_url,
                line_content=f"X-Frame-Options: {xfo}",
                description=(
                    f"X-Frame-Options has an invalid value '{xfo}'. "
                    "Valid values are DENY, SAMEORIGIN, or ALLOW-FROM uri. "
                    "An invalid value provides no protection."
                ),
                recommendation="Set X-Frame-Options to DENY or SAMEORIGIN.",
                cwe="CWE-1021",
            ))


def _check_x_content_type_options(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-CFG-010: X-Content-Type-Options not set to nosniff."""
    headers = client.get_headers(target_url)
    xcto = headers.get("X-Content-Type-Options", "")

    if xcto and xcto.lower() != "nosniff":
        findings.append(_finding(
            rule_id="DAST-CFG-010",
            name=f"Invalid X-Content-Type-Options: {xcto}",
            severity="LOW",
            file_path=target_url,
            line_content=f"X-Content-Type-Options: {xcto}",
            description=(
                f"X-Content-Type-Options is set to '{xcto}' instead of "
                "'nosniff'. This provides no MIME-sniffing protection."
            ),
            recommendation="Set X-Content-Type-Options: nosniff",
            cwe="CWE-16",
        ))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Module entry point
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def run_checks(
    client: DastHTTPClient,
    target_url: str,
    sitemap: SiteMap,
    credentials: CredentialManager | None = None,
    verbose: bool = False,
) -> list[Finding]:
    """Run all configuration and misconfiguration checks.

    Returns:
        List of Finding objects for any misconfigurations found.
    """
    findings: list[Finding] = []

    _check_security_headers(client, target_url, findings)
    _check_hsts(client, target_url, findings)
    _check_cookie_security(client, target_url, findings)
    _check_cors(client, target_url, findings)
    _check_http_methods(client, target_url, findings)
    _check_csp_quality(client, target_url, findings)
    _check_mixed_content(client, sitemap, findings)
    _check_cache_control(client, target_url, findings)
    _check_clickjacking(client, target_url, findings)
    _check_x_content_type_options(client, target_url, findings)

    return findings
