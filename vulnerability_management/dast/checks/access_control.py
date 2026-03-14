"""
DAST Check Module — Access Control.

Active checks that test for access control weaknesses:
  - Forced browsing (admin paths, hidden paths)
  - HTTP verb tampering
  - IDOR indicators
  - Missing authentication on sensitive endpoints
  - Privilege escalation via parameter tampering
  - robots.txt hidden paths accessible

Rule IDs: DAST-AC-001 through DAST-AC-006
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ...core.finding import Finding

if TYPE_CHECKING:
    from ...core.credential_manager import CredentialManager
    from ..crawler import SiteMap
    from ..http_client import DastHTTPClient

logger = logging.getLogger(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Constants
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Common admin / sensitive paths to probe
ADMIN_PATHS: list[tuple[str, str]] = [
    ("admin", "Admin panel"),
    ("admin/login", "Admin login"),
    ("administrator", "Administrator panel"),
    ("wp-admin", "WordPress admin"),
    ("wp-login.php", "WordPress login"),
    ("manager/html", "Tomcat manager"),
    ("phpmyadmin", "phpMyAdmin"),
    ("adminer.php", "Adminer DB tool"),
    ("_debug", "Debug endpoint"),
    ("debug/vars", "Debug variables"),
    ("actuator", "Spring Boot actuator"),
    ("actuator/env", "Spring Boot env"),
    ("actuator/health", "Spring Boot health"),
    ("console", "Console / REPL"),
    ("dashboard", "Dashboard"),
    ("manage", "Management panel"),
    ("panel", "Control panel"),
    ("api/admin", "Admin API"),
    (".well-known/openid-configuration", "OpenID config"),
    ("metrics", "Metrics endpoint"),
    ("health", "Health check"),
    ("status", "Status page"),
    ("info", "Info endpoint"),
]

# HTTP methods to test for verb tampering
VERB_TAMPER_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

# IDOR parameter patterns
IDOR_PARAMS = re.compile(
    r"(?:id|user_id|userId|uid|account|accountId|account_id"
    r"|order|orderId|order_id|profile|record|doc|document"
    r"|file_id|fileId|report|invoice|ticket|customer)",
    re.IGNORECASE,
)

# Numeric parameter value pattern
NUMERIC_VALUE = re.compile(r"^\d+$")


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
        category="access_control",
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

def _check_forced_browsing(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-AC-001: Forced browsing to admin/sensitive paths."""
    base = target_url.rstrip("/")

    for path, desc in ADMIN_PATHS:
        try:
            status, body = client.probe_path(target_url, path)
        except Exception as exc:
            logger.debug("Check %s failed for %s: %s", "DAST-AC-001", path, exc)
            continue

        if status == 200 and len(body) > 100:
            # Verify it's not a generic 200 (soft 404)
            # Check if body looks like an actual admin/management page
            admin_indicators = [
                "login", "username", "password", "dashboard",
                "admin", "manage", "configuration", "settings",
                "actuator", "health", "metrics",
            ]
            body_lower = body.lower()
            if any(ind in body_lower for ind in admin_indicators):
                findings.append(_finding(
                    rule_id="DAST-AC-001",
                    name=f"Accessible admin path: /{path}",
                    severity="HIGH" if "admin" in path.lower() else "MEDIUM",
                    file_path=f"{base}/{path}",
                    line_content=f"HTTP 200 — {desc}",
                    description=(
                        f"The {desc} is accessible at {base}/{path}. "
                        "Administrative interfaces should not be publicly "
                        "accessible without proper authentication."
                    ),
                    recommendation=(
                        f"Restrict access to /{path} via IP whitelisting, "
                        "VPN, or strong authentication. Remove unnecessary "
                        "management interfaces from production."
                    ),
                    cwe="CWE-425",
                ))


def _check_verb_tampering(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-AC-002: HTTP verb tampering bypasses access control."""
    # Find URLs that return 403 (forbidden) with GET
    forbidden_urls: list[str] = []
    for url in list(sitemap.urls)[:10]:
        try:
            resp = client.get(url, capture_evidence=False)
            if resp.status_code == 403:
                forbidden_urls.append(url)
        except Exception as exc:
            logger.debug("Check %s failed for %s: %s", "DAST-AC-002", url, exc)
            continue

    if not forbidden_urls:
        return

    # Try alternative methods on forbidden URLs
    for url in forbidden_urls[:3]:
        for method in ("POST", "PUT", "PATCH", "HEAD"):
            try:
                resp = client.request(method, url, capture_evidence=True)
            except Exception as exc:
                logger.debug("Check %s failed for %s: %s", "DAST-AC-002", url, exc)
                continue

            if resp.status_code == 200:
                findings.append(_finding(
                    rule_id="DAST-AC-002",
                    name=f"HTTP verb tampering bypass: {method}",
                    severity="HIGH",
                    file_path=url,
                    line_content=f"GET → 403, {method} → 200",
                    description=(
                        f"Access control at {url} can be bypassed using "
                        f"the {method} HTTP method. GET returns 403, but "
                        f"{method} returns 200. Access controls should be "
                        "consistent across all HTTP methods."
                    ),
                    recommendation=(
                        "Implement access control checks that apply to all "
                        "HTTP methods, not just GET. Use framework-level "
                        "authorization middleware."
                    ),
                    cwe="CWE-650",
                    evidence=[{
                        "method": method,
                        "url": url,
                        "status": resp.status_code,
                        "payload": f"GET→403, {method}→200",
                        "proof": resp.text[:500],
                    }],
                ))
                break  # One bypass per URL is enough


def _check_idor(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-AC-003: Insecure Direct Object Reference indicators."""
    found_params: set[str] = set()

    for url in sitemap.urls:
        if "?" not in url:
            continue

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name, values in params.items():
            if param_name in found_params:
                continue
            if not IDOR_PARAMS.search(param_name):
                continue

            # Check if value is numeric (sequential ID)
            value = values[0] if values else ""
            if not NUMERIC_VALUE.match(value):
                continue

            # Try accessing adjacent IDs
            original_id = int(value)
            test_ids = [original_id - 1, original_id + 1, original_id + 100]

            for test_id in test_ids:
                if test_id < 1:
                    continue

                modified_params = dict(params)
                modified_params[param_name] = [str(test_id)]
                new_query = urlencode(modified_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    resp = client.get(test_url, capture_evidence=True)
                except Exception as exc:
                    logger.debug("Check %s failed for %s: %s", "DAST-AC-003", test_url, exc)
                    continue

                if resp.status_code == 200 and len(resp.text) > 100:
                    found_params.add(param_name)
                    findings.append(_finding(
                        rule_id="DAST-AC-003",
                        name=f"Potential IDOR in: {param_name}",
                        severity="MEDIUM",
                        file_path=url.split("?")[0],
                        line_content=f"{param_name}={value} → {test_id} also returns 200",
                        description=(
                            f"Parameter '{param_name}' uses sequential numeric "
                            f"IDs. Changing the ID from {value} to {test_id} "
                            "returns a 200 response with content. This may "
                            "indicate an IDOR vulnerability if access control "
                            "is not properly enforced."
                        ),
                        recommendation=(
                            "Implement proper authorization checks — verify the "
                            "requesting user has access to the requested resource. "
                            "Use UUIDs instead of sequential IDs."
                        ),
                        cwe="CWE-639",
                        evidence=[{
                            "method": "GET",
                            "url": test_url,
                            "status": resp.status_code,
                            "payload": f"{param_name}={test_id}",
                            "proof": resp.text[:500],
                        }],
                    ))
                    break


def _check_robots_txt_paths(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-AC-004: Disallowed paths in robots.txt are accessible."""
    try:
        status, body = client.probe_path(target_url, "robots.txt")
    except Exception as exc:
        logger.debug("Check %s failed for %s: %s", "DAST-AC-004", target_url, exc)
        return

    if status != 200:
        return

    # Extract Disallow paths
    disallow_re = re.compile(r"Disallow:\s*(/\S+)")
    disallowed_paths = disallow_re.findall(body)

    for path in disallowed_paths[:10]:
        # Skip wildcard and root
        if path in ("/", "/*"):
            continue

        try:
            probe_status, probe_body = client.probe_path(target_url, path.lstrip("/"))
        except Exception as exc:
            logger.debug("Check %s failed for %s: %s", "DAST-AC-004", path, exc)
            continue

        if probe_status == 200 and len(probe_body) > 100:
            base = target_url.rstrip("/")
            findings.append(_finding(
                rule_id="DAST-AC-004",
                name=f"robots.txt disallowed path accessible: {path}",
                severity="LOW",
                file_path=f"{base}{path}",
                line_content=f"Disallow: {path} → HTTP 200",
                description=(
                    f"Path {path} is listed in robots.txt as Disallow but "
                    "is accessible with a 200 response. robots.txt is not "
                    "an access control mechanism — it only guides crawlers."
                ),
                recommendation=(
                    "Use proper access control (authentication, IP whitelist) "
                    "for sensitive paths instead of relying on robots.txt."
                ),
                cwe="CWE-425",
            ))


def _check_missing_auth_sensitive(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-AC-005: Sensitive pages accessible without authentication."""
    sensitive_patterns = re.compile(
        r"/(?:profile|account|settings|billing|payment|order|invoice"
        r"|user|admin|management|config|edit|delete|upload)",
        re.IGNORECASE,
    )

    for url in sitemap.urls:
        if not sensitive_patterns.search(url):
            continue

        try:
            resp = client.get(url, capture_evidence=False)
        except Exception as exc:
            logger.debug("Check %s failed for %s: %s", "DAST-AC-005", url, exc)
            continue

        # If we get content (not a redirect to login)
        if resp.status_code == 200 and len(resp.text) > 200:
            # Check if this is a real page, not a login redirect
            body_lower = resp.text.lower()
            is_login_page = any(
                ind in body_lower
                for ind in ("login", "sign in", "authenticate", "forgot password")
            )
            if not is_login_page:
                findings.append(_finding(
                    rule_id="DAST-AC-005",
                    name=f"Sensitive page without auth: {urlparse(url).path}",
                    severity="MEDIUM",
                    file_path=url,
                    line_content=f"HTTP 200 — {len(resp.text)} bytes",
                    description=(
                        f"Sensitive page at {url} is accessible without "
                        "authentication. Pages involving user data, settings, "
                        "or administrative functions should require login."
                    ),
                    recommendation=(
                        "Require authentication for all sensitive pages. "
                        "Implement server-side authorization checks."
                    ),
                    cwe="CWE-306",
                ))


def _check_privilege_escalation_params(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-AC-006: Privilege escalation via parameter tampering."""
    priv_params = re.compile(
        r"(?:role|admin|isAdmin|is_admin|privilege|level"
        r"|access|permission|group|type|status)",
        re.IGNORECASE,
    )

    for url in sitemap.urls:
        if "?" not in url:
            continue

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name in params:
            if not priv_params.search(param_name):
                continue

            # Try escalating the value
            escalation_values = ["admin", "1", "true", "root", "superadmin"]
            for value in escalation_values:
                modified_params = dict(params)
                modified_params[param_name] = [value]
                new_query = urlencode(modified_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    resp = client.get(test_url, capture_evidence=True)
                except Exception as exc:
                    logger.debug("Check %s failed for %s: %s", "DAST-AC-006", test_url, exc)
                    continue

                if resp.status_code == 200:
                    findings.append(_finding(
                        rule_id="DAST-AC-006",
                        name=f"Potential privilege escalation: {param_name}",
                        severity="MEDIUM",
                        file_path=url.split("?")[0],
                        line_content=f"{param_name}={value} → HTTP 200",
                        description=(
                            f"Parameter '{param_name}' may allow privilege "
                            f"escalation. Setting it to '{value}' returns a "
                            "200 response. This needs manual verification."
                        ),
                        recommendation=(
                            "Never trust client-side parameters for "
                            "authorization decisions. Derive user roles "
                            "from the server-side session."
                        ),
                        cwe="CWE-269",
                    ))
                    break
            break  # One param per URL


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
    """Run all access control checks.

    Returns:
        List of Finding objects for any access control issues found.
    """
    findings: list[Finding] = []

    _check_forced_browsing(client, target_url, findings)
    _check_verb_tampering(client, sitemap, findings)
    _check_idor(client, sitemap, findings)
    _check_robots_txt_paths(client, target_url, findings)
    _check_missing_auth_sensitive(client, sitemap, findings)
    _check_privilege_escalation_params(client, sitemap, findings)

    return findings
