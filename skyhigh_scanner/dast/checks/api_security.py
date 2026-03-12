"""
DAST Check Module — API Security.

Checks for API-specific security issues:
  - API key exposure in URLs
  - GraphQL introspection enabled
  - Verbose API error responses
  - Missing rate limiting headers
  - Missing authentication on API endpoints
  - CORS on API endpoints
  - Swagger/OpenAPI exposed without auth
  - API versioning and deprecation

Rule IDs: DAST-API-001 through DAST-API-008
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ...core.finding import Finding

if TYPE_CHECKING:
    from ...core.credential_manager import CredentialManager
    from ..crawler import SiteMap
    from ..http_client import DastHTTPClient


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Constants
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Common API documentation paths
API_DOC_PATHS = [
    "swagger.json",
    "swagger/v1/swagger.json",
    "api-docs",
    "api/docs",
    "v1/api-docs",
    "v2/api-docs",
    "openapi.json",
    "openapi.yaml",
    "api/swagger.json",
    "api/openapi.json",
    "graphql",
    "graphiql",
    "playground",
    "api/graphql",
    "api/playground",
    "redoc",
    "api-explorer",
]

# GraphQL introspection query
GRAPHQL_INTROSPECTION_QUERY = '{"query":"{ __schema { types { name } } }"}'

# API key patterns in URLs
API_KEY_IN_URL_RE = re.compile(
    r"[?&](?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key|auth[_-]?token)"
    r"=([^&]{8,})",
    re.IGNORECASE,
)

# Rate limiting response headers
RATE_LIMIT_HEADERS = [
    "X-RateLimit-Limit",
    "X-Rate-Limit-Limit",
    "RateLimit-Limit",
    "X-RateLimit-Remaining",
    "Retry-After",
]

# Stack trace / debug patterns in API responses
API_ERROR_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'"(?:stack|stackTrace|stack_trace)"'), "Stack trace in JSON response"),
    (re.compile(r'"(?:exception|exceptionType|exception_type)"'), "Exception details in response"),
    (re.compile(r'"(?:innerException|inner_error)"'), "Inner exception exposed"),
    (re.compile(r'"debug":\s*true'), "Debug mode enabled in API"),
    (re.compile(r'"(?:sql|query)":\s*"(?:SELECT|INSERT|UPDATE|DELETE)', re.I), "SQL query in response"),
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
) -> Finding:
    return Finding(
        rule_id=rule_id,
        name=name,
        category="api_security",
        severity=severity,
        file_path=file_path,
        line_num=0,
        line_content=line_content,
        description=description,
        recommendation=recommendation,
        cwe=cwe,
        target_type="dast",
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Checks
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _check_api_key_in_url(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-API-001: API keys exposed in URLs."""
    seen: set[str] = set()
    all_urls = sitemap.urls | {ep.url for ep in sitemap.api_endpoints}

    for url in all_urls:
        match = API_KEY_IN_URL_RE.search(url)
        if match:
            param_name = match.group(0).split("=")[0].lstrip("?&")
            if param_name in seen:
                continue
            seen.add(param_name)

            findings.append(_finding(
                rule_id="DAST-API-001",
                name=f"API key in URL parameter: {param_name}",
                severity="HIGH",
                file_path=url.split("?")[0],
                line_content=f"{param_name}=*** (redacted)",
                description=(
                    f"An API key is passed in the URL parameter '{param_name}'. "
                    "URLs are logged in browser history, server access logs, "
                    "referrer headers, and proxy caches."
                ),
                recommendation=(
                    "Pass API keys in the Authorization header or request body "
                    "instead of URL parameters."
                ),
                cwe="CWE-598",
            ))


def _check_graphql_introspection(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-API-002: GraphQL introspection enabled."""
    graphql_paths = ["graphql", "api/graphql", "graphql/v1"]
    base = target_url.rstrip("/")

    for path in graphql_paths:
        url = f"{base}/{path}"
        try:
            resp = client.post(
                url,
                data=GRAPHQL_INTROSPECTION_QUERY,
                headers={"Content-Type": "application/json"},
            )
        except Exception:
            continue

        if resp.status_code == 200:
            try:
                data = resp.json()
                if "data" in data and "__schema" in data.get("data", {}):
                    findings.append(_finding(
                        rule_id="DAST-API-002",
                        name="GraphQL introspection enabled",
                        severity="MEDIUM",
                        file_path=url,
                        line_content="Introspection query returned schema",
                        description=(
                            f"GraphQL introspection is enabled at {url}. "
                            "Introspection reveals the entire API schema, "
                            "including types, queries, mutations, and fields. "
                            "Attackers can map the full API surface."
                        ),
                        recommendation=(
                            "Disable GraphQL introspection in production. "
                            "Most GraphQL servers support disabling introspection."
                        ),
                        cwe="CWE-200",
                    ))
                    return
            except (ValueError, KeyError):
                continue


def _check_api_documentation_exposed(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-API-003: API documentation publicly accessible."""
    base = target_url.rstrip("/")

    for path in API_DOC_PATHS:
        try:
            status, body = client.probe_path(target_url, path)
        except Exception:
            continue

        if status == 200 and len(body) > 100:
            # Verify it's actually API documentation
            is_swagger = any(k in body for k in (
                '"swagger"', '"openapi"', "swagger-ui",
                "Swagger UI", "api-docs", "paths",
            ))
            is_graphql_ui = any(k in body for k in (
                "GraphiQL", "graphql-playground", "graphql",
            ))

            if is_swagger or is_graphql_ui:
                doc_type = "GraphQL playground" if is_graphql_ui else "API documentation (Swagger/OpenAPI)"
                findings.append(_finding(
                    rule_id="DAST-API-003",
                    name=f"API documentation exposed: {path}",
                    severity="MEDIUM",
                    file_path=f"{base}/{path}",
                    line_content=f"HTTP 200 — {doc_type}",
                    description=(
                        f"{doc_type} is publicly accessible at {base}/{path}. "
                        "This reveals API endpoints, parameters, authentication "
                        "mechanisms, and data models to potential attackers."
                    ),
                    recommendation=(
                        "Restrict API documentation to internal networks or "
                        "require authentication. Remove in production if "
                        "not needed."
                    ),
                    cwe="CWE-200",
                ))


def _check_verbose_api_errors(
    client: DastHTTPClient,
    target_url: str,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-API-004: Verbose error responses from API endpoints."""
    # Test API endpoints with invalid input to trigger errors
    seen_patterns: set[str] = set()

    api_urls = [ep.url for ep in sitemap.api_endpoints[:10]]  # Limit to 10 endpoints
    if not api_urls:
        # Try probing common API paths
        base = target_url.rstrip("/")
        api_urls = [f"{base}/api/v1/invalid_endpoint_test"]

    for url in api_urls:
        try:
            resp = client.get(url, capture_evidence=False)
        except Exception:
            continue

        body = resp.text
        for pattern, desc in API_ERROR_PATTERNS:
            if desc in seen_patterns:
                continue
            if pattern.search(body):
                seen_patterns.add(desc)
                findings.append(_finding(
                    rule_id="DAST-API-004",
                    name=f"Verbose API error: {desc}",
                    severity="MEDIUM",
                    file_path=url,
                    line_content=desc,
                    description=(
                        f"API endpoint returned verbose error information: "
                        f"{desc}. Detailed error messages help attackers "
                        "understand the application internals."
                    ),
                    recommendation=(
                        "Return generic error messages in production. "
                        "Log detailed errors server-side only."
                    ),
                    cwe="CWE-209",
                ))


def _check_rate_limiting(
    client: DastHTTPClient,
    target_url: str,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-API-005: Missing rate limiting on API endpoints."""
    # Check API endpoints for rate limiting headers
    api_urls = [ep.url for ep in sitemap.api_endpoints[:5]]
    if not api_urls:
        return

    for url in api_urls:
        try:
            resp = client.get(url, capture_evidence=False)
        except Exception:
            continue

        has_rate_limit = any(
            resp.headers.get(h) for h in RATE_LIMIT_HEADERS
        )
        if not has_rate_limit:
            findings.append(_finding(
                rule_id="DAST-API-005",
                name="Missing rate limiting on API",
                severity="LOW",
                file_path=url,
                line_content="No X-RateLimit-* headers found",
                description=(
                    f"API endpoint {url} does not include rate limiting "
                    "headers. Without rate limiting, APIs are vulnerable "
                    "to brute force and denial of service attacks."
                ),
                recommendation=(
                    "Implement rate limiting on all API endpoints. "
                    "Return X-RateLimit-Limit and X-RateLimit-Remaining headers."
                ),
                cwe="CWE-770",
            ))
            return  # One finding is enough — applies to the whole API


def _check_api_authentication(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-API-006: API endpoints accessible without authentication."""
    # Only meaningful if we're NOT authenticated
    sensitive_patterns = re.compile(
        r"/(?:admin|users|accounts|settings|config|internal|private|management)",
        re.IGNORECASE,
    )

    for ep in sitemap.api_endpoints[:10]:
        if not sensitive_patterns.search(ep.url):
            continue
        try:
            resp = client.get(ep.url, capture_evidence=False)
        except Exception:
            continue

        if resp.status_code == 200:
            content_type = resp.headers.get("Content-Type", "")
            if "json" in content_type and len(resp.text) > 50:
                findings.append(_finding(
                    rule_id="DAST-API-006",
                    name="Sensitive API endpoint unauthenticated",
                    severity="HIGH",
                    file_path=ep.url,
                    line_content=f"HTTP 200 — {len(resp.text)} bytes",
                    description=(
                        f"Sensitive API endpoint {ep.url} returns data "
                        "without requiring authentication. This may expose "
                        "user data, configuration, or administrative functions."
                    ),
                    recommendation=(
                        "Require authentication for all sensitive API endpoints. "
                        "Implement proper access control checks."
                    ),
                    cwe="CWE-306",
                ))


def _check_api_cors(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-API-007: Permissive CORS on API endpoints."""
    for ep in sitemap.api_endpoints[:5]:
        try:
            resp = client.get(
                ep.url,
                headers={"Origin": "https://evil.attacker.com"},
                capture_evidence=False,
            )
        except Exception:
            continue

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if acao in ("*", "https://evil.attacker.com"):
            severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
            findings.append(_finding(
                rule_id="DAST-API-007",
                name="Permissive CORS on API endpoint",
                severity=severity,
                file_path=ep.url,
                line_content=f"ACAO: {acao} | ACAC: {acac}",
                description=(
                    f"API endpoint {ep.url} has permissive CORS configuration "
                    f"(ACAO: {acao}). Any website can make cross-origin "
                    "requests to this API and read the response."
                ),
                recommendation=(
                    "Restrict CORS to specific trusted origins. "
                    "Never use wildcard with credentials on API endpoints."
                ),
                cwe="CWE-942",
            ))
            return  # One finding applies to the whole API


def _check_api_mass_assignment(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-API-008: Potential mass assignment via API."""
    # Check if API endpoints accept extra fields
    for ep in sitemap.api_endpoints[:5]:
        if ep.method not in ("POST", "PUT", "PATCH"):
            continue

        # Send a request with an extra admin/role field
        test_payload = {"__test_mass_assignment": True, "role": "admin", "isAdmin": True}
        try:
            resp = client.post(
                ep.url,
                json=test_payload,
                capture_evidence=False,
            )
        except Exception:
            continue

        # If server returns 200/201 without rejecting unknown fields
        if resp.status_code in (200, 201):
            try:
                data = resp.json()
                # If the response includes our injected fields, it's vulnerable
                if isinstance(data, dict) and (
                    data.get("role") == "admin"
                    or data.get("isAdmin") is True
                    or "__test_mass_assignment" in data
                ):
                    findings.append(_finding(
                        rule_id="DAST-API-008",
                        name="Potential mass assignment vulnerability",
                        severity="HIGH",
                        file_path=ep.url,
                        line_content="API accepted and returned injected fields",
                        description=(
                            f"API endpoint {ep.url} accepts and reflects "
                            "arbitrary fields including privilege-escalation "
                            "fields like 'role' and 'isAdmin'. This may allow "
                            "mass assignment attacks."
                        ),
                        recommendation=(
                            "Implement a whitelist of accepted fields. "
                            "Use DTOs or input schemas to restrict accepted "
                            "properties. Never bind directly to models."
                        ),
                        cwe="CWE-915",
                    ))
                    return
            except (ValueError, KeyError):
                continue


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
    """Run all API security checks.

    Returns:
        List of Finding objects for any API security issues found.
    """
    findings: list[Finding] = []

    _check_api_key_in_url(client, sitemap, findings)
    _check_graphql_introspection(client, target_url, findings)
    _check_api_documentation_exposed(client, target_url, findings)
    _check_verbose_api_errors(client, target_url, sitemap, findings)
    _check_rate_limiting(client, target_url, sitemap, findings)
    _check_api_authentication(client, sitemap, findings)
    _check_api_cors(client, sitemap, findings)
    _check_api_mass_assignment(client, sitemap, findings)

    return findings
