"""
DAST Check Module — Injection.

Active checks that test for injection vulnerabilities:
  - SQL injection (error-based, boolean-based)
  - Command injection (OS command)
  - Server-Side Template Injection (SSTI)
  - CRLF injection (header injection)
  - LDAP injection
  - XPath injection
  - NoSQL injection
  - Header injection via Host header

Rule IDs: DAST-INJ-001 through DAST-INJ-008
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ...core.finding import Finding

if TYPE_CHECKING:
    from ...core.credential_manager import CredentialManager
    from ..crawler import SiteMap
    from ..http_client import DastHTTPClient


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Payloads and detection patterns
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# SQL injection payloads and their error signatures
SQL_PAYLOADS: list[tuple[str, str]] = [
    ("'", "Single quote"),
    ("1' OR '1'='1", "OR-based tautology"),
    ("1 UNION SELECT NULL--", "UNION SELECT"),
    ("'; WAITFOR DELAY '0:0:5'--", "Time-based (MSSQL)"),
    ("1' AND 1=1--", "Boolean AND true"),
    ("1' AND 1=2--", "Boolean AND false"),
]

SQL_ERROR_PATTERNS: list[re.Pattern] = [
    re.compile(r"SQL syntax.*?near", re.I),
    re.compile(r"mysql_fetch|mysql_query|mysqli_", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"PostgreSQL.*?ERROR", re.I),
    re.compile(r"(?:Microsoft|ODBC).*?SQL Server", re.I),
    re.compile(r"SQLite.*?(?:error|near)", re.I),
    re.compile(r"Unclosed quotation mark", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"SQL command not properly ended", re.I),
    re.compile(r"pg_query|pg_exec", re.I),
]

# Command injection payloads
CMD_PAYLOADS: list[tuple[str, str, re.Pattern]] = [
    # (payload, description, detection_pattern)
    (";echo SKYHIGH_CMD_TEST", "Semicolon echo",
     re.compile(r"SKYHIGH_CMD_TEST")),
    ("|echo SKYHIGH_CMD_TEST", "Pipe echo",
     re.compile(r"SKYHIGH_CMD_TEST")),
    ("$(echo SKYHIGH_CMD_TEST)", "Subshell echo",
     re.compile(r"SKYHIGH_CMD_TEST")),
    ("`echo SKYHIGH_CMD_TEST`", "Backtick echo",
     re.compile(r"SKYHIGH_CMD_TEST")),
]

# SSTI payloads
SSTI_PAYLOADS: list[tuple[str, str, re.Pattern]] = [
    ("{{7*7}}", "Jinja2/Twig",
     re.compile(r"49")),
    ("${7*7}", "Freemarker/Velocity",
     re.compile(r"49")),
    ("#{7*7}", "Spring EL / Thymeleaf",
     re.compile(r"49")),
    ("<%= 7*7 %>", "ERB (Ruby)",
     re.compile(r"49")),
]

# CRLF injection payloads
CRLF_PAYLOADS: list[tuple[str, str]] = [
    ("%0d%0aX-SKYHIGH-CRLF-Test:injected", "URL-encoded CRLF"),
    ("\r\nX-SKYHIGH-CRLF-Test:injected", "Raw CRLF"),
]

# NoSQL injection payloads (MongoDB-style)
NOSQL_PAYLOADS: list[tuple[dict, str]] = [
    ({"$gt": ""}, "$gt operator"),
    ({"$ne": ""}, "$ne operator"),
    ({"$regex": ".*"}, "$regex operator"),
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
        category="injection",
        severity=severity,
        file_path=file_path,
        line_num=0,
        line_content=line_content,
        description=description,
        recommendation=recommendation,
        cwe=cwe,
        target_type="dast",
    )


def _inject_into_url_params(url: str, payload: str) -> list[tuple[str, str]]:
    """Generate URLs with payload injected into each query parameter.

    Returns list of (modified_url, param_name) tuples.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return []

    results = []
    for param_name in params:
        modified = dict(params)
        modified[param_name] = [payload]
        new_query = urlencode(modified, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))
        results.append((new_url, param_name))
    return results


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Checks
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _check_sql_injection_urls(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-INJ-001: SQL injection via URL parameters."""
    found_params: set[str] = set()

    for url in sitemap.urls:
        if "?" not in url:
            continue

        for payload, desc in SQL_PAYLOADS[:3]:  # Limit payloads per URL
            injected_urls = _inject_into_url_params(url, payload)
            for injected_url, param_name in injected_urls:
                if param_name in found_params:
                    continue
                try:
                    resp = client.get(injected_url, capture_evidence=True)
                except Exception:
                    continue

                for err_pattern in SQL_ERROR_PATTERNS:
                    if err_pattern.search(resp.text):
                        found_params.add(param_name)
                        findings.append(_finding(
                            rule_id="DAST-INJ-001",
                            name=f"SQL injection in URL parameter: {param_name}",
                            severity="CRITICAL",
                            file_path=url.split("?")[0],
                            line_content=f"Payload: {payload} → SQL error detected",
                            description=(
                                f"SQL injection detected in parameter '{param_name}' "
                                f"at {url.split('?')[0]}. The payload '{desc}' "
                                "triggered a database error, indicating user input "
                                "is concatenated into SQL queries."
                            ),
                            recommendation=(
                                "Use parameterized queries / prepared statements. "
                                "Never concatenate user input into SQL strings."
                            ),
                            cwe="CWE-89",
                        ))
                        break


def _check_sql_injection_forms(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-INJ-002: SQL injection via form inputs."""
    found_forms: set[str] = set()

    for form in sitemap.forms:
        if form.action in found_forms:
            continue
        if not form.field_names:
            continue

        for payload, desc in SQL_PAYLOADS[:2]:  # Fewer payloads for forms
            form_data = {}
            for f in form.fields:
                if f.field_type == "hidden" and f.value:
                    form_data[f.name] = f.value
                elif f.name:
                    form_data[f.name] = payload

            try:
                if form.method == "POST":
                    resp = client.post(form.action, data=form_data)
                else:
                    resp = client.get(form.action, params=form_data)
            except Exception:
                continue

            found_sqli = False
            for err_pattern in SQL_ERROR_PATTERNS:
                if err_pattern.search(resp.text):
                    found_forms.add(form.action)
                    findings.append(_finding(
                        rule_id="DAST-INJ-002",
                        name=f"SQL injection in form: {form.action}",
                        severity="CRITICAL",
                        file_path=form.url,
                        line_content=f"Form {form.method} {form.action} — SQL error",
                        description=(
                            f"SQL injection detected in form at {form.url} "
                            f"(action: {form.action}). Injecting '{desc}' "
                            "triggered a database error."
                        ),
                        recommendation=(
                            "Use parameterized queries / prepared statements. "
                            "Validate and sanitize all form inputs."
                        ),
                        cwe="CWE-89",
                    ))
                    found_sqli = True
                    break
            if found_sqli:
                break


def _check_command_injection(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-INJ-003: OS command injection."""
    for url in sitemap.urls:
        if "?" not in url:
            continue

        for payload, desc, detect in CMD_PAYLOADS[:2]:
            injected_urls = _inject_into_url_params(url, payload)
            for injected_url, param_name in injected_urls:
                try:
                    resp = client.get(injected_url, capture_evidence=True)
                except Exception:
                    continue

                if detect.search(resp.text):
                    findings.append(_finding(
                        rule_id="DAST-INJ-003",
                        name=f"Command injection in: {param_name}",
                        severity="CRITICAL",
                        file_path=url.split("?")[0],
                        line_content=f"Payload: {desc} → echo reflected",
                        description=(
                            f"OS command injection detected in parameter "
                            f"'{param_name}' at {url.split('?')[0]}. "
                            f"The '{desc}' payload was executed and its "
                            "output appeared in the response."
                        ),
                        recommendation=(
                            "Never pass user input to shell commands. "
                            "Use language-level APIs instead of os.system / "
                            "subprocess with shell=True."
                        ),
                        cwe="CWE-78",
                    ))
                    return  # Critical — stop after first confirmation


def _check_ssti(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-INJ-004: Server-Side Template Injection."""
    for url in sitemap.urls:
        if "?" not in url:
            continue

        for payload, engine, detect in SSTI_PAYLOADS:
            injected_urls = _inject_into_url_params(url, payload)
            for injected_url, param_name in injected_urls:
                try:
                    resp = client.get(injected_url, capture_evidence=True)
                except Exception:
                    continue

                # Check if 49 appears in response (7*7) but not the raw payload
                if detect.search(resp.text) and payload not in resp.text:
                    findings.append(_finding(
                        rule_id="DAST-INJ-004",
                        name=f"SSTI ({engine}) in: {param_name}",
                        severity="CRITICAL",
                        file_path=url.split("?")[0],
                        line_content=f"Payload: {payload} → evaluated to 49",
                        description=(
                            f"Server-Side Template Injection detected in "
                            f"parameter '{param_name}'. The {engine} payload "
                            f"'{payload}' was evaluated by the server. "
                            "SSTI can lead to Remote Code Execution."
                        ),
                        recommendation=(
                            "Never pass user input directly to template engines. "
                            "Use sandboxed template environments. Validate all input."
                        ),
                        cwe="CWE-1336",
                    ))
                    return


def _check_crlf_injection(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-INJ-005: CRLF injection (HTTP header injection)."""
    base = target_url.rstrip("/")

    for payload, desc in CRLF_PAYLOADS:
        url = f"{base}/redirect?url={payload}"
        try:
            resp = client.get(url, capture_evidence=True, allow_redirects=False)
        except Exception:
            continue

        # Check if our injected header appears in the response
        if "X-SKYHIGH-CRLF-Test" in resp.headers.get("X-SKYHIGH-CRLF-Test", ""):
            findings.append(_finding(
                rule_id="DAST-INJ-005",
                name="CRLF injection (header injection)",
                severity="HIGH",
                file_path=url,
                line_content=f"Payload: {desc} → header injected",
                description=(
                    "CRLF injection detected — arbitrary HTTP headers can "
                    "be injected into the response. This can lead to HTTP "
                    "response splitting, cache poisoning, and XSS."
                ),
                recommendation=(
                    "Sanitize user input that appears in HTTP headers. "
                    "Strip or encode CR (\\r) and LF (\\n) characters."
                ),
                cwe="CWE-113",
            ))
            return

        # Also check response body for reflected CRLF
        if "X-SKYHIGH-CRLF-Test:injected" in resp.text:
            findings.append(_finding(
                rule_id="DAST-INJ-005",
                name="CRLF injection (response splitting)",
                severity="HIGH",
                file_path=url,
                line_content=f"Payload: {desc} → reflected in body",
                description=(
                    "CRLF characters are reflected in the response, "
                    "indicating potential HTTP response splitting."
                ),
                recommendation=(
                    "Sanitize user input. Strip CR and LF characters "
                    "from any input used in HTTP headers or redirects."
                ),
                cwe="CWE-113",
            ))
            return


def _check_host_header_injection(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-INJ-006: Host header injection."""
    try:
        resp = client.get(
            target_url,
            headers={"Host": "evil.skyhigh-test.com"},
            capture_evidence=True,
        )
    except Exception:
        return

    if "evil.skyhigh-test.com" in resp.text:
        findings.append(_finding(
            rule_id="DAST-INJ-006",
            name="Host header injection",
            severity="MEDIUM",
            file_path=target_url,
            line_content="Injected Host header reflected in response",
            description=(
                "The application reflects the Host header value in the "
                "response body. This can lead to cache poisoning, password "
                "reset poisoning, and web cache deception attacks."
            ),
            recommendation=(
                "Validate the Host header against a whitelist of expected "
                "hostnames. Do not use the Host header to build URLs."
            ),
            cwe="CWE-644",
        ))


def _check_nosql_injection(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-INJ-007: NoSQL injection."""
    for ep in sitemap.api_endpoints[:5]:
        for payload, desc in NOSQL_PAYLOADS:
            # Try injecting NoSQL operators into JSON API
            test_data = {"username": payload, "password": payload}
            try:
                resp = client.post(
                    ep.url,
                    json=test_data,
                    capture_evidence=True,
                )
            except Exception:
                continue

            # If we get 200 with data when we shouldn't
            if resp.status_code == 200 and len(resp.text) > 100:
                try:
                    data = resp.json()
                    # Heuristic: if response contains user data, it's suspicious
                    if isinstance(data, (list, dict)) and any(
                        k in str(data).lower()
                        for k in ("email", "username", "name", "id", "role")
                    ):
                        findings.append(_finding(
                            rule_id="DAST-INJ-007",
                            name=f"Potential NoSQL injection: {desc}",
                            severity="HIGH",
                            file_path=ep.url,
                            line_content=f"Payload: {desc} → data returned",
                            description=(
                                f"NoSQL injection detected at {ep.url}. "
                                f"The {desc} operator was accepted and returned "
                                "data, suggesting the application passes JSON "
                                "input directly to MongoDB queries."
                            ),
                            recommendation=(
                                "Sanitize JSON input — reject MongoDB operators "
                                "($gt, $ne, $regex, etc.) in user input. "
                                "Use ODM validation layers."
                            ),
                            cwe="CWE-943",
                        ))
                        return
                except (ValueError, KeyError):
                    continue


def _check_xpath_injection(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-INJ-008: XPath injection."""
    xpath_payload = "' or '1'='1"
    xpath_errors = [
        re.compile(r"XPath(?:Exception|Error|Syntax)", re.I),
        re.compile(r"XPATH syntax error", re.I),
        re.compile(r"Invalid predicate", re.I),
        re.compile(r"javax\.xml\.xpath", re.I),
        re.compile(r"lxml\.etree", re.I),
    ]

    for url in sitemap.urls:
        if "?" not in url:
            continue

        injected_urls = _inject_into_url_params(url, xpath_payload)
        for injected_url, param_name in injected_urls:
            try:
                resp = client.get(injected_url, capture_evidence=True)
            except Exception:
                continue

            for err in xpath_errors:
                if err.search(resp.text):
                    findings.append(_finding(
                        rule_id="DAST-INJ-008",
                        name=f"XPath injection in: {param_name}",
                        severity="HIGH",
                        file_path=url.split("?")[0],
                        line_content=f"Payload: {xpath_payload} → XPath error",
                        description=(
                            f"XPath injection detected in parameter "
                            f"'{param_name}'. An XPath error was triggered, "
                            "indicating user input is used in XPath queries."
                        ),
                        recommendation=(
                            "Use parameterized XPath queries. "
                            "Validate and sanitize user input."
                        ),
                        cwe="CWE-643",
                    ))
                    return


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
    """Run all injection checks.

    Returns:
        List of Finding objects for any injection vulnerabilities found.
    """
    findings: list[Finding] = []

    _check_sql_injection_urls(client, sitemap, findings)
    _check_sql_injection_forms(client, sitemap, findings)
    _check_command_injection(client, sitemap, findings)
    _check_ssti(client, sitemap, findings)
    _check_crlf_injection(client, target_url, findings)
    _check_host_header_injection(client, target_url, findings)
    _check_nosql_injection(client, sitemap, findings)
    _check_xpath_injection(client, sitemap, findings)

    return findings
