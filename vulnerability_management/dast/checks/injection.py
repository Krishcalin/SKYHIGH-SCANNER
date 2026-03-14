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
  - Time-based blind SQL injection
  - Boolean-based blind SQL injection

Rule IDs: DAST-INJ-001 through DAST-INJ-012
"""

from __future__ import annotations

import logging
import re
import time
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ...core.finding import Finding

if TYPE_CHECKING:
    from ...core.credential_manager import CredentialManager
    from ..crawler import SiteMap
    from ..http_client import DastHTTPClient

logger = logging.getLogger(__name__)


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

# ── Blind SQL injection payloads ──────────────────────────────────

# Time-based blind SQL injection payloads
BLIND_TIME_PAYLOADS: list[tuple[str, str]] = [
    ("'; WAITFOR DELAY '0:0:5'--", "MSSQL WAITFOR"),
    ("' OR SLEEP(5)--", "MySQL SLEEP"),
    ("' OR pg_sleep(5)--", "PostgreSQL pg_sleep"),
    ("1; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--", "PostgreSQL conditional"),
    ("' OR BENCHMARK(10000000,SHA1('test'))--", "MySQL BENCHMARK"),
]

BLIND_TIME_THRESHOLD_S = 4.0  # Seconds: injected must exceed baseline by this much

# Boolean-based blind SQL injection payload pairs
BLIND_BOOLEAN_PAIRS: list[tuple[str, str, str]] = [
    # (true_payload, false_payload, description)
    ("' OR '1'='1", "' OR '1'='2", "OR string tautology"),
    ("' OR 1=1--", "' OR 1=2--", "OR integer tautology"),
    ("1' AND 1=1--", "1' AND 1=2--", "AND tautology"),
    ("1) OR (1=1", "1) OR (1=2", "Parenthesized OR"),
]

# ── LDAP injection payloads ──────────────────────────────────────

LDAP_PAYLOADS: list[tuple[str, str]] = [
    ("*", "Wildcard"),
    (")(cn=*))(|(cn=*", "Filter breakout (cn)"),
    ("*)(uid=*))(|(uid=*", "Filter breakout (uid)"),
    ("admin)(&)", "Null injection"),
    ("admin)(|(password=*", "Password enumeration"),
]

LDAP_ERROR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"javax\.naming\.(?:NamingException|directory)", re.I),
    re.compile(r"ldap_search|ldap_bind|ldap_connect", re.I),
    re.compile(r"LDAPError|LdapException|LDAP\s+error", re.I),
    re.compile(r"InvalidFilter|Bad\s+search\s+filter", re.I),
    re.compile(r"DSA is unwilling", re.I),
    re.compile(r"(?:Active Directory|LDAP).*?(?:error|exception)", re.I),
]

# ── HTTP Parameter Pollution payloads ────────────────────────────

HPP_PAYLOADS: list[tuple[str, str]] = [
    ("' OR '1'='1", "SQL injection via HPP"),
    ("<script>alert(1)</script>", "XSS via HPP"),
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
        category="injection",
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
                except Exception as exc:
                    logger.debug("Check %s failed for %s: %s", "DAST-INJ-001", injected_url, exc)
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
                            evidence=[{
                                "method": "GET",
                                "url": injected_url,
                                "status": resp.status_code,
                                "payload": payload,
                                "proof": resp.text[:500],
                            }],
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
            except Exception as exc:
                logger.debug("Check %s failed for %s: %s", "DAST-INJ-002", form.action, exc)
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
                        evidence=[{
                            "method": form.method,
                            "url": form.action,
                            "status": resp.status_code,
                            "payload": str(form_data),
                            "proof": resp.text[:500],
                        }],
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
                except Exception as exc:
                    logger.debug("Check %s failed for %s: %s", "DAST-INJ-003", injected_url, exc)
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
                        evidence=[{
                            "method": "GET",
                            "url": injected_url,
                            "status": resp.status_code,
                            "payload": payload,
                            "proof": resp.text[:500],
                        }],
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
                except Exception as exc:
                    logger.debug("Check %s failed for %s: %s", "DAST-INJ-004", injected_url, exc)
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
                        evidence=[{
                            "method": "GET",
                            "url": injected_url,
                            "status": resp.status_code,
                            "payload": payload,
                            "proof": resp.text[:500],
                        }],
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
        except Exception as exc:
            logger.debug("Check %s failed for %s: %s", "DAST-INJ-005", url, exc)
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
    except Exception as exc:
        logger.debug("Check %s failed for %s: %s", "DAST-INJ-006", target_url, exc)
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
            evidence=[{
                "method": "GET",
                "url": target_url,
                "status": resp.status_code,
                "payload": "Host: evil.skyhigh-test.com",
                "proof": resp.text[:500],
            }],
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
            except Exception as exc:
                logger.debug("Check %s failed for %s: %s", "DAST-INJ-007", ep.url, exc)
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
                            evidence=[{
                                "method": "POST",
                                "url": ep.url,
                                "status": resp.status_code,
                                "payload": str(test_data),
                                "proof": resp.text[:500],
                            }],
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
            except Exception as exc:
                logger.debug("Check %s failed for %s: %s", "DAST-INJ-008", injected_url, exc)
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
                        evidence=[{
                            "method": "GET",
                            "url": injected_url,
                            "status": resp.status_code,
                            "payload": xpath_payload,
                            "proof": resp.text[:500],
                        }],
                    ))
                    return


def _check_blind_sqli_time(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-INJ-009: Time-based blind SQL injection."""
    found_params: set[str] = set()
    urls_tested = 0

    for url in sitemap.urls:
        if "?" not in url:
            continue
        if urls_tested >= 5:
            break
        urls_tested += 1

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            continue

        # Measure baseline response time
        try:
            t0 = time.monotonic()
            client.get(url, capture_evidence=False)
            baseline_time = time.monotonic() - t0
        except Exception:
            continue

        for param_name in params:
            if param_name in found_params:
                continue

            payloads_tested = 0
            for payload, db_type in BLIND_TIME_PAYLOADS:
                if payloads_tested >= 2:
                    break
                payloads_tested += 1

                injected_urls = _inject_into_url_params(url, payload)
                for injected_url, p_name in injected_urls:
                    if p_name != param_name:
                        continue
                    try:
                        t0 = time.monotonic()
                        resp = client.get(injected_url, capture_evidence=True)
                        injected_time = time.monotonic() - t0
                    except Exception as exc:
                        logger.debug(
                            "Check %s failed for %s: %s",
                            "DAST-INJ-009", injected_url, exc,
                        )
                        continue

                    delta = injected_time - baseline_time
                    if delta >= BLIND_TIME_THRESHOLD_S:
                        # Confirm with second request
                        try:
                            t0 = time.monotonic()
                            client.get(injected_url, capture_evidence=False)
                            confirm_time = time.monotonic() - t0
                        except Exception:
                            continue

                        confirm_delta = confirm_time - baseline_time
                        if confirm_delta >= BLIND_TIME_THRESHOLD_S:
                            found_params.add(param_name)
                            findings.append(_finding(
                                rule_id="DAST-INJ-009",
                                name=f"Time-based blind SQL injection in: {param_name}",
                                severity="CRITICAL",
                                file_path=url.split("?")[0],
                                line_content=(
                                    f"Payload: {db_type} → "
                                    f"baseline {baseline_time:.1f}s, "
                                    f"injected {injected_time:.1f}s "
                                    f"(+{delta:.1f}s)"
                                ),
                                description=(
                                    f"Time-based blind SQL injection detected in "
                                    f"parameter '{param_name}' at {url.split('?')[0]}. "
                                    f"The {db_type} payload caused the server to respond "
                                    f"{delta:.1f}s slower than baseline, confirmed on "
                                    "a second request. This indicates the injected SQL "
                                    "is being executed by the database."
                                ),
                                recommendation=(
                                    "Use parameterized queries / prepared statements. "
                                    "Never concatenate user input into SQL strings. "
                                    "Consider using an ORM for database queries."
                                ),
                                cwe="CWE-89",
                                evidence=[{
                                    "method": "GET",
                                    "url": injected_url,
                                    "status": resp.status_code,
                                    "payload": payload,
                                    "proof": (
                                        f"Baseline: {baseline_time:.2f}s | "
                                        f"Injected: {injected_time:.2f}s | "
                                        f"Confirmed: {confirm_time:.2f}s"
                                    ),
                                }],
                            ))
                            break


def _check_blind_sqli_boolean(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-INJ-010: Boolean-based blind SQL injection."""
    found_params: set[str] = set()
    urls_tested = 0

    for url in sitemap.urls:
        if "?" not in url:
            continue
        if urls_tested >= 10:
            break
        urls_tested += 1

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            continue

        # Get baseline response
        try:
            baseline_resp = client.get(url, capture_evidence=False)
            baseline_len = len(baseline_resp.text)
        except Exception:
            continue

        for param_name in params:
            if param_name in found_params:
                continue

            for true_payload, false_payload, desc in BLIND_BOOLEAN_PAIRS:
                true_urls = _inject_into_url_params(url, true_payload)
                false_urls = _inject_into_url_params(url, false_payload)

                true_url = None
                false_url = None
                for u, p in true_urls:
                    if p == param_name:
                        true_url = u
                        break
                for u, p in false_urls:
                    if p == param_name:
                        false_url = u
                        break

                if not true_url or not false_url:
                    continue

                try:
                    true_resp = client.get(true_url, capture_evidence=True)
                    false_resp = client.get(false_url, capture_evidence=False)
                except Exception as exc:
                    logger.debug(
                        "Check %s failed for %s: %s",
                        "DAST-INJ-010", url, exc,
                    )
                    continue

                true_len = len(true_resp.text)
                false_len = len(false_resp.text)

                # True condition should match baseline, false should differ
                baseline_match = abs(true_len - baseline_len) < 50
                condition_diff = abs(true_len - false_len) > 100

                if baseline_match and condition_diff:
                    found_params.add(param_name)
                    findings.append(_finding(
                        rule_id="DAST-INJ-010",
                        name=f"Boolean-based blind SQL injection in: {param_name}",
                        severity="HIGH",
                        file_path=url.split("?")[0],
                        line_content=(
                            f"Payload: {desc} → true={true_len} chars, "
                            f"false={false_len} chars, baseline={baseline_len} chars"
                        ),
                        description=(
                            f"Boolean-based blind SQL injection detected in "
                            f"parameter '{param_name}' at {url.split('?')[0]}. "
                            f"The '{desc}' true condition produced a response similar "
                            f"to the baseline ({true_len} vs {baseline_len} chars), "
                            f"while the false condition differed significantly "
                            f"({false_len} chars). This indicates the application "
                            "evaluates injected SQL conditions."
                        ),
                        recommendation=(
                            "Use parameterized queries / prepared statements. "
                            "Never concatenate user input into SQL strings."
                        ),
                        cwe="CWE-89",
                        evidence=[{
                            "method": "GET",
                            "url": true_url,
                            "status": true_resp.status_code,
                            "payload": f"TRUE: {true_payload} | FALSE: {false_payload}",
                            "proof": (
                                f"Baseline: {baseline_len} chars | "
                                f"True: {true_len} chars | "
                                f"False: {false_len} chars"
                            ),
                        }],
                    ))
                    break


def _check_ldap_injection(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-INJ-011: LDAP injection."""
    urls_tested = 0

    for url in sitemap.urls:
        if "?" not in url:
            continue
        if urls_tested >= 10:
            break
        urls_tested += 1

        # Get baseline response length
        try:
            baseline_resp = client.get(url, capture_evidence=False)
            baseline_len = len(baseline_resp.text)
        except Exception:
            continue

        for payload, desc in LDAP_PAYLOADS:
            injected_urls = _inject_into_url_params(url, payload)
            for injected_url, param_name in injected_urls:
                try:
                    resp = client.get(injected_url, capture_evidence=True)
                except Exception as exc:
                    logger.debug(
                        "Check %s failed for %s: %s",
                        "DAST-INJ-011", injected_url, exc,
                    )
                    continue

                # Check for LDAP error patterns
                error_match = any(
                    p.search(resp.text) for p in LDAP_ERROR_PATTERNS
                )

                # Check wildcard response length anomaly
                length_anomaly = (
                    payload == "*"
                    and len(resp.text) - baseline_len > 200
                )

                if error_match or length_anomaly:
                    trigger = (
                        "LDAP error in response"
                        if error_match
                        else f"Wildcard response {len(resp.text)} chars "
                             f"vs baseline {baseline_len} chars"
                    )
                    findings.append(_finding(
                        rule_id="DAST-INJ-011",
                        name=f"LDAP injection in: {param_name}",
                        severity="HIGH",
                        file_path=url.split("?")[0],
                        line_content=f"Payload: {desc} — {trigger}",
                        description=(
                            f"LDAP injection detected in parameter "
                            f"'{param_name}' at {url.split('?')[0]}. "
                            f"The '{desc}' payload caused: {trigger}. "
                            "An attacker can manipulate LDAP queries to "
                            "bypass authentication or extract directory data."
                        ),
                        recommendation=(
                            "Use parameterized LDAP queries or an LDAP "
                            "framework that escapes special characters. "
                            "Validate all user input against an allowlist "
                            "before using it in LDAP filters."
                        ),
                        cwe="CWE-90",
                        evidence=[{
                            "method": "GET",
                            "url": injected_url,
                            "status": resp.status_code,
                            "payload": payload,
                            "proof": resp.text[:500],
                        }],
                    ))
                    return


def _check_http_param_pollution(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-INJ-012: HTTP Parameter Pollution."""
    urls_tested = 0

    for url in sitemap.urls:
        if "?" not in url:
            continue
        if urls_tested >= 10:
            break
        urls_tested += 1

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            continue

        # Check baseline for SQL errors (should be clean)
        try:
            baseline_resp = client.get(url, capture_evidence=False)
        except Exception:
            continue

        baseline_has_error = any(
            p.search(baseline_resp.text) for p in SQL_ERROR_PATTERNS
        )
        if baseline_has_error:
            continue  # Already has errors, skip

        for param_name, values in params.items():
            original_value = values[0] if values else ""

            for hpp_payload, desc in HPP_PAYLOADS:
                # Build HPP URL: duplicate param with payload
                hpp_query = parsed.query + f"&{param_name}={hpp_payload}"
                hpp_url = urlunparse(parsed._replace(query=hpp_query))

                try:
                    resp = client.get(hpp_url, capture_evidence=True)
                except Exception as exc:
                    logger.debug(
                        "Check %s failed for %s: %s",
                        "DAST-INJ-012", hpp_url, exc,
                    )
                    continue

                # Check if HPP triggered SQL error (bypass)
                hpp_triggered = any(
                    p.search(resp.text) for p in SQL_ERROR_PATTERNS
                )

                if hpp_triggered:
                    findings.append(_finding(
                        rule_id="DAST-INJ-012",
                        name=f"HTTP Parameter Pollution bypass in: {param_name}",
                        severity="MEDIUM",
                        file_path=url.split("?")[0],
                        line_content=(
                            f"HPP: {param_name}={original_value}"
                            f"&{param_name}={hpp_payload} — {desc}"
                        ),
                        description=(
                            f"HTTP Parameter Pollution detected in parameter "
                            f"'{param_name}' at {url.split('?')[0]}. Sending "
                            f"a duplicate parameter with an injection payload "
                            "triggered a database error, while the single "
                            "parameter did not. This indicates input filters "
                            "only validate the first occurrence, allowing the "
                            "duplicate to bypass protection."
                        ),
                        recommendation=(
                            "Validate all occurrences of duplicate parameters, "
                            "not just the first. Use a web application firewall "
                            "that normalizes duplicate parameters. Apply "
                            "parameterized queries as a defense-in-depth measure."
                        ),
                        cwe="CWE-235",
                        evidence=[{
                            "method": "GET",
                            "url": hpp_url,
                            "status": resp.status_code,
                            "payload": f"{param_name}={original_value}&{param_name}={hpp_payload}",
                            "proof": resp.text[:500],
                        }],
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
    _check_blind_sqli_time(client, sitemap, findings)
    _check_blind_sqli_boolean(client, sitemap, findings)
    _check_ldap_injection(client, sitemap, findings)
    _check_http_param_pollution(client, sitemap, findings)

    return findings
