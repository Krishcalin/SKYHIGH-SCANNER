"""
DAST Check Module — Information Disclosure.

Passive checks that detect information leakage through:
  - Server/technology version headers
  - Sensitive file exposure (.git, .env, backups, etc.)
  - Directory listing enabled
  - Debug/stack trace in error pages
  - Internal IP addresses in headers/responses
  - HTML comments containing sensitive patterns

Rule IDs: DAST-INFO-001 through DAST-INFO-012
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

# Sensitive files/paths to probe
SENSITIVE_PATHS: list[tuple[str, str, str]] = [
    # (path, description, indicator_pattern)
    (".git/HEAD", "Git repository exposed", r"ref:\s+refs/"),
    (".git/config", "Git config exposed", r"\[core\]"),
    (".env", "Environment file exposed", r"(?:API_KEY|SECRET|PASSWORD|DATABASE|TOKEN)"),
    (".env.local", "Local env file exposed", r"(?:API_KEY|SECRET|PASSWORD|DATABASE|TOKEN)"),
    (".env.production", "Production env file exposed", r"(?:API_KEY|SECRET|PASSWORD|DATABASE|TOKEN)"),
    (".htaccess", "Apache .htaccess exposed", r"(?:RewriteEngine|Deny|Allow|Redirect)"),
    (".htpasswd", "Apache password file exposed", r":[\$]"),
    ("wp-config.php.bak", "WordPress config backup", r"DB_PASSWORD"),
    ("web.config", "IIS web.config exposed", r"<configuration"),
    ("server-status", "Apache server-status enabled", r"Apache Server Status"),
    ("server-info", "Apache server-info enabled", r"Apache Server Information"),
    (".DS_Store", "macOS metadata file exposed", r"Bud1"),
    ("robots.txt", "robots.txt may reveal hidden paths", r"Disallow:\s+/"),
    (".well-known/security.txt", "Security policy file", r"Contact:"),
    ("phpinfo.php", "PHP info page exposed", r"phpinfo\(\)"),
    ("elmah.axd", "ELMAH error log exposed", r"Error Log"),
    ("trace.axd", "ASP.NET trace enabled", r"Trace Information"),
    ("crossdomain.xml", "Flash crossdomain policy", r"<cross-domain-policy"),
    ("clientaccesspolicy.xml", "Silverlight access policy", r"<access-policy"),
    ("backup.sql", "SQL backup file exposed", r"(?:CREATE TABLE|INSERT INTO|DROP TABLE)"),
    ("database.sql", "SQL dump exposed", r"(?:CREATE TABLE|INSERT INTO|DROP TABLE)"),
    ("dump.sql", "SQL dump exposed", r"(?:CREATE TABLE|INSERT INTO|DROP TABLE)"),
]

# Patterns for version info in Server header
VERSION_PATTERN = re.compile(
    r"(?:Apache|nginx|IIS|LiteSpeed|Tomcat|Jetty|Express|Kestrel|Caddy)"
    r"[/\s][\d.]+",
    re.IGNORECASE,
)

# Patterns that indicate debug/stack trace info
DEBUG_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"Traceback \(most recent call last\)"), "Python stack trace"),
    (re.compile(r"at\s+[\w.]+\([\w]+\.java:\d+\)"), "Java stack trace"),
    (re.compile(r"(?:Fatal error|Warning|Notice):.*?in\s+/[\w/]+\.php\s+on\s+line\s+\d+"), "PHP error"),
    (re.compile(r"Microsoft\.AspNetCore|System\.NullReferenceException"), ".NET stack trace"),
    (re.compile(r"node_modules/.+\.js:\d+:\d+"), "Node.js stack trace"),
    (re.compile(r"DJANGO_SETTINGS_MODULE|django\.core\.exceptions"), "Django debug info"),
    (re.compile(r"<b>Warning</b>:.*?<b>/[\w/]+\.php</b>.*?<b>\d+</b>"), "PHP warning (HTML)"),
    (re.compile(r"SQL syntax.*?near\s+'"), "SQL error message"),
]

# Internal IP regex
INTERNAL_IP_PATTERN = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)

# Sensitive HTML comment patterns
COMMENT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"<!--.*?(?:password|passwd|secret|api[_-]?key|token|credential).*?-->", re.I | re.S),
     "Sensitive keyword in HTML comment"),
    (re.compile(r"<!--.*?(?:TODO|FIXME|HACK|BUG|XXX).*?-->", re.I | re.S),
     "Developer note in HTML comment"),
    (re.compile(r"<!--.*?(?:BEGIN|END)\s+(?:DEBUG|STAGING|DEV).*?-->", re.I | re.S),
     "Debug/staging marker in HTML comment"),
]

# Technology-revealing headers
TECH_HEADERS = [
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Drupal-Dynamic-Cache",
    "X-Varnish",
    "X-Backend-Server",
    "X-Runtime",        # Ruby on Rails
    "X-Request-Id",     # Can reveal framework
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
        category="info_disclosure",
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

def _check_server_header(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-INFO-001: Server header version disclosure."""
    headers = client.get_headers(target_url)
    server = headers.get("Server", "")
    if server and VERSION_PATTERN.search(server):
        findings.append(_finding(
            rule_id="DAST-INFO-001",
            name="Server version disclosed",
            severity="LOW",
            file_path=target_url,
            line_content=f"Server: {server}",
            description=(
                f"The Server header reveals version information: {server}. "
                "This helps attackers identify specific vulnerabilities for the "
                "server software version."
            ),
            recommendation=(
                "Configure the web server to suppress version information. "
                "For Apache: ServerTokens Prod. For nginx: server_tokens off."
            ),
            cwe="CWE-200",
        ))


def _check_tech_headers(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-INFO-002: Technology stack disclosed via headers."""
    headers = client.get_headers(target_url)
    for header_name in TECH_HEADERS:
        value = headers.get(header_name, "")
        if value:
            findings.append(_finding(
                rule_id="DAST-INFO-002",
                name=f"Technology header disclosed: {header_name}",
                severity="LOW",
                file_path=target_url,
                line_content=f"{header_name}: {value}",
                description=(
                    f"The {header_name} header reveals technology stack information: "
                    f"{value}. This aids attackers in fingerprinting the application."
                ),
                recommendation=f"Remove the {header_name} response header.",
                cwe="CWE-200",
            ))


def _check_sensitive_files(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
    verbose: bool = False,
) -> None:
    """DAST-INFO-003: Sensitive files exposed."""
    base = target_url.rstrip("/")
    for path, desc, indicator in SENSITIVE_PATHS:
        url = f"{base}/{path}"
        try:
            status, body = client.probe_path(target_url, path)
        except Exception:
            continue
        if status == 200 and re.search(indicator, body):
            severity = "CRITICAL" if path in (
                ".env", ".env.local", ".env.production",
                ".htpasswd", "backup.sql", "database.sql", "dump.sql",
            ) else "HIGH" if path.startswith(".git") else "MEDIUM"
            findings.append(_finding(
                rule_id="DAST-INFO-003",
                name=f"Sensitive file exposed: {path}",
                severity=severity,
                file_path=url,
                line_content=f"HTTP 200 — {desc}",
                description=(
                    f"The file {path} is publicly accessible. {desc}. "
                    "This may expose source code, credentials, or internal "
                    "infrastructure details."
                ),
                recommendation=(
                    f"Remove or restrict access to {path}. "
                    "Configure the web server to block access to sensitive files."
                ),
                cwe="CWE-538",
            ))


def _check_directory_listing(
    client: DastHTTPClient,
    target_url: str,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-INFO-004: Directory listing enabled."""
    # Collect unique directory paths from crawled URLs
    dirs_to_check: set[str] = set()
    for url in sitemap.urls:
        # Extract directory portion
        path = url.split("?")[0].split("#")[0]
        last_slash = path.rfind("/")
        if last_slash > 8:  # After https://x
            dirs_to_check.add(path[:last_slash + 1])

    # Also try common directories
    base = target_url.rstrip("/")
    for d in ("images/", "uploads/", "static/", "assets/", "media/", "files/"):
        dirs_to_check.add(f"{base}/{d}")

    checked = 0
    for dir_url in dirs_to_check:
        if checked >= 20:  # Limit probing
            break
        try:
            status, body = client.probe_path(dir_url, "")
        except Exception:
            continue
        checked += 1
        if status == 200 and re.search(
            r"(?:Index of|Directory listing|Parent Directory|\[DIR\])",
            body, re.IGNORECASE,
        ):
            findings.append(_finding(
                rule_id="DAST-INFO-004",
                name="Directory listing enabled",
                severity="MEDIUM",
                file_path=dir_url,
                line_content="Directory listing detected",
                description=(
                    f"Directory listing is enabled at {dir_url}. "
                    "This allows attackers to browse server file structure "
                    "and discover sensitive files."
                ),
                recommendation=(
                    "Disable directory listing. Apache: Options -Indexes. "
                    "Nginx: autoindex off."
                ),
                cwe="CWE-548",
            ))


def _check_error_pages(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-INFO-005: Error pages reveal debug/stack trace information."""
    # Trigger error pages with known bad paths
    error_paths = [
        "nonexistent_path_404_test",
        "test.php?id='",             # May trigger SQL error
        "%00",                        # Null byte
        "../../../etc/passwd",        # May trigger error
    ]
    base = target_url.rstrip("/")
    seen_patterns: set[str] = set()

    for path in error_paths:
        try:
            status, body = client.probe_path(target_url, path)
        except Exception:
            continue

        for pattern, pattern_desc in DEBUG_PATTERNS:
            if pattern_desc in seen_patterns:
                continue
            if pattern.search(body):
                seen_patterns.add(pattern_desc)
                findings.append(_finding(
                    rule_id="DAST-INFO-005",
                    name=f"Debug information leaked: {pattern_desc}",
                    severity="MEDIUM",
                    file_path=f"{base}/{path}",
                    line_content=pattern_desc,
                    description=(
                        f"An error page reveals {pattern_desc}. "
                        "Stack traces and error messages can expose internal "
                        "paths, database structure, and framework versions."
                    ),
                    recommendation=(
                        "Configure custom error pages that do not reveal "
                        "internal details. Disable debug mode in production."
                    ),
                    cwe="CWE-209",
                ))


def _check_internal_ips(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-INFO-006: Internal IP addresses in response headers."""
    try:
        resp = client.get(target_url, capture_evidence=False)
    except Exception:
        return

    # Check all response headers
    for header_name, header_value in resp.headers.items():
        matches = INTERNAL_IP_PATTERN.findall(header_value)
        for ip in matches:
            findings.append(_finding(
                rule_id="DAST-INFO-006",
                name="Internal IP address disclosed in header",
                severity="LOW",
                file_path=target_url,
                line_content=f"{header_name}: {ip}",
                description=(
                    f"The {header_name} header contains an internal IP address "
                    f"({ip}). This reveals internal network topology."
                ),
                recommendation=(
                    "Configure reverse proxies and load balancers to strip "
                    "internal IP addresses from response headers."
                ),
                cwe="CWE-200",
            ))


def _check_html_comments(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-INFO-007: Sensitive information in HTML comments."""
    checked = 0
    for url in sitemap.urls:
        if checked >= 30:  # Limit pages to check
            break
        try:
            resp = client.get(url, capture_evidence=False)
        except Exception:
            continue
        checked += 1

        for pattern, desc in COMMENT_PATTERNS:
            match = pattern.search(resp.text)
            if match:
                # Truncate the match for display
                snippet = match.group(0)[:120]
                findings.append(_finding(
                    rule_id="DAST-INFO-007",
                    name=f"Sensitive HTML comment: {desc}",
                    severity="LOW",
                    file_path=url,
                    line_content=snippet,
                    description=(
                        f"{desc} found in HTML source of {url}. "
                        "Comments may reveal internal logic, credentials, "
                        "or TODO items that indicate security weaknesses."
                    ),
                    recommendation=(
                        "Remove sensitive comments from production HTML. "
                        "Use a build process that strips comments."
                    ),
                    cwe="CWE-615",
                ))


def _check_email_disclosure(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-INFO-008: Email addresses disclosed in responses."""
    email_re = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    seen_emails: set[str] = set()
    checked = 0

    for url in sitemap.urls:
        if checked >= 20:
            break
        try:
            resp = client.get(url, capture_evidence=False)
        except Exception:
            continue
        checked += 1

        for match in email_re.finditer(resp.text):
            email = match.group(0).lower()
            # Skip common false positives
            if email.endswith((".png", ".jpg", ".gif", ".css", ".js")):
                continue
            if email not in seen_emails:
                seen_emails.add(email)
                findings.append(_finding(
                    rule_id="DAST-INFO-008",
                    name="Email address disclosed",
                    severity="LOW",
                    file_path=url,
                    line_content=email,
                    description=(
                        f"Email address {email} found in page source. "
                        "Exposed emails can be harvested for phishing "
                        "and social engineering attacks."
                    ),
                    recommendation=(
                        "Use contact forms instead of displaying email "
                        "addresses directly. Obfuscate emails if they must "
                        "be displayed."
                    ),
                    cwe="CWE-200",
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
    """Run all information disclosure checks.

    Returns:
        List of Finding objects for any information disclosure issues found.
    """
    findings: list[Finding] = []

    _check_server_header(client, target_url, findings)
    _check_tech_headers(client, target_url, findings)
    _check_sensitive_files(client, target_url, findings, verbose)
    _check_directory_listing(client, target_url, sitemap, findings)
    _check_error_pages(client, target_url, findings)
    _check_internal_ips(client, target_url, findings)
    _check_html_comments(client, sitemap, findings)
    _check_email_disclosure(client, sitemap, findings)

    return findings
