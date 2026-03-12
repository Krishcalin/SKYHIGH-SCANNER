"""
DAST Check Module — Authentication & Session Management.

Checks for authentication and session weaknesses:
  - Missing anti-CSRF tokens in forms
  - Session token in URL
  - Login over HTTP
  - Password fields with autocomplete enabled
  - Weak session cookie attributes
  - Default credentials on login forms
  - Session fixation potential
  - Account lockout testing

Rule IDs: DAST-AUTH-001 through DAST-AUTH-009
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

# Common CSRF token field names
CSRF_TOKEN_NAMES = frozenset({
    "csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken",
    "_csrf", "_token", "authenticity_token", "__requestverificationtoken",
    "antiforgery", "__antiforgerytoken", "xsrf_token", "_xsrf",
    "verification_token", "form_token",
})

# Common session cookie name patterns
SESSION_COOKIE_PATTERNS = re.compile(
    r"(?:session|sess|sid|jsessionid|phpsessid|asp\.net_sessionid"
    r"|connect\.sid|laravel_session|_session|token|auth)",
    re.IGNORECASE,
)

# Login form indicators
LOGIN_INDICATORS = re.compile(
    r"(?:login|signin|sign-in|log-in|authenticate|password)",
    re.IGNORECASE,
)

# Password field detection
PASSWORD_FIELD_RE = re.compile(
    r"""<input[^>]*type\s*=\s*["']password["'][^>]*>""",
    re.IGNORECASE,
)

# Autocomplete on password field
PASSWORD_AUTOCOMPLETE_OFF_RE = re.compile(
    r"""<input[^>]*type\s*=\s*["']password["'][^>]*autocomplete\s*=\s*["'](?:off|new-password)["'][^>]*>""",
    re.IGNORECASE,
)

# Session ID in URL pattern
SESSION_IN_URL_RE = re.compile(
    r"[?&;](?:jsessionid|phpsessid|sid|session_id|sessid|token)=",
    re.IGNORECASE,
)

# Default credential pairs to test
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("root", "root"),
    ("test", "test"),
    ("user", "user"),
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
        category="auth_session",
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

def _check_csrf_tokens(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-AUTH-001: Missing CSRF tokens in POST forms."""
    for form in sitemap.forms:
        if form.method != "POST":
            continue

        field_names_lower = {f.lower() for f in form.field_names}
        has_csrf = bool(field_names_lower & CSRF_TOKEN_NAMES)

        if not has_csrf:
            findings.append(_finding(
                rule_id="DAST-AUTH-001",
                name="Missing CSRF token in POST form",
                severity="MEDIUM",
                file_path=form.url,
                line_content=f"POST {form.action} — fields: {', '.join(form.field_names[:5])}",
                description=(
                    f"A POST form at {form.url} (action: {form.action}) "
                    "does not contain a recognizable CSRF token field. "
                    "Without CSRF protection, attackers can forge requests "
                    "on behalf of authenticated users."
                ),
                recommendation=(
                    "Add a CSRF token to all state-changing forms. "
                    "Most frameworks provide built-in CSRF protection."
                ),
                cwe="CWE-352",
            ))


def _check_session_in_url(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-AUTH-002: Session tokens in URL parameters."""
    seen: set[str] = set()
    for url in sitemap.urls:
        if SESSION_IN_URL_RE.search(url):
            # Extract the parameter name
            match = SESSION_IN_URL_RE.search(url)
            param = match.group(0) if match else ""
            key = param.split("=")[0].lstrip("?&;")
            if key in seen:
                continue
            seen.add(key)

            findings.append(_finding(
                rule_id="DAST-AUTH-002",
                name="Session token in URL",
                severity="HIGH",
                file_path=url,
                line_content=f"URL contains session parameter: {key}",
                description=(
                    "Session tokens are passed in URL parameters. "
                    "URLs are logged in browser history, server logs, "
                    "referrer headers, and proxy logs, exposing session tokens."
                ),
                recommendation=(
                    "Store session tokens in cookies with HttpOnly and "
                    "Secure flags, not in URL parameters."
                ),
                cwe="CWE-598",
            ))


def _check_login_over_http(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-AUTH-003: Login forms submitted over HTTP."""
    for form in sitemap.forms:
        # Check if form has password field and action is HTTP
        has_password = any(
            f.field_type == "password" for f in form.fields
        )
        if has_password and form.action.startswith("http://"):
            findings.append(_finding(
                rule_id="DAST-AUTH-003",
                name="Login form submitted over HTTP",
                severity="HIGH",
                file_path=form.url,
                line_content=f"Form action: {form.action}",
                description=(
                    f"A login form at {form.url} submits credentials to "
                    f"{form.action} over unencrypted HTTP. Credentials "
                    "can be intercepted by network attackers."
                ),
                recommendation=(
                    "Ensure all login forms submit over HTTPS. "
                    "Redirect HTTP to HTTPS and enforce HSTS."
                ),
                cwe="CWE-319",
            ))


def _check_password_autocomplete(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-AUTH-004: Password fields with autocomplete enabled."""
    checked = 0
    for url in sitemap.urls:
        if checked >= 30:
            break
        try:
            resp = client.get(url, capture_evidence=False)
        except Exception:
            continue
        checked += 1

        # Only check pages with password fields
        pw_fields = PASSWORD_FIELD_RE.findall(resp.text)
        if not pw_fields:
            continue

        pw_autocomplete_off = PASSWORD_AUTOCOMPLETE_OFF_RE.findall(resp.text)
        if len(pw_fields) > len(pw_autocomplete_off):
            findings.append(_finding(
                rule_id="DAST-AUTH-004",
                name="Password autocomplete enabled",
                severity="LOW",
                file_path=url,
                line_content="<input type='password'> without autocomplete='off'",
                description=(
                    f"Password field(s) at {url} have autocomplete enabled. "
                    "Browsers may store passwords in plaintext, which can "
                    "be accessed by local attackers or malware."
                ),
                recommendation=(
                    "Add autocomplete='off' or autocomplete='new-password' "
                    "to password input fields."
                ),
                cwe="CWE-522",
            ))


def _check_session_cookie_security(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-AUTH-005: Session cookie security attributes."""
    try:
        resp = client.get(target_url, capture_evidence=False)
    except Exception:
        return

    set_cookie = resp.headers.get("Set-Cookie", "")
    if not set_cookie:
        return

    cookies = [c.strip() for c in set_cookie.split(",") if "=" in c]
    for cookie in cookies:
        cookie_name = cookie.split("=")[0].strip()
        if not SESSION_COOKIE_PATTERNS.search(cookie_name):
            continue

        cookie_lower = cookie.lower()

        # Check for session cookie without HttpOnly
        if "httponly" not in cookie_lower:
            findings.append(_finding(
                rule_id="DAST-AUTH-005",
                name=f"Session cookie missing HttpOnly: {cookie_name}",
                severity="HIGH",
                file_path=target_url,
                line_content=f"Set-Cookie: {cookie_name}=... (no HttpOnly)",
                description=(
                    f"Session cookie '{cookie_name}' does not have the "
                    "HttpOnly flag. XSS attacks can steal the session cookie."
                ),
                recommendation="Set HttpOnly flag on all session cookies.",
                cwe="CWE-1004",
            ))

        # Check for session cookie without Secure
        if "secure" not in cookie_lower and target_url.startswith("https://"):
            findings.append(_finding(
                rule_id="DAST-AUTH-005",
                name=f"Session cookie missing Secure: {cookie_name}",
                severity="HIGH",
                file_path=target_url,
                line_content=f"Set-Cookie: {cookie_name}=... (no Secure)",
                description=(
                    f"Session cookie '{cookie_name}' does not have the "
                    "Secure flag. The cookie may be sent over HTTP connections."
                ),
                recommendation="Set Secure flag on all session cookies.",
                cwe="CWE-614",
            ))


def _check_login_form_security(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-AUTH-006: Login form security checks."""
    for form in sitemap.forms:
        has_password = any(f.field_type == "password" for f in form.fields)
        if not has_password:
            continue

        # Check if form uses GET method for login
        if form.method == "GET":
            findings.append(_finding(
                rule_id="DAST-AUTH-006",
                name="Login form uses GET method",
                severity="HIGH",
                file_path=form.url,
                line_content=f"GET {form.action}",
                description=(
                    f"A login form at {form.url} uses the GET method. "
                    "Credentials will appear in the URL, browser history, "
                    "server logs, and referrer headers."
                ),
                recommendation="Change login forms to use the POST method.",
                cwe="CWE-598",
            ))


def _check_default_credentials(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-AUTH-007: Default credentials accepted on login forms."""
    for form in sitemap.forms:
        if form.method != "POST":
            continue
        has_password = any(f.field_type == "password" for f in form.fields)
        if not has_password:
            continue

        # Find username and password field names
        username_field = None
        password_field = None
        for f in form.fields:
            name_lower = f.name.lower()
            if f.field_type == "password":
                password_field = f.name
            elif name_lower in ("username", "user", "email", "login", "name", "usr"):
                username_field = f.name

        if not username_field or not password_field:
            continue

        # Try default credentials (limited to avoid lockout)
        for user, pw in DEFAULT_CREDENTIALS[:3]:  # Only test first 3 pairs
            form_data = {username_field: user, password_field: pw}
            # Add any hidden fields
            for f in form.fields:
                if f.field_type == "hidden" and f.value:
                    form_data[f.name] = f.value

            try:
                resp = client.post(form.action, data=form_data)
            except Exception:
                continue

            # Heuristic: login succeeded if redirected to non-login page
            # or if response doesn't contain error indicators
            if resp.status_code in (200, 301, 302, 303):
                final_url = resp.url if hasattr(resp, "url") else ""
                if final_url and not LOGIN_INDICATORS.search(final_url):
                    findings.append(_finding(
                        rule_id="DAST-AUTH-007",
                        name=f"Default credentials accepted: {user}/{pw}",
                        severity="CRITICAL",
                        file_path=form.url,
                        line_content=f"Login with {user}:{pw} → {resp.status_code}",
                        description=(
                            f"The login form at {form.url} accepted default "
                            f"credentials ({user}/{pw}). Default credentials "
                            "are widely known and easily exploitable."
                        ),
                        recommendation=(
                            "Change default credentials immediately. "
                            "Implement password complexity requirements. "
                            "Consider account lockout after failed attempts."
                        ),
                        cwe="CWE-798",
                    ))
                    return  # Stop after first successful login


def _check_session_fixation(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-AUTH-008: Potential session fixation."""
    # Make two requests and compare session cookies
    try:
        resp1 = client.get(target_url, capture_evidence=False)
        resp2 = client.get(target_url, capture_evidence=False)
    except Exception:
        return

    set_cookie1 = resp1.headers.get("Set-Cookie", "")
    set_cookie2 = resp2.headers.get("Set-Cookie", "")

    # If the server sends the same session cookie in every response,
    # and doesn't rotate, it might be vulnerable to fixation
    # This is a heuristic — true fixation requires pre/post auth comparison
    if set_cookie1 and set_cookie1 == set_cookie2:
        # Check if it's a session cookie
        cookie_name = set_cookie1.split("=")[0].strip()
        if SESSION_COOKIE_PATTERNS.search(cookie_name):
            findings.append(_finding(
                rule_id="DAST-AUTH-008",
                name="Potential session fixation vulnerability",
                severity="MEDIUM",
                file_path=target_url,
                line_content=f"Session cookie not regenerated: {cookie_name}",
                description=(
                    "The server returns the same session cookie across "
                    "multiple requests. If session IDs are not regenerated "
                    "after authentication, the application may be vulnerable "
                    "to session fixation attacks."
                ),
                recommendation=(
                    "Regenerate session IDs after successful authentication. "
                    "Invalidate old session IDs upon login."
                ),
                cwe="CWE-384",
            ))


def _check_logout_mechanism(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-AUTH-009: Missing or GET-based logout."""
    logout_re = re.compile(r"(?:logout|signout|sign-out|log-out)", re.IGNORECASE)

    # Check crawled URLs for logout links
    for url in sitemap.urls:
        if logout_re.search(url):
            # GET-based logout is a CSRF risk
            findings.append(_finding(
                rule_id="DAST-AUTH-009",
                name="Logout via GET request",
                severity="LOW",
                file_path=url,
                line_content=f"GET {url}",
                description=(
                    f"Logout endpoint at {url} is accessible via GET. "
                    "GET-based logout is vulnerable to CSRF — an attacker "
                    "can force logout via an image tag or link."
                ),
                recommendation=(
                    "Implement logout via POST with CSRF protection. "
                    "Invalidate the session server-side on logout."
                ),
                cwe="CWE-352",
            ))
            break


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
    """Run all authentication and session management checks.

    Returns:
        List of Finding objects for any auth/session issues found.
    """
    findings: list[Finding] = []

    _check_csrf_tokens(client, sitemap, findings)
    _check_session_in_url(client, sitemap, findings)
    _check_login_over_http(client, sitemap, findings)
    _check_password_autocomplete(client, sitemap, findings)
    _check_session_cookie_security(client, target_url, findings)
    _check_login_form_security(client, sitemap, findings)
    _check_default_credentials(client, sitemap, findings)
    _check_session_fixation(client, target_url, findings)
    _check_logout_mechanism(client, sitemap, findings)

    return findings
