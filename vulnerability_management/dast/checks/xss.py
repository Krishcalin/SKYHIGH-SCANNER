"""
DAST Check Module — Cross-Site Scripting (XSS).

Active checks that test for XSS vulnerabilities:
  - Reflected XSS via URL parameters
  - Reflected XSS via form inputs
  - DOM-based XSS indicators
  - XSS in HTTP headers (Referer, User-Agent)
  - XSS via error pages

Rule IDs: DAST-XSS-001 through DAST-XSS-007
"""

from __future__ import annotations

import hashlib
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
# Payloads
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Unique canary to detect reflection without executing
CANARY = "SKYHIGH"

# XSS payloads with detection strings
XSS_PAYLOADS: list[tuple[str, str, str]] = [
    # (payload, description, detection_string)
    (f'<{CANARY}xss>', "HTML tag injection",
     f"<{CANARY}xss>"),
    (f'"><img src=x onerror={CANARY}>', "Tag breakout img onerror",
     f"onerror={CANARY}"),
    (f"'><script>{CANARY}</script>", "Script injection (single quote)",
     f"<script>{CANARY}</script>"),
    (f'"><script>{CANARY}</script>', "Script injection (double quote)",
     f"<script>{CANARY}</script>"),
    (f"javascript:{CANARY}", "JavaScript URI",
     f"javascript:{CANARY}"),
    (f'{CANARY}<svg/onload=alert(1)>', "SVG onload",
     f"{CANARY}<svg"),
]

# DOM-based XSS sink patterns
DOM_XSS_SINKS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"document\.write\s*\("), "document.write()"),
    (re.compile(r"\.innerHTML\s*="), ".innerHTML assignment"),
    (re.compile(r"\.outerHTML\s*="), ".outerHTML assignment"),
    (re.compile(r"eval\s*\("), "eval()"),
    (re.compile(r"setTimeout\s*\(\s*['\"]"), "setTimeout with string"),
    (re.compile(r"setInterval\s*\(\s*['\"]"), "setInterval with string"),
    (re.compile(r"document\.location\s*="), "document.location assignment"),
    (re.compile(r"window\.location\s*="), "window.location assignment"),
]

# DOM-based XSS source patterns (user-controllable input)
DOM_XSS_SOURCES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"document\.URL"), "document.URL"),
    (re.compile(r"document\.documentURI"), "document.documentURI"),
    (re.compile(r"location\.(?:search|hash|href|pathname)"), "location property"),
    (re.compile(r"document\.referrer"), "document.referrer"),
    (re.compile(r"window\.name"), "window.name"),
    (re.compile(r"document\.cookie"), "document.cookie"),
]

# ── Stored XSS constants ────────────────────────────────────────

STORED_XSS_CANARY_PREFIX = "SKYHIGH_STORED_"
MAX_STORED_XSS_FORMS = 5
MAX_STORED_XSS_RECHECK_PAGES = 3

# Form types to skip for stored XSS
SKIP_FORM_TYPES = re.compile(r"search|file|upload|import|attach|login|logout", re.I)


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
        category="xss",
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


def _inject_param(url: str, param: str, payload: str) -> str:
    """Replace a specific parameter value in a URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Checks
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _check_reflected_xss_params(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-XSS-001: Reflected XSS via URL parameters."""
    found_params: set[str] = set()

    for url in sitemap.urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            continue

        for param_name in params:
            if param_name in found_params:
                continue

            for payload, desc, detect in XSS_PAYLOADS[:3]:  # Limit payloads
                injected_url = _inject_param(url, param_name, payload)
                try:
                    resp = client.get(injected_url, capture_evidence=True)
                except Exception as exc:
                    logger.debug("Check %s failed for %s: %s", "DAST-XSS-001", injected_url, exc)
                    continue

                if detect in resp.text:
                    found_params.add(param_name)
                    findings.append(_finding(
                        rule_id="DAST-XSS-001",
                        name=f"Reflected XSS in parameter: {param_name}",
                        severity="HIGH",
                        file_path=url.split("?")[0],
                        line_content=f"Payload: {desc} → reflected unescaped",
                        description=(
                            f"Reflected XSS detected in parameter '{param_name}' "
                            f"at {url.split('?')[0]}. The payload ({desc}) "
                            "was reflected in the response without proper "
                            "encoding or sanitization."
                        ),
                        recommendation=(
                            "Encode all user input before rendering in HTML. "
                            "Use context-aware output encoding. Implement a "
                            "Content Security Policy."
                        ),
                        cwe="CWE-79",
                        evidence=[{
                            "method": "GET",
                            "url": injected_url,
                            "status": resp.status_code,
                            "payload": payload,
                            "proof": resp.text[:500],
                        }],
                    ))
                    break  # Found XSS in this param, move to next


def _check_reflected_xss_forms(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-XSS-002: Reflected XSS via form inputs."""
    found_forms: set[str] = set()

    for form in sitemap.forms:
        if form.action in found_forms:
            continue
        if not form.field_names:
            continue

        # Use the simplest payload
        payload, desc, detect = XSS_PAYLOADS[0]

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
            logger.debug("Check %s failed for %s: %s", "DAST-XSS-002", form.action, exc)
            continue

        if detect in resp.text:
            found_forms.add(form.action)
            findings.append(_finding(
                rule_id="DAST-XSS-002",
                name=f"Reflected XSS in form: {form.action}",
                severity="HIGH",
                file_path=form.url,
                line_content=f"Form {form.method} {form.action} — {desc}",
                description=(
                    f"Reflected XSS detected in form at {form.url} "
                    f"(action: {form.action}). The payload was reflected "
                    "in the response without encoding."
                ),
                recommendation=(
                    "Encode all form input before rendering. Use framework-"
                    "provided escaping functions. Implement CSP."
                ),
                cwe="CWE-79",
            ))


def _check_dom_xss(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-XSS-003: DOM-based XSS indicators."""
    checked = 0
    found_sinks: set[str] = set()

    for url in sitemap.urls:
        if checked >= 20:
            break
        try:
            resp = client.get(url, capture_evidence=False)
        except Exception as exc:
            logger.debug("Check %s failed for %s: %s", "DAST-XSS-003", url, exc)
            continue
        checked += 1

        # Look for source→sink patterns in inline JavaScript
        js_content = resp.text

        # Check for dangerous sinks
        for sink_pattern, sink_desc in DOM_XSS_SINKS:
            if sink_desc in found_sinks:
                continue
            if not sink_pattern.search(js_content):
                continue

            # Check if any source feeds into nearby code
            for source_pattern, source_desc in DOM_XSS_SOURCES:
                if source_pattern.search(js_content):
                    found_sinks.add(sink_desc)
                    findings.append(_finding(
                        rule_id="DAST-XSS-003",
                        name=f"Potential DOM XSS: {sink_desc}",
                        severity="MEDIUM",
                        file_path=url,
                        line_content=f"Source: {source_desc} → Sink: {sink_desc}",
                        description=(
                            f"Potential DOM-based XSS at {url}. "
                            f"User-controllable source ({source_desc}) and "
                            f"dangerous sink ({sink_desc}) found in the same "
                            "page. Manual verification is recommended."
                        ),
                        recommendation=(
                            "Avoid using dangerous DOM sinks like innerHTML "
                            "and document.write. Use textContent or createElement "
                            "instead. Sanitize all user-controllable DOM sources."
                        ),
                        cwe="CWE-79",
                    ))
                    break


def _check_xss_in_headers(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-XSS-004: XSS via HTTP headers (Referer, User-Agent)."""
    payload = f"<{CANARY}header>"

    # Test Referer header injection
    try:
        resp = client.get(
            target_url,
            headers={"Referer": payload},
            capture_evidence=True,
        )
        if payload in resp.text:
            findings.append(_finding(
                rule_id="DAST-XSS-004",
                name="XSS via Referer header",
                severity="MEDIUM",
                file_path=target_url,
                line_content=f"Referer: {payload} → reflected",
                description=(
                    "The Referer header value is reflected in the response "
                    "without encoding. While not directly controllable by "
                    "attackers in all scenarios, this indicates insufficient "
                    "output encoding."
                ),
                recommendation=(
                    "Encode all HTTP header values before rendering in HTML. "
                    "Never trust any header value as safe."
                ),
                cwe="CWE-79",
            ))
    except Exception as exc:
        logger.debug("Check %s failed for %s: %s", "DAST-XSS-004", target_url, exc)

    # Test User-Agent header injection
    try:
        resp = client.get(
            target_url,
            headers={"User-Agent": payload},
            capture_evidence=True,
        )
        if payload in resp.text:
            findings.append(_finding(
                rule_id="DAST-XSS-004",
                name="XSS via User-Agent header",
                severity="MEDIUM",
                file_path=target_url,
                line_content=f"User-Agent: {payload} → reflected",
                description=(
                    "The User-Agent header value is reflected in the response "
                    "without encoding. User-Agent is logged and displayed in "
                    "admin panels, potentially leading to stored XSS."
                ),
                recommendation=(
                    "Encode all HTTP header values before rendering. "
                    "Sanitize User-Agent before storing or displaying."
                ),
                cwe="CWE-79",
            ))
    except Exception as exc:
        logger.debug("Check %s failed for %s: %s", "DAST-XSS-004", target_url, exc)


def _check_xss_error_pages(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-XSS-005: XSS in error pages."""
    payload = f"<{CANARY}err>"
    base = target_url.rstrip("/")

    # Inject into 404 path
    url = f"{base}/{payload}"
    try:
        resp = client.get(url, capture_evidence=True)
    except Exception as exc:
        logger.debug("Check %s failed for %s: %s", "DAST-XSS-005", url, exc)
        return

    if payload in resp.text:
        findings.append(_finding(
            rule_id="DAST-XSS-005",
            name="XSS in error page (404)",
            severity="MEDIUM",
            file_path=url,
            line_content=f"404 page reflects path: {payload}",
            description=(
                "The 404 error page reflects the requested URL path "
                "without encoding. An attacker can craft malicious URLs "
                "that execute JavaScript when visited."
            ),
            recommendation=(
                "Encode the requested URL before including it in error pages. "
                "Use a static error page that does not reflect user input."
            ),
            cwe="CWE-79",
        ))


def _generate_canary(form_action: str) -> str:
    """Generate a unique canary per form action."""
    h = hashlib.sha256(
        f"{form_action}{time.time()}".encode(),
    ).hexdigest()[:8]
    return f"{STORED_XSS_CANARY_PREFIX}{h}"


def _check_stored_xss(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-XSS-006 / DAST-XSS-007: Stored XSS via form submission."""
    # Phase 1: Filter eligible forms and submit payloads
    eligible_forms = []
    for form in sitemap.forms:
        if form.method.upper() != "POST":
            continue
        if form.has_file_upload:
            continue
        # Skip search/login/file upload forms
        action_path = urlparse(form.action).path.lower()
        if SKIP_FORM_TYPES.search(action_path):
            continue
        # Must have at least one text input field
        text_fields = [
            f for f in form.fields
            if f.field_type in ("text", "textarea", "email", "")
            and f.name
        ]
        if not text_fields:
            continue
        eligible_forms.append((form, text_fields))

    if not eligible_forms:
        return

    # Submit payloads and track canaries
    canaries: dict[str, str] = {}  # canary -> form_action

    for form, _text_fields in eligible_forms[:MAX_STORED_XSS_FORMS]:
        canary = _generate_canary(form.action)
        payload = f"<img src=x onerror={canary}>"

        form_data: dict[str, str] = {}
        for f in form.fields:
            if f.field_type == "hidden" and f.value:
                form_data[f.name] = f.value
            elif f.name and f.field_type in ("text", "textarea", "email", ""):
                form_data[f.name] = payload
            elif f.name:
                form_data[f.name] = "test"

        try:
            client.post(form.action, data=form_data, capture_evidence=False)
            canaries[canary] = form.action
        except Exception as exc:
            logger.debug(
                "Stored XSS inject failed for %s: %s", form.action, exc,
            )

    if not canaries:
        return

    # Phase 2: Re-crawl pages to check if canaries persist
    check_urls = list(sitemap.urls)[:MAX_STORED_XSS_RECHECK_PAGES * len(canaries)]

    for url in check_urls:
        try:
            resp = client.get(url, capture_evidence=True)
        except Exception:
            continue

        for canary, form_action in list(canaries.items()):
            if canary not in resp.text:
                continue

            # Check if canary appears with unescaped HTML
            unescaped_in_response = (
                f"onerror={canary}" in resp.text
                or f"<img src=x onerror={canary}>" in resp.text
            )

            if unescaped_in_response:
                findings.append(_finding(
                    rule_id="DAST-XSS-006",
                    name=f"Stored XSS via form: {form_action}",
                    severity="CRITICAL",
                    file_path=url,
                    line_content=(
                        f"Canary {canary} injected via {form_action} "
                        f"found unescaped at {url}"
                    ),
                    description=(
                        f"Stored XSS detected. A payload submitted to "
                        f"{form_action} was stored and rendered unescaped "
                        f"at {url}. An attacker can inject persistent "
                        "JavaScript that executes for every user visiting "
                        "the affected page."
                    ),
                    recommendation=(
                        "Encode all stored user input before rendering. "
                        "Use context-aware output encoding on both input "
                        "and output. Implement a strict Content Security "
                        "Policy."
                    ),
                    cwe="CWE-79",
                    evidence=[{
                        "method": "GET",
                        "url": url,
                        "status": resp.status_code,
                        "payload": f"<img src=x onerror={canary}>",
                        "proof": resp.text[:500],
                    }],
                ))
                canaries.pop(canary, None)
            else:
                # Canary text persists but HTML is encoded
                findings.append(_finding(
                    rule_id="DAST-XSS-007",
                    name=f"Stored XSS canary persists (encoded): {form_action}",
                    severity="HIGH",
                    file_path=url,
                    line_content=(
                        f"Canary {canary} stored via {form_action} "
                        f"found encoded at {url}"
                    ),
                    description=(
                        f"User input submitted to {form_action} is stored "
                        f"and appears at {url} with partial HTML encoding. "
                        "While the current encoding may prevent execution, "
                        "this indicates user content is persisted and "
                        "rendered, which may be exploitable in different "
                        "rendering contexts."
                    ),
                    recommendation=(
                        "Verify output encoding is applied consistently "
                        "across all rendering contexts (HTML, JavaScript, "
                        "CSS, URL). Use framework-provided auto-escaping."
                    ),
                    cwe="CWE-79",
                    evidence=[{
                        "method": "GET",
                        "url": url,
                        "status": resp.status_code,
                        "payload": f"<img src=x onerror={canary}>",
                        "proof": resp.text[:500],
                    }],
                ))
                canaries.pop(canary, None)


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
    """Run all XSS checks.

    Returns:
        List of Finding objects for any XSS vulnerabilities found.
    """
    findings: list[Finding] = []

    _check_reflected_xss_params(client, sitemap, findings)
    _check_reflected_xss_forms(client, sitemap, findings)
    _check_dom_xss(client, sitemap, findings)
    _check_xss_in_headers(client, target_url, findings)
    _check_xss_error_pages(client, target_url, findings)
    _check_stored_xss(client, sitemap, findings)

    return findings
