"""
DAST Check Module — Server-Side Request Forgery (SSRF).

Active checks that test for SSRF and related vulnerabilities:
  - SSRF via URL parameters (DAST-SSRF-001)
  - SSRF via form inputs (DAST-SSRF-002)
  - SSRF via redirect parameters (DAST-SSRF-003)
  - SSRF via header injection (DAST-SSRF-004)
  - Open redirect to internal resources (DAST-SSRF-005)

Rule IDs: DAST-SSRF-001 through DAST-SSRF-005
CWEs: CWE-918 (SSRF), CWE-601 (Open Redirect)
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
# SSRF targets and detection patterns
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SSRF_INTERNAL_TARGETS: list[tuple[str, str]] = [
    ("http://127.0.0.1", "localhost IPv4"),
    ("http://169.254.169.254/latest/meta-data/", "AWS EC2 metadata"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
    ("http://10.0.0.1", "internal network 10.x"),
    ("http://[::1]", "localhost IPv6"),
]

SSRF_DETECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ami-[0-9a-f]{8,17}"),
    re.compile(r"root:.*?:0:0:"),
    re.compile(r"latest/meta-data", re.I),
    re.compile(r"computeMetadata", re.I),
    re.compile(r"10\.0\.0\.\d+"),
]

SSRF_PARAM_NAMES: frozenset[str] = frozenset({
    "url", "redirect", "callback", "webhook", "fetch", "proxy",
    "forward", "dest", "target", "uri", "path", "next", "return",
    "returnUrl", "continue", "site", "link", "ref", "source", "src",
    "data", "load", "file", "page", "open", "domain", "host", "to",
    "out", "view", "dir", "show", "navigation", "go",
})

REDIRECT_PARAM_NAMES: frozenset[str] = frozenset({
    "redirect", "url", "next", "return", "returnUrl", "continue",
    "to", "dest", "forward", "go", "redir", "return_to",
    "redirect_uri", "redirect_url",
})

_INTERNAL_IP_MARKERS: list[str] = [
    "127.0.0.1", "169.254", "10.", "192.168", "localhost", "[::1]",
]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
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
        category="ssrf",
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


def _inject_into_url_params(
    url: str,
    payload: str,
) -> list[tuple[str, str]]:
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

def _check_ssrf_url_params(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-SSRF-001: SSRF via URL parameters."""
    found_params: set[str] = set()
    urls_checked = 0

    for url in sitemap.urls:
        if "?" not in url:
            continue
        if urls_checked >= 10:
            break

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            continue

        urls_checked += 1

        for param_name in params:
            if param_name.lower() not in SSRF_PARAM_NAMES:
                continue
            if param_name in found_params:
                continue

            for target_url, target_desc in SSRF_INTERNAL_TARGETS[:3]:
                injected_urls = _inject_into_url_params(url, target_url)
                for injected_url, injected_param in injected_urls:
                    if injected_param != param_name:
                        continue
                    try:
                        resp = client.get(
                            injected_url, capture_evidence=True,
                        )
                    except Exception as exc:
                        logger.debug(
                            "Check %s failed for %s: %s",
                            "DAST-SSRF-001", injected_url, exc,
                        )
                        continue

                    for pattern in SSRF_DETECTION_PATTERNS:
                        if pattern.search(resp.text):
                            found_params.add(param_name)
                            findings.append(_finding(
                                rule_id="DAST-SSRF-001",
                                name=(
                                    f"SSRF in URL parameter: "
                                    f"{param_name}"
                                ),
                                severity="CRITICAL",
                                file_path=url.split("?")[0],
                                line_content=(
                                    f"Payload: {target_url} "
                                    f"({target_desc}) "
                                    f"→ internal content detected"
                                ),
                                description=(
                                    f"Server-Side Request Forgery "
                                    f"detected in parameter "
                                    f"'{param_name}' at "
                                    f"{url.split('?')[0]}. Injecting "
                                    f"'{target_desc}' caused the "
                                    f"server to fetch an internal "
                                    f"resource and return its content "
                                    f"in the response."
                                ),
                                recommendation=(
                                    "Validate and sanitize URL "
                                    "parameters. Use allowlists for "
                                    "permitted domains and protocols. "
                                    "Block requests to internal/private "
                                    "IP ranges (127.0.0.0/8, "
                                    "169.254.0.0/16, 10.0.0.0/8, "
                                    "192.168.0.0/16)."
                                ),
                                cwe="CWE-918",
                                evidence=[{
                                    "method": "GET",
                                    "url": injected_url,
                                    "status": resp.status_code,
                                    "payload": target_url,
                                    "proof": resp.text[:500],
                                }],
                            ))
                            break


def _check_ssrf_form_inputs(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-SSRF-002: SSRF via form inputs."""
    found_forms: set[str] = set()
    forms_checked = 0

    for form in sitemap.forms:
        if forms_checked >= 5:
            break
        if form.action in found_forms:
            continue
        if not form.field_names:
            continue

        ssrf_fields = [
            f for f in form.fields
            if f.name and f.name.lower() in SSRF_PARAM_NAMES
        ]
        if not ssrf_fields:
            continue

        forms_checked += 1

        for target_url, target_desc in SSRF_INTERNAL_TARGETS[:3]:
            form_data = {}
            for f in form.fields:
                if f.field_type == "hidden" and f.value:
                    form_data[f.name] = f.value
                elif f.name and f.name.lower() in SSRF_PARAM_NAMES:
                    form_data[f.name] = target_url
                elif f.name:
                    form_data[f.name] = "test"

            try:
                if form.method == "POST":
                    resp = client.post(form.action, data=form_data)
                else:
                    resp = client.get(form.action, params=form_data)
            except Exception as exc:
                logger.debug(
                    "Check %s failed for %s: %s",
                    "DAST-SSRF-002", form.action, exc,
                )
                continue

            for pattern in SSRF_DETECTION_PATTERNS:
                if pattern.search(resp.text):
                    found_forms.add(form.action)
                    field_names = ", ".join(
                        f.name for f in ssrf_fields
                    )
                    findings.append(_finding(
                        rule_id="DAST-SSRF-002",
                        name=f"SSRF in form: {form.action}",
                        severity="CRITICAL",
                        file_path=form.url,
                        line_content=(
                            f"Form {form.method} {form.action} "
                            f"— internal content via "
                            f"{target_desc}"
                        ),
                        description=(
                            f"Server-Side Request Forgery "
                            f"detected in form at {form.url} "
                            f"(action: {form.action}). "
                            f"Fields [{field_names}] accepted "
                            f"an internal URL ({target_desc}) "
                            f"and the server returned internal "
                            f"resource content."
                        ),
                        recommendation=(
                            "Validate URLs submitted through "
                            "forms. Use allowlists for "
                            "permitted domains. Block requests "
                            "to private IP ranges and cloud "
                            "metadata endpoints."
                        ),
                        cwe="CWE-918",
                        evidence=[{
                            "method": form.method,
                            "url": form.action,
                            "status": resp.status_code,
                            "payload": str(form_data),
                            "proof": resp.text[:500],
                        }],
                    ))
                    break
            if form.action in found_forms:
                break


def _check_ssrf_redirect_params(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-SSRF-003: SSRF via redirect parameters."""
    found_params: set[str] = set()

    for url in sitemap.urls:
        if "?" not in url:
            continue

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            continue

        for param_name in params:
            if param_name.lower() not in REDIRECT_PARAM_NAMES:
                continue
            if param_name in found_params:
                continue

            for target_url, target_desc in SSRF_INTERNAL_TARGETS[:3]:
                injected_urls = _inject_into_url_params(
                    url, target_url,
                )
                for injected_url, injected_param in injected_urls:
                    if injected_param != param_name:
                        continue
                    try:
                        resp = client.get(
                            injected_url,
                            capture_evidence=True,
                            allow_redirects=False,
                        )
                    except Exception as exc:
                        logger.debug(
                            "Check %s failed for %s: %s",
                            "DAST-SSRF-003", injected_url, exc,
                        )
                        continue

                    location = resp.headers.get("Location", "")
                    if any(
                        marker in location
                        for marker in _INTERNAL_IP_MARKERS
                    ):
                        found_params.add(param_name)
                        findings.append(_finding(
                            rule_id="DAST-SSRF-003",
                            name=(
                                f"SSRF redirect in parameter: "
                                f"{param_name}"
                            ),
                            severity="HIGH",
                            file_path=url.split("?")[0],
                            line_content=(
                                f"Payload: {target_url} "
                                f"→ redirect to internal IP"
                            ),
                            description=(
                                f"The parameter '{param_name}' at "
                                f"{url.split('?')[0]} accepts "
                                f"internal URLs and redirects to "
                                f"them. Injecting '{target_desc}' "
                                f"caused a redirect to an internal "
                                f"address ({location})."
                            ),
                            recommendation=(
                                "Validate redirect targets against "
                                "an allowlist. Block redirects to "
                                "internal/private IP ranges and "
                                "cloud metadata endpoints."
                            ),
                            cwe="CWE-918",
                            evidence=[{
                                "method": "GET",
                                "url": injected_url,
                                "status": resp.status_code,
                                "location": location,
                                "payload": target_url,
                            }],
                        ))
                        break
                if param_name in found_params:
                    break


def _check_ssrf_header_injection(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-SSRF-004: SSRF via header injection."""
    try:
        baseline_resp = client.get(
            target_url, capture_evidence=True,
        )
    except Exception as exc:
        logger.debug(
            "Check %s failed for %s: %s",
            "DAST-SSRF-004", target_url, exc,
        )
        return

    baseline_len = len(baseline_resp.text)

    internal_headers = [
        ({"X-Forwarded-For": "127.0.0.1"}, "X-Forwarded-For"),
        (
            {"Referer": "http://169.254.169.254/latest/meta-data/"},
            "Referer",
        ),
    ]

    for headers, header_name in internal_headers:
        try:
            resp = client.get(
                target_url,
                headers=headers,
                capture_evidence=True,
            )
        except Exception as exc:
            logger.debug(
                "Check %s failed for %s: %s",
                "DAST-SSRF-004", target_url, exc,
            )
            continue

        body_diff = abs(len(resp.text) - baseline_len)
        if body_diff <= 200:
            continue

        for pattern in SSRF_DETECTION_PATTERNS:
            if pattern.search(resp.text):
                findings.append(_finding(
                    rule_id="DAST-SSRF-004",
                    name=f"SSRF via {header_name} header",
                    severity="MEDIUM",
                    file_path=target_url,
                    line_content=(
                        f"{header_name} with internal IP "
                        f"triggered different response"
                    ),
                    description=(
                        f"The application responds differently "
                        f"when the {header_name} header points "
                        f"to an internal address. The response "
                        f"body changed significantly "
                        f"(delta: {body_diff} chars) and "
                        f"contains internal resource indicators."
                    ),
                    recommendation=(
                        "Do not trust X-Forwarded-For or "
                        "Referer headers for routing "
                        "decisions. Validate forwarded headers "
                        "against known proxy addresses."
                    ),
                    cwe="CWE-918",
                    evidence=[{
                        "method": "GET",
                        "url": target_url,
                        "status": resp.status_code,
                        "payload": str(headers),
                        "baseline_length": baseline_len,
                        "response_length": len(resp.text),
                        "proof": resp.text[:500],
                    }],
                ))
                return


def _check_open_redirect_internal(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-SSRF-005: Open redirect to internal resources."""
    redirect_targets = [
        ("http://127.0.0.1", "localhost IPv4"),
        ("http://169.254.169.254", "cloud metadata"),
    ]
    found_params: set[str] = set()

    for url in sitemap.urls:
        if "?" not in url:
            continue

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            continue

        for param_name in params:
            if param_name.lower() not in REDIRECT_PARAM_NAMES:
                continue
            if param_name in found_params:
                continue

            for redir_url, redir_desc in redirect_targets:
                injected_urls = _inject_into_url_params(
                    url, redir_url,
                )
                for injected_url, injected_param in injected_urls:
                    if injected_param != param_name:
                        continue
                    try:
                        resp = client.get(
                            injected_url,
                            capture_evidence=True,
                            allow_redirects=False,
                        )
                    except Exception as exc:
                        logger.debug(
                            "Check %s failed for %s: %s",
                            "DAST-SSRF-005", injected_url, exc,
                        )
                        continue

                    if resp.status_code not in (
                        301, 302, 303, 307, 308,
                    ):
                        continue

                    location = resp.headers.get("Location", "")
                    if redir_url in location:
                        found_params.add(param_name)
                        findings.append(_finding(
                            rule_id="DAST-SSRF-005",
                            name=(
                                f"Open redirect to internal: "
                                f"{param_name}"
                            ),
                            severity="HIGH",
                            file_path=url.split("?")[0],
                            line_content=(
                                f"Payload: {redir_url} "
                                f"→ {resp.status_code} redirect"
                            ),
                            description=(
                                f"Open redirect to internal "
                                f"resource detected in parameter "
                                f"'{param_name}' at "
                                f"{url.split('?')[0]}. Injecting "
                                f"'{redir_desc}' caused a "
                                f"{resp.status_code} redirect to "
                                f"{location}. This can be chained "
                                f"with SSRF to access internal "
                                f"services."
                            ),
                            recommendation=(
                                "Validate redirect targets against "
                                "an allowlist of permitted domains. "
                                "Never redirect to user-controlled "
                                "URLs without validation. Block "
                                "internal IP ranges."
                            ),
                            cwe="CWE-601",
                            evidence=[{
                                "method": "GET",
                                "url": injected_url,
                                "status": resp.status_code,
                                "location": location,
                                "payload": redir_url,
                            }],
                        ))
                        break
                if param_name in found_params:
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
    """Run all SSRF checks.

    Returns:
        List of Finding objects for any SSRF vulnerabilities found.
    """
    findings: list[Finding] = []

    _check_ssrf_url_params(client, sitemap, findings)
    _check_ssrf_form_inputs(client, sitemap, findings)
    _check_ssrf_redirect_params(client, sitemap, findings)
    _check_ssrf_header_injection(client, target_url, findings)
    _check_open_redirect_internal(client, sitemap, findings)

    return findings
