"""
DAST Check Module — File Inclusion & Path Traversal.

Active checks that test for:
  - Local File Inclusion (LFI)
  - Remote File Inclusion (RFI)
  - Path traversal (directory traversal)
  - Null byte injection (for older systems)
  - Backup file discovery

Rule IDs: DAST-FI-001 through DAST-FI-005
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
# Payloads and detection
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# LFI payloads targeting known files
LFI_PAYLOADS: list[tuple[str, str, re.Pattern]] = [
    # (payload, description, detection_pattern)
    ("../../../etc/passwd", "Unix passwd (3 levels)",
     re.compile(r"root:.*?:0:0:")),
    ("../../../../../../etc/passwd", "Unix passwd (6 levels)",
     re.compile(r"root:.*?:0:0:")),
    ("....//....//....//etc/passwd", "Double-dot bypass",
     re.compile(r"root:.*?:0:0:")),
    ("..\\..\\..\\windows\\win.ini", "Windows win.ini (backslash)",
     re.compile(r"\[(?:fonts|extensions|mci|Mail)\]", re.I)),
    ("../../../windows/win.ini", "Windows win.ini (forward slash)",
     re.compile(r"\[(?:fonts|extensions|mci|Mail)\]", re.I)),
    ("/etc/passwd", "Absolute path /etc/passwd",
     re.compile(r"root:.*?:0:0:")),
    ("....//....//etc/shadow", "Shadow file attempt",
     re.compile(r"root:[\$!*]")),
]

# URL-encoded LFI variants
LFI_ENCODED_PAYLOADS: list[tuple[str, str, re.Pattern]] = [
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL-encoded traversal",
     re.compile(r"root:.*?:0:0:")),
    ("..%252f..%252f..%252fetc%252fpasswd", "Double-encoded traversal",
     re.compile(r"root:.*?:0:0:")),
    ("..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", "UTF-8 overlong encoding",
     re.compile(r"root:.*?:0:0:")),
]

# RFI detection: use a non-routable IP to detect inclusion attempts
# We look for connection errors that indicate the server tried to fetch
RFI_PAYLOADS: list[tuple[str, str]] = [
    ("http://192.0.2.1/skyhigh_rfi_test.txt", "HTTP RFI"),
    ("https://192.0.2.1/skyhigh_rfi_test.txt", "HTTPS RFI"),
]

# Path-like URL parameters that are likely file inclusion points
FILE_PARAM_NAMES = re.compile(
    r"(?:file|path|page|include|template|view|doc|document|folder"
    r"|dir|load|read|download|resource|src|source|lang|language"
    r"|module|action|content|layout|theme)",
    re.IGNORECASE,
)

# Backup file extensions to probe
BACKUP_EXTENSIONS = [
    ".bak", ".backup", ".old", ".orig", ".save",
    ".swp", ".swo", "~", ".copy", ".tmp",
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
        category="file_inclusion",
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


def _get_file_params(url: str) -> list[str]:
    """Extract parameter names that look like file inclusion points."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    return [p for p in params if FILE_PARAM_NAMES.search(p)]


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

def _check_lfi_params(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-FI-001: Local File Inclusion via URL parameters."""
    found_params: set[str] = set()

    for url in sitemap.urls:
        file_params = _get_file_params(url)
        if not file_params:
            continue

        for param_name in file_params:
            if param_name in found_params:
                continue

            for payload, desc, detect in LFI_PAYLOADS[:3]:
                injected_url = _inject_param(url, param_name, payload)
                try:
                    resp = client.get(injected_url, capture_evidence=True)
                except Exception as exc:
                    logger.debug("Check %s failed for %s: %s", "DAST-FI-001", injected_url, exc)
                    continue

                if detect.search(resp.text):
                    found_params.add(param_name)
                    findings.append(_finding(
                        rule_id="DAST-FI-001",
                        name=f"Local File Inclusion in: {param_name}",
                        severity="CRITICAL",
                        file_path=url.split("?")[0],
                        line_content=f"Payload: {desc} → file content returned",
                        description=(
                            f"Local File Inclusion detected in parameter "
                            f"'{param_name}' at {url.split('?')[0]}. "
                            f"The payload '{desc}' successfully read a "
                            "local file. This can lead to sensitive data "
                            "exposure and potentially RCE via log poisoning."
                        ),
                        recommendation=(
                            "Never use user input to construct file paths. "
                            "Use a whitelist of allowed files. Implement "
                            "chroot or file path validation."
                        ),
                        cwe="CWE-98",
                        evidence=[{
                            "method": "GET",
                            "url": injected_url,
                            "status": resp.status_code,
                            "payload": payload,
                            "proof": resp.text[:500],
                        }],
                    ))
                    break


def _check_lfi_encoded(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-FI-002: LFI with encoding bypass."""
    for url in sitemap.urls:
        file_params = _get_file_params(url)
        if not file_params:
            continue

        for param_name in file_params:
            for payload, desc, detect in LFI_ENCODED_PAYLOADS:
                injected_url = _inject_param(url, param_name, payload)
                try:
                    resp = client.get(injected_url, capture_evidence=True)
                except Exception as exc:
                    logger.debug("Check %s failed for %s: %s", "DAST-FI-002", injected_url, exc)
                    continue

                if detect.search(resp.text):
                    findings.append(_finding(
                        rule_id="DAST-FI-002",
                        name=f"LFI with encoding bypass: {param_name}",
                        severity="CRITICAL",
                        file_path=url.split("?")[0],
                        line_content=f"Payload: {desc}",
                        description=(
                            f"Local File Inclusion detected using encoding "
                            f"bypass ({desc}) in parameter '{param_name}'. "
                            "Input filters may be present but are bypassable."
                        ),
                        recommendation=(
                            "Do not rely on blacklisting traversal sequences. "
                            "Use a whitelist approach. Canonicalize paths before "
                            "validating."
                        ),
                        cwe="CWE-98",
                    ))
                    return


def _check_path_traversal(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-FI-003: Path traversal in all URL parameters."""
    # This checks ALL parameters, not just file-like ones
    found_params: set[str] = set()

    for url in sitemap.urls:
        if "?" not in url:
            continue

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name in params:
            if param_name in found_params:
                continue

            # Use a single reliable payload
            payload = "../../../../../../etc/passwd"
            injected_url = _inject_param(url, param_name, payload)
            try:
                resp = client.get(injected_url, capture_evidence=True)
            except Exception as exc:
                logger.debug("Check %s failed for %s: %s", "DAST-FI-003", injected_url, exc)
                continue

            if re.search(r"root:.*?:0:0:", resp.text):
                found_params.add(param_name)
                findings.append(_finding(
                    rule_id="DAST-FI-003",
                    name=f"Path traversal in: {param_name}",
                    severity="HIGH",
                    file_path=url.split("?")[0],
                    line_content=f"../../etc/passwd in {param_name} → file read",
                    description=(
                        f"Path traversal detected in parameter '{param_name}'. "
                        "Directory traversal sequences (../) are not filtered, "
                        "allowing access to files outside the intended directory."
                    ),
                    recommendation=(
                        "Validate file paths — ensure they resolve within "
                        "the intended directory. Use Path.resolve() and "
                        "check that the result starts with the base directory."
                    ),
                    cwe="CWE-22",
                    evidence=[{
                        "method": "GET",
                        "url": injected_url,
                        "status": resp.status_code,
                        "payload": payload,
                        "proof": resp.text[:500],
                    }],
                ))


def _check_rfi(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-FI-004: Remote File Inclusion."""
    for url in sitemap.urls:
        file_params = _get_file_params(url)
        if not file_params:
            continue

        for param_name in file_params:
            for payload, desc in RFI_PAYLOADS:
                injected_url = _inject_param(url, param_name, payload)
                try:
                    # Use a short timeout — RFI will try to fetch the URL
                    resp = client.get(
                        injected_url,
                        capture_evidence=True,
                        timeout=5,
                    )
                except Exception as exc:
                    logger.debug("Check %s failed for %s: %s", "DAST-FI-004", injected_url, exc)
                    continue

                # Check for signs the server attempted to include the URL
                # This is heuristic — look for connection errors in response
                rfi_indicators = [
                    "192.0.2.1",  # Our test IP reflected
                    "allow_url_include",
                    "failed to open stream",
                    "include(",
                    "require(",
                ]
                if any(indicator in resp.text for indicator in rfi_indicators):
                    findings.append(_finding(
                        rule_id="DAST-FI-004",
                        name=f"Potential RFI in: {param_name}",
                        severity="CRITICAL",
                        file_path=url.split("?")[0],
                        line_content=f"Payload: {desc} → inclusion attempted",
                        description=(
                            f"Remote File Inclusion detected in parameter "
                            f"'{param_name}'. The server attempted to include "
                            "a remote URL, which can lead to Remote Code Execution."
                        ),
                        recommendation=(
                            "Disable allow_url_include in PHP. Never use user "
                            "input to construct include paths. Use a whitelist "
                            "of allowed includes."
                        ),
                        cwe="CWE-98",
                        evidence=[{
                            "method": "GET",
                            "url": injected_url,
                            "status": resp.status_code,
                            "payload": payload,
                            "proof": resp.text[:500],
                        }],
                    ))
                    return


def _check_backup_files(
    client: DastHTTPClient,
    sitemap: SiteMap,
    findings: list[Finding],
) -> None:
    """DAST-FI-005: Backup files accessible alongside originals."""
    checked = 0
    for url in sitemap.urls:
        if checked >= 15:
            break

        # Only check pages with extensions
        parsed = urlparse(url)
        path = parsed.path
        if "." not in path.split("/")[-1]:
            continue

        for ext in BACKUP_EXTENSIONS[:5]:
            backup_url = url.split("?")[0] + ext
            try:
                status, body = client.probe_path(backup_url, "")
            except Exception as exc:
                logger.debug("Check %s failed for %s: %s", "DAST-FI-005", backup_url, exc)
                continue
            checked += 1

            if status == 200 and len(body) > 50:
                findings.append(_finding(
                    rule_id="DAST-FI-005",
                    name=f"Backup file accessible: {path}{ext}",
                    severity="MEDIUM",
                    file_path=backup_url,
                    line_content=f"HTTP 200 — {len(body)} bytes",
                    description=(
                        f"Backup file {path}{ext} is accessible. "
                        "Backup files may contain source code, credentials, "
                        "or configuration that should not be public."
                    ),
                    recommendation=(
                        "Remove backup files from the web server. "
                        "Configure the server to block access to common "
                        "backup extensions."
                    ),
                    cwe="CWE-530",
                ))
                break  # One backup per original file is enough


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
    """Run all file inclusion and path traversal checks.

    Returns:
        List of Finding objects for any file inclusion issues found.
    """
    findings: list[Finding] = []

    _check_lfi_params(client, sitemap, findings)
    _check_lfi_encoded(client, sitemap, findings)
    _check_path_traversal(client, sitemap, findings)
    _check_rfi(client, sitemap, findings)
    _check_backup_files(client, sitemap, findings)

    return findings
