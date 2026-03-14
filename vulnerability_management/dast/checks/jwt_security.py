"""
DAST Check Module — JWT Token Security.

Active checks that test for JWT-related vulnerabilities:
  - Algorithm confusion (none algorithm) (DAST-JWT-001)
  - Signature stripping (DAST-JWT-002)
  - Expired token acceptance (DAST-JWT-003)
  - Claim tampering (DAST-JWT-004)
  - Weak signing secret (DAST-JWT-005)

Rule IDs: DAST-JWT-001 through DAST-JWT-005
CWEs: CWE-347 (Improper Verification of Cryptographic Signature),
      CWE-613 (Insufficient Session Expiration),
      CWE-345 (Insufficient Verification of Data Authenticity),
      CWE-326 (Inadequate Encryption Strength)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
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
# Constants
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

NONE_ALGORITHMS = ["none", "None", "NONE", "nOnE"]

ADMIN_CLAIMS = [
    ("role", "admin"),
    ("admin", True),
    ("is_admin", True),
    ("role", "superuser"),
    ("access", "admin"),
]

JWT_BEARER_RE = re.compile(
    r'Bearer\s+(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)',
)

WEAK_SECRETS = [
    "secret", "password", "key", "123456", "jwt_secret",
    "changeme", "test", "admin", "default", "jwt",
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
        category="jwt",
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


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding fix."""
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def _b64url_encode(data: bytes) -> str:
    """Base64url encode, strip padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _decode_jwt(token: str) -> tuple[dict, dict, str] | None:
    """Decode JWT into (header, payload, signature). Returns None on failure."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _encode_jwt_unsigned(header: dict, payload: dict) -> str:
    """Encode JWT with no signature: header.payload."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def _collect_jwts(
    client: DastHTTPClient,
    sitemap: SiteMap,
    target_url: str,
) -> list[tuple[str, str]]:
    """Collect JWT tokens from API endpoint responses.

    Returns list of (token, source_url) tuples.
    Strategy:
    - GET first 10 API endpoints from sitemap
    - Check Authorization headers, Set-Cookie headers, response body
    - Also check target_url itself
    """
    seen_tokens: set[str] = set()
    results: list[tuple[str, str]] = []

    urls_to_check: list[str] = [target_url]
    for ep in sitemap.api_endpoints[:10]:
        urls_to_check.append(ep.url)

    for url in urls_to_check:
        if len(results) >= 5:
            break
        try:
            resp = client.get(url, capture_evidence=False)
        except Exception as exc:
            logger.debug("JWT collection failed for %s: %s", url, exc)
            continue

        # Check Set-Cookie headers for JWT tokens
        for cookie_val in resp.headers.get_all("Set-Cookie", []):
            for match in JWT_BEARER_RE.finditer(cookie_val):
                token = match.group(1)
                if token not in seen_tokens:
                    seen_tokens.add(token)
                    results.append((token, url))
            # Also check raw cookie value for eyJ pattern
            jwt_match = re.search(
                r'(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.'
                r'[A-Za-z0-9_-]*)',
                cookie_val,
            )
            if jwt_match:
                token = jwt_match.group(1)
                if token not in seen_tokens:
                    seen_tokens.add(token)
                    results.append((token, url))

        # Check response body for JWT tokens
        for match in re.finditer(
            r'(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)',
            resp.text,
        ):
            token = match.group(1)
            if token not in seen_tokens:
                seen_tokens.add(token)
                results.append((token, url))

        if len(results) >= 5:
            break

    return results[:5]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Checks
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _check_alg_none(
    client: DastHTTPClient,
    target_url: str,
    tokens: list[tuple[str, str]],
    findings: list[Finding],
) -> None:
    """DAST-JWT-001: Algorithm confusion (none algorithm) — CRITICAL, CWE-347."""
    for token, source_url in tokens:
        decoded = _decode_jwt(token)
        if decoded is None:
            continue
        header, payload, _sig = decoded

        for alg_variant in NONE_ALGORITHMS:
            tampered_header = dict(header)
            tampered_header["alg"] = alg_variant
            modified_token = _encode_jwt_unsigned(tampered_header, payload)

            try:
                resp = client.get(
                    source_url,
                    headers={"Authorization": f"Bearer {modified_token}"},
                    capture_evidence=True,
                )
            except Exception as exc:
                logger.debug(
                    "Check %s failed for %s: %s",
                    "DAST-JWT-001", source_url, exc,
                )
                continue

            if resp.status_code == 200:
                findings.append(_finding(
                    rule_id="DAST-JWT-001",
                    name=(
                        f"JWT algorithm confusion (none) at: "
                        f"{source_url}"
                    ),
                    severity="CRITICAL",
                    file_path=source_url,
                    line_content=(
                        f"alg={alg_variant} accepted with empty "
                        f"signature — HTTP {resp.status_code}"
                    ),
                    description=(
                        f"The server at {source_url} accepts JWT "
                        f"tokens with the algorithm set to "
                        f"'{alg_variant}' and an empty signature. "
                        f"This allows an attacker to forge arbitrary "
                        f"tokens without knowing the signing key, "
                        f"bypassing all authentication and "
                        f"authorization controls."
                    ),
                    recommendation=(
                        "Explicitly validate the JWT algorithm on "
                        "the server side. Reject tokens with "
                        "'none' algorithm. Use an allowlist of "
                        "permitted algorithms (e.g., HS256, RS256) "
                        "and never rely on the token's alg header "
                        "alone."
                    ),
                    cwe="CWE-347",
                    evidence=[{
                        "method": "GET",
                        "url": source_url,
                        "status": resp.status_code,
                        "payload": f"alg={alg_variant}, empty signature",
                        "modified_token": modified_token[:80] + "...",
                    }],
                ))
                return


def _check_signature_stripping(
    client: DastHTTPClient,
    target_url: str,
    tokens: list[tuple[str, str]],
    findings: list[Finding],
) -> None:
    """DAST-JWT-002: Signature stripping — CRITICAL, CWE-347."""
    for token, source_url in tokens:
        parts = token.split(".")
        if len(parts) != 3:
            continue

        # Keep header and payload, remove signature
        stripped_token = f"{parts[0]}.{parts[1]}."

        try:
            resp = client.get(
                source_url,
                headers={"Authorization": f"Bearer {stripped_token}"},
                capture_evidence=True,
            )
        except Exception as exc:
            logger.debug(
                "Check %s failed for %s: %s",
                "DAST-JWT-002", source_url, exc,
            )
            continue

        if resp.status_code == 200:
            findings.append(_finding(
                rule_id="DAST-JWT-002",
                name=(
                    f"JWT signature stripping accepted at: "
                    f"{source_url}"
                ),
                severity="CRITICAL",
                file_path=source_url,
                line_content=(
                    f"Token with empty signature accepted "
                    f"— HTTP {resp.status_code}"
                ),
                description=(
                    f"The server at {source_url} accepts JWT "
                    f"tokens with the signature portion removed. "
                    f"This indicates the server does not verify "
                    f"JWT signatures, allowing an attacker to "
                    f"modify token claims (e.g., user ID, role) "
                    f"without detection."
                ),
                recommendation=(
                    "Always verify the JWT signature on the "
                    "server side before trusting any claims. "
                    "Reject tokens with missing or empty "
                    "signatures. Use a well-tested JWT library "
                    "that enforces signature verification by "
                    "default."
                ),
                cwe="CWE-347",
                evidence=[{
                    "method": "GET",
                    "url": source_url,
                    "status": resp.status_code,
                    "payload": "Signature removed from token",
                    "stripped_token": stripped_token[:80] + "...",
                }],
            ))
            return


def _check_expired_tokens(
    client: DastHTTPClient,
    target_url: str,
    tokens: list[tuple[str, str]],
    findings: list[Finding],
) -> None:
    """DAST-JWT-003: Expired token accepted — HIGH, CWE-613."""
    now = int(time.time())

    for token, source_url in tokens:
        decoded = _decode_jwt(token)
        if decoded is None:
            continue
        _header, payload, _sig = decoded

        exp = payload.get("exp")
        if exp is None:
            continue

        try:
            exp_ts = int(exp)
        except (TypeError, ValueError):
            continue

        if exp_ts >= now:
            # Token is not yet expired, skip
            continue

        # Token is expired — test if server still accepts it
        try:
            resp = client.get(
                source_url,
                headers={"Authorization": f"Bearer {token}"},
                capture_evidence=True,
            )
        except Exception as exc:
            logger.debug(
                "Check %s failed for %s: %s",
                "DAST-JWT-003", source_url, exc,
            )
            continue

        if resp.status_code == 200:
            expired_ago = now - exp_ts
            findings.append(_finding(
                rule_id="DAST-JWT-003",
                name=(
                    f"Expired JWT accepted at: {source_url}"
                ),
                severity="HIGH",
                file_path=source_url,
                line_content=(
                    f"Token expired {expired_ago}s ago still "
                    f"accepted — HTTP {resp.status_code}"
                ),
                description=(
                    f"The server at {source_url} accepts JWT "
                    f"tokens that have expired (exp claim = "
                    f"{exp_ts}, expired {expired_ago} seconds "
                    f"ago). This means session tokens remain "
                    f"valid indefinitely, allowing stolen or "
                    f"leaked tokens to be reused long after they "
                    f"should have been invalidated."
                ),
                recommendation=(
                    "Validate the 'exp' claim on every request "
                    "and reject expired tokens. Use short-lived "
                    "access tokens (5-15 minutes) with refresh "
                    "token rotation. Implement server-side token "
                    "revocation for sensitive operations."
                ),
                cwe="CWE-613",
                evidence=[{
                    "method": "GET",
                    "url": source_url,
                    "status": resp.status_code,
                    "exp_claim": exp_ts,
                    "current_time": now,
                    "expired_seconds_ago": expired_ago,
                }],
            ))
            return


def _check_claim_tampering(
    client: DastHTTPClient,
    target_url: str,
    tokens: list[tuple[str, str]],
    findings: list[Finding],
) -> None:
    """DAST-JWT-004: Claim tampering — CRITICAL, CWE-345."""
    for token, source_url in tokens:
        decoded = _decode_jwt(token)
        if decoded is None:
            continue
        header, payload, _sig = decoded

        for claim_key, claim_value in ADMIN_CLAIMS:
            tampered_payload = dict(payload)
            tampered_payload[claim_key] = claim_value

            tampered_header = dict(header)
            tampered_header["alg"] = "none"
            modified_token = _encode_jwt_unsigned(
                tampered_header, tampered_payload,
            )

            try:
                resp = client.get(
                    source_url,
                    headers={
                        "Authorization": f"Bearer {modified_token}",
                    },
                    capture_evidence=True,
                )
            except Exception as exc:
                logger.debug(
                    "Check %s failed for %s: %s",
                    "DAST-JWT-004", source_url, exc,
                )
                continue

            if resp.status_code == 200:
                findings.append(_finding(
                    rule_id="DAST-JWT-004",
                    name=(
                        f"JWT claim tampering accepted at: "
                        f"{source_url}"
                    ),
                    severity="CRITICAL",
                    file_path=source_url,
                    line_content=(
                        f"Tampered claim {claim_key}="
                        f"{claim_value} accepted "
                        f"— HTTP {resp.status_code}"
                    ),
                    description=(
                        f"The server at {source_url} accepts a "
                        f"JWT token with tampered claims "
                        f"({claim_key}={claim_value}) and the "
                        f"algorithm set to 'none'. An attacker "
                        f"can escalate privileges by modifying "
                        f"role or permission claims in the token "
                        f"without a valid signature."
                    ),
                    recommendation=(
                        "Always verify the JWT signature before "
                        "trusting any claims. Reject tokens with "
                        "'none' algorithm. Validate claim values "
                        "against the authorization backend. Use "
                        "server-side session storage for "
                        "sensitive permissions."
                    ),
                    cwe="CWE-345",
                    evidence=[{
                        "method": "GET",
                        "url": source_url,
                        "status": resp.status_code,
                        "tampered_claim": f"{claim_key}={claim_value}",
                        "modified_token": modified_token[:80] + "...",
                    }],
                ))
                return


def _check_weak_secret(
    client: DastHTTPClient,
    target_url: str,
    tokens: list[tuple[str, str]],
    findings: list[Finding],
) -> None:
    """DAST-JWT-005: Weak signing secret — HIGH, CWE-326."""
    for token, source_url in tokens:
        decoded = _decode_jwt(token)
        if decoded is None:
            continue
        header, _payload, signature = decoded

        alg = header.get("alg", "")
        if not isinstance(alg, str) or not alg.startswith("HS"):
            continue

        # Determine hash algorithm from alg claim
        hash_map = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        hash_func = hash_map.get(alg)
        if hash_func is None:
            continue

        # Extract raw header and payload segments
        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}"

        for secret in WEAK_SECRETS:
            computed = hmac.new(
                secret.encode(),
                signing_input.encode(),
                hash_func,
            ).digest()
            computed_sig = _b64url_encode(computed)

            if computed_sig == signature:
                findings.append(_finding(
                    rule_id="DAST-JWT-005",
                    name=(
                        f"JWT signed with weak secret: "
                        f"'{secret}'"
                    ),
                    severity="HIGH",
                    file_path=source_url,
                    line_content=(
                        f"Token {alg} signature matches weak "
                        f"secret '{secret}'"
                    ),
                    description=(
                        f"The JWT token from {source_url} is "
                        f"signed with the {alg} algorithm using "
                        f"the weak secret '{secret}'. An attacker "
                        f"can use this secret to forge valid "
                        f"tokens with arbitrary claims, fully "
                        f"compromising authentication and "
                        f"authorization."
                    ),
                    recommendation=(
                        "Use a cryptographically strong random "
                        "secret of at least 256 bits for HMAC "
                        "signing. Consider using asymmetric "
                        "algorithms (RS256, ES256) instead of "
                        "shared secrets. Rotate signing keys "
                        "periodically and store them securely "
                        "(e.g., in a secrets manager)."
                    ),
                    cwe="CWE-326",
                    evidence=[{
                        "source_url": source_url,
                        "algorithm": alg,
                        "weak_secret": secret,
                        "token_preview": token[:80] + "...",
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
    """Run all JWT security checks.

    Returns:
        List of Finding objects for any JWT vulnerabilities found.
    """
    findings: list[Finding] = []

    tokens = _collect_jwts(client, sitemap, target_url)
    if not tokens:
        return findings

    _check_alg_none(client, target_url, tokens, findings)
    _check_signature_stripping(client, target_url, tokens, findings)
    _check_expired_tokens(client, target_url, tokens, findings)
    _check_claim_tampering(client, target_url, tokens, findings)
    _check_weak_secret(client, target_url, tokens, findings)

    return findings
