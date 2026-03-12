"""
WAF (Web Application Firewall) detection utility for DAST scanning.

Probes the target with benign and known-bad requests to identify WAF
presence.  Returns a ``WAFInfo`` object — produces **no** findings.
Called from ``dast_scanner.py`` between crawl and check dispatch.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlencode, urlparse, urlunparse

if TYPE_CHECKING:
    from .http_client import DastHTTPClient

logger = logging.getLogger(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# WAFInfo dataclass
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class WAFInfo:
    """Result of WAF detection probing."""

    detected: bool = False
    name: str = ""
    confidence: str = ""          # "high", "medium", "low"
    evidence: list[str] = field(default_factory=list)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# WAF signature database
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WAF_SIGNATURES: list[dict] = [
    {
        "name": "Cloudflare",
        "headers": {"cf-ray": r".+", "cf-cache-status": r".+", "server": r"(?i)cloudflare"},
        "cookies": ["__cfduid", "cf_clearance"],
        "body_patterns": [],
        "status_codes": [403],
    },
    {
        "name": "AWS WAF",
        "headers": {"x-amzn-waf-action": r".+", "x-amzn-requestid": r".+"},
        "cookies": [],
        "body_patterns": [
            re.compile(r"ERROR:\s*The request could not be satisfied", re.I),
            re.compile(r"Request\s+blocked", re.I),
        ],
        "status_codes": [403],
    },
    {
        "name": "Imperva/Incapsula",
        "headers": {"x-cdn": r"(?i)imperva", "x-iinfo": r".+"},
        "cookies": ["incap_ses_", "visid_incap_"],
        "body_patterns": [],
        "status_codes": [403],
    },
    {
        "name": "Akamai",
        "headers": {"x-akamai-transformed": r".+", "server": r"(?i)AkamaiGHost"},
        "cookies": ["ak_bmsc", "bm_sz"],
        "body_patterns": [],
        "status_codes": [403],
    },
    {
        "name": "ModSecurity",
        "headers": {},
        "cookies": [],
        "body_patterns": [
            re.compile(r"ModSecurity|Mod_Security|NOYB", re.I),
        ],
        "status_codes": [403, 406],
    },
    {
        "name": "F5 BIG-IP",
        "headers": {"x-wa-info": r".+", "server": r"(?i)BigIP"},
        "cookies": ["BIGipServer", "TS"],
        "body_patterns": [],
        "status_codes": [403],
    },
    {
        "name": "Sucuri",
        "headers": {"x-sucuri-id": r".+", "server": r"(?i)Sucuri"},
        "cookies": [],
        "body_patterns": [re.compile(r"Sucuri WebSite Firewall", re.I)],
        "status_codes": [403],
    },
    {
        "name": "Barracuda",
        "headers": {"server": r"(?i)Barracuda"},
        "cookies": ["barra_counter_session"],
        "body_patterns": [],
        "status_codes": [403],
    },
]

_XSS_PROBE = "<script>alert(1)</script>"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Internal probes
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _probe_waf_headers(
    client: DastHTTPClient, target_url: str,
) -> list[tuple[str, str]]:
    """Check response headers and cookies for WAF signatures.

    Returns list of ``(waf_name, evidence_string)`` tuples.
    """
    resp = client.get(target_url)
    matches: list[tuple[str, str]] = []
    hdrs = {k.lower(): v for k, v in resp.headers.items()}
    cookie_str = resp.headers.get("set-cookie", "")

    for sig in WAF_SIGNATURES:
        for hdr_name, pattern in sig["headers"].items():
            value = hdrs.get(hdr_name.lower(), "")
            if value and re.search(pattern, value):
                matches.append((sig["name"], f"header {hdr_name}: {value}"))
        for cookie_sub in sig["cookies"]:
            if cookie_sub.lower() in cookie_str.lower():
                matches.append((sig["name"], f"cookie matching '{cookie_sub}'"))
    return matches


def _probe_waf_block(
    client: DastHTTPClient, target_url: str,
) -> list[tuple[str, str]]:
    """Send known-bad payload and check for WAF block response.

    Appends ``?skyhigh_waf_test=<script>alert(1)</script>`` to *target_url*.
    Returns list of ``(waf_name, evidence_string)`` tuples.
    """
    parsed = urlparse(target_url)
    sep = "&" if parsed.query else ""
    probe_url = urlunparse(parsed._replace(
        query=parsed.query + sep + urlencode({"skyhigh_waf_test": _XSS_PROBE}),
    ))

    resp = client.get(probe_url)
    matches: list[tuple[str, str]] = []
    body = resp.text or ""

    for sig in WAF_SIGNATURES:
        if resp.status_code in sig["status_codes"] and sig["body_patterns"]:
            for pat in sig["body_patterns"]:
                if pat.search(body):
                    matches.append((sig["name"], f"block page matched (HTTP {resp.status_code})"))
                    break
    return matches


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Public API
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def detect_waf(client: DastHTTPClient, target_url: str) -> WAFInfo:
    """Detect WAF by probing target with benign and known-bad requests.

    Strategy:
      1. ``_probe_waf_headers()`` — GET target, check response headers/cookies.
      2. ``_probe_waf_block()``   — GET with XSS payload, check for block.
    """
    try:
        header_matches = _probe_waf_headers(client, target_url)
    except Exception:
        logger.debug("WAF header probe failed for %s", target_url, exc_info=True)
        header_matches = []

    try:
        block_matches = _probe_waf_block(client, target_url)
    except Exception:
        logger.debug("WAF block probe failed for %s", target_url, exc_info=True)
        block_matches = []

    # Aggregate by WAF name
    header_names = {name for name, _ in header_matches}

    all_evidence: dict[str, list[str]] = {}
    all_confidence: dict[str, str] = {}

    for name, ev in header_matches:
        all_evidence.setdefault(name, []).append(ev)
        all_confidence[name] = "high"

    for name, ev in block_matches:
        all_evidence.setdefault(name, []).append(ev)
        if name in header_names:
            all_confidence[name] = "high"
        elif name not in all_confidence:
            all_confidence[name] = "medium"

    if not all_confidence:
        logger.debug("No WAF detected for %s", target_url)
        return WAFInfo()

    # Pick the WAF with highest confidence, then most evidence
    conf_rank = {"high": 3, "medium": 2, "low": 1}
    best = max(
        all_confidence,
        key=lambda n: (conf_rank.get(all_confidence[n], 0), len(all_evidence.get(n, []))),
    )

    info = WAFInfo(
        detected=True,
        name=best,
        confidence=all_confidence[best],
        evidence=all_evidence[best],
    )
    logger.info("WAF detected: %s (confidence=%s)", info.name, info.confidence)
    return info
