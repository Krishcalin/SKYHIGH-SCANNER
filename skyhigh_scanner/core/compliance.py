"""
Compliance framework mapping engine.

Maps CWE identifiers and finding categories to controls in:
  - NIST SP 800-53 Rev 5
  - ISO 27001:2022
  - PCI DSS v4.0
  - CIS Controls v8

Usage::

    from skyhigh_scanner.core.compliance import enrich_finding, compliance_summary

    enrich_finding(finding)              # mutates finding.compliance
    stats = compliance_summary(findings) # framework → control → count
"""

from __future__ import annotations

# ── Framework metadata ────────────────────────────────────────────────

FRAMEWORKS = {
    "nist_800_53": "NIST SP 800-53 Rev 5",
    "iso_27001": "ISO 27001:2022",
    "pci_dss": "PCI DSS v4.0",
    "cis_controls": "CIS Controls v8",
}

# ── CWE → Framework control mappings ─────────────────────────────────
# Each CWE maps to a dict of {framework_key: [control_ids]}.
# Coverage: ~80 CWEs covering the most common vulnerability classes.

CWE_MAP: dict[str, dict[str, list[str]]] = {
    # ── Injection ──────────────────────────────────────────────────
    "CWE-78": {  # OS Command Injection
        "nist_800_53": ["SI-10", "SI-3"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "CWE-79": {  # Cross-site Scripting (XSS)
        "nist_800_53": ["SI-10", "SI-3"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "CWE-89": {  # SQL Injection
        "nist_800_53": ["SI-10", "SI-3"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "CWE-94": {  # Code Injection
        "nist_800_53": ["SI-10", "SI-3"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "CWE-77": {  # Command Injection
        "nist_800_53": ["SI-10", "SI-3"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "CWE-917": {  # Expression Language Injection (Log4Shell etc.)
        "nist_800_53": ["SI-10", "SI-3"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "CWE-502": {  # Deserialization of Untrusted Data
        "nist_800_53": ["SI-10", "SI-3"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },

    # ── Authentication & Access Control ───────────────────────────
    "CWE-287": {  # Improper Authentication
        "nist_800_53": ["IA-2", "IA-5"],
        "iso_27001": ["A.8.5", "A.5.17"],
        "pci_dss": ["8.3.1", "8.3.6"],
        "cis_controls": ["6.3", "6.5"],
    },
    "CWE-306": {  # Missing Authentication
        "nist_800_53": ["IA-2", "AC-3"],
        "iso_27001": ["A.8.5"],
        "pci_dss": ["8.3.1"],
        "cis_controls": ["6.3"],
    },
    "CWE-284": {  # Improper Access Control
        "nist_800_53": ["AC-3", "AC-6"],
        "iso_27001": ["A.8.3", "A.5.15"],
        "pci_dss": ["7.2.1", "7.2.2"],
        "cis_controls": ["6.1", "6.8"],
    },
    "CWE-269": {  # Improper Privilege Management
        "nist_800_53": ["AC-6", "AC-2"],
        "iso_27001": ["A.8.2", "A.5.15"],
        "pci_dss": ["7.2.1", "7.2.2"],
        "cis_controls": ["5.4", "6.8"],
    },
    "CWE-250": {  # Execution with Unnecessary Privileges
        "nist_800_53": ["AC-6", "CM-7"],
        "iso_27001": ["A.8.2"],
        "pci_dss": ["7.2.1"],
        "cis_controls": ["5.4"],
    },
    "CWE-732": {  # Incorrect Permission Assignment
        "nist_800_53": ["AC-3", "AC-6"],
        "iso_27001": ["A.8.3"],
        "pci_dss": ["7.2.1"],
        "cis_controls": ["6.1"],
    },
    "CWE-276": {  # Incorrect Default Permissions
        "nist_800_53": ["AC-3", "CM-6"],
        "iso_27001": ["A.8.3", "A.8.9"],
        "pci_dss": ["7.2.1", "2.2.1"],
        "cis_controls": ["4.1", "6.1"],
    },

    # ── Password & Credentials ────────────────────────────────────
    "CWE-521": {  # Weak Password Requirements
        "nist_800_53": ["IA-5"],
        "iso_27001": ["A.5.17"],
        "pci_dss": ["8.3.6"],
        "cis_controls": ["5.2"],
    },
    "CWE-262": {  # Not Using Password Aging
        "nist_800_53": ["IA-5"],
        "iso_27001": ["A.5.17"],
        "pci_dss": ["8.3.9"],
        "cis_controls": ["5.2"],
    },
    "CWE-798": {  # Hard-coded Credentials
        "nist_800_53": ["IA-5", "SC-12"],
        "iso_27001": ["A.5.17", "A.8.9"],
        "pci_dss": ["8.3.1", "8.6.1"],
        "cis_controls": ["16.7"],
    },
    "CWE-256": {  # Plaintext Storage of Password
        "nist_800_53": ["IA-5", "SC-28"],
        "iso_27001": ["A.5.17", "A.8.24"],
        "pci_dss": ["8.3.2"],
        "cis_controls": ["3.11"],
    },
    "CWE-522": {  # Insufficiently Protected Credentials
        "nist_800_53": ["IA-5", "SC-8"],
        "iso_27001": ["A.5.17"],
        "pci_dss": ["8.3.2"],
        "cis_controls": ["3.11"],
    },
    "CWE-307": {  # Improper Restriction of Auth Attempts
        "nist_800_53": ["AC-7"],
        "iso_27001": ["A.8.5"],
        "pci_dss": ["8.3.4"],
        "cis_controls": ["6.3"],
    },

    # ── Cryptography ──────────────────────────────────────────────
    "CWE-327": {  # Use of Broken Cryptographic Algorithm
        "nist_800_53": ["SC-13", "SC-12"],
        "iso_27001": ["A.8.24"],
        "pci_dss": ["4.2.1", "2.2.7"],
        "cis_controls": ["3.10"],
    },
    "CWE-326": {  # Inadequate Encryption Strength
        "nist_800_53": ["SC-13"],
        "iso_27001": ["A.8.24"],
        "pci_dss": ["4.2.1"],
        "cis_controls": ["3.10"],
    },
    "CWE-295": {  # Improper Certificate Validation
        "nist_800_53": ["SC-8", "SC-23"],
        "iso_27001": ["A.8.24"],
        "pci_dss": ["4.2.1"],
        "cis_controls": ["3.10"],
    },
    "CWE-319": {  # Cleartext Transmission
        "nist_800_53": ["SC-8"],
        "iso_27001": ["A.8.24"],
        "pci_dss": ["4.2.1"],
        "cis_controls": ["3.10"],
    },
    "CWE-311": {  # Missing Encryption of Sensitive Data
        "nist_800_53": ["SC-28", "SC-8"],
        "iso_27001": ["A.8.24"],
        "pci_dss": ["3.5.1", "4.2.1"],
        "cis_controls": ["3.11"],
    },
    "CWE-330": {  # Insufficient Randomness
        "nist_800_53": ["SC-13"],
        "iso_27001": ["A.8.24"],
        "pci_dss": ["4.2.1"],
        "cis_controls": ["3.10"],
    },

    # ── Information Disclosure ────────────────────────────────────
    "CWE-200": {  # Exposure of Sensitive Information
        "nist_800_53": ["SI-11", "AC-3"],
        "iso_27001": ["A.8.11", "A.5.12"],
        "pci_dss": ["3.4.1", "6.2.4"],
        "cis_controls": ["3.1", "3.4"],
    },
    "CWE-209": {  # Error Info Disclosure
        "nist_800_53": ["SI-11"],
        "iso_27001": ["A.8.11"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "CWE-532": {  # Information Exposure Through Log Files
        "nist_800_53": ["AU-3", "SI-11"],
        "iso_27001": ["A.8.15", "A.8.11"],
        "pci_dss": ["10.3.4"],
        "cis_controls": ["8.3"],
    },
    "CWE-215": {  # Insertion of Sensitive Info Into Debug Code
        "nist_800_53": ["SI-11"],
        "iso_27001": ["A.8.11"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },

    # ── Session Management ────────────────────────────────────────
    "CWE-613": {  # Insufficient Session Expiration
        "nist_800_53": ["AC-12", "SC-23"],
        "iso_27001": ["A.8.5"],
        "pci_dss": ["8.2.8"],
        "cis_controls": ["6.3"],
    },
    "CWE-384": {  # Session Fixation
        "nist_800_53": ["SC-23"],
        "iso_27001": ["A.8.5"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "CWE-614": {  # Sensitive Cookie Without Secure Flag
        "nist_800_53": ["SC-8", "SC-23"],
        "iso_27001": ["A.8.24"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },

    # ── Input Validation ──────────────────────────────────────────
    "CWE-20": {  # Improper Input Validation
        "nist_800_53": ["SI-10"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "CWE-22": {  # Path Traversal
        "nist_800_53": ["SI-10", "AC-3"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "CWE-434": {  # Unrestricted File Upload
        "nist_800_53": ["SI-10", "CM-7"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "CWE-611": {  # XXE
        "nist_800_53": ["SI-10"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "CWE-918": {  # SSRF
        "nist_800_53": ["SI-10", "SC-7"],
        "iso_27001": ["A.8.28", "A.8.20"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "CWE-352": {  # CSRF
        "nist_800_53": ["SI-10", "SC-23"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },

    # ── Configuration & Hardening ─────────────────────────────────
    "CWE-16": {  # Configuration
        "nist_800_53": ["CM-6", "CM-7"],
        "iso_27001": ["A.8.9"],
        "pci_dss": ["2.2.1"],
        "cis_controls": ["4.1"],
    },
    "CWE-1188": {  # Insecure Default Initialization
        "nist_800_53": ["CM-6"],
        "iso_27001": ["A.8.9"],
        "pci_dss": ["2.2.1"],
        "cis_controls": ["4.1"],
    },

    # ── Software Composition / Patching ───────────────────────────
    "CWE-1104": {  # Use of Unmaintained / Outdated Software
        "nist_800_53": ["SI-2", "SA-22"],
        "iso_27001": ["A.8.8", "A.8.19"],
        "pci_dss": ["6.3.3"],
        "cis_controls": ["7.4", "7.5"],
    },
    "CWE-1035": {  # Known Vulnerable Component
        "nist_800_53": ["SI-2", "SA-22"],
        "iso_27001": ["A.8.8"],
        "pci_dss": ["6.3.3"],
        "cis_controls": ["7.4"],
    },
    "CWE-937": {  # Using Components with Known Vulnerabilities (OWASP)
        "nist_800_53": ["SI-2", "SA-22"],
        "iso_27001": ["A.8.8"],
        "pci_dss": ["6.3.3"],
        "cis_controls": ["7.4"],
    },

    # ── Logging & Monitoring ──────────────────────────────────────
    "CWE-778": {  # Insufficient Logging
        "nist_800_53": ["AU-2", "AU-3", "AU-12"],
        "iso_27001": ["A.8.15"],
        "pci_dss": ["10.2.1", "10.2.2"],
        "cis_controls": ["8.2", "8.5"],
    },
    "CWE-223": {  # Omission of Security-relevant Information
        "nist_800_53": ["AU-3"],
        "iso_27001": ["A.8.15"],
        "pci_dss": ["10.2.1"],
        "cis_controls": ["8.5"],
    },
    "CWE-779": {  # Logging of Excessive Data
        "nist_800_53": ["AU-3", "AU-4"],
        "iso_27001": ["A.8.15"],
        "pci_dss": ["10.3.4"],
        "cis_controls": ["8.3"],
    },

    # ── Memory & Buffer Errors ────────────────────────────────────
    "CWE-119": {  # Buffer Errors
        "nist_800_53": ["SI-16"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "CWE-120": {  # Buffer Overflow
        "nist_800_53": ["SI-16"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "CWE-125": {  # Out-of-bounds Read
        "nist_800_53": ["SI-16"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "CWE-787": {  # Out-of-bounds Write
        "nist_800_53": ["SI-16"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "CWE-416": {  # Use After Free
        "nist_800_53": ["SI-16"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "CWE-190": {  # Integer Overflow
        "nist_800_53": ["SI-16"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },

    # ── Network ───────────────────────────────────────────────────
    "CWE-400": {  # Uncontrolled Resource Consumption (DoS)
        "nist_800_53": ["SC-5", "SI-10"],
        "iso_27001": ["A.8.20"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["13.1"],
    },
    "CWE-444": {  # HTTP Request Smuggling
        "nist_800_53": ["SI-10", "SC-7"],
        "iso_27001": ["A.8.28", "A.8.20"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "CWE-601": {  # Open Redirect
        "nist_800_53": ["SI-10"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },

    # ── Race Conditions ───────────────────────────────────────────
    "CWE-362": {  # Race Condition
        "nist_800_53": ["SI-16"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },

    # ── Miscellaneous ─────────────────────────────────────────────
    "CWE-345": {  # Insufficient Verification of Data Authenticity
        "nist_800_53": ["SI-7", "SC-8"],
        "iso_27001": ["A.8.24"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["3.10"],
    },
    "CWE-347": {  # Improper Verification of Cryptographic Signature
        "nist_800_53": ["SI-7", "SC-13"],
        "iso_27001": ["A.8.24"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["3.10"],
    },
}


# ── Category → Framework fallback mappings ────────────────────────────
# Used when a finding has no CWE or the CWE isn't in CWE_MAP.
# Keys are substrings matched against finding.category (case-insensitive).

CATEGORY_MAP: dict[str, dict[str, list[str]]] = {
    "authentication": {
        "nist_800_53": ["IA-2", "IA-5"],
        "iso_27001": ["A.8.5", "A.5.17"],
        "pci_dss": ["8.3.1"],
        "cis_controls": ["6.3", "6.5"],
    },
    "password": {
        "nist_800_53": ["IA-5"],
        "iso_27001": ["A.5.17"],
        "pci_dss": ["8.3.6"],
        "cis_controls": ["5.2"],
    },
    "access control": {
        "nist_800_53": ["AC-3", "AC-6"],
        "iso_27001": ["A.8.3", "A.5.15"],
        "pci_dss": ["7.2.1"],
        "cis_controls": ["6.1", "6.8"],
    },
    "privilege": {
        "nist_800_53": ["AC-6"],
        "iso_27001": ["A.8.2"],
        "pci_dss": ["7.2.1"],
        "cis_controls": ["5.4"],
    },
    "encryption": {
        "nist_800_53": ["SC-13", "SC-8"],
        "iso_27001": ["A.8.24"],
        "pci_dss": ["4.2.1"],
        "cis_controls": ["3.10"],
    },
    "tls": {
        "nist_800_53": ["SC-8", "SC-13"],
        "iso_27001": ["A.8.24"],
        "pci_dss": ["4.2.1"],
        "cis_controls": ["3.10"],
    },
    "ssh": {
        "nist_800_53": ["SC-8", "IA-2"],
        "iso_27001": ["A.8.24", "A.8.5"],
        "pci_dss": ["4.2.1", "8.3.1"],
        "cis_controls": ["3.10", "6.3"],
    },
    "logging": {
        "nist_800_53": ["AU-2", "AU-3", "AU-12"],
        "iso_27001": ["A.8.15"],
        "pci_dss": ["10.2.1"],
        "cis_controls": ["8.2", "8.5"],
    },
    "audit": {
        "nist_800_53": ["AU-2", "AU-12"],
        "iso_27001": ["A.8.15"],
        "pci_dss": ["10.2.1"],
        "cis_controls": ["8.2"],
    },
    "patch": {
        "nist_800_53": ["SI-2"],
        "iso_27001": ["A.8.8"],
        "pci_dss": ["6.3.3"],
        "cis_controls": ["7.4"],
    },
    "known cve": {
        "nist_800_53": ["SI-2", "SA-22"],
        "iso_27001": ["A.8.8"],
        "pci_dss": ["6.3.3"],
        "cis_controls": ["7.4"],
    },
    "version": {
        "nist_800_53": ["SI-2"],
        "iso_27001": ["A.8.8"],
        "pci_dss": ["6.3.3"],
        "cis_controls": ["7.4"],
    },
    "eol": {
        "nist_800_53": ["SA-22"],
        "iso_27001": ["A.8.8", "A.8.19"],
        "pci_dss": ["6.3.3"],
        "cis_controls": ["7.5"],
    },
    "configuration": {
        "nist_800_53": ["CM-6", "CM-7"],
        "iso_27001": ["A.8.9"],
        "pci_dss": ["2.2.1"],
        "cis_controls": ["4.1"],
    },
    "hardening": {
        "nist_800_53": ["CM-6", "CM-7"],
        "iso_27001": ["A.8.9"],
        "pci_dss": ["2.2.1"],
        "cis_controls": ["4.1"],
    },
    "service": {
        "nist_800_53": ["CM-7"],
        "iso_27001": ["A.8.9"],
        "pci_dss": ["2.2.5"],
        "cis_controls": ["4.8"],
    },
    "network": {
        "nist_800_53": ["SC-7"],
        "iso_27001": ["A.8.20", "A.8.21"],
        "pci_dss": ["1.3.1"],
        "cis_controls": ["13.1"],
    },
    "firewall": {
        "nist_800_53": ["SC-7"],
        "iso_27001": ["A.8.20"],
        "pci_dss": ["1.2.1", "1.3.1"],
        "cis_controls": ["13.1"],
    },
    "snmp": {
        "nist_800_53": ["CM-6", "IA-2"],
        "iso_27001": ["A.8.9"],
        "pci_dss": ["2.2.1"],
        "cis_controls": ["4.1"],
    },
    "banner": {
        "nist_800_53": ["AC-8"],
        "iso_27001": ["A.8.9"],
        "pci_dss": ["2.2.1"],
        "cis_controls": ["4.1"],
    },
    "discovery": {
        "nist_800_53": ["CM-7"],
        "iso_27001": ["A.8.9"],
        "pci_dss": ["2.2.5"],
        "cis_controls": ["4.8"],
    },
    "ntp": {
        "nist_800_53": ["AU-8"],
        "iso_27001": ["A.8.17"],
        "pci_dss": ["10.6.1"],
        "cis_controls": ["8.4"],
    },
    "routing": {
        "nist_800_53": ["SC-7", "SC-8"],
        "iso_27001": ["A.8.20"],
        "pci_dss": ["1.3.1"],
        "cis_controls": ["13.1"],
    },
    "layer 2": {
        "nist_800_53": ["SC-7"],
        "iso_27001": ["A.8.20"],
        "pci_dss": ["1.3.1"],
        "cis_controls": ["13.1"],
    },
    "session": {
        "nist_800_53": ["AC-12", "SC-23"],
        "iso_27001": ["A.8.5"],
        "pci_dss": ["8.2.8"],
        "cis_controls": ["6.3"],
    },
    "injection": {
        "nist_800_53": ["SI-10"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "xss": {
        "nist_800_53": ["SI-10"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "csrf": {
        "nist_800_53": ["SI-10", "SC-23"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "file upload": {
        "nist_800_53": ["SI-10", "CM-7"],
        "iso_27001": ["A.8.28"],
        "pci_dss": ["6.2.4"],
        "cis_controls": ["16.12"],
    },
    "data protection": {
        "nist_800_53": ["SC-28", "SC-8"],
        "iso_27001": ["A.8.24", "A.5.12"],
        "pci_dss": ["3.4.1", "3.5.1"],
        "cis_controls": ["3.11"],
    },
    "backup": {
        "nist_800_53": ["CP-9"],
        "iso_27001": ["A.8.13"],
        "pci_dss": ["9.4.1"],
        "cis_controls": ["11.2"],
    },
    "mfa": {
        "nist_800_53": ["IA-2"],
        "iso_27001": ["A.8.5"],
        "pci_dss": ["8.4.2"],
        "cis_controls": ["6.3", "6.5"],
    },
    "management": {
        "nist_800_53": ["CM-6", "AC-3"],
        "iso_27001": ["A.8.9"],
        "pci_dss": ["2.2.1"],
        "cis_controls": ["4.1"],
    },
}


# ── Core mapping functions ────────────────────────────────────────────

def _extract_cwe_id(cwe: str | None) -> str | None:
    """Normalise a CWE string to 'CWE-NNN' format.

    Handles: 'CWE-89', 'cwe-89', '89', 'CWE89'.
    """
    if not cwe:
        return None
    cwe = cwe.strip().upper()
    # Strip "CWE" or "CWE-" prefix and re-add consistently
    if cwe.startswith("CWE-"):
        return cwe
    if cwe.startswith("CWE"):
        return f"CWE-{cwe[3:]}"
    if cwe.isdigit():
        return f"CWE-{cwe}"
    return None


def _lookup_cwe(cwe_id: str) -> dict[str, list[str]]:
    """Look up a CWE ID in the mapping table."""
    return CWE_MAP.get(cwe_id, {})


def _lookup_category(category: str) -> dict[str, list[str]]:
    """Match a finding category against CATEGORY_MAP (substring, case-insensitive)."""
    cat_lower = category.lower()
    for key, mapping in CATEGORY_MAP.items():
        if key in cat_lower:
            return mapping
    return {}


def map_finding(cwe: str | None = None,
                category: str = "") -> dict[str, list[str]]:
    """Resolve compliance controls for a finding.

    Tries CWE-based mapping first; falls back to category-based mapping.

    Returns:
        Dict of {framework_key: [control_ids]} or empty dict.
    """
    cwe_id = _extract_cwe_id(cwe)
    if cwe_id:
        result = _lookup_cwe(cwe_id)
        if result:
            return result
    return _lookup_category(category)


def enrich_finding(finding) -> None:
    """Enrich a Finding object with compliance mapping data.

    Sets ``finding.compliance`` to a dict of {framework_key: [control_ids]}.
    """
    mapping = map_finding(cwe=finding.cwe, category=finding.category)
    if mapping:
        finding.compliance = mapping


def enrich_findings(findings: list) -> int:
    """Enrich a list of Finding objects with compliance data.

    Returns:
        Number of findings that received compliance mappings.
    """
    count = 0
    for f in findings:
        mapping = map_finding(cwe=f.cwe, category=f.category)
        if mapping:
            f.compliance = mapping
            count += 1
    return count


# ── Reporting helpers ─────────────────────────────────────────────────

def compliance_summary(findings: list,
                       frameworks: list[str] | None = None) -> dict[str, dict[str, int]]:
    """Aggregate compliance control counts across all findings.

    Args:
        findings: List of Finding objects (must have .compliance set).
        frameworks: Optional list of framework keys to include.
                    Defaults to all frameworks.

    Returns:
        ``{framework_key: {control_id: finding_count}}`` sorted by count desc.
    """
    fw_keys = frameworks or list(FRAMEWORKS.keys())
    result: dict[str, dict[str, int]] = {}

    for fw in fw_keys:
        controls: dict[str, int] = {}
        for f in findings:
            comp = getattr(f, "compliance", None)
            if not comp:
                continue
            for ctrl in comp.get(fw, []):
                controls[ctrl] = controls.get(ctrl, 0) + 1
        # Sort by count descending
        result[fw] = dict(sorted(controls.items(), key=lambda x: -x[1]))

    return result


def filter_by_framework(findings: list, framework: str,
                        controls: list[str] | None = None) -> list:
    """Filter findings to those mapped to a specific framework.

    Args:
        findings: List of Finding objects.
        framework: Framework key (e.g. 'pci_dss').
        controls: Optional list of specific control IDs to filter by.

    Returns:
        Filtered list of findings.
    """
    result = []
    for f in findings:
        comp = getattr(f, "compliance", None)
        if not comp:
            continue
        ctrls = comp.get(framework, [])
        if not ctrls:
            continue
        if controls:
            if any(c in controls for c in ctrls):
                result.append(f)
        else:
            result.append(f)
    return result


def format_controls(compliance: dict[str, list[str]] | None,
                    framework: str | None = None) -> str:
    """Format compliance controls as a human-readable string.

    Args:
        compliance: The compliance dict from a Finding.
        framework: If set, only show controls for this framework.

    Returns:
        Formatted string like 'NIST: SI-10, SI-3 | PCI: 6.2.4'.
    """
    if not compliance:
        return ""

    short_names = {
        "nist_800_53": "NIST",
        "iso_27001": "ISO",
        "pci_dss": "PCI",
        "cis_controls": "CIS",
    }

    if framework:
        ctrls = compliance.get(framework, [])
        label = short_names.get(framework, framework)
        return f"{label}: {', '.join(ctrls)}" if ctrls else ""

    parts = []
    for fw, ctrls in compliance.items():
        if ctrls:
            label = short_names.get(fw, fw)
            parts.append(f"{label}: {', '.join(ctrls)}")
    return " | ".join(parts)
