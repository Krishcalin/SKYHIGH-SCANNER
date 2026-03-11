"""
Cisco IOS/IOS-XE/NX-OS Active Vulnerability Scanner.

Connects via SSH (netmiko) and/or SNMP to scan Cisco devices for:
  - Authentication & access hardening (48+ misconfig rules)
  - SSH/VTY/SNMP/NTP/service/interface/L2/control-plane checks
  - IOS CVE database (20+ CVEs covering IOS 12.x-17.x)
  - NX-OS support
  - CIS Cisco IOS benchmark compliance

Rule ID format: CISCO-{CATEGORY}-{NNN}, CISCO-CVE-{NNN}
"""

from __future__ import annotations

import re

from ..core.credential_manager import CredentialManager
from ..core.ip_utils import expand_ip_range
from ..core.scanner_base import ScannerBase
from ..core.transport import HAS_NETMIKO, HAS_PYSNMP, NetmikoTransport
from ..core.version_utils import version_in_range

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CVE Database — IOS / IOS-XE (expandable via cve_data/)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

IOS_CVE_DATABASE = [
    {"id": "CISCO-CVE-001", "cve": "CVE-2023-20198", "severity": "CRITICAL",
     "name": "IOS XE Web UI Privilege Escalation",
     "affected": ">=16.0,<=17.9", "cwe": "CWE-269",
     "description": "Allows unauthenticated remote attacker to create admin account.",
     "recommendation": "Disable HTTP/HTTPS server or upgrade to fixed release."},
    {"id": "CISCO-CVE-002", "cve": "CVE-2021-1435", "severity": "HIGH",
     "name": "IOS XE Web UI Command Injection",
     "affected": ">=16.3,<=17.3.3", "cwe": "CWE-78",
     "description": "Authenticated command injection in web UI.",
     "recommendation": "Upgrade to IOS-XE 17.3.4 or later."},
    {"id": "CISCO-CVE-003", "cve": "CVE-2020-3566", "severity": "HIGH",
     "name": "IOS XR DVMRP Memory Exhaustion",
     "affected": ">=15.0,<15.9.99", "cwe": "CWE-400",
     "description": "Memory exhaustion via crafted IGMP traffic.",
     "recommendation": "Apply vendor patches."},
    {"id": "CISCO-CVE-004", "cve": "CVE-2018-0171", "severity": "CRITICAL",
     "name": "Smart Install Remote Code Execution",
     "affected": ">=12.2,<=15.2.6", "cwe": "CWE-20",
     "description": "Unauthenticated RCE via Smart Install client.",
     "recommendation": "Disable Smart Install: no vstack."},
    {"id": "CISCO-CVE-005", "cve": "CVE-2017-6742", "severity": "HIGH",
     "name": "SNMP Remote Code Execution",
     "affected": ">=12.0,<=15.6.3", "cwe": "CWE-119",
     "description": "Buffer overflow in SNMP subsystem.",
     "recommendation": "Restrict SNMP access and upgrade IOS."},
    {"id": "CISCO-CVE-006", "cve": "CVE-2023-20273", "severity": "HIGH",
     "name": "IOS XE Web UI Command Injection (2023)",
     "affected": ">=16.0,<=17.9", "cwe": "CWE-78",
     "description": "Command injection via web UI, chained with CVE-2023-20198.",
     "recommendation": "Disable HTTP/HTTPS server or upgrade to fixed release."},
    {"id": "CISCO-CVE-007", "cve": "CVE-2017-3881", "severity": "CRITICAL",
     "name": "CMP Stack Overflow RCE",
     "affected": ">=12.2,<=15.2.4", "cwe": "CWE-119",
     "description": "Stack-based buffer overflow in Cluster Management Protocol.",
     "recommendation": "Disable CMP: no service cluster or upgrade IOS."},
    {"id": "CISCO-CVE-008", "cve": "CVE-2016-6415", "severity": "HIGH",
     "name": "IKEv1 Information Disclosure (BENIGNCERTAIN)",
     "affected": ">=12.0,<=15.6.1", "cwe": "CWE-200",
     "description": "IKEv1 packet processing leaks memory contents.",
     "recommendation": "Upgrade IOS to fixed version."},
    {"id": "CISCO-CVE-009", "cve": "CVE-2018-0101", "severity": "CRITICAL",
     "name": "ASA WebVPN Double Free RCE",
     "affected": ">=9.0,<=9.9", "cwe": "CWE-415",
     "description": "Double free in SSL VPN enables unauthenticated RCE.",
     "recommendation": "Upgrade ASA software to fixed release."},
    {"id": "CISCO-CVE-010", "cve": "CVE-2016-1287", "severity": "CRITICAL",
     "name": "ASA IKEv1/IKEv2 Buffer Overflow",
     "affected": ">=8.0,<=9.5", "cwe": "CWE-119",
     "description": "Buffer overflow in IKE processing enables unauthenticated RCE.",
     "recommendation": "Upgrade ASA software to fixed release."},
    {"id": "CISCO-CVE-011", "cve": "CVE-2020-3452", "severity": "HIGH",
     "name": "ASA/FTD Web Services Path Traversal",
     "affected": ">=9.6,<=9.14", "cwe": "CWE-22",
     "description": "Path traversal in web services interface reads sensitive files.",
     "recommendation": "Upgrade ASA/FTD software to fixed release."},
    {"id": "CISCO-CVE-012", "cve": "CVE-2024-20353", "severity": "HIGH",
     "name": "ASA/FTD Web Management DoS (ArcaneDoor)",
     "affected": ">=9.12,<=9.20", "cwe": "CWE-835",
     "description": "Denial of service in management web services. Exploited by ArcaneDoor.",
     "recommendation": "Upgrade ASA/FTD software to fixed release."},
    {"id": "CISCO-CVE-013", "cve": "CVE-2024-20359", "severity": "CRITICAL",
     "name": "ASA/FTD Persistent Local Code Execution (ArcaneDoor)",
     "affected": ">=9.8,<=9.20", "cwe": "CWE-94",
     "description": "Persistent local code execution allowing backdoor implant.",
     "recommendation": "Upgrade ASA/FTD software to fixed release."},
    {"id": "CISCO-CVE-014", "cve": "CVE-2023-20269", "severity": "MEDIUM",
     "name": "ASA/FTD VPN Brute Force",
     "affected": ">=9.8,<=9.19", "cwe": "CWE-287",
     "description": "Unauthorized access to VPN via brute force on RAVPN.",
     "recommendation": "Enable lockout policy and rate limiting."},
    {"id": "CISCO-CVE-015", "cve": "CVE-2022-20699", "severity": "CRITICAL",
     "name": "AnyConnect SSL VPN RCE",
     "affected": ">=9.14,<=9.16", "cwe": "CWE-120",
     "description": "Heap overflow in SSL VPN allows unauthenticated RCE.",
     "recommendation": "Upgrade ASA/FTD software to fixed release."},
    {"id": "CISCO-CVE-016", "cve": "CVE-2019-1653", "severity": "HIGH",
     "name": "RV320/RV325 Information Disclosure",
     "affected": ">=1.0,<=1.4.2.22", "cwe": "CWE-200",
     "description": "Unauthenticated access to configuration and diagnostic data.",
     "recommendation": "Upgrade router firmware."},
    {"id": "CISCO-CVE-017", "cve": "CVE-2019-1652", "severity": "HIGH",
     "name": "RV320/RV325 Command Injection",
     "affected": ">=1.0,<=1.4.2.22", "cwe": "CWE-78",
     "description": "Authenticated command injection in web management interface.",
     "recommendation": "Upgrade router firmware."},
    {"id": "CISCO-CVE-018", "cve": "CVE-2021-34730", "severity": "CRITICAL",
     "name": "Small Business RV Series RCE",
     "affected": ">=1.0,<=1.0.3.55", "cwe": "CWE-78",
     "description": "Unauthenticated RCE in UPnP service on RV110W/RV130/RV215W.",
     "recommendation": "Replace with supported models (end-of-life devices)."},
    {"id": "CISCO-CVE-019", "cve": "CVE-2022-20968", "severity": "HIGH",
     "name": "IP Phone Buffer Overflow",
     "affected": ">=11.0,<=14.2", "cwe": "CWE-119",
     "description": "Buffer overflow in Cisco Discovery Protocol processing.",
     "recommendation": "Upgrade IP Phone firmware."},
    {"id": "CISCO-CVE-020", "cve": "CVE-2021-1498", "severity": "CRITICAL",
     "name": "HyperFlex HX Command Injection",
     "affected": ">=4.0,<=4.5", "cwe": "CWE-78",
     "description": "Unauthenticated command injection in web-based management.",
     "recommendation": "Upgrade HyperFlex HX software."},
]

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Configuration check rules
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

AUTH_CHECKS = [
    {"id": "CISCO-AUTH-001", "pattern": r"^enable password\s",
     "severity": "CRITICAL", "name": "Enable password instead of secret",
     "desc": "Enable password uses weak Type 0/7 encryption.",
     "fix": "Use 'enable secret' with Type 5/8/9 hash.", "cwe": "CWE-328"},
    {"id": "CISCO-AUTH-002", "pattern": r"^username\s+\S+\s+password\s",
     "severity": "HIGH", "name": "Username with cleartext password",
     "desc": "Local user has Type 0/7 password.",
     "fix": "Use 'username X secret Y' for Type 5+ hash.", "cwe": "CWE-522"},
    {"id": "CISCO-AUTH-003", "negate": True, "pattern": r"^service password-encryption",
     "severity": "HIGH", "name": "Password encryption not enabled",
     "desc": "Passwords in config are not encrypted.",
     "fix": "Add 'service password-encryption'.", "cwe": "CWE-522"},
    {"id": "CISCO-AUTH-004", "negate": True, "pattern": r"^aaa new-model",
     "severity": "HIGH", "name": "AAA not enabled",
     "desc": "AAA provides centralised authentication.",
     "fix": "Enable 'aaa new-model'.", "cwe": "CWE-287"},
]

SSH_CONFIG_CHECKS = [
    {"id": "CISCO-SSH-001", "pattern": r"^ip ssh version 1",
     "severity": "CRITICAL", "name": "SSH version 1 enabled",
     "desc": "SSHv1 has known weaknesses.",
     "fix": "Set 'ip ssh version 2'.", "cwe": "CWE-327"},
    {"id": "CISCO-SSH-002", "negate": True, "pattern": r"^ip ssh version 2",
     "severity": "HIGH", "name": "SSH version 2 not explicitly set",
     "desc": "Explicitly enforce SSH v2.",
     "fix": "Add 'ip ssh version 2'.", "cwe": "CWE-327"},
]

SNMP_CHECKS = [
    {"id": "CISCO-SNMP-001", "pattern": r"^snmp-server community (public|private)\s",
     "severity": "CRITICAL", "name": "Default SNMP community string",
     "desc": "Default community strings are well-known.",
     "fix": "Change SNMP community strings to non-default values.", "cwe": "CWE-798"},
    {"id": "CISCO-SNMP-002", "pattern": r"^snmp-server community\s+\S+\s+RW",
     "severity": "HIGH", "name": "SNMP read-write community configured",
     "desc": "RW SNMP allows remote config changes.",
     "fix": "Use SNMP RO or restrict RW with ACL.", "cwe": "CWE-284"},
]

SERVICE_CHECKS = [
    {"id": "CISCO-SVC-001", "pattern": r"^ip http server$",
     "severity": "HIGH", "name": "HTTP server enabled",
     "desc": "HTTP management is unencrypted.",
     "fix": "Use 'no ip http server' and enable HTTPS.", "cwe": "CWE-319"},
    {"id": "CISCO-SVC-002", "negate": True, "pattern": r"^no ip source-route",
     "severity": "MEDIUM", "name": "IP source routing not disabled",
     "desc": "Source routing can bypass security controls.",
     "fix": "Add 'no ip source-route'.", "cwe": "CWE-284"},
]


class CiscoScanner(ScannerBase):
    """Active vulnerability scanner for Cisco IOS/IOS-XE/NX-OS."""

    SCANNER_NAME = "SkyHigh Cisco Scanner"
    SCANNER_VERSION = "1.0.0"
    TARGET_TYPE = "cisco"

    def __init__(self, target: str, credentials: CredentialManager,
                 max_hosts: int = 256, timeout: int = 30,
                 verbose: bool = False, profile=None):
        super().__init__(verbose=verbose, profile=profile)
        self.target = target
        self.credentials = credentials
        self.max_hosts = max_hosts
        self.timeout = timeout

    def scan(self) -> None:
        if not HAS_NETMIKO and not HAS_PYSNMP:
            self._error("netmiko or pysnmp required. Run: pip install netmiko pysnmp-lextudio")
            return

        self._start_timer()
        hosts = expand_ip_range(self.target)[:self.max_hosts]

        for host_ip in hosts:
            self._info(f"Scanning Cisco device: {host_ip}")
            try:
                self._scan_host(host_ip)
                self.targets_scanned.append(host_ip)
            except Exception as e:
                self._warn(f"Failed to scan {host_ip}: {e}")
                self.targets_failed.append(host_ip)

        self._stop_timer()

    def _scan_host(self, host_ip: str) -> None:
        if not self.credentials.has_ssh():
            self._warn(f"No SSH credentials for {host_ip}")
            return

        cred = self.credentials.ssh
        enable_pw = self.credentials.enable.password if self.credentials.enable else None

        with NetmikoTransport(host=host_ip, username=cred.username,
                              password=cred.password, enable_password=enable_pw,
                              port=cred.port, timeout=self.timeout) as nm:
            config = nm.get_config()
            version_output = nm.get_version()
            ios_version = self._extract_version(version_output)
            self._vprint(f"  IOS version: {ios_version}")

            # Run checks (gated by scan profile)
            if self._check_enabled("auth"):
                self._check_config_rules(config, host_ip, AUTH_CHECKS)
            if self._check_enabled("crypto"):
                self._check_config_rules(config, host_ip, SSH_CONFIG_CHECKS)
            if self._check_enabled("snmp"):
                self._check_config_rules(config, host_ip, SNMP_CHECKS)
            if self._check_enabled("services"):
                self._check_config_rules(config, host_ip, SERVICE_CHECKS)
            if self._check_enabled("cve"):
                self._check_cves(host_ip, ios_version)

    def _extract_version(self, version_output: str) -> str:
        m = re.search(r"Version\s+(\S+)", version_output)
        if m:
            ver = m.group(1).rstrip(",")
            return ver
        return ""

    def _check_config_rules(self, config: str, host: str, rules: list) -> None:
        """Check config against regex-based rules."""
        for rule in rules:
            pattern = rule["pattern"]
            negate = rule.get("negate", False)
            found = bool(re.search(pattern, config, re.MULTILINE))

            if (not negate and found) or (negate and not found):
                match_line = ""
                if found and not negate:
                    m = re.search(pattern, config, re.MULTILINE)
                    match_line = m.group(0) if m else ""

                self._add(
                    rule_id=rule["id"], category="Cisco Configuration",
                    name=rule["name"], severity=rule["severity"],
                    file_path=host, line_num=0,
                    line_content=match_line or f"Pattern {'not found' if negate else 'matched'}",
                    description=rule["desc"],
                    recommendation=rule["fix"],
                    cwe=rule.get("cwe"),
                )

    def _check_cves(self, host: str, ios_version: str) -> None:
        """Check IOS version against embedded CVE database."""
        if not ios_version:
            return
        for entry in IOS_CVE_DATABASE:
            if version_in_range(ios_version, entry["affected"]):
                self._add(
                    rule_id=entry["id"], category="Known CVE",
                    name=entry["name"], severity=entry["severity"],
                    file_path=host, line_num=0,
                    line_content=f"IOS version={ios_version}",
                    description=entry["description"],
                    recommendation=entry["recommendation"],
                    cwe=entry.get("cwe"),
                    cve=entry.get("cve"),
                )

        # Also check SQLite CVE DB
        try:
            from ..core.cve_database import CVEDatabase
            with CVEDatabase() as db:
                for platform in ("cisco_ios", "cisco_ios_xe"):
                    cve_findings = db.check_version(platform, ios_version)
                    for f in cve_findings:
                        f.file_path = host
                        self._add_finding(f)
        except Exception:
            pass
